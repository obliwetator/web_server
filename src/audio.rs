use std::{fs, io::Write, path::Path, process::Stdio};

use actix_files::NamedFile;
use actix_web::{
    get,
    http::header::{ContentDisposition, DispositionParam, DispositionType},
    web, Either, HttpRequest, HttpResponse, Responder,
};

use serde::Deserialize;
use serde_json::json;
use sqlx::{Pool, Postgres};

use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::{
    DBErrors, HashMapContainer, StartEnd, CLIPS_PATH, NO_SILENCE_RECORDING_PATH, RECORDING_PATH,
};

#[get("/audio/waveform/{file}")]
async fn get_waveform_data(req: HttpRequest, path: web::Path<String>) -> impl Responder {
    let file_name = path.into_inner();
    match NamedFile::open_async(format!("{}{}", CLIPS_PATH, file_name)).await {
        Ok(ok) => ok
            .use_last_modified(true)
            .set_content_disposition(ContentDisposition {
                disposition: DispositionType::Attachment,
                parameters: vec![DispositionParam::Filename(file_name)],
            })
            .into_response(&req),
        Err(_) => HttpResponse::NotFound().body("File not found"),
    }
}

async fn _get_file(path: web::Path<(i64, i64, i32, String, String)>) -> NamedFile {
    let (guild_id, channel_id, year, month, file_name_from_url) = path.into_inner();

    match NamedFile::open(format!(
        "{}{}/{}/{}/{}/{}",
        RECORDING_PATH, guild_id, channel_id, year, month, file_name_from_url
    )) {
        Ok(ok) => ok,
        Err(err) => {
            panic!("{err}")
        }
    }
}

fn get_file_path_root(base_path: &str, path: &(i64, i64, i32, String, String)) -> String {
    let guild_id = &path.0;
    let channel_id = &path.1;
    let year = &path.2;
    let month = &path.3;

    let file_path = format!(
        "{}{}/{}/{}/{}",
        base_path, guild_id, channel_id, year, month
    );

    file_path
}

fn file_exists(path: &str) -> bool {
    let rs = match Path::new(path).try_exists() {
        Ok(ok) => ok,
        Err(err) => {
            panic!("{err}")
        }
    };

    rs
}

fn handle_idempotency_key(req: &HttpRequest) -> Result<String, ()> {
    let header = match req.headers().get("Idempotency-Key") {
        Some(ok) => ok,
        None => {
            error!("Idempotency key is missing");
            return Err(());
        }
    };

    let res = match header.to_str() {
        Ok(ok) => ok.to_owned(),
        Err(_) => {
            error!("No value in Idempotency header");
            return Err(());
        }
    };

    Ok(res)
}

#[get("/remove_silence/{guild_id}/{channel_id}/{year}/{month}/{file_name}")]
async fn remove_silence(
    req: HttpRequest,
    path: web::Path<(i64, i64, i32, String, String)>,
    hashmap: web::Data<HashMapContainer>,
    pool: web::Data<Pool<Postgres>>,
) -> impl Responder {
    let path = path.into_inner();

    let file_path: String = get_file_path_root(RECORDING_PATH, &path);
    let no_silence_file_path = get_file_path_root(NO_SILENCE_RECORDING_PATH, &path);
    let file_no_silence = no_silence_file_path.to_owned() + path.4.as_str() + ".ogg";

    let idemonpotency = match handle_idempotency_key(&req) {
        Ok(ok) => ok,
        Err(_) => return HttpResponse::BadRequest().finish(),
    };

    info!("File name: {}", path.4);

    // We have they key in the hashmap. We are processing the request
    if hashmap.0.read().await.contains_key(&path.4) {
        info!("Already processing");
        let lock = hashmap.0.read().await;
        let sender = lock.get(&path.4).unwrap();
        let mut rec = sender.subscribe();
        let value = rec.recv().await.unwrap();

        if value == 0 {
            info!("received value");
            // placeholder
        }

        let json = json!({"url":file_no_silence,"message":" Success"});
        return HttpResponse::Accepted().json(json);
    } else {
        // It's the first time we receive the request
        // ---OR---
        // We have already processed this request and the file already exists on the server

        // Check if file exists before we try to process it.
        if file_exists(&(no_silence_file_path.to_owned() + "/" + &path.4 + ".ogg")) {
            info!("file already exists");
            let json = json!({"url":file_no_silence,"message":"File already exists"});
            return HttpResponse::Ok().json(json);
        } else {
            info!("Creating new file");
            let (tx, _) = broadcast::channel::<i32>(10);
            // File no present and its the first time we receive a request for this file
            {
                hashmap
                    .0
                    .write()
                    .await
                    .insert(path.4.to_owned(), tx.clone());
            }
            // Crate the directory for the file
            let res = fs::create_dir_all(&no_silence_file_path);
            {
                match res {
                    Ok(_) => (),
                    Err(err) => {
                        // Something went very wrong when making the dir
                        hashmap.0.write().await.remove(&idemonpotency);
                        panic!("{err}")
                    }
                }
            }

            let file: String = file_path.to_owned() + "/" + path.4.as_str() + ".ogg";
            let file_no_silence = no_silence_file_path.to_owned() + "/" + path.4.as_str() + ".ogg";
            let file_no_silence_clone = file_no_silence.to_owned();

            let hashmap_clone = hashmap.clone();
            tokio::spawn(async move {
                let file_name = path.4.clone();
                let command = match std::process::Command::new("ffmpeg")
                    .args(["-i", &file])
                    .args([
                        "-af",
                        "silenceremove=stop_periods=-1:stop_duration=1:stop_threshold=-40dB",
                    ])
                    .arg(file_no_silence_clone)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                {
                    Ok(result) => result,
                    Err(err) => {
                        // Something when very wrong when spawing the process
                        hashmap_clone.0.write().await.remove(&path.4);
                        panic!("error: {}", err);
                    }
                };

                let _output = command.wait_with_output().unwrap();
                // info!("Err: {}", String::from_utf8(output.stderr).unwrap());
                // info!("Status: {}", output.status);
                // info!("Out: {}", String::from_utf8(output.stdout).unwrap());

                sqlx::query!(
                    "UPDATE public.audio_files
				SET silence=true
				WHERE file_name=$1;",
                    file_name
                )
                .execute(pool.get_ref())
                .await
                .unwrap();

                match tx.send(0) {
                    Ok(_) => {
                        // Value received
                        info!("Value sent success");
                    }
                    Err(_) => {
                        warn!("There were no receivers to receive the value.")
                    }
                }
                {
                    hashmap_clone.0.write().await.remove(&path.4);
                }
            });

            let json = json!({"url": file_no_silence,"message":"Request Accepted"});
            return HttpResponse::Ok().json(json);
        }
    }

    // if file_exists(&(no_silence_file_path.to_owned() + "/" + &path.4 + ".ogg")) {
    //     // That file was already created
    //     let file_no_silence = no_silence_file_path + path.4.as_str() + ".ogg";
    //     info!("Audio with removed silence already exists");
    //     let json = json!({"url":file_no_silence,"message":"File already exists"});
    //     HttpResponse::Conflict().json(json)
    // } else {

    //     hashmap.0.write().await.remove(&idemonpotency.to_owned());

    // }
}

#[get("/find/{guild_id}/{channel_id}/{year}/{month}/{file_name}")]
async fn find_similar(
    _req: HttpRequest,
    path: web::Path<(u64, String, i32, String, String)>,
) -> impl Responder {
    let (guild_id, channel_id, year, month, file_name) = path.into_inner();

    let file_path = format!(
        "{}{}/{}/{}/{}",
        RECORDING_PATH, guild_id, channel_id, year, month
    );
    let files = match std::fs::read_dir(&file_path) {
        Ok(ok) => ok,
        Err(err) => {
            panic!("cannot read files {}", err);
        }
    };

    for file in files {
        let file_name = file.unwrap().file_name();
        let file_n = file_name.to_string_lossy();
        // file_n.rsplit_once('/');
        let start = std::time::Instant::now();
        let command = std::process::Command::new("ffprobe")
            .arg("-show_entries")
            .arg("format=duration")
            .args(["-of", "default=noprint_wrappers=1:nokey=1"])
            .arg(format!("{}/{}", file_path, file_n))
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        let output = command.wait_with_output().unwrap();

        let duration = start.elapsed();

        info!("Time elapsed in ffprobe is: {:?}", duration);

        info!("Out: {}", String::from_utf8(output.stdout).unwrap());
        // info!("ERR: {}", String::from_utf8(output.stderr).unwrap());
    }

    let (_time, user_id) = file_name.split_once('-').expect("expected valid string");

    info!("1: {}, 2: {}", user_id, _time);

    // info!("{:#?}", files);
    return "";
}

#[derive(Deserialize)]
struct AudioQuery {
    silence: Option<bool>,
}
#[get("/audio/{guild_id}/{channel_id}/{year}/{month}/{file_name}")]
async fn get_audio(
    req: HttpRequest,
    path: web::Path<(u64, String, i32, String, String)>,
    query_param: web::Query<AudioQuery>,
) -> impl Responder {
    use actix_files::NamedFile;
    let (guild_id, channel_id, year, month, file_name) = path.into_inner();

    let path = {
        if let Some(value) = query_param.silence {
            if value {
                format!(
                    "{}{}/{}/{}/{}/{}",
                    NO_SILENCE_RECORDING_PATH, guild_id, channel_id, year, month, file_name
                )
            } else {
                format!(
                    "{}{}/{}/{}/{}/{}",
                    RECORDING_PATH, guild_id, channel_id, year, month, file_name
                )
            }
        } else {
            format!(
                "{}{}/{}/{}/{}/{}",
                RECORDING_PATH, guild_id, channel_id, year, month, file_name
            )
        }
    };

    let res = match NamedFile::open_async(path).await {
        Ok(ok) => ok.into_response(&req),
        Err(_) => return HttpResponse::NotFound().finish(),
    };

    res
}

#[get("/download/{guild_id}/{channel_id}/{year}/{month}/{file_name}")]
async fn download_audio(
    pool: web::Data<Pool<Postgres>>,
    _req: HttpRequest,
    path: web::Path<(i64, i64, i32, String, String)>,
    clip_duration: web::Query<StartEnd>,
) -> Either<HttpResponse, actix_files::NamedFile> {
    let (guild_id, channel_id, year, month, file_name_from_url) = path.into_inner();

    info!("{:#?}", clip_duration);

    let file_name_without_guild_id = format!("{}/{}/{}", year, month, file_name_from_url);
    if clip_duration.end.is_some() && clip_duration.start.is_some() {
        // Clip
        let child = crop_ffmpeg(
            clip_duration.start.unwrap(),
            clip_duration.end.unwrap(),
            format!(
                "{}{}/{}/{}",
                RECORDING_PATH, guild_id, channel_id, &file_name_without_guild_id
            )
            .as_str(),
        )
        .await;

        // Check if the user provided a name. Otherwise use the file name
        let clip_name = if clip_duration.name.is_some() {
            clip_duration.name.as_ref().unwrap()
        } else {
            &file_name_without_guild_id
        };

        let output = child.wait_with_output().unwrap();
        // TODO: use the user id of the person who clipped it
        // Needs to implement a login system first
        let (_time_stamp, id_and_user) = file_name_from_url
            .split_once('-')
            .expect("expected valid string");

        let (user_id, _user) = id_and_user.split_once('-').expect("expected valid string");

        match save_bytes_to_file(
            output.stdout.clone(),
            pool,
            user_id,
            clip_name,
            &file_name_without_guild_id,
            &guild_id,
            &clip_duration,
        )
        .await
        {
            Ok(_) => {}
            Err(_) => return Either::Left(HttpResponse::BadRequest().body("duplicate")),
        };

        Either::Left(
            HttpResponse::Ok()
                // tell the browser what type of file it is
                .content_type("audio/ogg")
                // tell the browser to download the file
                .append_header((
                    "content-disposition",
                    format!("attachment; filename=\"{clip_name}.ogg\""),
                ))
                // send the bytes
                .body(output.stdout),
        )
    } else {
        // Download full file
        info!(
            "file_paht: {:#?}",
            format!(
                "{}{}/{}/{}",
                RECORDING_PATH, guild_id, channel_id, &file_name_without_guild_id
            )
        );
        let file = actix_files::NamedFile::open(
            format!(
                "{}{}/{}/{}",
                RECORDING_PATH, guild_id, channel_id, &file_name_without_guild_id
            )
            .as_str(),
        )
        .unwrap();

        Either::Right(
            file.use_last_modified(true)
                .set_content_disposition(ContentDisposition {
                    disposition: DispositionType::Attachment,
                    parameters: vec![],
                }),
        )
    }
}

async fn save_bytes_to_file(
    bytes: Vec<u8>,
    pool: web::Data<Pool<Postgres>>,
    user_id: &str,
    clip_name: &str,
    file_name: &str,
    guild_id: &i64,
    clip_duration: &web::Query<StartEnd>,
) -> Result<(), DBErrors> {
    let path = format!("{}{}.ogg", CLIPS_PATH, clip_name);
    info!(path);
    let mut command = match std::process::Command::new("ffmpeg")
        // override file
        .arg("-y")
        // input
        .args(["-i", "-"])
        .args(["-c:a", "copy"])
        // since we pipe the output we have to tell ffmpeg whats its gonna be
        .args(["-f", "ogg"])
        .arg(path)
        // output to file
        // .arg(&file_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(result) => result,
        Err(err) => {
            panic!("error: {}", err);
        }
    };

    let stdin = command.stdin.as_mut().unwrap();
    stdin.write_all(&bytes).expect("could not write to stdin");

    let output = command.wait_with_output();

    info!("output = {:?}", output);

    let result = match sqlx::query!(
			"INSERT INTO favorites (user_id, clip_name, file_name, clip_start, clip_end, guild_id) VALUES ($1, $2, $3, $4, $5, $6)",
			user_id.parse::<i64>().unwrap(),
			clip_name,
			file_name,
			clip_duration.start.unwrap(),
			clip_duration.end.unwrap(),
			guild_id
		)
		.execute(pool.get_ref())
		.await {
		Ok(_) => {Ok(())},
		Err(err) => {
			let db_error = err.as_database_error().unwrap().code().unwrap();
			error!("TODO: send response back: {}", db_error);
			match db_error.as_ref() {
				"23505" => {Err(DBErrors::UniqueViolation)}
				_ => {Err(DBErrors::Unknown)}
			}

		},
	};

    result
}

// TODO: save it to a file as well
async fn crop_ffmpeg(start: f32, end: f32, file_path: &str) -> std::process::Child {
    let command = match std::process::Command::new("ffmpeg")
        // seek to
        .args(["-ss", &start.to_string()])
        // input
        .args(["-i", file_path])
        // length
        .args(["-t", &end.to_string()])
        // copy the codec
        .args(["-c", "copy"])
        // since we pipe the output we have to tell ffmpeg whats its gonna be
        .args(["-f", "ogg"])
        // output to pipe
        .arg("-")
        // output to file
        // .arg(&file_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(result) => result,
        Err(err) => {
            panic!("error: {}", err);
        }
    };

    command
}
