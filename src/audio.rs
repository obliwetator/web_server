use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
};

use actix_files::NamedFile;
use actix_web::{
    get,
    http::header::{ContentDisposition, DispositionParam, DispositionType},
    web, Either, HttpRequest, HttpResponse, Responder,
};
use sqlx::{Pool, Postgres};
use tracing::{error, info};

use crate::{DBErrors, StartEnd, CLIPS_PATH, NO_SILENCE_RECORDING_PATH, RECORDING_PATH};

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
    let path = path.into_inner();
    let guild_id = &path.0;
    let channel_id = &path.1;
    let year = &path.2;
    let month = &path.3;
    let file_name_from_url = &path.4;

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
            panic!()
        }
    };

    let res = match header.to_str() {
        Ok(ok) => ok.to_owned(),
        Err(_) => {
            panic!()
        }
    };

    Ok(res)
}

#[get("/remove_silence/{guild_id}/{channel_id}/{year}/{month}/{file_name}")]
async fn remove_silence(
    req: HttpRequest,
    path: web::Path<(i64, i64, i32, String, String)>,
    hashmap: web::Data<Arc<Mutex<HashMap<String, tokio::sync::broadcast::Receiver<f32>>>>>,
) -> Either<HttpResponse, actix_files::NamedFile> {
    let (tx, mut rx1) = tokio::sync::broadcast::channel::<f32>(2);

    let idemonpotency = match handle_idempotency_key(&req) {
        Ok(ok) => ok,
        Err(_) => return Either::Left(HttpResponse::BadRequest().finish()),
    };
    if let Some(item) = hashmap.lock().unwrap().insert(idemonpotency, rx1) {
        // a reqeust with the same key has been already handled by this function
        info!("{:?}", item);

        return Either::Left(HttpResponse::Accepted().finish());
    }

    let path = path.into_inner();
    let file_path = get_file_path_root(RECORDING_PATH, &path);
    let no_silence_file_path = get_file_path_root(NO_SILENCE_RECORDING_PATH, &path);

    panic!("");

    info!("File name: {}", path.4);
    info!("File Path: {}", file_path);
    info!("no_silence_file_path: {}", no_silence_file_path);

    if file_exists(&(no_silence_file_path + &path.4)) {
        // That file was already created
        let file_no_silence = no_silence_file_path + path.4.as_str();
        let file = match NamedFile::open_async(file_no_silence).await {
            Ok(ok) => ok,
            Err(err) => {
                panic!("{err}")
            }
        };
        Either::Left(HttpResponse::NotFound().finish())
    } else {
        let res = fs::create_dir_all(&no_silence_file_path);
        match res {
            Ok(_) => (),
            Err(err) => {
                panic!("{err}")
            }
        }

        let file = file_path + path.4.as_str();
        let file_no_silence = no_silence_file_path + path.4.as_str();

        let command = match Command::new("ffmpeg")
            .args(["-i", &file])
            .args([
                "-af",
                "silenceremove=stop_periods=-1:stop_duration=1:stop_threshold=-40dB",
            ])
            .arg(file_no_silence)
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

        let output = command.wait_with_output().unwrap();

        info!("Err: {:#?}", output.stderr);
        info!("Status: {}", output.status);
        info!("Out: {:#?}", output.stdout);

        Either::Left(HttpResponse::Ok().finish())
    }
}

#[get("/audio/{guild_id}/{channel_id}/{year}/{month}/{file_name}")]
async fn get_audio(
    req: HttpRequest,
    path: web::Path<(u64, String, i32, String, String)>,
) -> impl Responder {
    use actix_files::NamedFile;
    let path = path.into_inner();
    let guild_id = path.0;
    let channel_id = path.1;
    let year = path.2;
    let month = path.3;
    let file_name = path.4;

    info!(
        "{}{}/{}/{}/{}/{}",
        RECORDING_PATH, guild_id, channel_id, year, month, file_name
    );

    NamedFile::open_async(format!(
        "{}{}/{}/{}/{}/{}",
        RECORDING_PATH, guild_id, channel_id, year, month, file_name
    ))
    .await
    .unwrap()
    .into_response(&req)

    // HttpResponse::Ok()
}

#[get("/download/{guild_id}/{channel_id}/{year}/{month}/{file_name}")]
async fn download_audio(
    pool: web::Data<Pool<Postgres>>,
    _req: HttpRequest,
    path: web::Path<(i64, i64, i32, String, String)>,
    clip_duration: web::Query<StartEnd>,
) -> Either<HttpResponse, actix_files::NamedFile> {
    let path = path.into_inner();
    let guild_id = &path.0;
    let channel_id = &path.1;
    let year = &path.2;
    let month = &path.3;
    let file_name_from_url = &path.4;

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
        let (user_id, _) = file_name_from_url
            .split_once('-')
            .expect("expected valid string");

        match save_bytes_to_file(
            output.stdout.clone(),
            pool,
            user_id,
            clip_name,
            &file_name_without_guild_id,
            guild_id,
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
    let mut command = match Command::new("ffmpeg")
        // override file
        .arg("-y")
        // input
        .args(["-i", "-"])
        .args(["-c:v", "copy"])
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
async fn crop_ffmpeg(start: f32, end: f32, file_path: &str) -> Child {
    let command = match Command::new("ffmpeg")
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
