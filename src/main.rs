use sqlx::Postgres;
use std::collections::HashMap;
use std::io::Write;
use std::process::{Child, Command, Stdio};

use actix_cors::Cors;
use actix_web::http::header::{ContentDisposition, DispositionType};
use actix_web::{get, web, App, Either, HttpRequest, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use sqlx::pool::Pool;
use sqlx::postgres::PgPoolOptions;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Serialize, Debug)]
struct Directories {
    year: i32,
    months: Option<Months>,
}

#[derive(Serialize, Debug)]

struct File {
    file: String,
    comment: Option<String>,
}

type Months = HashMap<String, Option<Vec<File>>>;

#[get("/{guild_id}")]
async fn get_years_dir(_path: web::Path<String>) -> impl Responder {
    // let guild_id = path.into_inner();
    // let entries = match std::fs::read_dir(format!("../FBI-agent/voice_recordings/{}", guild_id)) {
    //     Ok(ok) => ok,
    //     Err(_) => {
    //         return HttpResponse::NotFound()
    //             .body("guild_id does not exist or is innacessible to you\n")
    //     }
    // };

    // let mut dirs = Directories {
    //     year: vec![(HashMap::new())],
    // };

    // for entry in entries {
    //     if let Ok(entry) = entry {
    //         println!("{:#?}", entry.file_name());

    //         dirs.name
    //             .push(entry.file_name().to_str().unwrap().to_owned())
    //     } else {
    //         println!("cannot get entry");
    //     }
    // }

    println!();
    HttpResponse::Ok().json("no")
}

#[get("/{guild_id}/{year}")]
async fn get_months_dir(_path: web::Path<(String, i32)>) -> impl Responder {
    // let (guild_id, year) = path.into_inner();
    // let entries = match std::fs::read_dir(format!(
    //     "../FBI-agent/voice_recordings/{}/{}",
    //     guild_id, year
    // )) {
    //     Ok(ok) => ok,
    //     Err(_) => {
    //         return HttpResponse::NotFound().body("year does not exist or is innacessible to you\n")
    //     }
    // };

    // let mut dirs = Directories {
    //     year: 2022,
    //     name: vec![],
    // };

    // for entry in entries {
    //     if let Ok(entry) = entry {
    //         println!("{:#?}", entry.file_name());

    //         dirs.name
    //             .push(entry.file_name().to_str().unwrap().to_owned())
    //     } else {
    //         println!("cannot get entry");
    //     }
    // }

    println!();
    HttpResponse::Ok().json("no")
}

#[get("/{guild_id}/{year}/{month}")]
async fn get_recording_for_month(_path: web::Path<(String, i32, String)>) -> impl Responder {
    // let (guild_id, year, month) = path.into_inner();
    // let entries = match std::fs::read_dir(format!(
    //     "../FBI-agent/voice_recordings/{}/{}/{}",
    //     guild_id, year, month
    // )) {
    //     Ok(ok) => ok,
    //     Err(_) => {
    //         return HttpResponse::NotFound()
    //             .body("files does not exist or are innacessible to you\n")
    //     }
    // };

    // let mut dirs = Directories {
    //     year: 2022,
    //     name: vec![],
    // };

    // for entry in entries {
    //     if let Ok(entry) = entry {
    //         println!("{:#?}", entry.file_name());

    //         dirs.name
    //             .push(entry.file_name().to_str().unwrap().to_owned())
    //     } else {
    //         println!("cannot get entry");
    //     }
    // }

    println!();
    HttpResponse::Ok().json("no")
}

#[get("/current/{guild_id}")]
async fn get_current_month(path: web::Path<String>) -> impl Responder {
    let guild_id = path.into_inner();

    let years = match std::fs::read_dir(format!(
        "/home/tulipan/projects/FBI-agent/voice_recordings/{}",
        guild_id
    )) {
        Ok(ok) => ok,
        Err(err) => {
            error!("{}", err);
            return HttpResponse::NotFound()
                .body("files does not exist or are innacessible to you 1\n");
        }
    };

    let mut dirs_vec = Vec::new();

    // Get all the year(s) for this guild
    for year in years {
        if let Ok(entry) = year {
            let year_as_int = entry
                .file_name()
                .to_str()
                .unwrap()
                .to_owned()
                .parse::<i32>()
                .unwrap();

            let mut dirs = Directories {
                year: year_as_int,
                months: Some(HashMap::new()),
            };

            println!("{}", year_as_int);

            let months = match std::fs::read_dir(format!(
                "/home/tulipan/projects/FBI-agent/voice_recordings/{}/{}",
                guild_id, year_as_int
            )) {
                Ok(ok) => ok,
                Err(err) => {
                    error!("{}", err);
                    return HttpResponse::NotFound()
                        .body("files does not exist or are innacessible to you 2\n");
                }
            };

            for month in months {
                if let Ok(entry) = month {
                    let month_as_string = entry.file_name().to_str().unwrap().to_owned();

                    dirs.months
                        .as_mut()
                        .unwrap()
                        .insert(month_as_string.to_owned(), Some(vec![]));

                    let entries = match std::fs::read_dir(format!(
                        "/home/tulipan/projects/FBI-agent/voice_recordings/{}/{}/{}",
                        guild_id, year_as_int, &month_as_string
                    )) {
                        Ok(ok) => ok,
                        Err(err) => {
                            error!("{}", err);
                            return HttpResponse::NotFound()
                                .body("files does not exist or are innacessible to you 3\n");
                        }
                    };

                    for entry in entries {
                        if let Ok(entry) = entry {
                            let file_name = File {
                                file: entry.file_name().to_str().unwrap().to_owned(),
                                comment: None,
                            };
                            dirs.months
                                .as_mut()
                                .unwrap()
                                .get_mut(&month_as_string)
                                .unwrap()
                                .as_mut()
                                .unwrap()
                                .push(file_name);
                        } else {
                            println!("error for file");
                        }
                    }
                } else {
                    println!("error for month")
                }
            }
            dirs_vec.push(dirs);
        } else {
            println!("error for year");
        }
    }
    println!("get_current_month");
    HttpResponse::Ok().json(dirs_vec)
}

#[get("/audio/{guild_id}/{year}/{month}/{file_name}")]
async fn get_audio(
    req: HttpRequest,
    path: web::Path<(u64, i32, String, String)>,
) -> impl Responder {
    use actix_files::NamedFile;
    let path = path.into_inner();
    let guild_id = path.0;
    let year = path.1;
    let month = path.2;
    let file_name = path.3;

    NamedFile::open_async(format!(
        "/home/tulipan/projects/FBI-agent/voice_recordings/{}/{}/{}/{}",
        guild_id, year, month, file_name
    ))
    .await
    .unwrap()
    .into_response(&req)

    // HttpResponse::Ok()
}

#[derive(Deserialize, Debug)]
struct StartEnd {
    start: Option<f32>,
    end: Option<f32>,
    name: Option<String>,
}

#[get("/download/{guild_id}/{year}/{month}/{file_name}")]
async fn download_audio(
    pool: web::Data<Pool<Postgres>>,
    _req: HttpRequest,
    path: web::Path<(u64, i32, String, String)>,
    clip_duration: web::Query<StartEnd>,
) -> Either<HttpResponse, actix_files::NamedFile> {
    let path = path.into_inner();
    let guild_id = &path.0;
    let year = &path.1;
    let month = &path.2;
    let file_name = &path.3;

    let file_path = format!(
        "/home/tulipan/projects/FBI-agent/voice_recordings/{}/{}/{}/{}",
        guild_id, year, month, file_name
    );
    if clip_duration.end.is_some() && clip_duration.start.is_some() {
        let child = crop_ffmpeg(
            clip_duration.start.unwrap(),
            clip_duration.end.unwrap(),
            &file_path,
        )
        .await;

        let output = child.wait_with_output().unwrap();
        let (user_id, _) = file_name.split_once('-').expect("expected valid string");

        // println!("Result: {:?}", &output.stdout);
        // println!("Error: {}", String::from_utf8(output.stderr).unwrap());
        save_bytes_to_file(output.stdout.clone(), pool, user_id, file_name).await;

        Either::Left(
            HttpResponse::Ok()
                // tell the browser what type of file it is
                .content_type("audio/ogg")
                // tell the browser to download the file
                .append_header(("content-disposition", "attachment;"))
                // send the bytes
                .body(output.stdout),
        )
    } else {
        let file = actix_files::NamedFile::open(&file_path).unwrap();

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
    file_name: &str,
) {
    let path = format!("/home/tulipan/projects/FBI-agent/clips/{}", "file_name.ogg");
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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

    println!("output = {:?}", output);

    let result = sqlx::query!(
        "INSERT INTO favorites (user_id, clip_name) VALUES ($1, $2) ON CONFLICT (user_id) DO NOTHING",
        user_id.parse::<i64>().unwrap(),
        user_id
    )
    .execute(pool.get_ref())
    .await
    .unwrap();
}

// TODO: save it to a file as well
async fn crop_ffmpeg(start: f32, end: f32, file_name: &str) -> Child {
    let command = match Command::new("ffmpeg")
        // seek to
        .args(["-ss", &start.to_string()])
        // input
        .args(["-i", file_name])
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

async fn not_found() -> impl Responder {
    HttpResponse::NotFound().json("not found")
}

#[get("/test")]
async fn test1(pool: web::Data<Pool<Postgres>>) -> impl Responder {
    let result = sqlx::query!("select * from favorites")
        .fetch_all(pool.get_ref())
        .await;
    println!("{:#?}", result);
    HttpResponse::Ok().json("no")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://postgres:okcpli4t94@localhost/sakiot_rouvas")
        .await
        .expect("cannot connect to database");

    let subscriber = FmtSubscriber::builder()
        // .with_thread_names(true)
        // .with_file(true)
        // .with_target(true)
        // .with_line_number(true)
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::INFO)
        .pretty()
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    HttpServer::new(move || {
        let test = web::scope("/get")
            .service(get_years_dir)
            .service(get_months_dir)
            .service(get_recording_for_month);
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(test)
            .service(get_current_month)
            .service(get_audio)
            .service(download_audio)
            .service(test1)
            .default_service(web::route().to(not_found))
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_header()
                    .allow_any_method(),
            )
        // .wrap_fn(|req, srv| {
        //     let fut = srv.call(req);
        //     async {
        //         let mut res = fut.await?;
        //         res.headers_mut()
        //             .insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("text/plain"));
        //         Ok(res)
        //     }
        // })
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
