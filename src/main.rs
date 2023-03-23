mod auth;
mod clips;
mod grpc;
mod jwt_numeric_date;
mod roles;
mod user;

use actix_web::body::EitherBody;
use actix_web::middleware::Logger;
use actix_web::web::ReqData;
use auth::{discord_login, get_token, ACCESS_SECRET, REFRESH_SECRET};
use clips::{get_clip, get_clips, play_clip};
use jsonwebtoken::{DecodingKey, EncodingKey};
use sqlx::Postgres;
use std::collections::HashMap;
use std::fs::ReadDir;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use tonic::transport::Server;
use user::{get_current_user, get_current_user_guilds};

use actix_cors::Cors;
use actix_web::http::header::{ContentDisposition, DispositionType};
use actix_web::{
    get, web, App, Either, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
};
use serde::{Deserialize, Serialize};
use sqlx::pool::Pool;
use sqlx::postgres::PgPoolOptions;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Serialize, Debug)]
pub struct Directories {
    year: i32,
    months: Option<Months>,
}

#[derive(Serialize, Debug)]
pub struct Channels {
    channel_id: String,
    dirs: Vec<Directories>,
}

#[derive(Serialize, Debug)]
struct File {
    file: String,
    comment: Option<String>,
}

#[derive(Debug)]
enum DBErrors {
    Unknown,
    UniqueViolation,
}

type Months = HashMap<String, Option<Vec<File>>>;
pub const RECORDING_PATH: &str = "/home/tulipan/projects/FBI-agent/voice_recordings/";
pub const CLIPS_PATH: &str = "/home/tulipan/projects/FBI-agent/clips/";

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

#[inline]
async fn for_entry(entries: ReadDir, channel: u64, dirs: &mut Directories, month_as_string: &str) {
    for entry in entries {
        if let Ok(entry) = entry {
            let file_name = File {
                file: entry.file_name().to_str().unwrap().to_owned(),
                comment: None,
            };
            dirs.months
                .as_mut()
                .unwrap()
                .get_mut(month_as_string)
                .unwrap()
                .as_mut()
                .unwrap()
                .push(file_name);
        } else {
            println!("error for file");
        }
    }
}

pub async fn get_months_v2(path: web::Path<String>) -> Result<Vec<Channels>, HttpResponse> {
    let guild_id = path.into_inner();

    let mut dirs_vec = Vec::new();

    if let Some(value) = for_channel_ids(guild_id, &mut dirs_vec).await {
        return value;
    }

    Ok(dirs_vec)
}

async fn for_channel_ids(
    guild_id: String,
    dirs_vec: &mut Vec<Channels>,
) -> Option<Result<Vec<Channels>, HttpResponse>> {
    let channel_ids = match std::fs::read_dir(format!(
        "/home/tulipan/projects/FBI-agent/voice_recordings_v2/{}",
        guild_id
    )) {
        Ok(ok) => ok,
        Err(err) => {
            error!("{}", err);
            return Some(Err(HttpResponse::NotFound()
                .body("files does not exist or are innacessible to you 1\n")));
        }
    };

    for channel_id in channel_ids {
        if let Ok(entry) = channel_id {
            let channel = entry
                .file_name()
                .to_str()
                .unwrap()
                .to_owned()
                .parse::<u64>()
                .unwrap();

            let years = match std::fs::read_dir(format!(
                "/home/tulipan/projects/FBI-agent/voice_recordings_v2/{}/{}",
                guild_id, channel
            )) {
                Ok(ok) => ok,
                Err(err) => {
                    error!("{}", err);
                    return Some(Err(HttpResponse::NotFound()
                        .body("files does not exist or are innacessible to you 2\n")));
                }
            };

            let mut channels = Channels {
                channel_id: channel.to_string(),
                dirs: Vec::new(),
            };

            if let Some(value) = for_years(years, &guild_id, channel, &mut channels).await {
                return Some(value);
            }

            dirs_vec.push(channels);
        }
    }

    // info!("{:#?}", dirs_vec);

    None
}

#[inline]
async fn for_years(
    years: ReadDir,
    guild_id: &String,
    channel: u64,
    dirs_vec: &mut Channels,
) -> Option<Result<Vec<Channels>, HttpResponse>> {
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
                "/home/tulipan/projects/FBI-agent/voice_recordings_v2/{}/{}/{}",
                guild_id, channel, year_as_int
            )) {
                Ok(ok) => ok,
                Err(err) => {
                    error!("{}", err);
                    return Some(Err(HttpResponse::NotFound()
                        .body("files does not exist or are innacessible to you 2\n")));
                }
            };

            if let Some(value) = for_months(months, &mut dirs, guild_id, channel, year_as_int).await
            {
                return Some(value);
            }

            dirs_vec.dirs.push(dirs);
        }
    }
    None
}

#[inline]
async fn for_months(
    months: ReadDir,
    dirs: &mut Directories,
    guild_id: &String,
    channel: u64,
    year_as_int: i32,
) -> Option<Result<Vec<Channels>, HttpResponse>> {
    for month in months {
        if let Ok(entry) = month {
            let month_as_string = entry.file_name().to_str().unwrap().to_owned();

            dirs.months
                .as_mut()
                .unwrap()
                .insert(month_as_string.to_owned(), Some(vec![]));

            let entries = match std::fs::read_dir(format!(
                "/home/tulipan/projects/FBI-agent/voice_recordings_v2/{}/{}/{}/{}",
                guild_id, channel, year_as_int, &month_as_string
            )) {
                Ok(ok) => ok,
                Err(err) => {
                    error!("{}", err);
                    return Some(Err(HttpResponse::NotFound()
                        .body("files does not exist or are innacessible to you 3\n")));
                }
            };

            for_entry(entries, channel, dirs, &month_as_string).await;
        } else {
            println!("error for month")
        }
    }
    None
}

pub async fn get_months(path: web::Path<String>) -> Result<Vec<Directories>, HttpResponse> {
    let guild_id = path.into_inner();

    let years = match std::fs::read_dir(format!(
        "/home/tulipan/projects/FBI-agent/voice_recordings/{}",
        guild_id
    )) {
        Ok(ok) => ok,
        Err(err) => {
            error!("{}", err);
            return Err(HttpResponse::NotFound()
                .body("files does not exist or are innacessible to you 1\n"));
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
                    return Err(HttpResponse::NotFound()
                        .body("files does not exist or are innacessible to you 2\n"));
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
                            return Err(HttpResponse::NotFound()
                                .body("files does not exist or are innacessible to you 3\n"));
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

    Ok(dirs_vec)
}

#[get("/current/{guild_id}")]
async fn get_current_month(path: web::Path<String>) -> impl Responder {
    let result = get_months_v2(path).await;

    let resp = match result {
        Ok(dirs_vec) => HttpResponse::Ok().json(dirs_vec),
        Err(err) => err,
    };

    resp
}

async fn get_current_month_permission(
    path: web::Path<String>,
    token: Option<ReqData<Token<Access>>>,
) -> impl Responder {
    let result = get_months(path).await;

    let resp = match result {
        Ok(dirs_vec) => HttpResponse::Ok().json(dirs_vec),
        Err(err) => err,
    };

    resp
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

    println!(
        "/home/tulipan/projects/FBI-agent/voice_recordings_v2/{}/{}/{}/{}/{}",
        guild_id, channel_id, year, month, file_name
    );

    NamedFile::open_async(format!(
        "/home/tulipan/projects/FBI-agent/voice_recordings_v2/{}/{}/{}/{}/{}",
        guild_id, channel_id, year, month, file_name
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
    path: web::Path<(i64, i32, String, String)>,
    clip_duration: web::Query<StartEnd>,
) -> Either<HttpResponse, actix_files::NamedFile> {
    let path = path.into_inner();
    let guild_id = &path.0;
    let year = &path.1;
    let month = &path.2;
    let file_name_from_url = &path.3;

    info!("{:#?}", clip_duration);

    let file_name_without_guild_id = format!("{}/{}/{}", year, month, file_name_from_url);
    if clip_duration.end.is_some() && clip_duration.start.is_some() {
        // Clip
        let child = crop_ffmpeg(
            clip_duration.start.unwrap(),
            clip_duration.end.unwrap(),
            format!(
                "{}{}/{}",
                RECORDING_PATH, guild_id, &file_name_without_guild_id
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
        // println!("Result: {:?}", &output.stdout);
        // println!("Error: {}", String::from_utf8(output.stderr).unwrap());
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
                "{}{}/{}",
                RECORDING_PATH, guild_id, &file_name_without_guild_id
            )
        );
        let file = actix_files::NamedFile::open(
            format!(
                "{}{}/{}",
                RECORDING_PATH, guild_id, &file_name_without_guild_id
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

async fn not_found() -> impl Responder {
    HttpResponse::NotFound().json("not found")
}

pub struct AccessKeys {
    pub access_encode: EncodingKey,
    pub refresh_encode: EncodingKey,
    pub access_decode: DecodingKey,
    pub refresh_decode: DecodingKey,
}

#[actix_web::main]
async fn main() {
    // std::env::set_var("RUST_LOG", "debug");
    // std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();

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

    let b = HttpServer::new(move || {
        let logger = Logger::default();
        // Create the singing keys once. reuse them for every encode/decode
        let keys = AccessKeys {
            access_encode: EncodingKey::from_secret(ACCESS_SECRET.as_bytes()),
            refresh_encode: EncodingKey::from_secret(REFRESH_SECRET.as_bytes()),
            access_decode: DecodingKey::from_secret(ACCESS_SECRET.as_bytes()),
            refresh_decode: DecodingKey::from_secret(REFRESH_SECRET.as_bytes()),
        };
        let get_scope = web::scope("/get")
            .service(get_years_dir)
            .service(get_months_dir)
            .service(get_recording_for_month);
        let api_scope = web::scope("/api")
            .wrap(AuthMiddleware)
            .service(discord_login)
            .service(get_current_user)
            .service(get_current_user_guilds)
            .service(get_token);
        App::new()
            .wrap(logger)
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(reqwest::Client::new()))
            .service(get_scope)
            .service(api_scope)
            .app_data(web::Data::new(keys))
            .service(get_current_month)
            .service(get_audio)
            .service(download_audio)
            .service(get_clips)
            .service(get_clip)
            .service(play_clip)
            .default_service(web::route().to(not_found))
            .wrap(
                Cors::permissive(), // Cors::default()
                                    //     .allow_any_origin()
                                    //     .allow_any_header()
                                    //     .allow_any_method(),
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
    .bind(("127.0.0.1", 8080))
    .unwrap()
    .run();

    let _tonic = tokio::spawn(async move {
        let addr = "[::1]:50051".parse().unwrap();
        let greeter = MyGreeter::default();

        println!("GreeterServer listening on {}", addr);

        Server::builder()
            .add_service(GreeterServer::new(greeter))
            .serve(addr)
            .await
    });

    let _c = tokio::spawn(async move { b.await });
    let _res = tokio::join!(_c, _tonic);
}

use std::future::{ready, Ready};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::LocalBoxFuture;

use crate::auth::{Access, Refresh, Token};
use crate::grpc::hello_world::greeter_server::GreeterServer;
use crate::grpc::MyGreeter;

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct AuthMiddleware;

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = SayHiMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SayHiMiddleware { service }))
    }
}

pub struct SayHiMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SayHiMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        info!("PATH: {:#?}", req.path());
        if req.path() == "/api/discord_login" {
            // Dont validate the token if user is trying to login
            let res = self.service.call(req);

            Box::pin(async move {
                // forwarded responses map to "left" body
                res.await.map(ServiceResponse::map_into_left_body)
            })
        } else {
            let headers = req.headers();
            let cookie = match headers.get("cookie") {
                Some(cookie) => cookie,
                None => {
                    let (request, _pl) = req.into_parts();

                    let response = HttpResponse::Unauthorized().finish().map_into_right_body();
                    return Box::pin(async { Ok(ServiceResponse::new(request, response)) });
                }
            };

            let keys = req.app_data::<web::Data<AccessKeys>>().unwrap();

            let (access_token, refresh_token) = get_access_and_refresh_tokens(cookie);

            info!("COOKIES: {:#?}", access_token);

            let decoded_access = Token::<Access>::decode(access_token, keys);
            let _decoded_refresh = Token::<Refresh>::decode(refresh_token, keys);

            req.extensions_mut().insert(decoded_access);
            let res = self.service.call(req);

            Box::pin(async move {
                // forwarded responses map to "left" body
                res.await.map(ServiceResponse::map_into_left_body)
            })
        }
    }
}

fn get_access_and_refresh_tokens(cookie: &reqwest::header::HeaderValue) -> (&str, &str) {
    let tokens = cookie.to_str().unwrap();
    let access_refresh: Vec<&str> = tokens.split(';').collect();

    let access: Vec<&str> = access_refresh[0].split('=').collect();
    let access_token = access[1];

    let refresh: Vec<&str> = access_refresh[1].split('=').collect();
    let refresh_token = refresh[1];

    (access_token, refresh_token)
}
