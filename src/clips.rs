use std::fs::remove_file;

use actix_web::{
    get,
    http::header::{ContentDisposition, DispositionType},
    post, web, HttpRequest, HttpResponse, Responder,
};

use serde::{Deserialize, Serialize};

use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_with::{As, DisplayFromStr};
use sqlx::{Pool, Postgres};
use tracing::{error, info};

use hello_world::jammer_client::JammerClient;
use hello_world::JamData;

pub mod hello_world {
    #![allow(non_snake_case)]
    tonic::include_proto!("helloworld");
}

use crate::{clips::hello_world::jam_response::JamResponseEnum, errors::ApiResponse, CLIPS_PATH};
use serde_json::json;

type DisplayFromstr = As<DisplayFromStr>;

#[derive(Serialize, Debug)]
struct Favorites {
    #[serde(with = "DisplayFromstr")]
    user_id: i64,
    clip_name: String,
    file_name: String,
    clip_start: Option<f32>,
    clip_end: Option<f32>,
    #[serde(with = "DisplayFromstr")]
    guild_id: i64,
    // id: i64,
}

#[get("/audio/clips/{guild_id}/{clip_name}")]
pub async fn get_clip(
    req: HttpRequest,
    _pool: web::Data<Pool<Postgres>>,
    path: web::Path<(i64, String)>,
) -> impl Responder {
    use actix_files::NamedFile;

    let path = path.into_inner();
    // let guild_id = path.0;
    let clip_name = path.1;

    info!("clips path: {}", format!("{}{}.ogg", CLIPS_PATH, clip_name));
    match NamedFile::open_async(format!("{}{}.ogg", CLIPS_PATH, clip_name)).await {
        Ok(ok) => ok
            .use_last_modified(true)
            .set_content_disposition(ContentDisposition {
                disposition: DispositionType::Attachment,
                parameters: vec![],
            })
            .into_response(&req),
        Err(_) => HttpResponse::NotFound().body("File not found"),
    }

    // HttpResponse::Ok().json(result)
}

#[get("/audio/clips/{guild_id}")]
pub async fn get_clips(
    _req: HttpRequest,
    pool: web::Data<Pool<Postgres>>,
    path: web::Path<i64>,
) -> impl Responder {
    let guild_id = path.into_inner();

    let result = match sqlx::query_as!(
        Favorites,
        r#"
    	SELECT user_id,
        clip_name,
    	file_name,
    	clip_start,
    	clip_end,
    	guild_id
    	FROM favorites
    	WHERE guild_id = $1
    	"#,
        guild_id
    )
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(ok) => ok,
        Err(_) => {
            panic!("cannot select *")
        }
    };

    HttpResponse::Ok().json(result)
}
#[derive(Deserialize, PartialEq, Debug)]
pub struct JamItBody {
    #[serde(with = "DisplayFromstr")]
    guild_id: i64,
    clip_name: String,
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
#[serde(tag = "code")]
pub enum JamItResponse {
    OK,
    NotPresentInChannel,
    Unkown,
}

#[derive(Deserialize, PartialEq, Debug)]
pub struct A {
    code: JamItResponse,
}

// TODO: Get GRPC Client
#[post("/jamit")]
pub async fn play_clip(info: web::Json<JamItBody>) -> impl Responder {
    let mut client = JammerClient::connect("http://[::1]:50052").await.unwrap();

    let request = tonic::Request::new(JamData {
        clip_name: info.clip_name.clone(),
        guild_id: info.guild_id,
    });

    let response = client.jam_it(request).await.unwrap();

    info!("{:#?}", response);

    let jam_response = response.into_inner();

    // let response = client
    //     .get(format!(
    //         "{}?clip_name={}&guild_id={}",
    //         "http://localhost:3000", info.clip_name, info.guild_id
    //     ))
    //     .send()
    //     .await
    //     .unwrap();

    // let res = response.text().await.unwrap();
    // info!("res: {}", res);

    // let json = response.json::<A>().await;
    // info!("??? : {:#?}", json);
    // let res = json.unwrap();

    // HttpResponse::Ok().body("ok")
    match jam_response.resp() {
        JamResponseEnum::Ok => HttpResponse::Ok().body("ok"),
        JamResponseEnum::NotPressent => HttpResponse::Ok().json(json!({"code" : 1})),
        JamResponseEnum::Unkown => HttpResponse::Ok().json(json!({"code" : 2})),
    }
}

#[post("audio/clips/delete/{guild_id}")]
pub async fn delete(
    file_name: String,
    pool: web::Data<Pool<Postgres>>,
    _path: web::Path<i64>,
) -> impl Responder {
    // let guild_id = path.into_inner();
    let guild_id = 5423;

    let result = match sqlx::query!(
        r#"
    	DELETE FROM favorites
    	WHERE guild_id = $1 AND
		file_name = $2
    	"#,
        guild_id,
        file_name
    )
    .execute(pool.get_ref())
    .await
    {
        Ok(ok) => ok,
        Err(_) => return HttpResponse::Ok().json(ApiResponse::FILE_ALREADY_DELETED()),
    };

    if result.rows_affected() == 1 {
        // we succesfully delete something
        let res = remove_file(format!("{}{}", CLIPS_PATH, file_name));

        let _res = match res {
            Ok(_) => {
                info!("file deleted");
                HttpResponse::Ok().json(ApiResponse::OK())
            }
            Err(_err) => {
                error!("file cannot be deleted");
                error!("{:?}", _err.kind());
                HttpResponse::NotFound().json({})
            }
        };
        return _res;
    } else {
        return HttpResponse::NotFound().json(ApiResponse::OK());
    }
}
