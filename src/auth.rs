#![allow(dead_code)]
use actix_files::NamedFile;
use actix_web::{cookie::Cookie, get, web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{decode, encode, EncodingKey, Header, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Pool, Postgres};
use time::{Duration, OffsetDateTime};

use crate::{
    get_access_and_refresh_tokens,
    user::{get_user, get_user_guilds},
    AccessKeys,
};

pub const CLIENT_ID: &str = "877617434029350972";
pub const CLIENT_SECRET: &str = "NisxjUCXUkB4Q6iJAFEfNVAos8_GiLNi";

pub const BASE_URL: &str = "https://discord.com/api/v10/";

pub const BASE_AUTH_URL: &str = "https://discord.com/oauth2/authorize/";
pub const TOKEN_URL: &str = "https://discord.com/api/oauth2/token/";
pub const ACCESS_SECRET: &str = "1708fd0a1828410128b1ed92ba688acd8a4b283e7c6d365c88e66b8fffe0cc0657dd77a2cd8142b7b41b9a54437e10bc1f8b25ef12b0d6109b1ac53fad5f73be";
pub const REFRESH_SECRET: &str = "cd33b16763bc28372f6e21779daf23b6e3334e61e790b716f23126eb1c84194da7ce9f9ef1e56365d589fb45514ce4bcbc46549f5122706e3d167648bfe4f598";
const JWT_ACCESS_EXPIRY: i64 = 7;

// trait Token {
//     fn encode(id: i64, access_token: String, key: &EncodingKey) -> String;
// }

#[derive(Clone)]
pub struct Access;
#[derive(Clone)]
pub struct Refresh;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token<T> {
    // aud: String,         // Optional. Audience
    #[serde(with = "jwt_numeric_date")]
    pub exp: OffsetDateTime, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    pub id: i64,
    pub token: String,
    // iat: usize,          // Optional. Issued at (as UTC timestamp)
    // iss: String,         // Optional. Issuer
    // nbf: usize,          // Optional. Not Before (as UTC timestamp)
    // sub: String,         // Optional. Subject (whom token refers to)
    state: std::marker::PhantomData<T>,
}

impl Token<Access> {
    pub fn encode(id: i64, access_token: String, key: &EncodingKey) -> String {
        let iat = OffsetDateTime::now_utc();
        let exp = iat + Duration::days(JWT_ACCESS_EXPIRY);

        let access = Self {
            exp,
            id,
            token: access_token,
            state: std::marker::PhantomData::<Access>,
        };
        encode(&Header::default(), &access, key).unwrap()
    }
    pub fn decode(token: &str, keys: &AccessKeys) -> Self {
        decode::<Self>(token, &keys.access_decode, &Validation::default())
            .unwrap()
            .claims
    }
}

impl Token<Refresh> {
    pub fn encode(id: i64, refresh_token: String, key: &EncodingKey) -> String {
        let iat = OffsetDateTime::now_utc();
        let exp = iat + Duration::days(JWT_ACCESS_EXPIRY);

        let refresh = Self {
            exp,
            id,
            token: refresh_token,
            state: std::marker::PhantomData::<Refresh>,
        };
        encode(&Header::default(), &refresh, key).unwrap()
    }
    pub fn decode(token: &str, keys: &AccessKeys) -> Self {
        decode::<Self>(token, &keys.refresh_decode, &Validation::default())
            .unwrap()
            .claims
    }
}

#[derive(Deserialize, Debug)]
pub struct DiscordLoginCode {
    code: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DiscordBotAuthData {
    client_id: &'static str,
    client_secret: &'static str,
    grant_type: &'static str,
    code: String,
    redirect_uri: &'static str,
}

#[derive(Serialize, Deserialize, Debug)]
struct DiscordBotAuthDataRefresh {
    client_id: &'static str,
    client_secret: &'static str,
    grant_type: &'static str,
    refresh_token: &'static str,
}

impl DiscordBotAuthDataRefresh {
    fn new(refresh_token: &'static str) -> Self {
        Self {
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            grant_type: "refresh_token",
            refresh_token,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DiscordTokenData {
    access_token: String,
    expires_in: i32,
    refresh_token: String,
    scope: String,
    token_type: String,
}

impl Default for DiscordBotAuthData {
    fn default() -> Self {
        Self {
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            grant_type: "authorization_code",
            code: String::from(""),
            redirect_uri: "https://dev.patrykstyla.com/api/discord_login",
        }
    }
}

pub async fn request_access_token(code: String, client: web::Data<Client>) -> DiscordTokenData {
    let data = DiscordBotAuthData {
        code,
        ..Default::default()
    };

    let result = client
        .post(format!("{}oauth2/token", BASE_URL))
        .form(&data)
        .send()
        .await
        .unwrap();

    // let text = result.text().await.unwrap();
    let json = result.json::<DiscordTokenData>().await.unwrap();

    json
}

pub async fn request_refresh_token(
    refresh_token: &'static str,
    client: web::Data<Client>,
) -> DiscordTokenData {
    let data = DiscordBotAuthDataRefresh::new(refresh_token);

    let result = client
        .post(format!("{}oauth2/token", BASE_URL))
        .form(&data)
        .send()
        .await
        .unwrap();

    // let text = result.text().await.unwrap();
    let json = result.json::<DiscordTokenData>().await.unwrap();

    json
}

#[get("/discord_login")]
pub async fn discord_login(
    req: HttpRequest,
    query: web::Query<DiscordLoginCode>,
    pool: web::Data<Pool<Postgres>>,
    client: web::Data<Client>,
    keys: web::Data<AccessKeys>,
) -> impl Responder {
    let data = request_access_token(query.code.to_owned(), client.clone()).await;

    let user = get_user(client.clone(), &data.access_token, &pool).await;
    let _guilds = get_user_guilds(client, &data.access_token, user.id, &pool).await;

    // let guilds_id: Vec<i64> = guilds.iter().map(|a| a.id).collect();

    let (access_token, refresh_token) =
        create_jwt_tokens(data.access_token, data.refresh_token, user.id, &keys).await;
    let mut b = NamedFile::open_async("callback.html")
        .await
        .unwrap()
        .into_response(&req);

    let access_token_cookie = Cookie::build("access_token", access_token)
        .max_age(actix_web::cookie::time::Duration::days(7))
        .domain(".patrykstyla.com")
        .secure(true)
        .finish();

    let refresh_token_cookie = Cookie::build("refresh_token", refresh_token)
        .max_age(actix_web::cookie::time::Duration::days(7))
        .domain(".patrykstyla.com")
        .secure(true)
        .finish();

    b.add_cookie(&access_token_cookie).unwrap();
    b.add_cookie(&refresh_token_cookie).unwrap();

    b
}

#[get("/token")]
pub async fn get_token(req: HttpRequest) -> impl Responder {
    let headers = req.headers();
    let cookie = match headers.get("cookie") {
        Some(cookie) => cookie,
        None => {
            panic!("");
        }
    };

    let (access_token, _) = get_access_and_refresh_tokens(cookie);

    let json = json!({ "token": access_token });

    HttpResponse::Ok().json(json)
}

async fn create_jwt_tokens(
    access_token: String,
    refresh_token: String,
    id: i64,
    keys: &web::Data<AccessKeys>,
) -> (String, String) {
    let access_token = Token::<Access>::encode(id, access_token, &keys.access_encode);

    let refresh_token = Token::<Refresh>::encode(id, refresh_token, &keys.refresh_encode);

    (access_token, refresh_token)
}

mod jwt_numeric_date {
    //! Custom serialization of OffsetDateTime to conform with the JWT spec (RFC 7519 section 2, "Numeric Date")
    use serde::{self, Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    /// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
    pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let timestamp = date.unix_timestamp();
        serializer.serialize_i64(timestamp)
    }

    /// Attempts to deserialize an i64 and use as a Unix timestamp
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        OffsetDateTime::from_unix_timestamp(i64::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Unix timestamp value"))
    }
}
