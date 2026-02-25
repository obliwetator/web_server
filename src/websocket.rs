use std::time::{Duration, Instant};
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

use actix::{Actor, ActorContext, AsyncContext, StreamHandler};
use actix_web::{get, web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use tracing::{error, info};

/// Define HTTP actor
#[derive(Debug)]
struct MyWs {
    hb: Instant,
}

impl Actor for MyWs {
    type Context = ws::WebsocketContext<Self>;
}

impl MyWs {
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            if Instant::now().duration_since(act.hb) > HEARTBEAT_INTERVAL + CLIENT_TIMEOUT {
                error!("Websocket Client heartbeat failed, disconnecting!");

                ctx.stop();
                return;
            }

            ctx.ping(b"");
        });
    }
}

/// Handler for ws::Message message
impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for MyWs {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        info!("WS Msg {:#?}", msg);
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.hb = Instant::now();
                ctx.pong(&msg)
            }
            Ok(ws::Message::Pong(_)) => {
                self.hb = Instant::now();
            }
            Ok(ws::Message::Text(text)) => ctx.text(text),
            Ok(ws::Message::Binary(bin)) => ctx.binary(bin),
            _ => (),
        }
    }

    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
    }
}

#[get("/ws/")]
pub async fn web_socket(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
    let resp = ws::WsResponseBuilder::new(MyWs { hb: Instant::now() }, &req, stream).start();
    // let resp = ws::start(MyWs {}, &req, stream);
    error!("{:?}", resp);
    resp
}
