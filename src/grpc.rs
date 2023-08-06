use tonic::{Request, Response, Status};

use hello_world::greeter_server::Greeter;
use hello_world::{HelloReply, HelloRequest};
use tracing::info;

pub mod hello_world {
    tonic::include_proto!("test1");
}

#[derive(Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        info!("Got a request from {:?}", request.remote_addr());

        let reply = hello_world::HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}
