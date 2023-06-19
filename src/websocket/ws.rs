/// Define HTTP actor
use crate::*;
use actix::AsyncContext;
use serde_json::Value;
pub struct MyWs {
    pub client: Arc<PrismaClient>,
}

impl MyWs {
    pub fn new(client: Arc<PrismaClient>) -> Self {
        MyWs { client }
    }
}

impl Actor for MyWs {
    type Context = ws::WebsocketContext<Self>;
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for MyWs {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => ctx.pong(&msg),
            Ok(ws::Message::Text(text)) => {
                let request_array: Value = json_parse(&text);
                if !request_array.is_array() {
                    ctx.text("Invalid request");
                    return;
                }

                let request_type = request_array[0].as_str().unwrap();
                let _sub_id = request_array[1].as_str().unwrap();
                match request_type {
                    "EVENT" => {
                        let event: Value = json_parse(&request_array[2].to_string());
                        let event: EventData = serde_json::from_value(event).unwrap();
                        println!("Received event: {:?}", event);
                        let event_string = json_stringify(&event);
                        let client = self.client.clone();
                        let fut = async move {
                            let res = save_event(&client, event.clone()).await;
                            /*   let _ = ctx.address().do_send(Text(format!(
                                "Requested Saved event: {:?}",
                                "event_string"
                            ))); */
                            match res {
                                Ok(_) => println!("Saved event: {:?}", event.clone()),
                                Err(e) => println!("Error saving event: {:?}", e),
                            }
                        };

                        let fut_obj = actix::fut::wrap_future::<_, Self>(fut);
                        ctx.spawn(fut_obj);
                        ctx.text(format!("Requested Saved event: {:?}", event_string));
                    }
                    "REQ" => {
                        ctx.text("Requesting Data");
                    }
                    _ => {
                        ctx.text("Unknown request type");
                    }
                }
            }
            Ok(ws::Message::Binary(bin)) => ctx.binary(bin),
            _ => (),
        }
    }
}

pub async fn ws_index(
    data: web::Data<Arc<PrismaClient>>,
    req: HttpRequest,
    stream: web::Payload,
) -> Result<HttpResponse, Error> {
    let client = data.get_ref().clone();
    let resp = ws::start(MyWs::new(client), &req, stream);
    println!("{:?}", resp);
    resp
}

#[cfg(test)]
mod test {
    use prisma_client_rust::serde_json::{self, Value};

    use crate::{json_parse, EventData};

    #[test]
    fn test_ws_index() {
        let incoming_request = r#"["REQ","Sub Id",{"id":"0x1","pubkey":"0x2","created_at":123,"content":"0x4","tags":[["tag1","b"]],"sig":"0x6"}]"#;

        let event: Value = json_parse(&incoming_request);
        let event: EventData = serde_json::from_value(event[2].clone()).unwrap();
        println!("Received event: {:?}", event);
    }
}
