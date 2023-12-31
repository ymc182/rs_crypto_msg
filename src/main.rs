use std::sync::Arc;

use actix::{Actor, StreamHandler};
use actix_web::Error;
use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web_actors::ws;
use secp256k1::hashes::sha256;
use secp256k1::rand::rngs::OsRng;
use secp256k1::schnorr::Signature;
use secp256k1::{KeyPair, Message, Secp256k1, XOnlyPublicKey};
mod event_data;
mod helper;
#[allow(warnings, unused)]
mod prisma;
mod sign;
mod websocket;

use actix_web::web::Json;
pub use event_data::*;
use hex::{decode, encode};
use prisma::event;
use prisma::PrismaClient;
use prisma_client_rust::{serde_json, NewClientError, QueryError};
use serde::{Deserialize, Serialize};

use crate::sign::{create_event_sig, verify_event_sig};

pub use helper::*;
use websocket::ws_index;

#[get("/")]
async fn entry() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

#[post("/create-event")]
async fn create_event(req_body: Json<EventData>) -> impl Responder {
    let event_data = req_body.into_inner();
    let is_verified = verify_event_sig(&event_data);
    if !is_verified {
        return HttpResponse::BadRequest().body("Invalid signature");
    }
    HttpResponse::Ok().body("Event created")
}

#[post("/sign-event")]
async fn sign_event(req_body: Json<SignEventData>) -> impl Responder {
    let event_data = req_body.into_inner();
    let event = create_event_sig(
        event_data.secret_key,
        event_data.content,
        event_data.kind,
        serde_json::to_string(&event_data.tags).unwrap(),
        event_data.created_at,
    );

    HttpResponse::Ok().body(serde_json::to_string(&event).unwrap())
}

#[get("/key-pair")]
async fn create_key_pair() -> impl Responder {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
    let secret_key_hex = secret_key.display_secret().to_string();
    let public_key_hex = public_key.to_string()[2..].to_string(); // remove 02/03 prefix
    let key_pair = serde_json::json!({
            "secret_key": secret_key_hex,
            "public_key": public_key_hex,
    });
    HttpResponse::Ok().body(key_pair.to_string())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let _client: PrismaClient = PrismaClient::_builder()
        .build()
        .await
        .expect("Failed to build client");

    println!("Client Created");
    println!("Server running at http://{}:{}", "localhost", "8080");
    let data = web::Data::new(Arc::new(_client));
    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .service(echo)
            .service(
                web::scope("/api")
                    .service(create_event)
                    .service(create_key_pair)
                    .service(sign_event)
                    .service(entry),
            )
            .route("/ws/", web::get().to(ws_index))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

pub async fn save_event(
    client: &PrismaClient,
    event: EventData,
) -> Result<event::Data, QueryError> {
    let tags = serde_json::to_string(&event.tags).unwrap();

    let saved_event = client
        .event()
        .create(
            event.id,
            event.pubkey,
            event.kind.try_into().unwrap(),
            event.created_at.try_into().unwrap(),
            event.content,
            tags,
            event.sig,
            vec![],
        )
        .exec()
        .await;
    println!("Saved event: {:?}", saved_event);
    saved_event
}

//impl to_string for EventData return a json compatible string

impl ToString for EventData {
    fn to_string(&self) -> String {
        let event = serde_json::json!({
                "id": self.id,
                "pubkey": self.pubkey,
                "created_at": self.created_at,
                "content": self.content,
                "tags": self.tags,
                "sig": self.sig,
        });
        event.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::Secp256k1;

    #[test]
    fn test_create_event_sig() {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        let secret_key_hex = secret_key.display_secret().to_string();
        let content = "test content".to_string();
        let tags = "[[\"test\", \"tag\"], [\"test2\", \"tag2\"]]".to_string();
        let created_at = 12345;
        let kind = 1;
        let event = create_event_sig(secret_key_hex, content, kind, tags, created_at);
        assert_eq!(event.pubkey, public_key.to_string()[2..].to_string());
        assert_eq!(event.content, "test content".to_string());
        assert_eq!(
            event.tags,
            vec![
                vec!["test".to_string(), "tag".to_string()],
                vec!["test2".to_string(), "tag2".to_string()]
            ]
        );
        assert_eq!(event.created_at, created_at);
    }

    #[test]
    fn test_verify_event_sig() {
        let secp = Secp256k1::new();
        let (secret_key, _public_key) = secp.generate_keypair(&mut OsRng);

        let secret_key_hex = secret_key.display_secret().to_string();
        let content = "test content".to_string();
        let tags = "[[\"test\", \"tag\"], [\"test2\", \"tag2\"]]".to_string();
        let created_at = 12345;
        let kind = 1;
        let event = create_event_sig(secret_key_hex, content, kind, tags, created_at);
        let result = verify_event_sig(&event);
        assert_eq!(result, true);
    }
}
