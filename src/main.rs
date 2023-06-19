use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use secp256k1::hashes::sha256;
use secp256k1::rand::rngs::OsRng;
use secp256k1::schnorr::Signature;
use secp256k1::{KeyPair, Message, Secp256k1, XOnlyPublicKey};

#[allow(warnings, unused)]
mod prisma;
use actix_web::web::Json;
use hex::{decode, encode};
use prisma::event;
use prisma::PrismaClient;
use prisma_client_rust::{serde_json, NewClientError};
use serde::{Deserialize, Serialize};

use crate::sign::{create_event_sig, verify_event_sig};
mod sign;
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EventData {
    pub id: String,
    pub pubkey: String,
    pub created_at: u128,
    pub content: String,
    pub tags: Vec<Vec<String>>,
    pub sig: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SignEventData {
    pub secret_key: String,
    pub content: String,
    pub tags: Vec<Vec<String>>,
    pub created_at: u128,
}

#[get("/")]
async fn hello() -> impl Responder {
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
    HttpServer::new(|| {
        App::new().service(hello).service(echo).service(
            web::scope("/api")
                .service(create_event)
                .service(create_key_pair)
                .service(sign_event),
        )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

pub async fn save_event(client: PrismaClient, event: EventData) -> Result<(), NewClientError> {
    let tags = serde_json::to_string(&event.tags).unwrap();

    let saved_event = client
        .event()
        .create(
            event.id,
            event.pubkey,
            event.created_at.try_into().unwrap(),
            event.content,
            tags,
            event.sig,
            vec![],
        )
        .exec()
        .await;
    println!("Saved event: {:?}", saved_event);
    Ok(())
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
        let event = create_event_sig(secret_key_hex, content, tags, created_at);
        assert_eq!(event.pubkey, public_key.to_string());
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
        let event = create_event_sig(secret_key_hex, content, tags, created_at);
        let result = verify_event_sig(&event);
        assert_eq!(result, true);
    }
}
