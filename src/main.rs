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
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EventData {
    pub id: String,
    pub pubkey: String,
    pub created_at: u128,
    pub content: String,
    pub tags: Vec<Vec<String>>,
    pub sig: String,
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

#[get("/key-pair")]
async fn create_key_pair() -> impl Responder {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
    let secret_key_hex = secret_key.display_secret().to_string();
    let public_key_hex = public_key.to_string()[2..].to_string();
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
                .service(create_key_pair),
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

pub fn create_event_sig(
    secret_key_hex: String,
    content: String,
    tags: String,
    created_at: u128,
) -> EventData {
    let secp = Secp256k1::new();
    let key_pair = KeyPair::from_seckey_str(&secp, &secret_key_hex).expect("Invalid secret key");
    let pubkey = key_pair.public_key().to_string();
    let tags: Vec<Vec<String>> = serde_json::from_str(&tags).unwrap();
    let tag_string = serde_json::to_string(&tags).unwrap();
    let id = serde_json::json!([0, pubkey, created_at, tag_string, content]);
    let id_string = id.to_string();
    let message = Message::from_hashed_data::<sha256::Hash>(id_string.as_bytes());
    let id_hashed = encode(message.as_ref());
    let sig = secp.sign_schnorr(&message, &key_pair);
    let sig_encoded = encode(sig.as_ref());
    return EventData {
        id: id_hashed,
        pubkey,
        created_at,
        content,
        tags,
        sig: sig_encoded,
    };
}

pub fn verify_event_sig(event: &EventData) -> bool {
    let secp = Secp256k1::new();

    let pubkey_str = "02".to_string() + &event.pubkey.clone();
    let pubkey_bytes = decode(&pubkey_str).expect("Failed to decode pubkey");
    let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes).unwrap();
    let x_only_pubkey = XOnlyPublicKey::from(pubkey);
    let tags = serde_json::to_string(&event.tags).unwrap();

    let id = serde_json::json!([0, event.pubkey, event.created_at, tags, event.content]);
    let id_string = id.to_string();

    let message = Message::from_hashed_data::<sha256::Hash>(id_string.as_bytes());

    let sig_bytes = decode(&event.sig).expect("Failed to decode signature");
    let sig = Signature::from_slice(&sig_bytes).unwrap();

    let ver_result = secp.verify_schnorr(&sig, &message, &x_only_pubkey);
    if ver_result.is_err() {
        return false;
    }
    return true;
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
