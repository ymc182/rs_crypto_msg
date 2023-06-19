use crate::*;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EventData {
    pub id: String,
    pub pubkey: String,
    pub created_at: u128,
    pub kind: u128,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SignEventData {
    pub secret_key: String,
    pub content: String,
    pub kind: u128,
    pub tags: Vec<Vec<String>>,
    pub created_at: u128,
}
