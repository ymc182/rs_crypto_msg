use crate::*;
use serde::{de::DeserializeOwned, Serialize};

pub fn json_parse<T: DeserializeOwned>(json: &str) -> T {
    serde_json::from_str(json).unwrap()
}

pub fn json_stringify<T: Serialize>(json: &T) -> String {
    serde_json::to_string(json).unwrap()
}
