use crate::*;

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
        pubkey: pubkey[2..].to_string(), // remove 02 prefix
        created_at,
        content,
        tags,
        sig: sig_encoded,
    };
}

pub fn verify_event_sig(event: &EventData) -> bool {
    let secp = Secp256k1::new();
    //check pubkey without prefix is odd or even

    let original_pubkey = &event.pubkey.clone();

    let is_odd = original_pubkey
        .chars()
        .last()
        .unwrap()
        .to_digit(16)
        .unwrap()
        % 2
        == 1;
    let pubkey_with_prefix: String = if is_odd {
        "02".to_string() + &original_pubkey
    } else {
        "03".to_string() + &original_pubkey
    };

    println!("pubkey_with_prefix: {}", pubkey_with_prefix);
    // println!("pubkey_str: {}", pubkey_str);
    let pubkey_bytes = decode(&pubkey_with_prefix).expect("Failed to decode pubkey");
    let pubkey_prefix_bytes = decode(&pubkey_with_prefix).expect("Failed to decode pubkey");

    // println!("pubkey_bytes: {:?}", pubkey_bytes);
    println!("pubkey_prefix_bytes: {:?}", pubkey_prefix_bytes);

    let secp_pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes).unwrap();
    let x_only_pubkey = XOnlyPublicKey::from(secp_pubkey);
    let tags = serde_json::to_string(&event.tags).unwrap();

    let id = serde_json::json!([0, pubkey_with_prefix, event.created_at, tags, event.content]);
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
