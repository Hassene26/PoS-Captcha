use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::RngCore;

/// Accepts a hex-encoded 32-byte key (64 hex chars).
pub fn encrypt_aes(json_payload: &str, hex_key: &str) -> String {
    let key_bytes = hex::decode(hex_key).expect("AES key is not valid hex");
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt handles placing the AuthTag at the end of the ciphertext bytes
    let ciphertext = cipher.encrypt(nonce, json_payload.as_bytes()).expect("encryption failure");
    
    let (real_ciphertext, auth_tag) = ciphertext.split_at(ciphertext.len() - 16);
    
    format!(
        "{}.{}.{}",
        STANDARD.encode(&nonce_bytes),
        STANDARD.encode(real_ciphertext),
        STANDARD.encode(auth_tag)
    )
}

/// Accepts a hex-encoded 32-byte key (64 hex chars).
pub fn decrypt_aes(encrypted_payload: &str, hex_key: &str) -> Option<String> {
    let parts: Vec<&str> = encrypted_payload.split('.').collect();
    if parts.len() != 3 { return None; }
    
    let nonce_bytes = STANDARD.decode(parts[0]).ok()?;
    let ciphertext = STANDARD.decode(parts[1]).ok()?;
    let auth_tag = STANDARD.decode(parts[2]).ok()?;
    
    let mut combined_ciphertext = ciphertext;
    combined_ciphertext.extend_from_slice(&auth_tag);
    
    let key_bytes = hex::decode(hex_key).ok()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, combined_ciphertext.as_ref()).ok()?;
    String::from_utf8(plaintext).ok()
}
