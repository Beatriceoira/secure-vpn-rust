use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

pub const NONCE_SIZE: usize = 12;

pub fn encrypt(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(nonce_bytes);

    Ok(cipher.encrypt(nonce, plaintext)?)
}

pub fn decrypt(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(nonce_bytes);

    Ok(cipher.decrypt(nonce, ciphertext)?)
}