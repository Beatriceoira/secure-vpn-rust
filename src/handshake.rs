use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::packet::{
    CLIENT_HELLO,
    SERVER_HELLO,
    PUBLIC_KEY_SIZE,
};

/// Generate a fresh ephemeral X25519 key pair.
///
/// The private key is intentionally ephemeral and should only
/// be used for this handshake/session.
pub fn generate_keypair() -> (EphemeralSecret, PublicKey) {
    let mut rng = rand::rng();
    let private_key = EphemeralSecret::random_from_rng(&mut rng);

    let public_key = PublicKey::from(&private_key);

    (private_key, public_key)
}

/// Derive the VPN session key from the X25519 shared secret.
///
/// Both sides perform this operation with their own private key
/// and the peer's public key, producing the same 32-byte key.
pub fn derive_session_key(
    private_key: EphemeralSecret,
    peer_public_key: &PublicKey,
) -> [u8; 32] {
    let shared_secret =
        private_key.diffie_hellman(peer_public_key);

    let hkdf =
        Hkdf::<Sha256>::new(
            None,
            shared_secret.as_bytes(),
        );

    let mut session_key = [0u8; 32];

    hkdf.expand(
        b"secure-vpn-session-key",
        &mut session_key,
    )
    .expect("32-byte HKDF output should be valid");

    session_key
}

pub fn parse_handshake(
    packet: &[u8],
) -> Option<(u8, [u8; PUBLIC_KEY_SIZE])> {
    if packet.len() != 1 + PUBLIC_KEY_SIZE {
        return None;
    }

    let message_type = packet[0];

    if message_type != CLIENT_HELLO
        && message_type != SERVER_HELLO
    {
        return None;
    }

    let public_key: [u8; PUBLIC_KEY_SIZE] =
        packet[1..33].try_into().ok()?;

    Some((message_type, public_key))
}


mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_same_key() {
        let (client_private, client_public) =
            generate_keypair();

        let (server_private, server_public) =
            generate_keypair();

        let client_key =
            derive_session_key(
                client_private,
                &server_public,
            );

        let server_key =
            derive_session_key(
                server_private,
                &client_public,
            );

        assert_eq!(client_key, server_key);
    }
}

