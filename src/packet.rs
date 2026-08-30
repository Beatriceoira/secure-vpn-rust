use std::convert::TryInto;

pub const COUNTER_SIZE: usize = 8;
pub const NONCE_SIZE: usize = 12;
pub const PUBLIC_KEY_SIZE: usize = 32;

pub const CLIENT_HELLO: u8 = 0x01;
pub const SERVER_HELLO: u8 = 0x02;

/// Build an encrypted VPN data packet.
///
/// Format:
///
/// [ counter ][ nonce ][ ciphertext ]
pub fn build_packet(
    counter: u64,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(
        COUNTER_SIZE + NONCE_SIZE + ciphertext.len(),
    );

    packet.extend_from_slice(&counter.to_be_bytes());
    packet.extend_from_slice(nonce);
    packet.extend_from_slice(ciphertext);

    packet
}

/// Parse an encrypted VPN data packet.
pub fn parse_packet(
    packet: &[u8],
) -> Option<(u64, [u8; NONCE_SIZE], &[u8])> {
    if packet.len() < COUNTER_SIZE + NONCE_SIZE {
        return None;
    }

    let counter = u64::from_be_bytes(
        packet[0..8].try_into().ok()?
    );

    let nonce: [u8; NONCE_SIZE] =
        packet[8..20].try_into().ok()?;

    let ciphertext = &packet[20..];

    Some((counter, nonce, ciphertext))
}

/// Build a CLIENT_HELLO handshake packet.
pub fn build_client_hello(
    public_key: &[u8; PUBLIC_KEY_SIZE],
) -> Vec<u8> {
    let mut packet =
        Vec::with_capacity(1 + PUBLIC_KEY_SIZE);

    packet.push(CLIENT_HELLO);
    packet.extend_from_slice(public_key);

    packet
}

/// Build a SERVER_HELLO handshake packet.
pub fn build_server_hello(
    public_key: &[u8; PUBLIC_KEY_SIZE],
) -> Vec<u8> {
    let mut packet =
        Vec::with_capacity(1 + PUBLIC_KEY_SIZE);

    packet.push(SERVER_HELLO);
    packet.extend_from_slice(public_key);

    packet
}

