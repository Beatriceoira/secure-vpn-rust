use std::convert::TryInto;

pub const COUNTER_SIZE: usize = 8;
pub const NONCE_SIZE: usize = 12;

pub fn build_packet(
    counter: u64,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(
        COUNTER_SIZE + NONCE_SIZE + ciphertext.len()
    );

    packet.extend_from_slice(&counter.to_be_bytes());
    packet.extend_from_slice(nonce);
    packet.extend_from_slice(ciphertext);

    packet
}

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