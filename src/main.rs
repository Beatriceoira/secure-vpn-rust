use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;

use x25519_dalek::PublicKey;

mod crypto;
mod handshake;
mod packet;
mod tunnel;

const SERVER_TUN_IP: &str = "10.8.0.1";
const TUN_NETMASK: &str = "255.255.255.0";
const SERVER_UDP: &str = "192.168.56.102:51820";

fn check_replay(highest: &mut Option<u64>, counter: u64) -> bool {
    if let Some(previous) = *highest {
        if counter <= previous {
            return false;
        }
    }

    *highest = Some(counter);
    true
}

#[cfg(test)]
mod tests {
    use super::check_replay;

    #[test]
    fn replay_protection_rejects_old_and_duplicate_packets() {
        let mut highest = None;

        assert!(check_replay(&mut highest, 1));
        assert!(check_replay(&mut highest, 2));
        assert!(!check_replay(&mut highest, 2));
        assert!(!check_replay(&mut highest, 1));
        assert!(check_replay(&mut highest, 3));
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting encrypted VPN server...");

    // ==================================================
    // Create TUN interface
    // ==================================================

    let tun = tunnel::create_tun("tun0", SERVER_TUN_IP, TUN_NETMASK)?;

    println!("TUN interface created: {}", SERVER_TUN_IP);

    // Split the TUN device into independent reader/writer
    // handles so a blocking read cannot prevent writes.
    let (mut tun_reader, mut tun_writer) = tun.split();

    // ==================================================
    // Create UDP socket
    // ==================================================

    let socket = Arc::new(UdpSocket::bind(SERVER_UDP)?);

    println!("UDP server listening on {}", SERVER_UDP);

    // Current VPN client address.
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Counter for encrypted packets sent by server.
    let mut send_counter: u64 = 0;

    // Highest authenticated packet counter received from client.
    let highest_received_counter = Arc::new(Mutex::new(None::<u64>));

    // ==================================================
    // HANDSHAKE
    // ==================================================

    println!("Waiting for CLIENT_HELLO...");

    let mut handshake_buffer = [0u8; 1500];

    let (size, client_addr_value) = socket.recv_from(&mut handshake_buffer)?;

    println!(
        "Received {} byte handshake from {}",
        size, client_addr_value
    );

    let Some((message_type, client_public_bytes)) =
        handshake::parse_handshake(&handshake_buffer[..size])
    else {
        return Err("Invalid handshake packet".into());
    };

    if message_type != packet::CLIENT_HELLO {
        return Err("Expected CLIENT_HELLO".into());
    }

    println!("CLIENT_HELLO received.");

    // Remember client address.
    *client_addr.lock().unwrap() = Some(client_addr_value);

    // Convert raw bytes into X25519 PublicKey.
    let client_public_key = PublicKey::from(client_public_bytes);

    // Generate server ephemeral key pair.
    println!("Generating server key pair...");

    let (server_private, server_public) = handshake::generate_keypair();

    // Derive session key.
    let session_key = handshake::derive_session_key(server_private, &client_public_key);

    println!("Session key successfully derived.");

    // Build SERVER_HELLO.
    let server_public_bytes = server_public.to_bytes();

    let response = packet::build_server_hello(&server_public_bytes);

    socket.send_to(&response, client_addr_value)?;

    println!("SERVER_HELLO sent to {}", client_addr_value);

    println!("VPN handshake complete.");

    // ==================================================
    // UDP -> DECRYPT -> TUN
    // ==================================================

    {
        let socket = Arc::clone(&socket);
        let client_addr = Arc::clone(&client_addr);
        let highest_received_counter = Arc::clone(&highest_received_counter);

        thread::spawn(move || {
            let mut buffer = [0u8; 1500];

            loop {
                match socket.recv_from(&mut buffer) {
                    Ok((size, addr)) => {
                        println!("UDP packet received: {} bytes from {}", size, addr);

                        // Remember the client's UDP address.
                        *client_addr.lock().unwrap() = Some(addr);

                        // Parse:
                        //
                        // [ counter ][ nonce ][ ciphertext ]
                        //

                        let Some((counter, nonce, ciphertext)) =
                            packet::parse_packet(&buffer[..size])
                        else {
                            eprintln!("Invalid VPN packet");
                            continue;
                        };

                        // --------------------------------------------------
                        // Replay protection
                        // --------------------------------------------------
                        //
                        // First reject packets that are already known to be
                        // old or duplicated.
                        //
                        // IMPORTANT:
                        // We do NOT update the highest counter yet.
                        // The packet must first pass authentication.

                        {
                            let highest = highest_received_counter.lock().unwrap();

                            if let Some(previous) = *highest {
                                if counter <= previous {
                                    eprintln!("Replay/old packet rejected: counter={}", counter);
                                    continue;
                                }
                            }
                        }

                        // --------------------------------------------------
                        // Decrypt and authenticate
                        // --------------------------------------------------

                        match crypto::decrypt(&session_key, &nonce, ciphertext) {
                            Ok(plaintext) => {
                                // --------------------------------------------------
                                // Update replay state only AFTER successful
                                // authentication/decryption.
                                // --------------------------------------------------

                                {
                                    let mut highest = highest_received_counter.lock().unwrap();

                                    // Re-check the counter while holding
                                    // the lock before updating it.
                                    //
                                    // This protects the state if multiple
                                    // receive paths are introduced later.
                                    if let Some(previous) = *highest {
                                        if counter <= previous {
                                            eprintln!(
                                                "Replay/old packet rejected after authentication: counter={}",
                                                counter
                                            );
                                            continue;
                                        }
                                    }

                                    *highest = Some(counter);
                                }

                                println!(
                                    "UDP -> TUN: counter={}, {} bytes decrypted",
                                    counter,
                                    plaintext.len()
                                );

                                if let Err(e) = tunnel::write_packet(&mut tun_writer, &plaintext) {
                                    eprintln!("TUN write error: {}", e);
                                } else {
                                    println!("Packet successfully written to TUN.");
                                }
                            }

                            Err(_) => {
                                eprintln!("Authentication/decryption failed");
                            }
                        }
                    }

                    Err(e) => {
                        eprintln!("UDP receive error: {}", e);
                    }
                }
            }
        });
    }

    // ==================================================
    // TUN -> ENCRYPT -> UDP
    // ==================================================

    let mut buffer = [0u8; 1500];

    loop {
        let size = match tunnel::read_packet(&mut tun_reader, &mut buffer) {
            Ok(size) => size,

            Err(e) => {
                eprintln!("TUN read error: {}", e);
                continue;
            }
        };

        println!("TUN packet received: {} bytes", size);

        // Get current VPN client.
        let destination = *client_addr.lock().unwrap();

        let Some(addr) = destination else {
            println!("No VPN client connected yet.");
            continue;
        };

        // Generate unique nonce.
        let nonce = rand::random::<[u8; 12]>();

        // Encrypt IP packet using negotiated
        // session key.
        match crypto::encrypt(&session_key, &nonce, &buffer[..size]) {
            Ok(ciphertext) => {
                // Build:
                //
                // [ counter ][ nonce ][ ciphertext ]
                //

                let packet = packet::build_packet(send_counter, &nonce, &ciphertext);

                match socket.send_to(&packet, addr) {
                    Ok(sent) => {
                        println!(
                            "TUN -> UDP: counter={}, {} bytes encrypted, sent {} bytes",
                            send_counter, size, sent
                        );
                    }

                    Err(e) => {
                        eprintln!("UDP send error: {}", e);
                    }
                }

                send_counter += 1;
            }

            Err(e) => {
                eprintln!("Encryption failed: {}", e);
            }
        }
    }
}
