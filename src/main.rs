
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;

mod crypto;
mod tunnel;

const SERVER_TUN_IP: &str = "10.8.0.1";
const TUN_NETMASK: &str = "255.255.255.0";
const SERVER_UDP: &str = "192.168.56.102:51820";

// Temporary development key.
// DO NOT use this key in a real VPN.
const VPN_KEY: [u8; 32] = [42u8; 32];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting encrypted VPN server...");

    // --------------------------------------------------
    // Create TUN interface
    // --------------------------------------------------

    let tun = tunnel::create_tun(
        "tun0",
        SERVER_TUN_IP,
        TUN_NETMASK,
    )?;

    println!(
        "TUN interface created: {}",
        SERVER_TUN_IP
    );

    // --------------------------------------------------
    // Create UDP socket
    // --------------------------------------------------

    let socket = Arc::new(
        UdpSocket::bind(SERVER_UDP)?
    );

    println!(
        "UDP server listening on {}",
        SERVER_UDP
    );

    let tun = Arc::new(Mutex::new(tun));

    // Stores the client's UDP address after
    // receiving the first packet.
    let client_addr: Arc<Mutex<Option<SocketAddr>>> =
        Arc::new(Mutex::new(None));

    // ==================================================
    // UDP -> DECRYPT -> TUN
    // ==================================================

    {
        let socket = Arc::clone(&socket);
        let tun = Arc::clone(&tun);
        let client_addr = Arc::clone(&client_addr);

        thread::spawn(move || {
            let mut buffer = [0u8; 1500];

            loop {
                match socket.recv_from(&mut buffer) {
                    Ok((size, addr)) => {
                        println!(
                            "UDP packet received: {} bytes from {}",
                            size,
                            addr
                        );

                        // Remember the client address.
                        *client_addr.lock().unwrap() =
                            Some(addr);

                        // Packet must contain:
                        //
                        // 12 bytes nonce
                        // + ciphertext
                        //
                        if size < crypto::NONCE_SIZE {
                            eprintln!(
                                "Packet too small"
                            );
                            continue;
                        }

                        // Extract nonce.
                        let nonce_bytes: [u8; 12] =
                            match buffer[..12].try_into() {
                                Ok(nonce) => nonce,
                                Err(_) => {
                                    eprintln!(
                                        "Invalid nonce"
                                    );
                                    continue;
                                }
                            };

                        // Remaining bytes are ciphertext.
                        let ciphertext =
                            &buffer[12..size];

                        // Decrypt and authenticate.
                        match crypto::decrypt(
                            &VPN_KEY,
                            &nonce_bytes,
                            ciphertext,
                        ) {
                            Ok(plaintext) => {
                                println!(
                                    "UDP -> TUN: {} bytes decrypted",
                                    plaintext.len()
                                );

                                let mut tun =
                                    tun.lock().unwrap();

                                if let Err(e) =
                                    tunnel::write_packet(
                                        &mut tun,
                                        &plaintext,
                                    )
                                {
                                    eprintln!(
                                        "TUN write error: {}",
                                        e
                                    );
                                }
                            }

                            Err(_) => {
                                eprintln!(
                                    "Authentication/decryption failed"
                                );
                            }
                        }
                    }

                    Err(e) => {
                        eprintln!(
                            "UDP receive error: {}",
                            e
                        );
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
        let size = {
            let mut tun =
                tun.lock().unwrap();

            match tunnel::read_packet(
                &mut tun,
                &mut buffer,
            ) {
                Ok(size) => size,

                Err(e) => {
                    eprintln!(
                        "TUN read error: {}",
                        e
                    );
                    continue;
                }
            }
        };

        println!(
            "TUN packet received: {} bytes",
            size
        );

        // We need to know where to send the
        // encrypted packet.
        let destination =
            *client_addr.lock().unwrap();

        let Some(addr) = destination else {
            println!(
                "No VPN client connected yet."
            );
            continue;
        };

        // Generate a fresh nonce for this packet.
        let nonce =
            rand::random::<[u8; 12]>();

        // Encrypt the IP packet.
        match crypto::encrypt(
            &VPN_KEY,
            &nonce,
            &buffer[..size],
        ) {
            Ok(ciphertext) => {
                // Packet format:
                //
                // [ 12-byte nonce ][ ciphertext + auth tag ]
                //
                let mut packet =
                    Vec::with_capacity(
                        12 + ciphertext.len()
                    );

                packet.extend_from_slice(
                    &nonce
                );

                packet.extend_from_slice(
                    &ciphertext
                );

                // Send encrypted packet.
                match socket.send_to(
                    &packet,
                    addr,
                ) {
                    Ok(sent) => {
                        println!(
                            "TUN -> UDP: {} bytes encrypted, sent {} bytes",
                            size,
                            sent
                        );
                    }

                    Err(e) => {
                        eprintln!(
                            "UDP send error: {}",
                            e
                        );
                    }
                }
            }

            Err(e) => {
                eprintln!(
                    "Encryption failed: {}",
                    e
                );
            }
        }
    }
}

