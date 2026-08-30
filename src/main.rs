use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;

mod crypto;
mod packet;
mod tunnel;

const SERVER_TUN_IP: &str = "10.8.0.1";
const TUN_NETMASK: &str = "255.255.255.0";
const SERVER_UDP: &str = "192.168.56.102:51820";

// Temporary development key.
// DO NOT use this key in a real VPN.
const VPN_KEY: [u8; 32] = [42u8; 32];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting encrypted VPN server...");

    // ==================================================
    // Create TUN interface
    // ==================================================

    let tun = tunnel::create_tun(
        "tun0",
        SERVER_TUN_IP,
        TUN_NETMASK,
    )?;

    println!(
        "TUN interface created: {}",
        SERVER_TUN_IP
    );

    // ==================================================
    // Create UDP socket
    // ==================================================

    let socket = Arc::new(
        UdpSocket::bind(SERVER_UDP)?
    );

    println!(
        "UDP server listening on {}",
        SERVER_UDP
    );

    let tun = Arc::new(Mutex::new(tun));

    // Client UDP address.
    let client_addr: Arc<Mutex<Option<SocketAddr>>> =
        Arc::new(Mutex::new(None));

    // Counter for packets sent by the server.
    let mut send_counter: u64 = 0;

    // Highest packet counter received from the client.
    let highest_received_counter =
        Arc::new(Mutex::new(None::<u64>));

    // ==================================================
    // UDP -> DECRYPT -> TUN
    // ==================================================

    {
        let socket = Arc::clone(&socket);
        let tun = Arc::clone(&tun);
        let client_addr = Arc::clone(&client_addr);
        let highest_received_counter =
            Arc::clone(&highest_received_counter);

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

                        // Remember the client's UDP address.
                        *client_addr
                            .lock()
                            .unwrap() = Some(addr);

                        // Parse:
                        //
                        // [ counter ][ nonce ][ ciphertext ]
                        //

                        let Some((counter, nonce, ciphertext)) =
                            packet::parse_packet(&buffer[..size])
                        else {
                            eprintln!(
                                "Invalid VPN packet"
                            );
                            continue;
                        };

                        // Basic replay protection.
                        {
                            let mut highest =
                                highest_received_counter
                                    .lock()
                                    .unwrap();

                            if let Some(previous) = *highest {
                                if counter <= previous {
                                    eprintln!(
                                        "Replay/old packet rejected: counter={}",
                                        counter
                                    );
                                    continue;
                                }
                            }

                            *highest = Some(counter);
                        }

                        // Decrypt and authenticate.
                        match crypto::decrypt(
                            &VPN_KEY,
                            &nonce,
                            ciphertext,
                        ) {
                            Ok(plaintext) => {
                                println!(
                                    "UDP -> TUN: counter={}, {} bytes decrypted",
                                    counter,
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

        // Get the current VPN client.
        let destination =
            *client_addr.lock().unwrap();

        let Some(addr) = destination else {
            println!(
                "No VPN client connected yet."
            );
            continue;
        };

        // Generate a unique nonce.
        let nonce =
            rand::random::<[u8; 12]>();

        // Encrypt the IP packet.
        match crypto::encrypt(
            &VPN_KEY,
            &nonce,
            &buffer[..size],
        ) {
            Ok(ciphertext) => {
                // Build:
                //
                // [ counter ][ nonce ][ ciphertext ]
                //

                let packet = packet::build_packet(
                    send_counter,
                    &nonce,
                    &ciphertext,
                );

                match socket.send_to(
                    &packet,
                    addr,
                ) {
                    Ok(sent) => {
                        println!(
                            "TUN -> UDP: counter={}, {} bytes encrypted, sent {} bytes",
                            send_counter,
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

                send_counter += 1;
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
