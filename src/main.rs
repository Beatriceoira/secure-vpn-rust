use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;

mod tunnel;

const SERVER_TUN_IP: &str = "10.8.0.1";
const TUN_NETMASK: &str = "255.255.255.0";
const SERVER_UDP: &str = "192.168.56.102:51820";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting VPN server...");

    let tun = tunnel::create_tun(
        "tun0",
        SERVER_TUN_IP,
        TUN_NETMASK,
    )?;

    println!("TUN interface created: {}", SERVER_TUN_IP);

    let socket = Arc::new(UdpSocket::bind(SERVER_UDP)?);

    println!("UDP server listening on {}", SERVER_UDP);

    let tun = Arc::new(Mutex::new(tun));

    let client_addr: Arc<Mutex<Option<SocketAddr>>> =
        Arc::new(Mutex::new(None));

    // UDP -> TUN
    {
        let socket = Arc::clone(&socket);
        let tun = Arc::clone(&tun);
        let client_addr = Arc::clone(&client_addr);

        thread::spawn(move || {
            let mut buffer = [0u8; 1500];

            loop {
                match socket.recv_from(&mut buffer) {
                    Ok((size, addr)) => {
                        println!("UDP -> TUN: {} bytes from {}", size, addr);

                        *client_addr.lock().unwrap() = Some(addr);

                        let mut tun = tun.lock().unwrap();

                        if let Err(e) =
                            tunnel::write_packet(&mut tun, &buffer[..size])
                        {
                            eprintln!("TUN write error: {}", e);
                        }
                    }

                    Err(e) => {
                        eprintln!("UDP receive error: {}", e);
                    }
                }
            }
        });
    }

    // TUN -> UDP
    let mut buffer = [0u8; 1500];

    loop {
        let size = {
            let mut tun = tun.lock().unwrap();

            match tunnel::read_packet(&mut tun, &mut buffer) {
                Ok(size) => size,
                Err(e) => {
                    eprintln!("TUN read error: {}", e);
                    continue;
                }
            }
        };

        let destination = *client_addr.lock().unwrap();

        if let Some(addr) = destination {
            println!("TUN -> UDP: {} bytes to {}", size, addr);

            if let Err(e) =
                socket.send_to(&buffer[..size], addr)
            {
                eprintln!("UDP send error: {}", e);
            }
        } else {
            println!("No VPN client connected yet.");
        }
    }
}