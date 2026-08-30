use std::net::UdpSocket;

fn main() -> std::io::Result<()>{
	let socket = UdpSocket::bind("192.168.56.102:51820")?;
	println!("VPN server listening on 192.168.56.102:51820");
	
	let mut buffer = [0u8; 1560];

	loop{
		let (size, client_addr) = socket.recv_from(&mut buffer)?;
		
		println!(
			"Received {} bytes from {}",
			size, client_addr
			);

			socket.send_to(&buffer[..size], client_addr)?;
		}
}	
