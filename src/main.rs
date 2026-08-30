mod tunnel;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating TUN interface...");

    let mut tun = tunnel::create_tun(
        "tun0",
        "10.8.0.1",
        "255.255.255.0",
    )?;

    println!("TUN interface created.");
    println!("Waiting for packets...");

    loop {
        let packet = tunnel::read_packet(&mut tun)?;

        println!("Received {} byte packet", packet.len());
    }
}