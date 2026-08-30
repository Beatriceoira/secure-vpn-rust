use std::io::{self, Read};
use tun::{Configuration, Device};

pub fn create_tun(
    name: &str,
    address: &str,
    netmask: &str,
) -> Result<Device, Box<dyn std::error::Error>> {
    let mut config = Configuration::default();

    config
        .tun_name(name)
        .address(address)
        .netmask(netmask)
        .up();

   
    let device = tun::create(&config)?;

    Ok(device)
}

pub fn read_packet(device: &mut Device) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; 1500];

    let size = device.read(&mut buffer)?;

    buffer.truncate(size);

    Ok(buffer)
}