use std::io::{self, Read, Write};
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

pub fn read_packet<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
) -> io::Result<usize> {
    reader.read(buffer)
}

pub fn write_packet<W: Write>(
    writer: &mut W,
    packet: &[u8],
) -> io::Result<()> {
    writer.write_all(packet)
}