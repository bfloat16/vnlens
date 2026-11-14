//! Non-reflected CRC-16, polynomial 0x8005, initial value zero (CRI HCA).
#[must_use]
pub fn crc16_8005(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x8005
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
#[path = "../../tests/checksum/crc16.rs"]
mod tests;
