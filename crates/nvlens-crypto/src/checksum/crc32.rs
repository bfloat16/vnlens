//! IEEE CRC-32 (polynomial `0xEDB88320`), table built at compile time.

const TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[n] = c;
        n += 1;
    }
    t
};

/// CRC-32 over `data` with a custom initial register `seed`.
///
/// Standard CRC-32 corresponds to `seed == 0`. Some engines seed the register
/// with a per-block value; pass it here.
#[must_use]
pub fn ieee(seed: u32, data: &[u8]) -> u32 {
    let mut crc = !seed;
    for &b in data {
        crc = TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
#[path = "../../tests/checksum/crc32.rs"]
mod tests;
