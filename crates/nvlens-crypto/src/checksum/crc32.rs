//! IEEE CRC-32 (polynomial `0xEDB88320`), table built at compile time.

use nvlens_io::BinaryReader;

// Eight byte-position tables remove the serial dependency between bytes.
// SSE2 has no CRC instruction or gather; CRC32 (SSE4.2) uses a different
// polynomial. This portable slicing-by-eight path retains IEEE CRC-32.
const TABLE: [[u32; 256]; 8] = {
    let mut tables = [[0u32; 256]; 8];
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
        tables[0][n] = c;
        n += 1;
    }
    let mut lane = 1;
    while lane < 8 {
        n = 0;
        while n < 256 {
            let previous = tables[lane - 1][n];
            tables[lane][n] = tables[0][(previous & 255) as usize] ^ (previous >> 8);
            n += 1;
        }
        lane += 1;
    }
    tables
};

/// CRC-32 over `data` with a custom initial register `seed`.
///
/// Standard CRC-32 corresponds to `seed == 0`. Some engines seed the register
/// with a per-block value; pass it here.
#[must_use]
pub fn ieee(seed: u32, data: &[u8]) -> u32 {
    let mut crc = !seed;
    let (blocks, tail) = data.as_chunks::<8>();
    for block in blocks {
        let value = crc ^ BinaryReader::u32_le(block);
        crc = TABLE[7][(value & 255) as usize]
            ^ TABLE[6][((value >> 8) & 255) as usize]
            ^ TABLE[5][((value >> 16) & 255) as usize]
            ^ TABLE[4][(value >> 24) as usize]
            ^ TABLE[3][usize::from(block[4])]
            ^ TABLE[2][usize::from(block[5])]
            ^ TABLE[1][usize::from(block[6])]
            ^ TABLE[0][usize::from(block[7])];
    }
    for &b in tail {
        crc = TABLE[0][((crc ^ u32::from(b)) & 255) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
#[path = "../../tests/checksum/crc32.rs"]
mod tests;
