//! TLG6 Golomb residual coding, as defined by TVPTLG6DecodeGolombValues.
//! Runs alternate zero/nonzero and use LSB-first gamma lengths. Nonzero
//! residuals use the 2004-03-25 adaptive Golomb table and a four-byte unary
//! escape window. Output bytes represent signed errors modulo 256.
use std::io;
use vnlens_io::{BinaryIo, BitOrder, BitReader};

const LENGTHS: [[usize; 9]; 4] = [
    [3, 7, 15, 27, 63, 108, 223, 448, 130],
    [3, 5, 13, 24, 51, 95, 192, 384, 257],
    [2, 5, 12, 21, 39, 86, 155, 320, 384],
    [2, 3, 9, 18, 33, 61, 129, 258, 511],
];
const TABLE: [[u8; 4]; 1024] = {
    let mut table = [[0; 4]; 1024];
    let mut n = 0;
    while n < 4 {
        let mut a = 0;
        let mut k = 0;
        while k < 9 {
            let mut i = 0;
            while i < LENGTHS[n][k] {
                table[a][n] = k as u8;
                a += 1;
                i += 1;
            }
            k += 1;
        }
        n += 1;
    }
    table
};

/// Decodes one channel with the declared bit count and residual count.
/// Bounds derive from the stream and pixel count; no zero-padding is invented.
/// Malformed runs, residuals and truncated fields return an I/O error.
pub fn decode(bytes: &[u8], bit_count: u32, count: usize) -> io::Result<Vec<u8>> {
    let mut bits = BitReader::new(bytes, BitOrder::Lsb);
    let mut zero = bits.read_bit()? == 0;
    let mut out = Vec::new();
    let mut a = 0usize;
    let mut n = 3usize;
    while out.len() < count {
        let mut base = 1usize;
        let mut exponent = 0;
        while bits.read_bit()? == 0 {
            base = base
                .checked_mul(2)
                .filter(|&v| v <= count - out.len())
                .ok_or_else(|| BinaryIo::invalid_input("TLG6 run exceeds channel"))?;
            exponent += 1;
        }
        let extra = usize::try_from(bits.read_bits_le_u64(exponent)?)
            .map_err(|_| BinaryIo::invalid_input("TLG6 run exceeds address space"))?;
        let length = base
            .checked_add(extra)
            .filter(|&v| v <= count - out.len())
            .ok_or_else(|| BinaryIo::invalid_input("TLG6 run exceeds channel"))?;
        if zero {
            out.resize(out.len() + length, 0);
        } else {
            for _ in 0..length {
                let k = *TABLE
                    .get(a)
                    .and_then(|row| row.get(n))
                    .ok_or_else(|| BinaryIo::invalid_input("Invalid TLG6 adaptive state"))?;
                let window = 32 - bits.position().1;
                let mut quotient = 0;
                while quotient < u32::from(window) && bits.read_bit()? == 0 {
                    quotient += 1;
                }
                if quotient == u32::from(window) {
                    quotient = bits.read_bits_le(8)?;
                }
                let code = (quotient << k) + bits.read_bits_le(k)?;
                if code > 254 {
                    return Err(BinaryIo::invalid_input("TLG6 residual exceeds signed byte"));
                }
                let magnitude = code >> 1;
                let value = if code & 1 == 0 {
                    -(magnitude as i32) - 1
                } else {
                    magnitude as i32 + 1
                };
                out.push(value as u8);
                a += magnitude as usize;
                if n == 0 {
                    a >>= 1;
                    n = 3;
                } else {
                    n -= 1;
                }
            }
        }
        zero = !zero;
    }
    let (byte, bit) = bits.position();
    if byte as u64 * 8 + u64::from(bit) > u64::from(bit_count) {
        return Err(BinaryIo::unexpected_eof(
            "TLG6 code exceeds declared bit length",
        ));
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/compress/tlg6.rs"]
mod tests;
