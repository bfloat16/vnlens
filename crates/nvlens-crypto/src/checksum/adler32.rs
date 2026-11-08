//! Adler-32 checksum (RFC 1950).

const MOD_ADLER: u32 = 65_521;

/// Computes Adler-32 with the standard initial value.
#[must_use]
pub fn checksum(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;

    for chunk in data.chunks(5_552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }

    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_vectors() {
        assert_eq!(checksum(b""), 0x0000_0001);
        assert_eq!(checksum(b"Wikipedia"), 0x11E6_0398);
    }
}
