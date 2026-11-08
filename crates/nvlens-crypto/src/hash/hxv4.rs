//! CompoundStorageMedia hashes UTF-16LE name + domain. Directory SipHash-2-4
//! has zero keys and stores the result little-endian; file names use BLAKE2s-256.
//! The caller supplies canonical spelling (including the directory's slash).
use blake2::{Blake2s256, Digest};
use nvlens_io::{BinaryReader, BinaryWriter};
fn wide(value: &str, domain: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in value.encode_utf16().chain(domain.encode_utf16()) {
        let mut word = [0; 2];
        BinaryWriter::u16_le(unit, &mut word);
        bytes.extend(word);
    }
    bytes
}
#[must_use]
pub fn filename(value: &str, domain: &str) -> [u8; 32] {
    Blake2s256::digest(wide(value, domain)).into()
}
#[must_use]
pub fn directory(value: &str, domain: &str) -> [u8; 8] {
    let bytes = wide(value, domain);
    let mut v = [
        0x736f6d6570736575u64,
        0x646f72616e646f6d,
        0x6c7967656e657261,
        0x7465646279746573,
    ];
    let (words, tail) = bytes.as_chunks::<8>();
    for word in words {
        let m = BinaryReader::u64_le(word);
        v[3] ^= m;
        round(&mut v);
        round(&mut v);
        v[0] ^= m;
    }
    let mut last = [0; 8];
    last[..tail.len()].copy_from_slice(tail);
    last[7] = bytes.len() as u8;
    let m = BinaryReader::u64_le(&last);
    v[3] ^= m;
    round(&mut v);
    round(&mut v);
    v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    let mut out = [0; 8];
    BinaryWriter::u64_le(v[0] ^ v[1] ^ v[2] ^ v[3], &mut out);
    out
}
fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stored_directory_byte_order_and_domain() {
        assert_eq!(
            directory("", "xp3hnp"),
            [0x94, 0xd4, 0xa9, 0x7c, 0x61, 0x49, 0x86, 0x21]
        );
        assert_ne!(
            directory("scenario", "xp3hnp"),
            directory("scenario/", "xp3hnp")
        );
        assert_ne!(filename("a.tjs", "xp3hnp"), filename("a.tjs", "other"));
    }
}
