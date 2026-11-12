#![allow(clippy::unwrap_used)]

use super::*;

/// Encodes bytes into a minimal MDF fixture.
pub(crate) fn encode_fixture(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use vnlens_io::BinaryWriter;

    let mut out = Vec::from(b"mdf\0".as_slice());
    let mut len = [0u8; 4];
    BinaryWriter::u32_le(u32::try_from(data.len()).unwrap(), &mut len);
    out.extend_from_slice(&len);
    let mut encoder = ZlibEncoder::new(out, Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn decodes_plain_fixture() {
    let payload = b"PSB\0minimal";
    let mdf = encode_fixture(payload);
    assert_eq!(decode(&mdf, None).unwrap(), payload);
}

#[test]
fn decodes_encrypted_fixture() {
    let payload = b"PSB\0encrypted";
    let mut mdf = encode_fixture(payload);
    cipher::mdf::MdfStream::new("game_info.psb.m", Some(131)).apply(&mut mdf[8..]);
    let key = MdfKey {
        key: "game_info.psb.m",
        key_len: Some(131),
    };
    assert_eq!(decode(&mdf, Some(key)).unwrap(), payload);
}

/// One Zstandard single-segment frame containing a raw final block.
pub(crate) fn mzs_fixture(data: &[u8]) -> Vec<u8> {
    use vnlens_io::BinaryWriter;
    let mut bytes = b"mzs\0".to_vec();
    let mut word = [0; 4];
    BinaryWriter::u32_le(data.len() as u32, &mut word);
    bytes.extend(word);
    bytes.extend([0x28, 0xb5, 0x2f, 0xfd, 0xa0]);
    bytes.extend(word);
    BinaryWriter::u32_le(((data.len() as u32) << 3) | 1, &mut word);
    bytes.extend(&word[..3]);
    bytes.extend(data);
    bytes
}
#[test]
fn mzs_plain_encrypted_and_declared_length() {
    use vnlens_io::BinaryWriter;
    let data = b"PSB\0Zstandard fixture";
    let bytes = mzs_fixture(data);
    assert_eq!(decode(&bytes, None).unwrap(), data);
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end], None).is_err());
    }
    let mut encrypted = bytes.clone();
    cipher::mdf::MdfStream::new("synthetic_info.psb.m", Some(131)).apply(&mut encrypted[8..]);
    assert_eq!(
        decode(
            &encrypted,
            Some(MdfKey {
                key: "synthetic_info.psb.m",
                key_len: Some(131)
            })
        )
        .unwrap(),
        data
    );
    assert!(decode(&encrypted, None).is_err());
    for length in [0, data.len() as u32 - 1, data.len() as u32 + 1] {
        let mut malformed = bytes.clone();
        BinaryWriter::u32_le(length, &mut malformed[4..]);
        assert!(decode(&malformed, None).is_err());
    }
}

pub(crate) fn psz_fixture(data: &[u8]) -> Vec<u8> {
    use vnlens_io::BinaryWriter;
    let compressed = encode_fixture(data);
    let mut out = b"PSZ\0".to_vec();
    for value in [(compressed.len() - 8) as u32, data.len() as u32, 0] {
        let mut bytes = [0; 4];
        BinaryWriter::u32_le(value, &mut bytes);
        out.extend(bytes);
    }
    out.extend_from_slice(&compressed[8..]);
    out
}

#[test]
fn psz_lengths_reserved_field_checksums_empty_and_truncation() {
    use vnlens_io::BinaryWriter;
    for payload in [&b"PSB\0PSZ shell"[..], &[]] {
        let bytes = psz_fixture(payload);
        let header = ShellHeader::read(&bytes.as_slice()).unwrap();
        assert_eq!(header.kind, ShellKind::Psz);
        assert_eq!(header.decoded_len, payload.len() as u64);
        assert_eq!(header.payload_offset, 16);
        assert_eq!(header.payload_len, bytes.len() as u64 - 16);
        assert_eq!(decode(&bytes, None).unwrap(), payload);
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end], None).is_err(), "truncated at {end}");
        }
        let mut modified = bytes.clone();
        BinaryWriter::u32_le(0x12345678, &mut modified[12..]);
        assert_eq!(
            ShellHeader::read(&modified.as_slice()).unwrap().reserved,
            Some(0x12345678)
        );
        assert_eq!(decode(&modified, None).unwrap(), payload);
        for value in [payload.len() as u32 + 1, 0] {
            if value == payload.len() as u32 {
                continue;
            }
            let mut malformed = bytes.clone();
            BinaryWriter::u32_le(value, &mut malformed[8..]);
            assert!(decode(&malformed, None).is_err());
        }
        let mut malformed = bytes.clone();
        let last = malformed.len() - 1;
        malformed[last] ^= 1;
        assert!(decode(&malformed, None).is_err());
    }
}

#[test]
fn mdf_complete_stream_requires_its_checksum_and_declared_size() {
    use vnlens_io::BinaryWriter;
    let data = b"complete MDF stream";
    let bytes = encode_fixture(data);
    for end in 0..bytes.len() {
        assert!(
            decode(&bytes[..end], None).is_err(),
            "truncated MDF at {end}"
        );
    }
    for value in [0, data.len() as u32 - 1, data.len() as u32 + 1] {
        let mut malformed = bytes.clone();
        BinaryWriter::u32_le(value, &mut malformed[4..]);
        assert!(decode(&malformed, None).is_err());
    }
}
