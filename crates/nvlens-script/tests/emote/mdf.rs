#![allow(clippy::unwrap_used)]

use super::*;

/// Encodes bytes into a minimal MDF fixture.
pub(crate) fn encode_fixture(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use nvlens_io::BinaryWriter;

    let mut out = Vec::from(MAGIC.as_slice());
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
    cipher::mdf::MdfStream::new("game_info.psb.m", Some(131)).apply(&mut mdf[HEADER_LEN..]);
    let key = MdfKey {
        key: "game_info.psb.m",
        key_len: Some(131),
    };
    assert_eq!(decode(&mdf, Some(key)).unwrap(), payload);
}

/// One Zstandard single-segment frame containing a raw final block.
pub(crate) fn mzs_fixture(data: &[u8]) -> Vec<u8> {
    use nvlens_io::BinaryWriter;
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
    use nvlens_io::BinaryWriter;
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
