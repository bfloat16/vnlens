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
