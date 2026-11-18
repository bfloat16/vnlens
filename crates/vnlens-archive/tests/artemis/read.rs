#![allow(clippy::unwrap_used)]
use super::*;
use vnlens_io::BinaryWriter;

#[test]
fn rejects_bad_versions_truncated_indices_names_and_payload_ranges() {
    let bytes = super::super::tests::fixture(&[("name", b"abc")]);
    let end = 7 + BinaryReader::u32_le(&bytes[3..]) as usize;
    for length in 0..bytes.len() {
        let source: std::sync::Arc<[u8]> = bytes[..length].into();
        assert!(
            matches!(index(&source), Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }
    let mut wrong = bytes.clone();
    wrong[0] = b'x';
    let source: std::sync::Arc<[u8]> = wrong.into();
    assert!(matches!(index(&source), Err(Error::InvalidFormat)));
    let mut wrong = bytes.clone();
    wrong[2] = b'9';
    let source: std::sync::Arc<[u8]> = wrong.into();
    assert!(matches!(index(&source), Err(Error::Unsupported(_))));
    let mut wrong = bytes.clone();
    wrong[15] = 0xff;
    let source: std::sync::Arc<[u8]> = wrong.into();
    assert!(matches!(index(&source), Err(Error::Corrupt { .. })));
    let mut wrong = bytes.clone();
    BinaryWriter::u32_le(u32::MAX, &mut wrong[30..]);
    let source: std::sync::Arc<[u8]> = wrong.into();
    assert!(matches!(index(&source), Err(Error::Io(_))));
    let mut wrong = bytes;
    BinaryWriter::u32_le(0, &mut wrong[end - 4..]);
    let source: std::sync::Arc<[u8]> = wrong.into();
    assert!(matches!(index(&source), Err(Error::Corrupt { .. })));
}
