use super::*;
use nvlens_io::BinaryWriter;
#[test]
fn wave_box_preserves_ogg_payload_and_checks_header_bounds() -> Result<()> {
    let mut bytes = vec![0; 64];
    BinaryWriter::u32_le(64, &mut bytes);
    bytes[4..8].copy_from_slice(b"bw  ");
    BinaryWriter::u32_le(4, &mut bytes[8..]);
    BinaryWriter::u32_le(3, &mut bytes[48..]);
    bytes.extend(b"OggS");
    assert_eq!(ogg_payload(&bytes)?, Some(b"OggS".as_slice()));
    for length in [8, 47, 63, 67] {
        assert!(ogg_payload(&bytes[..length]).is_err());
    }
    BinaryWriter::u32_le(1, &mut bytes[48..]);
    assert!(matches!(ogg_payload(&bytes), Err(Error::Unsupported(_))));
    assert!(ogg_payload(b"unrelated")?.is_none());
    Ok(())
}
