use super::*;
use nvlens_io::BinaryWriter;

#[test]
fn chunk_checks_the_final_short_portion_and_exact_bounds() -> io::Result<()> {
    // One zero byte, with a zero key: the final checksum is still present.
    let mut bytes = vec![0; 11];
    BinaryWriter::u32_le(!1 ^ 0xc92e_568b, &mut bytes);
    BinaryWriter::u32_le(8 ^ 0xc92e_568b, &mut bytes[4..]);
    assert_eq!(decrypt_chunk(&mut BinaryReader::new(&bytes), 0)?, [0]);
    assert_eq!(
        decrypt_chunk(&mut BinaryReader::new(&bytes[..10]), 0)
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
    bytes[9] = 1;
    assert!(decrypt_chunk(&mut BinaryReader::new(&bytes), 0).is_err());
    Ok(())
}
