use super::*;
use nvlens_io::BinaryWriter;
#[test]
fn overlaps_pixels_and_truncation() -> io::Result<()> {
    let mut block = vec![0; 8];
    block.extend([1, b'A', 0x13, 0]);
    BinaryWriter::u32_le(12, &mut block);
    BinaryWriter::u32_le(6, &mut block[4..]);
    assert_eq!(decode(&block, 2, 1)?, b"AAAAAA");
    assert_eq!(
        decode(&block[..11], 2, 1).err().map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
    block[10] = 0;
    assert!(decode(&block, 2, 1).is_err());
    block.truncate(8);
    block.extend([1, 1, 2, 3, 0x10, 0]);
    BinaryWriter::u32_le(14, &mut block);
    assert_eq!(decode(&block, 1, 3)?, [1, 2, 3, 1, 2, 3]);
    Ok(())
}
