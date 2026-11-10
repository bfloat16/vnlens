use super::*;
use sha2::{Digest, Sha256};

#[test]
fn lz_vector_truncation_padding_and_filter() -> Result<()> {
    let packed = [0x00, 0xa4, 0x01, 0x70, 0x80, 0x8f, 0xf7, 0xec, 0];
    let decoded = decompress(&packed, 512, true)?;
    assert_eq!(decoded.len(), 512);
    assert_eq!(
        Sha256::digest(&decoded)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "4c6474903705cb450bb6434c29e8854f17d8324efca1fdb9ee9008599060883a"
    );
    for cut in 0..packed.len() {
        assert!(decompress(&packed[..cut], 512, true).is_err());
        assert!(plausible_prefix(&packed[..cut], packed.len(), 512));
    }
    assert!(decompress(&packed, 511, true).is_err());
    assert!(decompress(&packed, 513, true).is_err());
    let mut padded = packed.to_vec();
    padded.push(0);
    assert!(decompress(&padded, 512, true).is_err());
    assert_eq!(decompress(&padded, 512, false)?, decoded);
    let mut bytes = [
        0x90, 0xe8, 0, 0, 0, 0, 0xff, 0x25, 1, 0, 0, 0, 0xff, 0x25, 1, 0, 0, 0, 0xe9, 1, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    fix_branches(&mut bytes);
    assert_eq!(BinaryReader::u32_le(&bytes[2..]), u32::MAX);
    assert_eq!(BinaryReader::u32_le(&bytes[14..]), 5);
    assert_eq!(BinaryReader::u32_le(&bytes[19..]), 1u32.wrapping_sub(18));
    Ok(())
}
