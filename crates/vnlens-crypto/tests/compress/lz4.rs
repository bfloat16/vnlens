use super::*;

#[test]
fn literals_overlapping_matches_and_invalid_blocks() -> io::Result<()> {
    assert_eq!(
        decompress(b"\x35abc\x03\x00\x50tail!", 17)?,
        b"abcabcabcabctail!"
    );
    let mut long = vec![0xf0, 255, 1];
    long.extend(vec![42; 271]);
    assert_eq!(decompress(&long, 271)?, vec![42; 271]);
    for bytes in [&b"\xf0"[..], &b"\x00\x00\x00"[..], &b"\x10a\x02\x00"[..]] {
        assert!(decompress(bytes, 10).is_err());
    }
    assert!(decompress(b"\x10a", 2).is_err());
    assert!(decompress(b"\x20ab", 1).is_err());
    Ok(())
}
