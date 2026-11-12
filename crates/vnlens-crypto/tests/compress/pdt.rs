use super::*;

#[test]
fn literals_overlapping_matches_and_alpha() -> std::io::Result<()> {
    assert_eq!(
        colors(&[0x80, 1, 2, 3, 1, 0], 3, None)?,
        [1, 2, 3, 255, 1, 2, 3, 255, 1, 2, 3, 255]
    );
    assert_eq!(alpha(&[0x80, 127, 1, 0], 4, None)?, [127; 4]);
    assert_eq!(indices(&[0x80, 5, 0x10], 4, &[1; 16], None)?, [5; 4]);
    assert!(colors(&[0, 0, 0], 1, None).is_err());
    assert_eq!(
        alpha(&[0x80], 1, None).err().map(|e| e.kind()),
        Some(std::io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}
