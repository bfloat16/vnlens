use super::*;

#[test]
fn overlapping_and_extended_runs_and_header_prefix() -> std::io::Result<()> {
    // Literal A, then distance 1 / extended length 264.
    let data = [0, b'A', 0xe0, 255, 0];
    assert_eq!(decompress(&data, 265)?, vec![b'A'; 265]);
    assert_eq!(prefix(&data, 265, 54)?, vec![b'A'; 54]);
    assert!(decompress(&data, 264).is_err());
    assert!(decompress(&data[..4], 265).is_err());
    assert!(decompress(&[0x20, 0], 3).is_err());
    assert!(decompress(&[1, b'A'], 2).is_err());
    Ok(())
}
