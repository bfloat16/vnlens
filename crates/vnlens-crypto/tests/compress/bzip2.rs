use super::*;

#[test]
fn crc_length_and_truncation_are_checked() -> io::Result<()> {
    use std::io::Write;
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
    encoder.write_all(b"NScripter NBZ known plaintext\n")?;
    let bytes = encoder.finish()?;
    assert_eq!(decompress(&bytes, 30)?, b"NScripter NBZ known plaintext\n");
    assert!(decompress(&bytes, 29).is_err());
    assert!(decompress(&bytes, 31).is_err());
    assert!(decompress(&bytes[..bytes.len() - 5], 30).is_err());
    let mut broken = bytes;
    broken[10] ^= 1;
    assert!(decompress(&broken, 30).is_err());
    Ok(())
}
