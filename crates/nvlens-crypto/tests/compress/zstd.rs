use super::*;
use nvlens_io::BinaryWriter;
#[test]
fn frame_checksum_and_truncation() -> io::Result<()> {
    // Single-segment raw block "abc"; XXH64(seed=0) = 44bc2cf5ad770999.
    let mut frame = vec![
        0x28, 0xb5, 0x2f, 0xfd, 0x24, 3, 0x19, 0, 0, b'a', b'b', b'c',
    ];
    let mut checksum = [0; 4];
    BinaryWriter::u32_le(0xad770999, &mut checksum);
    frame.extend(checksum);
    let mut out = Vec::new();
    decoder(frame.as_slice())?.read_to_end(&mut out)?;
    assert_eq!(out, b"abc");
    for length in 0..frame.len() {
        let result =
            decoder(&frame[..length]).and_then(|mut reader| reader.read_to_end(&mut Vec::new()));
        assert!(result.is_err(), "length={length}");
    }
    let last = frame.len() - 1;
    frame[last] ^= 1;
    assert!(
        decoder(frame.as_slice())?
            .read_to_end(&mut Vec::new())
            .is_err()
    );
    Ok(())
}
