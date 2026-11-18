use super::*;
use vnlens_io::BitWriter;

#[test]
fn literals_overlapping_matches_and_initialized_history() -> io::Result<()> {
    // 1+'A', 0+239+3, 0+0+0: literal, five-byte overlapping match,
    // then a two-byte match into the initialized space-filled history.
    let mut bits = BitWriter::new(BitOrder::Msb);
    bits.write_bits(1, 1)?;
    bits.write_bits(u32::from(b'A'), 8)?;
    bits.write_bits(0, 1)?;
    bits.write_bits(239, 8)?;
    bits.write_bits(3, 4)?;
    bits.write_bits(0, 1)?;
    bits.write_bits(0, 8)?;
    bits.write_bits(0, 4)?;
    let bytes = bits.into_bytes();
    assert_eq!(lzss(&bytes, 8)?, b"AAAAAA  ");
    assert!(lzss(&bytes, 7).is_err());
    assert_eq!(
        lzss(&bytes[..1], 1).err().map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}

#[test]
fn spb_serpentine_absolute_delta_wrapping_and_repeat_controls() -> io::Result<()> {
    let mut bits = BitWriter::new(BitOrder::Msb);
    // Five pixels: absolute B plane; +/- differences with wrapping in G;
    // repeated R plane. Row two reverses traversal direction.
    bits.write_bits(10, 8)?;
    bits.write_bits(6, 3)?;
    for value in [11, 12, 13, 14] {
        bits.write_bits(value, 8)?;
    }
    bits.write_bits(255, 8)?;
    bits.write_bits(7, 3)?;
    bits.write_bits(1, 1)?;
    for value in [1, 2, 3, 0] {
        bits.write_bits(value, 2)?;
    }
    bits.write_bits(42, 8)?;
    bits.write_bits(0, 3)?;
    let bytes = bits.into_bytes();
    assert_eq!(
        spb(&bytes, 1, 5)?,
        [10, 255, 42, 11, 0, 42, 12, 255, 42, 13, 1, 42, 14, 1, 42]
    );
    assert!(spb(&bytes[..bytes.len() - 1], 1, 5).is_err());
    assert!(spb(&bytes, 0, 5).is_err());
    // Nine pixels spanning three rows; the middle row runs right to left.
    let mut bits = BitWriter::new(BitOrder::Msb);
    for first in [0, 20, 40] {
        bits.write_bits(first, 8)?;
        for group in 0..2 {
            bits.write_bits(6, 3)?;
            for i in 1..=4 {
                bits.write_bits(first + group * 4 + i, 8)?;
            }
        }
    }
    let out = spb(&bits.into_bytes(), 3, 3)?;
    assert_eq!(
        out.chunks_exact(3).map(|p| p[0]).collect::<Vec<_>>(),
        [0, 1, 2, 5, 4, 3, 6, 7, 8]
    );
    Ok(())
}
