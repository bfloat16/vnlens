use super::*;
use vnlens_io::BinaryWriter;
fn word(b: &mut Vec<u8>, v: u32) {
    let p = b.len();
    b.resize(p + 4, 0);
    BinaryWriter::u32_le(v, &mut b[p..]);
}
fn sample() -> Vec<u8> {
    let mut b = RAW.to_vec();
    b.push(3);
    word(&mut b, 2);
    word(&mut b, 2);
    word(&mut b, 1);
    word(&mut b, 21);
    word(&mut b, 21);
    for planes in [[[1, 2], [10, 20], [3, 4]], [[5, 6], [30, 40], [7, 8]]] {
        for p in planes {
            b.push(1);
            word(&mut b, 2);
            b.extend(p);
        }
    }
    b
}
#[test]
fn golden_pixels_arbitrary_block_height_offsets_and_truncation() -> Result<()> {
    let bytes = sample();
    let image = Tlg.decode(&bytes)?;
    let PixelBuffer::Bgra8(pixels) = image.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(
        pixels,
        [
            11, 10, 13, 255, 33, 30, 37, 255, 46, 40, 50, 255, 114, 100, 122, 255
        ]
    );
    let mut wrapped = SDS.to_vec();
    word(&mut wrapped, bytes.len() as u32);
    wrapped.extend(&bytes);
    let tags = b"4:LEFT=2:-3,3:TOP=1:7,";
    wrapped.extend(b"tags");
    word(&mut wrapped, tags.len() as u32);
    wrapped.extend(tags);
    let image = Tlg.decode(&wrapped)?;
    assert_eq!((image.meta.offset_x, image.meta.offset_y), (-3, 7));
    for len in 0..bytes.len() {
        assert!(Tlg.decode(&bytes[..len]).is_err());
    }
    Ok(())
}
