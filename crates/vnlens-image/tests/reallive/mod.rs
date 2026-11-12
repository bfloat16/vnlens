use super::*;
use vnlens_io::BinaryWriter;

fn fixture(indexed: bool) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes[..5].copy_from_slice(if indexed { b"PDT11" } else { b"PDT10" });
    BinaryWriter::u32_le(3, &mut bytes[12..]);
    BinaryWriter::u32_le(1, &mut bytes[16..]);
    if indexed {
        bytes.resize(32 + 1024 + 64, 0);
        bytes[32 + 5 * 4..32 + 5 * 4 + 4].copy_from_slice(&[1, 2, 3, 0]);
        for at in (32 + 1024..32 + 1024 + 64).step_by(4) {
            BinaryWriter::u32_le(1, &mut bytes[at..]);
        }
        bytes.extend([0x80, 5, 0]);
    } else {
        bytes.extend([0x80, 1, 2, 3, 1, 0]);
    }
    let alpha = bytes.len() as u32;
    BinaryWriter::u32_le(alpha, &mut bytes[28..]);
    bytes.extend([0x80, 127, 0, 0]);
    let size = bytes.len() as u32;
    BinaryWriter::u32_le(size, &mut bytes[8..]);
    bytes
}

#[test]
fn reallive_pdt_versions_palette_alpha_and_registration() -> Result<()> {
    for indexed in [false, true] {
        let bytes = fixture(indexed);
        let meta = crate::metadata_as("pdt/reallive", &bytes)?.ok_or(Error::InvalidFormat)?;
        assert_eq!((meta.width, meta.height), (3, 1));
        let image = crate::decode_as("pdt/reallive", &bytes)?;
        assert!(
            matches!(image.pixels, PixelBuffer::Bgra8(pixels) if pixels == [1, 2, 3, 127].repeat(3))
        );
        assert!(matches!(
            Pdt.decode_with_options(
                &bytes,
                None,
                &Default::default(),
                Some(&AtomicBool::new(true))
            ),
            Err(Error::Cancelled)
        ));
        for length in [0, 7, 31, bytes.len() - 1] {
            assert!(
                matches!(Pdt.decode(&bytes[..length]), Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
            );
        }
        let mut bad = bytes;
        BinaryWriter::u32_le(31, &mut bad[28..]);
        assert!(matches!(Pdt.decode(&bad), Err(Error::Corrupt { .. })));
    }
    Ok(())
}
