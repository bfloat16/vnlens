#![allow(clippy::unwrap_used)]
use super::*;
use vnlens_io::{BinaryWriter, BitOrder, BitWriter};

fn section(id: &[u8; 8], body: &[u8]) -> Vec<u8> {
    let mut out = id.to_vec();
    let mut size = [0; 8];
    BinaryWriter::u64_le(body.len() as u64, &mut size);
    out.extend(size);
    out.extend(body);
    out
}

fn fixture(descript: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    let mut info = vec![0; 68];
    for (offset, value) in [
        (0, 0x20100),
        (4, 0x03020000),
        (8, u32::MAX),
        (12, 0x04000001),
        (16, 1),
        (20, 1),
        (24, 32),
        (52, 1),
    ] {
        BinaryWriter::u32_le(value, &mut info[offset..]);
    }
    header.extend(section(b"ImageInf", &info));
    if !descript.is_empty() {
        header.extend(section(b"descript", descript));
    }
    let mut bits = BitWriter::new(BitOrder::Msb);
    for bit in [0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0] {
        bits.write_bits_le(bit, 1).unwrap();
    }
    let mut frame = vec![1, 0, 0, 0];
    frame.extend(bits.into_bytes());
    let stream = section(b"ImageFrm", &frame);
    let mut out = vec![0; 64];
    out[..8].copy_from_slice(b"Entis\x1a\0\0");
    BinaryWriter::u32_le(0x03000100, &mut out[8..]);
    let description = b"Entis Rasterized Image\0";
    out[16..16 + description.len()].copy_from_slice(description);
    out.extend(section(b"Header  ", &header));
    out.extend(section(b"Stream  ", &stream));
    out
}

#[test]
fn eri_metadata_frames_and_reference_composition() {
    struct Resolver(Vec<u8>);
    impl ResourceResolver for Resolver {
        fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
            Ok((name == "base.eri").then(|| self.0.clone()))
        }
    }
    let base = fixture(b"#hot-spot\n3,-4\n");
    let meta = crate::metadata_as("eri/entisgls", &base).unwrap().unwrap();
    assert_eq!(
        (meta.width, meta.height, meta.offset_x, meta.offset_y),
        (1, 1, 3, -4)
    );
    assert_eq!(crate::frame_count_as("eri/entisgls", &base).unwrap(), 1);
    let delta = fixture(b"#reference-file\nbase.eri\n");
    let composed =
        crate::decode_with_resources_as("eri/entisgls", &delta, Some(&Resolver(base))).unwrap();
    assert!(matches!(composed.pixels, PixelBuffer::Bgra8(ref b) if b == &[0, 0, 0, 0]));
    let cycle = fixture(b"#reference-file\nbase.eri\n");
    assert!(matches!(
        crate::decode_with_resources_as("eri/entisgls", &delta, Some(&Resolver(cycle))),
        Err(Error::Corrupt { .. })
    ));
}
