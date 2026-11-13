#![allow(clippy::unwrap_used)]
use super::*;
use vnlens_io::BinaryWriter;

fn section(id: &[u8; 8], body: &[u8]) -> Vec<u8> {
    let mut out = id.to_vec();
    let mut size = [0; 8];
    BinaryWriter::u64_le(body.len() as u64, &mut size);
    out.extend(size);
    out.extend(body);
    out
}

fn fixture(description: &[u8], declared_samples: u32, payload: &[u8]) -> Vec<u8> {
    let mut info = vec![0; 40];
    for (offset, value) in [
        (0, 0x20300),
        (4, 0x03020000),
        (8, 0xfffffffc),
        (12, 1),
        (16, 22050),
        (36, 8),
    ] {
        BinaryWriter::u32_le(value, &mut info[offset..]);
    }
    let header = section(b"SoundInf", &info);
    let mut stm = vec![1, 1, 0, 0, 0, 0, 0, 0];
    BinaryWriter::u32_le(declared_samples, &mut stm[4..]);
    stm.extend(payload);
    let stream = section(b"SoundStm", &stm);
    let mut out = vec![0; 64];
    out[..8].copy_from_slice(b"Entis\x1a\0\0");
    BinaryWriter::u32_le(0x03000100, &mut out[8..]);
    out[16..16 + description.len()].copy_from_slice(description);
    out.extend(section(b"Header  ", &header));
    out.extend(section(b"Stream  ", &stream));
    out
}

#[test]
fn mio_metadata_and_pcm_decode() {
    let bytes = fixture(
        b"Music Interleaved and Orthogonal transformed\0",
        2,
        &[128, 1],
    );
    let meta = crate::metadata_as("mio/entisgls", &bytes).unwrap().unwrap();
    assert_eq!(
        (meta.channels, meta.sample_rate, meta.frames),
        (1, 22050, Some(2))
    );
    let pcm = crate::decode_as("mio/entisgls", &bytes).unwrap();
    assert_eq!(&*pcm.samples, &[0.0, 1.0 / 128.0]);
    let wrong = fixture(b"Entis Rasterized Image\0", 2, &[128, 1]);
    assert!(matches!(
        crate::decode_as("mio/entisgls", &wrong),
        Err(Error::InvalidFormat)
    ));
}
