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

fn words(values: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for &value in values {
        let mut word = [0; 4];
        BinaryWriter::u32_le(value, &mut word);
        out.extend(word);
    }
    out
}

fn movie() -> Arc<dyn ReadAt> {
    let file = words(&[0x20100, 1, 1, 2, 1000]);
    let image = words(&[
        0x20100,
        0x03020000,
        u32::MAX,
        0x04000001,
        1,
        1,
        32,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
    ]);
    let sound = words(&[0x20300, 0x03020000, 0xfffffffc, 1, 2, 0, 0, 0, 0, 8]);
    let mut header = section(b"FileHdr ", &file);
    header.extend(section(b"ImageInf", &image));
    header.extend(section(b"SoundInf", &sound));

    let mut bits = BitWriter::new(BitOrder::Msb);
    for bit in [0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0] {
        bits.write_bits_le(bit, 1).unwrap();
    }
    let mut frame = vec![1, 0, 0, 0];
    frame.extend(bits.into_bytes());
    let mut stm = vec![1, 1, 0, 0, 0, 0, 0, 0];
    BinaryWriter::u32_le(2, &mut stm[4..]);
    stm.extend([128, 1]);

    let mut stream = section(b"ImageFrm", &frame);
    stream.extend(section(b"ImageFrm", &frame));
    stream.extend(section(b"SoundStm", &stm));

    let mut out = vec![0; 64];
    out[..8].copy_from_slice(b"Entis\x1a\0\0");
    BinaryWriter::u32_le(0x03000100, &mut out[8..]);
    let description = b"Moving Entis Image\0";
    out[16..16 + description.len()].copy_from_slice(description);
    out.extend(section(b"Header  ", &header));
    out.extend(section(b"Stream  ", &stream));
    Arc::new(Arc::<[u8]>::from(out))
}

#[test]
fn mei_video_and_audio_cursors_decode_and_seek() {
    let source = movie();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut video = Mei.open(source.clone(), cancel.clone()).unwrap();
    assert_eq!(video.meta().container, "mei");
    assert_eq!(video.meta().duration, Some(1.0));
    video.seek(0.5).unwrap();
    let picture = video.next_picture().unwrap().unwrap();
    assert!((picture.time - 0.5).abs() < 1e-6);
    assert_eq!(picture.bgra, [0, 0, 0, 0]);
    assert!(video.next_picture().unwrap().is_none());

    let mut audio = crate::AudioDecoder::open_source_as("mei/entisgls", source, None, cancel)
        .unwrap()
        .unwrap();
    audio.seek(0.5).unwrap();
    let frame = audio.next_frame().unwrap().unwrap();
    assert!((frame.time - 0.5).abs() < 1e-6);
    assert_eq!(frame.samples, [1.0 / 128.0]);
}
