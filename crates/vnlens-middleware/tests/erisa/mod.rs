#![allow(clippy::unwrap_used)]
use super::*;
use std::{
    borrow::Cow,
    sync::{Arc, Mutex, atomic::AtomicBool},
};
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
fn image(second: Option<&[u8]>) -> Vec<u8> {
    let file = words(&[0x20100, 1, 1, 1 + u32::from(second.is_some()), 200]);
    let info = words(&[
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
    let mut header = section(b"FileHdr ", &file);
    header.extend(section(b"ImageInf", &info));
    header.extend(section(b"descript", b"#hot-spot\n5,-7\n"));
    let mut bits = BitWriter::new(BitOrder::Msb);
    // Separator, color operation zero, zero run selector, Gamma(16).
    for bit in [0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0] {
        bits.write_bits_le(bit, 1).unwrap();
    }
    let mut frame = vec![1, 0, 0, 0];
    frame.extend(bits.into_bytes());
    let mut stream = section(b"ImageFrm", &frame);
    if let Some(second) = second {
        stream.extend(section(b"ImageFrm", second));
    }
    let mut out = vec![0; 64];
    out[..8].copy_from_slice(b"Entis\x1a\0\0");
    BinaryWriter::u32_le(0x03000100, &mut out[8..]);
    let description = b"Entis Rasterized Image\0";
    out[16..16 + description.len()].copy_from_slice(description);
    out.extend(section(b"Header  ", &header));
    out.extend(section(b"Stream  ", &stream));
    out
}

#[derive(Debug)]
struct Indexed {
    bytes: Arc<[u8]>,
    reads: Mutex<Vec<(u64, usize)>>,
}
impl ReadAt for Indexed {
    fn len(&self) -> u64 {
        self.bytes.as_ref().len() as u64
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        self.reads
            .lock()
            .map_err(|_| io::Error::other("Read log lock poisoned"))?
            .push((offset, size));
        self.bytes.read_at(offset, size)
    }
}

#[test]
fn media_index_is_lazy_and_pixel_decode_preserves_metadata() {
    let bytes: Arc<[u8]> = image(Some(&[0xff])).into();
    let source = Indexed {
        bytes,
        reads: Mutex::new(Vec::new()),
    };
    let file = MediaFile::open(&source).unwrap();
    assert_eq!(file.tags["hot-spot"], "5,-7");
    let payloads: Vec<_> = file
        .stream
        .iter()
        .filter(|s| s.id == *b"ImageFrm")
        .collect();
    for &(offset, size) in &*source.reads.lock().unwrap() {
        assert!(
            payloads
                .iter()
                .all(|s| offset + size as u64 <= s.offset || offset >= s.offset + s.size)
        );
    }
    let mut decoder = RasterDecoder::new(&file).unwrap();
    assert_eq!(
        decoder
            .decode_at(0, &source, &AtomicBool::new(false))
            .unwrap(),
        [0, 0, 0, 0]
    );
    assert!(
        decoder
            .decode_at(1, &source, &AtomicBool::new(false))
            .is_err()
    );
    assert!(matches!(
        decoder.decode_at(0, &source, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
}

#[test]
fn truncated_sections_are_unexpected_eof() {
    let data = image(None);
    let source = &data[..data.len() - 1];
    assert!(
        matches!(MediaFile::open(&source), Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
    );
}

#[test]
fn pcm_audio_uses_chunk_counts_and_cancelled_decode_stops() {
    let info = words(&[0x20300, 0x03020000, 0xfffffffc, 1, 22050, 0, 0, 0, 0, 8]);
    let header = section(b"SoundInf", &info);
    let mut data_header = vec![1, 1, 0, 0, 0, 0, 0, 0];
    BinaryWriter::u32_le(2, &mut data_header[4..]);
    data_header.extend([128, 1]);
    let stream = section(b"SoundStm", &data_header);
    let mut out = vec![0; 64];
    out[..8].copy_from_slice(b"Entis\x1a\0\0");
    BinaryWriter::u32_le(0x03000100, &mut out[8..]);
    out.extend(section(b"Header  ", &header));
    out.extend(section(b"Stream  ", &stream));
    let source = out.as_slice();
    let file = MediaFile::open(&source).unwrap();
    let info = SoundInfo::read(&file, &source).unwrap().unwrap();
    let chunks = sound_chunks(&file, &source).unwrap();
    assert_eq!(chunks[0].samples, 2);
    let mut decoder = SoundDecoder::new(info).unwrap();
    assert_eq!(
        decoder
            .decode(&source, &chunks[0].section, &AtomicBool::new(false))
            .unwrap(),
        [0.0, 1.0 / 128.0]
    );
    assert!(matches!(
        decoder.decode(&source, &chunks[0].section, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
}
