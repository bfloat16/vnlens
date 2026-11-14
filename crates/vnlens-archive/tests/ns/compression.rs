use super::*;
use crate::ns::fixtures;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use vnlens_io::BinaryWriter;

struct Observed {
    bytes: Arc<[u8]>,
    payload_reads: Arc<AtomicUsize>,
}
impl ReadAt for Observed {
    fn len(&self) -> u64 {
        self.bytes.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        if size != 0 && offset < 512 {
            self.payload_reads.fetch_add(1, Ordering::Relaxed);
        }
        self.bytes.read_at(offset, size)
    }
}
fn row(offset: u64, physical: u64, kind: u8, size: u32) -> Vec<u8> {
    let mut bytes = vec![0; 24];
    BinaryWriter::u64_le(offset, &mut bytes);
    BinaryWriter::u64_le(physical, &mut bytes[8..]);
    bytes[16] = kind;
    BinaryWriter::u32_le(size, &mut bytes[20..]);
    bytes
}

#[test]
fn mixed_blocks_are_lazy_random_access_and_unused_corruption_is_isolated() -> Result<()> {
    let (header, index) = fixtures::table(
        &[
            row(0, 0, 0, 0),
            row(4, 0, 1, 0),
            row(8, 16, 3, 12),
            row(25, 64, 3, 1),
        ],
        29,
    );
    let mut bytes = vec![0; 512];
    bytes[..4].copy_from_slice(b"raw!");
    let compressed = b"\x35abc\x03\x00\x50tail!";
    bytes[16..16 + compressed.len()].copy_from_slice(compressed);
    bytes[64] = 0xf0;
    bytes.extend_from_slice(&index);
    let mut fs = fixtures::fs_header();
    BinaryWriter::u64_le(512, &mut fs[0x178..]);
    BinaryWriter::u64_le(index.len() as u64, &mut fs[0x180..]);
    fs[0x188..0x198].copy_from_slice(&header);
    let reads = Arc::new(AtomicUsize::new(0));
    let source: Arc<dyn ReadAt> = Arc::new(Observed {
        bytes: bytes.into(),
        payload_reads: reads.clone(),
    });
    let source = open(source.clone(), &fs, &AtomicBool::new(false))?;
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    assert_eq!(source.len(), 29);
    assert!(matches!(source.read_at(0, 4)?, Cow::Borrowed(b"raw!")));
    assert_eq!(
        source.read_at(2, 23)?.as_ref(),
        b"w!\0\0\0\0abcabcabcabctail!"
    );
    assert_eq!(source.read_at(11, 5)?.as_ref(), b"abcab");
    assert!(source.read_at(25, 4).is_err());
    assert!(source.read_at(29, 1).is_err());
    assert!(source.read_at(30, 0).is_err());
    assert!(source.read_at(29, 0)?.is_empty());
    assert!(matches!(
        open(fixtures::source(vec![0; 512]), &fs, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}
