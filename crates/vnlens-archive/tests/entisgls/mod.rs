#![allow(clippy::unwrap_used)]
use super::*;
use std::sync::Mutex;
use vnlens_io::BinaryWriter;

#[derive(Debug)]
struct Reads {
    bytes: Arc<[u8]>,
    ranges: Mutex<Vec<(u64, usize)>>,
}
impl ReadAt for Reads {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, at: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        self.ranges
            .lock()
            .map_err(|_| io::Error::other("Read log poisoned"))?
            .push((at, size));
        self.bytes.read_at(at, size)
    }
}

fn section(id: &[u8; 8], bytes: &[u8]) -> Vec<u8> {
    let mut result = id.to_vec();
    let mut length = [0; 8];
    BinaryWriter::u64_le(bytes.len() as u64, &mut length);
    result.extend(length);
    result.extend(bytes);
    result
}
fn indexed(resources: &[(&str, u32, &[u8], u64)]) -> Vec<u8> {
    let index_size = 4 + resources
        .iter()
        .map(|(name, _, _, _)| 41 + name.len())
        .sum::<usize>();
    let mut offset = 16 + index_size;
    let mut index = vec![0; 4];
    BinaryWriter::u32_le(resources.len() as u32, &mut index);
    let mut bodies = Vec::new();
    for &(name, encoding, bytes, logical) in resources {
        let mut row = vec![0; 40];
        BinaryWriter::u64_le(logical, &mut row);
        BinaryWriter::u32_le(0x01000000, &mut row[8..]);
        BinaryWriter::u32_le(encoding, &mut row[12..]);
        BinaryWriter::u64_le(offset as u64, &mut row[16..]);
        BinaryWriter::u32_le(name.len() as u32 + 1, &mut row[36..]);
        row.extend(name.as_bytes());
        row.push(0);
        index.extend(row);
        let record = section(b"filedata", bytes);
        offset += record.len();
        bodies.extend(record);
    }
    let mut out = vec![0; 64];
    out[..8].copy_from_slice(b"Entis\x1a\0\0");
    BinaryWriter::u32_le(0x02000400, &mut out[8..]);
    let description = b"ERISA-Archive file\0";
    out[16..16 + description.len()].copy_from_slice(description);
    out.extend(section(b"DirEntry", &index));
    out.extend(bodies);
    out
}

#[test]
fn lazy_mount_keeps_storage_ranges_names_and_raw_reads() {
    let data = indexed(&[
        ("../音声.wav", 0, b"RIFF", 4),
        ("bad.csx", 0x80000010, &[0xff; 9], 20),
    ]);
    let view = Arc::new(ArcView::from_bytes(Default::default(), data.into()));
    let pack = Noa.open(&view, &ArchiveOptions::default()).unwrap();
    assert_eq!(pack.entries().len(), 2);
    assert_eq!(pack.entries()[0].name, "../音声.wav");
    assert!(matches!(
        pack.open_entry(&pack.entries()[0]).unwrap(),
        Cow::Borrowed(b"RIFF")
    ));
    assert!(pack.open_entry(&pack.entries()[1]).is_err());
    assert_eq!(pack.open_entry_raw(&pack.entries()[1]).unwrap().len(), 9);
    assert_eq!(pack.entries()[1].packed.unwrap().unpacked_size, 20);
}

#[test]
fn truncated_archive_and_large_index() {
    let data = indexed(&[("empty", 0, &[], 0)]);
    let short = Arc::new(ArcView::from_bytes(
        Default::default(),
        data[..data.len() - 1].into(),
    ));
    assert!(
        matches!(Noa.open(&short, &ArchiveOptions::default()), Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
    );
    let names: Vec<_> = (0..70_000).map(|i| format!("{i}.dat")).collect();
    let resources: Vec<_> = names.iter().map(|s| (s.as_str(), 0, &[][..], 0)).collect();
    let data = indexed(&resources);
    let view = Arc::new(ArcView::from_bytes(Default::default(), data.into()));
    assert_eq!(
        Noa.open(&view, &ArchiveOptions::default())
            .unwrap()
            .entries()
            .len(),
        70_000
    );
}

#[test]
fn source_mount_does_not_read_payloads() {
    let bytes: Arc<[u8]> =
        indexed(&[("good", 0, b"DATA", 4), ("bad", 0x80000010, &[0xff; 8], 5)]).into();
    let source = Arc::new(Reads {
        bytes,
        ranges: Mutex::new(Vec::new()),
    });
    let pack = Noa
        .open_source(source.clone(), "nested.noa", &Default::default())
        .unwrap()
        .unwrap();
    for &(at, size) in &*source.ranges.lock().unwrap() {
        assert!(
            pack.entries()
                .iter()
                .all(|e| at + size as u64 <= e.offset || at >= e.offset + e.size)
        );
    }
    assert_eq!(
        pack.open_entry(&pack.entries()[0]).unwrap().as_ref(),
        b"DATA"
    );
    assert!(pack.open_entry(&pack.entries()[1]).is_err());
}

#[test]
fn nested_directory_can_reference_earlier_storage() {
    let mut bytes = indexed(&[("root", 0, b"DATA", 4), ("dir", 0, &[], 0)]);
    let index_start = 80;
    let second = index_start + 4 + 41 + 4;
    let relative = BinaryReader::u64_le(&bytes[second + 16..]);
    let wrapper = 64 + relative as usize;
    let first_payload = 64 + BinaryReader::u64_le(&bytes[index_start + 4 + 16..]) as usize + 16;
    let mut child_index = vec![0; 4];
    BinaryWriter::u32_le(1, &mut child_index);
    let mut row = vec![0; 40];
    BinaryWriter::u64_le(4, &mut row);
    BinaryWriter::u32_le(0x01000000, &mut row[8..]);
    let relative = first_payload as i64 - 16 - (wrapper + 16) as i64;
    BinaryWriter::u64_le(relative as u64, &mut row[16..]);
    BinaryWriter::u32_le(6, &mut row[36..]);
    row.extend(b"alias\0");
    child_index.extend(row);
    let child = section(b"DirEntry", &child_index);
    BinaryWriter::u32_le(0x01000010, &mut bytes[second + 8..]);
    bytes.truncate(wrapper);
    bytes.extend(section(b"filedata", &child));
    let view = Arc::new(ArcView::from_bytes(Default::default(), bytes.into()));
    let pack = Noa.open(&view, &Default::default()).unwrap();
    assert_eq!(pack.entries()[1].name, "dir/alias");
    assert_eq!(
        pack.open_entry(&pack.entries()[1]).unwrap().as_ref(),
        b"DATA"
    );
}
