use super::*;
use std::sync::Mutex;
use vnlens_io::BinaryWriter;
struct Source {
    bytes: Vec<u8>,
    reads: Mutex<Vec<(u64, usize)>>,
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
        self.reads
            .lock()
            .map_err(|_| std::io::Error::other("read log poisoned"))?
            .push((offset, size));
        let at = usize::try_from(offset).map_err(|_| std::io::Error::other("offset overflow"))?;
        self.bytes
            .get(at..at + size)
            .map(Cow::Borrowed)
            .ok_or_else(|| std::io::ErrorKind::UnexpectedEof.into())
    }
}
#[test]
fn pac_index_is_lazy_and_preserves_names() -> Result<()> {
    let mut bytes = vec![0; 0x804 + 80 + 4];
    bytes[..4].copy_from_slice(b"PAC ");
    BinaryWriter::u32_le(2, &mut bytes[8..]);
    for (i, &name) in [b"A.PGD".as_slice(), b"../B.PGD"].iter().enumerate() {
        let at = 0x804 + i * 40;
        bytes[at..at + name.len()].copy_from_slice(name);
        BinaryWriter::u32_le(2, &mut bytes[at + 32..]);
        BinaryWriter::u32_le((0x854 + i * 2) as u32, &mut bytes[at + 36..]);
    }
    let source = Source {
        bytes,
        reads: Mutex::new(Vec::new()),
    };
    let entries = index(&source)?;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].name, "../B.PGD");
    assert_eq!(
        *source
            .reads
            .lock()
            .map_err(|_| std::io::Error::other("read log poisoned"))?,
        [(0, 12), (0x804, 80)]
    );
    Ok(())
}
