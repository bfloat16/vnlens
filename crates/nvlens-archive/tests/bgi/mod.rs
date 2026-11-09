use super::*;
use nvlens_io::BinaryWriter;
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};
struct Temp(std::path::PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn fixture(record: usize, name_size: usize) -> Result<Temp> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "nvlens-bgi-{}-{}-{}.arc",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Unsupported(e.to_string()))?
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut bytes = vec![0; 16 + 2 * record];
    bytes[..12].copy_from_slice(if record == 128 {
        b"BURIKO ARC20"
    } else {
        b"PackFile    "
    });
    BinaryWriter::u32_le(2, &mut bytes[12..]);
    for (i, (name, size, offset)) in [("ok.txt", 2, 0), ("bad.bin", 16, 2)]
        .into_iter()
        .enumerate()
    {
        let start = 16 + i * record;
        bytes[start..start + name.len()].copy_from_slice(name.as_bytes());
        BinaryWriter::u32_le(offset, &mut bytes[start + name_size..]);
        BinaryWriter::u32_le(size, &mut bytes[start + name_size + 4..]);
    }
    bytes.extend(b"okDSC FORMAT 1.00\0");
    fs::write(&path, bytes)?;
    Ok(Temp(path))
}
#[test]
fn both_indices_are_lazy_and_corrupt_unused_content_does_not_block_mount() -> Result<()> {
    for (record, name_size) in [(128, 96), (32, 16)] {
        let temp = fixture(record, name_size)?;
        let view = Arc::new(ArcView::open(&temp.0)?);
        let arc = BgiArchiveFormat.open(&view, &ArchiveOptions::default())?;
        assert_eq!(arc.entries().len(), 2);
        assert_eq!(&*arc.open_entry(&arc.entries()[0])?, b"ok");
        assert!(matches!(
            arc.open_entry_raw(&arc.entries()[0])?,
            Cow::Borrowed(_)
        ));
        assert!(arc.open_entry(&arc.entries()[1]).is_err());
        assert_eq!(
            &*arc.open_entry_raw(&arc.entries()[1])?,
            b"DSC FORMAT 1.00\0"
        );
    }
    Ok(())
}
