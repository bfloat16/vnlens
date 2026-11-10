use super::*;
use nvlens_io::BinaryWriter;
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn arc_parts_and_ordinal_references_are_lazy() -> Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_nanos();
    let root = Temp(std::env::temp_dir().join(format!(
        "nvlens-csystem-parts-{}-{stamp}",
        std::process::id()
    )));
    std::fs::create_dir_all(&root.0)?;
    let mut rows = Vec::new();
    for (id, part) in [(17, 0), (42, 1), (99, 2)] {
        for value in [23, id, 4, 4, 0] {
            let mut word = [0; 4];
            BinaryWriter::u32_le(value, &mut word);
            rows.extend(word);
        }
        rows.extend(b"b0");
        rows.extend([0; 4]);
        rows.push(part);
    }
    let mut packed = Vec::new();
    for chunk in rows.chunks(8) {
        packed.push(255);
        packed.extend(chunk);
    }
    let mut bytes = Vec::new();
    for len in [rows.len(), packed.len()] {
        bytes.extend(format!("{len:08}").bytes().map(|b| (b - b'0') ^ 127));
    }
    bytes.extend(packed);
    let path = root.0.join("Arc02.dat");
    std::fs::write(&path, bytes)?;
    let mut options = ArchiveOptions::default();
    options.paths.insert("csystem_root", root.0.clone());
    let archive = Dat.open(&Arc::new(ArcView::open(path)?), &options)?;
    // No payload exists while all three volumes' entries are listed.
    assert_eq!(archive.entries().len(), 3);
    std::fs::write(root.0.join("Arc05a.dat"), b"part")?;
    assert_eq!(&*archive.open_entry(&archive.entries()[1])?, b"part");
    assert_eq!(
        archive.read_companion("picture/1.b0")?,
        Some(b"part".to_vec())
    );
    assert!(archive.open_entry(&archive.entries()[0]).is_err());
    std::fs::write(root.0.join("Arc05b.dat"), b"end!")?;
    assert_eq!(&*archive.open_entry(&archive.entries()[2])?, b"end!");
    Ok(())
}
#[test]
fn volume_references_are_lazy_and_export_index_bytes_as_an_index() -> Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .as_nanos();
    let root =
        Temp(std::env::temp_dir().join(format!("nvlens-csystem-{}-{stamp}", std::process::id())));
    std::fs::create_dir_all(root.0.join("Resources"))?;
    let mut bytes = vec![0; 48];
    BinaryWriter::u32_le(1, &mut bytes);
    BinaryWriter::u32_le(2, &mut bytes[4..]);
    BinaryWriter::u32_le(5, &mut bytes[12..]);
    BinaryWriter::u32_le(3, &mut bytes[24..]);
    BinaryWriter::u32_le(1, &mut bytes[28..]);
    BinaryWriter::u64_le(5, &mut bytes[32..]);
    let path = root.0.join("Resources/Data00.dat");
    std::fs::write(&path, &bytes)?;
    let mut options = ArchiveOptions::default();
    options.paths.insert("csystem_root", root.0.clone());
    let catalog = Dat.open(&Arc::new(ArcView::open(path)?), &options)?;
    let entry = &catalog.entries()[0];
    assert_eq!(entry.name, "Data000.dat.index");
    assert!(catalog.has_references(entry));
    assert_eq!(&*catalog.open_entry(entry)?, &bytes[4..]);
    // The referenced data file did not exist while the catalog was mounted.
    std::fs::write(root.0.join("Resources/Data000.dat"), b"firstX")?;
    let volume = catalog
        .open_references(entry)?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(volume.entries().len(), 2);
    assert_eq!(&*volume.open_entry(&volume.entries()[0])?, b"first");
    assert!(volume.open_entry(&volume.entries()[1]).is_err());
    Ok(())
}
