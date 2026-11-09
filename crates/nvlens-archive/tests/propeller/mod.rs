use super::*;
use nvlens_io::BinaryWriter;

struct Temp(std::path::PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
#[test]
fn mount_does_not_decode_scripts_and_retains_nested_names_and_raw_payloads() -> Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Unsupported(e.to_string()))?
        .as_nanos();
    let path = Temp(std::env::temp_dir().join(format!(
        "nvlens-propeller-{}-{stamp}.mpk",
        std::process::id()
    )));
    let mut data = vec![0; 8];
    data.extend(b"OggS");
    data.extend([0x88]); // Intentionally truncated MSC; mount must not parse it.
    let offset = data.len();
    BinaryWriter::u32_le(offset as u32, &mut data);
    BinaryWriter::u32_le(2, &mut data[4..]);
    let mut index = vec![0; 80];
    for (i, (name, start, size)) in [("\\nested\\sound.ogv", 8, 4), ("\\broken.msc", 12, 1)]
        .into_iter()
        .enumerate()
    {
        let row = &mut index[i * 40..(i + 1) * 40];
        row[..name.len()].copy_from_slice(name.as_bytes());
        BinaryWriter::u32_le(start, &mut row[32..]);
        BinaryWriter::u32_le(size, &mut row[36..]);
    }
    nvlens_crypto::cipher::xor::apply(&mut index, &[0x58])
        .map_err(|e| Error::Unsupported(e.to_string()))?;
    data.extend(index);
    std::fs::write(&path.0, &data)?;
    let view = Arc::new(ArcView::open(&path.0)?);
    assert!(matches!(
        Mpk.open(&view, &ArchiveOptions::default()),
        Err(Error::UnknownScheme(_))
    ));
    let mut options = ArchiveOptions::default();
    options
        .keys
        .insert("propeller_mpk", nvlens_core::Secret::new(vec![0x58]));
    options
        .keys
        .insert("propeller_msc", nvlens_core::Secret::new(vec![0x88]));
    let archive = Mpk.open(&view, &options)?;
    assert_eq!(archive.entries()[0].name, "\\nested\\sound.ogv");
    assert_eq!(archive.entries()[0].kind, ResourceKind::Unknown);
    assert!(matches!(
        archive.open_entry(&archive.entries()[0])?,
        Cow::Borrowed(b"OggS")
    ));
    assert_eq!(archive.open_entry(&archive.entries()[1])?.as_ref(), [0]);
    assert_eq!(
        archive.open_entry_raw(&archive.entries()[1])?.as_ref(),
        [0x88]
    );
    Ok(())
}
