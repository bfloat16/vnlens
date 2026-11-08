use super::*;
use nvlens_core::{ArchiveRoute, Catalog, Secret};
use nvlens_io::BinaryWriter;
use std::{borrow::Cow, fs, path::PathBuf};
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temp() -> Result<Temp> {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Unsupported(e.to_string()))?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("nvlens-siglus-{}-{id}", std::process::id()));
    fs::create_dir(&path)?;
    Ok(Temp(path))
}
#[test]
fn scene_mount_is_lazy_and_preserves_names_and_raw_payloads() -> Result<()> {
    let temp = temp()?;
    let mut data = vec![0; 132];
    for (at, value) in [
        (0, 92),
        (52, 92),
        (56, 2),
        (60, 108),
        (64, 2),
        (68, 116),
        (72, 2),
        (76, 132),
        (80, 2),
        (88, 614),
        (92, 0),
        (96, 2),
        (100, 2),
        (104, 2),
        (116, 0),
        (120, 11),
        (124, 11),
        (128, 1),
    ] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    for (i, unit) in "好😀x".encode_utf16().enumerate() {
        BinaryWriter::u16_le(unit, &mut data[108 + i * 2..]);
    }
    // First name uses one supplementary character; adjust the two UTF-16 ranges.
    BinaryWriter::u32_le(3, &mut data[96..]);
    BinaryWriter::u32_le(3, &mut data[100..]);
    BinaryWriter::u32_le(1, &mut data[104..]);
    let mut block = vec![0; 8];
    BinaryWriter::u32_le(11, &mut block);
    BinaryWriter::u32_le(2, &mut block[4..]);
    block.extend([3, b'o', b'k']);
    data.extend(block);
    data.push(0xff);
    let path = temp.0.join("Scene.pck");
    fs::write(&path, &data)?;
    let mut route = ArchiveRoute::new("pck/siglus");
    route
        .options
        .keys
        .insert("siglus_scene", Secret::new(vec![0; 256]));
    let catalog = Catalog::load();
    let opened = catalog.open(&path, &route)?;
    let entries = opened.archive.entries();
    assert_eq!(entries[0].name, "好😀.ss");
    assert_eq!(entries[1].name, "x.ss");
    assert_eq!(&*opened.archive.open_entry(&entries[0])?, b"ok");
    assert!(matches!(
        opened.archive.open_entry_raw(&entries[1])?,
        Cow::Borrowed([0xff])
    ));
    assert!(opened.archive.open_entry(&entries[1]).is_err());
    drop(opened);
    BinaryWriter::u32_le(1000, &mut data[128..]);
    fs::write(&path, data)?;
    assert!(catalog.open(&path, &route).is_err());
    Ok(())
}
#[test]
fn voice_indices_do_not_decode_unused_streams() -> Result<()> {
    let temp = temp()?;
    for (name, stride) in [("voice.ovk", 16), ("voice.nwk", 12)] {
        let mut data = vec![0; 4 + stride * 2];
        BinaryWriter::u32_le(2, &mut data);
        let base = data.len() as u32;
        for i in 0..2 {
            let at = 4 + i * stride;
            BinaryWriter::u32_le(2, &mut data[at..]);
            BinaryWriter::u32_le(base + i as u32 * 2, &mut data[at + 4..]);
            BinaryWriter::u32_le(100 + i as u32, &mut data[at + 8..]);
        }
        data.extend(b"okxx");
        let path = temp.0.join(name);
        fs::write(&path, data)?;
        let opened = Catalog::load().open(path, &ArchiveRoute::new("voice/siglus"))?;
        assert_eq!(opened.archive.entries().len(), 2);
        assert_eq!(
            &*opened.archive.open_entry(&opened.archive.entries()[0])?,
            b"ok"
        );
    }
    Ok(())
}

#[test]
fn movie_index_mounts_without_reading_encoded_video() -> Result<()> {
    let temp = temp()?;
    let mut data = vec![0; 168 + 28 + 32];
    BinaryWriter::u32_le(168, &mut data);
    BinaryWriter::u16_le(0x101, &mut data[4..]);
    BinaryWriter::u32_le(1, &mut data[76..]);
    BinaryWriter::u32_le(1, &mut data[80..]);
    data.extend(b"broken video");
    let path = temp.0.join("movie.omv");
    fs::write(&path, &data)?;
    let opened = Catalog::load().open(&path, &ArchiveRoute::new("omv/siglus"))?;
    assert_eq!(opened.archive.entries()[0].name, "movie.ogv");
    assert_eq!(
        &*opened.archive.open_entry(&opened.archive.entries()[0])?,
        b"broken video"
    );
    drop(opened);
    data.truncate(200);
    fs::write(&path, data)?;
    assert!(
        Catalog::load()
            .open(&path, &ArchiveRoute::new("omv/siglus"))
            .is_err()
    );
    Ok(())
}
