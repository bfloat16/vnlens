use super::*;
use vnlens_core::{ArchiveRoute, Catalog, Error};
use vnlens_io::{BinaryWriter, ReadAt};

mod local;

fn cat(big: bool, named: bool) -> Vec<u8> {
    let mut data = vec![0; 116];
    data[0] = if big { 0 } else { 1 } | if named { 2 } else { 0 };
    for (at, value) in [
        (4, 1),
        (12, 32),
        (16, 84),
        (20, 2),
        (36, 2),
        (40, 2),
        (44, 16),
        (52, 64),
        (56, 80),
        (60, 4),
        (64, 4),
    ] {
        if big {
            BinaryWriter::u32_be(value, &mut data[at..]);
        } else {
            BinaryWriter::u32_le(value, &mut data[at..]);
        }
    }
    if named {
        data[32] = 1;
        if big {
            BinaryWriter::u32_be(44, &mut data[68..]);
        } else {
            BinaryWriter::u32_le(44, &mut data[68..]);
        }
        data[76..81].copy_from_slice(b"../a\0");
    }
    data[96..100].copy_from_slice(b"DDS ");
    data[112..116].copy_from_slice(b"bad!");
    data
}

struct IndexOnly {
    data: Arc<[u8]>,
    index_end: u64,
}
impl ReadAt for IndexOnly {
    fn len(&self) -> u64 {
        self.data.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
        if offset + size as u64 > self.index_end {
            return Err(std::io::Error::other("Payload must remain lazy"));
        }
        self.data.read_at(offset, size)
    }
}

#[test]
fn cat_registration_byte_orders_names_and_lazy_payloads() -> Result<()> {
    for big in [false, true] {
        let data = cat(big, false);
        let entries = read::cat(&IndexOnly {
            data: data.clone().into(),
            index_end: 96,
        })?;
        assert_eq!(entries.len(), 2);
        assert_eq!((entries[0].offset, entries[0].size), (96, 4));
        let opened = Catalog::load().open_view(
            Arc::new(ArcView::from_bytes("test.cat".into(), data.into())),
            &ArchiveRoute::new("cat/tamsoft"),
        )?;
        let archive = opened.archive;
        assert_eq!(archive.entries()[0].name, "0");
        assert!(matches!(
            archive.open_entry(&archive.entries()[0])?,
            Cow::Borrowed(_)
        ));
        assert_eq!(archive.open_entry(&archive.entries()[0])?.as_ref(), b"DDS ");
        assert_eq!(
            archive.open_entry_raw(&archive.entries()[1])?.as_ref(),
            b"bad!"
        );
        let source = archive
            .open_entry_source(&archive.entries()[0])?
            .ok_or(Error::InvalidFormat)?;
        assert_eq!(source.read_at(1, 2)?.as_ref(), b"DS");
        assert_eq!(
            read::cat(&Arc::<[u8]>::from(cat(big, true)))?[0].name,
            "../a"
        );
    }
    Ok(())
}

#[test]
fn texture_array_and_font_mount_without_payload() -> Result<()> {
    let mut data = vec![0; 28];
    for (at, value) in [(0, 20), (4, 2), (8, 28), (12, 0), (16, 4)] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    data[20..].copy_from_slice(b"DDS bad!");
    let entries = read::textures(&IndexOnly {
        data: data.clone().into(),
        index_end: 20,
    })?;
    assert_eq!(
        entries
            .iter()
            .map(|e| (e.name.as_str(), e.offset, e.size))
            .collect::<Vec<_>>(),
        [("0", 20, 4), ("1", 24, 4)]
    );
    let mut font = vec![0; 52];
    font[..8].copy_from_slice(b"EMOJIPCK");
    for (at, value) in [(8, 1), (12, 1), (16, 1), (20, 52)] {
        BinaryWriter::u32_le(value, &mut font[at..]);
    }
    font.extend_from_slice(&data);
    let entries = read::semb(&IndexOnly {
        data: font.into(),
        index_end: 24,
    })?;
    assert_eq!((entries[0].offset, entries[0].size), (24, 28));
    assert_eq!((entries[1].offset, entries[1].size), (52, 28));
    Ok(())
}

#[test]
fn malformed_ranges_and_truncation_keep_errors() {
    for end in [0, 11, 31, 51, 60, 79, 99] {
        assert!(read::cat(&Arc::<[u8]>::from(cat(false, false)[..end].to_vec())).is_err());
    }
    let mut data = cat(false, false);
    BinaryWriter::u32_le(u32::MAX, &mut data[52..]);
    assert!(matches!(
        read::cat(&Arc::<[u8]>::from(data)),
        Err(Error::Corrupt { .. })
    ));
    let mut data = vec![0; 20];
    for (at, value) in [(0, 20), (4, 2), (8, 20), (12, 1), (16, 0)] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    assert!(read::textures(&Arc::<[u8]>::from(data)).is_err());
}

#[test]
fn native_cp932_names_and_null_records() -> Result<()> {
    let mut data = cat(false, true);
    data[76..81].copy_from_slice(&[0x82, 0xa0, 0, 0, 0]);
    let entries = read::cat(&Arc::<[u8]>::from(data.clone()))?;
    assert_eq!(entries[0].name, "あ");
    data[76..81].copy_from_slice(&[0x81, 0, 0, 0, 0]);
    assert!(matches!(
        read::cat(&Arc::<[u8]>::from(data)),
        Err(Error::Corrupt { .. })
    ));
    let mut data = cat(false, false);
    BinaryWriter::u32_le(0, &mut data[52..]);
    assert_eq!(read::cat(&Arc::<[u8]>::from(data))?.len(), 1);
    Ok(())
}
