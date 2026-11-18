use super::*;
use std::sync::Mutex;
use vnlens_core::ResourceKind;
use vnlens_io::{BinaryWriter, BitOrder, BitWriter};

fn fixture(nsa: bool, rows: &[(&[u8], u8, &[u8], u32)]) -> Vec<u8> {
    let base = 6 + rows
        .iter()
        .map(|(name, _, _, _)| <[u8]>::len(name) + 1 + if nsa { 13 } else { 8 })
        .sum::<usize>();
    let mut out = vec![0; base];
    BinaryWriter::u16_be(rows.len() as u16, &mut out);
    BinaryWriter::u32_be(base as u32, &mut out[2..]);
    let mut pos = 6;
    let mut offset = 0;
    for &(name, codec, data, size) in rows {
        out[pos..pos + name.len()].copy_from_slice(name);
        pos += name.len() + 1;
        if nsa {
            out[pos] = codec;
            pos += 1;
        }
        BinaryWriter::u32_be(offset, &mut out[pos..]);
        BinaryWriter::u32_be(data.len() as u32, &mut out[pos + 4..]);
        pos += 8;
        if nsa {
            BinaryWriter::u32_be(size, &mut out[pos..]);
            pos += 4;
        }
        offset += data.len() as u32;
        out.extend(data);
    }
    out
}
fn view(bytes: Vec<u8>) -> Arc<ArcView> {
    Arc::new(ArcView::from_bytes("synthetic.nsa".into(), bytes.into()))
}
struct IndexOnly {
    bytes: Arc<[u8]>,
    base: u64,
    reads: Mutex<Vec<(u64, usize)>>,
}
impl ReadAt for IndexOnly {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
        assert!(
            offset + size as u64 <= self.base,
            "mount touched an entry payload"
        );
        self.reads
            .lock()
            .map_err(|_| std::io::Error::other("poisoned read log"))?
            .push((offset, size));
        self.bytes.read_at(offset, size)
    }
}

#[test]
fn index_is_lazy_and_raw_resources_keep_original_names_and_bytes() -> Result<()> {
    let data = fixture(
        true,
        &[
            (b"nested\\\x90\x85.bmp", 1, b"broken spb", 123),
            (b"voice.wav", 0, b"RIFF", 4),
        ],
    );
    let base = u64::from(vnlens_io::BinaryReader::u32_be(&data[2..]));
    let source = IndexOnly {
        bytes: data.clone().into(),
        base,
        reads: Mutex::new(Vec::new()),
    };
    let (entries, _) = read::index(&source, true)?;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "nested\\水.bmp");
    let package = Nsa.open(&view(data), &ArchiveOptions::default())?;
    assert!(package.open_entry(&package.entries()[0]).is_err());
    assert_eq!(
        package.open_entry_raw(&package.entries()[0])?.as_ref(),
        b"broken spb"
    );
    assert!(matches!(
        package.open_entry(&package.entries()[1])?,
        Cow::Borrowed(b"RIFF")
    ));
    assert_eq!(
        package
            .open_entry_source(&package.entries()[1])?
            .ok_or(Error::InvalidFormat)?
            .read_at(0, 4)?
            .as_ref(),
        b"RIFF"
    );
    assert_eq!(package.entries()[1].kind, ResourceKind::Unknown);
    Ok(())
}

#[test]
fn sar_lzss_spb_and_index_bounds() -> Result<()> {
    let sar = Sar.open(
        &view(fixture(false, &[(b"dir/a.wav", 0, b"RIFF", 4)])),
        &ArchiveOptions::default(),
    )?;
    assert_eq!(sar.open_entry(&sar.entries()[0])?.as_ref(), b"RIFF");
    let mut bits = BitWriter::new(BitOrder::Msb);
    for byte in b"BM!" {
        bits.write_bits(1, 1)?;
        bits.write_bits(u32::from(*byte), 8)?;
    }
    let lzss = bits.into_bytes();
    let mut bits = BitWriter::new(BitOrder::Msb);
    for value in [1, 2, 3] {
        bits.write_bits(value, 8)?;
        bits.write_bits(0, 3)?;
    }
    let mut spb = vec![0; 4];
    BinaryWriter::u16_be(2, &mut spb);
    BinaryWriter::u16_be(2, &mut spb[2..]);
    spb.extend(bits.into_bytes());
    let bytes = fixture(true, &[(b"a.bmp", 2, &lzss, 3), (b"b.bmp", 1, &spb, 72)]);
    let package = Nsa.open(&view(bytes.clone()), &ArchiveOptions::default())?;
    assert_eq!(package.open_entry(&package.entries()[0])?.as_ref(), b"BM!");
    let bmp = package.open_entry(&package.entries()[1])?;
    assert_eq!(&bmp[..2], b"BM");
    assert_eq!(&bmp[54..], [1, 2, 3, 1, 2, 3, 0, 0, 1, 2, 3, 1, 2, 3, 0, 0]);
    let image = vnlens_image::decode_as("image/standard", &bmp)?;
    assert_eq!((image.meta.width, image.meta.height), (2, 2));
    for end in 0..6 {
        assert!(
            Nsa.open(&view(bytes[..end].to_vec()), &ArchiveOptions::default())
                .is_err()
        );
    }
    let mut invalid = bytes.clone();
    BinaryWriter::u32_be(5, &mut invalid[2..]);
    assert!(
        Nsa.open(&view(invalid), &ArchiveOptions::default())
            .is_err()
    );
    let mut invalid = bytes.clone();
    BinaryWriter::u32_be(u32::MAX, &mut invalid[13..]); // first stored length
    assert!(
        Nsa.open(&view(invalid), &ArchiveOptions::default())
            .is_err()
    );
    let mut invalid = bytes;
    invalid[6] = 0x81;
    invalid[7] = 0x20;
    assert!(
        Nsa.open(&view(invalid), &ArchiveOptions::default())
            .is_err()
    );
    Ok(())
}

#[test]
fn nbz_plugin_codec_and_stored_files_have_the_same_logical_bytes() -> Result<()> {
    // Python libbz2's independent known-answer vector for the bytes "RIFF".
    let mut nbz = vec![0; 4];
    BinaryWriter::u32_be(4, &mut nbz);
    nbz.extend([
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x51, 0x40, 0xb0, 0xfb, 0x0,
        0x0, 0x1, 0x86, 0x0, 0x1, 0x20, 0x10, 0x0, 0x20, 0x0, 0x30, 0xcc, 0xc, 0xf5, 0x6, 0x71,
        0x77, 0x24, 0x53, 0x85, 0x9, 0x5, 0x14, 0xb, 0xf, 0xb0,
    ]);
    let script: Vec<u8> = b"*start\r\nend\r\n".iter().map(|b| b ^ 0x84).collect();
    let package = Nsa.open(
        &view(fixture(
            true,
            &[
                (b"raw.nbz", 0, &nbz, nbz.len() as u32),
                (b"compressed.nbz", 4, &nbz, 0),
                (b"compressed.wav", 4, &nbz, 4),
                (b"nscript.dat", 0, &script, script.len() as u32),
            ],
        )),
        &ArchiveOptions::default(),
    )?;
    for entry in &package.entries()[..3] {
        assert_eq!(package.open_entry(entry)?.as_ref(), b"RIFF");
        assert_eq!(package.open_entry_raw(entry)?.as_ref(), nbz);
        assert!(package.open_entry_source(entry)?.is_none());
    }
    assert_eq!(
        package.open_entry(&package.entries()[3])?.as_ref(),
        b"*start\r\nend\r\n"
    );
    assert_eq!(
        package.open_entry_raw(&package.entries()[3])?.as_ref(),
        script
    );
    assert!(package.open_entry_source(&package.entries()[3])?.is_none());
    Ok(())
}

#[cfg(test)]
#[path = "local.rs"]
mod local;
