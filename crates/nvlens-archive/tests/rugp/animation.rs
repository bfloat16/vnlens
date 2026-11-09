use super::*;
use nvlens_io::BinaryWriter;

#[test]
fn frame_reads_keep_raw_ranges_and_include_only_required_dependencies() -> Result<()> {
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| Error::Unsupported(error.to_string()))?
        .as_nanos();
    let path =
        Temp(std::env::temp_dir().join(format!("nvlens-rsi-{}-{nonce}", std::process::id())));
    let mut data = vec![0; 23 + 4 * 15];
    BinaryWriter::u16_le(4, &mut data[11..]);
    BinaryWriter::u16_le(4, &mut data[13..]);
    BinaryWriter::u16_le(4, &mut data[21..]);
    let key = [0x74, 0x69, 0x27, 0x03];
    let delta = [0x54, 0x65, 0x91, 0x01];
    for (i, (mode, offset, length)) in [(1, 0, 4), (0, 4, 4), (1, 8, 4), (0, 12, 1)]
        .into_iter()
        .enumerate()
    {
        let at = 23 + i * 15;
        data[at] = mode;
        BinaryWriter::u32_le(offset, &mut data[at + 1..]);
        BinaryWriter::u16_le(0x575, &mut data[at + 7..]);
        BinaryWriter::u16_le(8, &mut data[at + 9..]);
        BinaryWriter::u32_le(length, &mut data[at + 11..]);
    }
    data.extend(key);
    data.extend(delta);
    data.extend(key);
    data.push(0); // Invalid pixels in an unrequested frame do not affect indexing.
    std::fs::write(&path.0, &data)?;
    let sources = Arc::new(Sources {
        root: u32::MAX,
        primary: Arc::new(ArcView::open(&path.0)?),
        volumes: vec![ici::Volume {
            name: "test.rio".into(),
            base: 0,
            size: data.len() as u64,
        }],
        paths: vec![path.0.clone()],
        opened: vec![OnceLock::new()],
        shift: 0,
        children: HashMap::new(),
        patches: HashMap::new(),
    });
    let frames = Frames::open(
        sources,
        Object {
            class: Class {
                name: "CRsi".into(),
                schema: 1,
                encoded: None,
            },
            flags: 8,
            offset: 0,
            size: data.len() as u32,
            name: None,
            parent: None,
        },
    )?;
    assert_eq!(frames.entries.len(), 4);
    for (index, expected, dependencies) in [(1, [28, 17, 23, 255], 2), (2, [104, 81, 73, 255], 1)] {
        let raw = frames.open_entry_raw(&frames.entries[index])?;
        assert!(matches!(raw, Cow::Borrowed(_)));
        assert_eq!(&*raw, if index == 1 { &delta } else { &key });
        let decoded = frames.open_entry(&frames.entries[index])?;
        assert_eq!(BinaryReader::u32_le(&decoded[12..]), dependencies);
        let image = nvlens_image::decode(&decoded)?.ok_or(Error::InvalidFormat)?;
        let nvlens_image::PixelBuffer::Rgba8(pixels) = image.pixels else {
            return Err(Error::InvalidFormat);
        };
        assert_eq!(pixels, expected.repeat(16));
    }
    assert!(nvlens_image::decode(&frames.open_entry(&frames.entries[3])?).is_err());
    drop(frames);
    Ok(())
}
