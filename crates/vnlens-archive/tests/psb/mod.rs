#![allow(clippy::unwrap_used)]

use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use vnlens_core::{Catalog, Error};
use vnlens_io::{BinaryReader, BinaryWriter};

#[test]
fn catalog_opens_standalone_psb_resources() {
    crate::init();
    let dir = unique_temp_dir();
    fs::create_dir_all(&dir).unwrap();
    let psb_path = dir.join("standalone.psb");
    fs::write(&psb_path, minimal_resource_psb()).unwrap();

    let catalog = Catalog::load();
    let opened = catalog
        .open(
            &psb_path,
            &vnlens_core::ArchiveRoute::new(PsbContainer.tag()),
        )
        .unwrap();
    assert_eq!(opened.format_tag, PsbContainer.tag());
    assert_eq!(opened.archive.entries()[0].name, "resources/0000");
    assert_eq!(
        opened
            .archive
            .open_entry_raw(&opened.archive.entries()[0])
            .unwrap()
            .as_ref(),
        b"res"
    );

    drop(opened);
    fs::remove_dir_all(&dir).unwrap();
}

fn minimal_resource_psb() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"PSB\0");
    push_u16(&mut out, 3);
    push_u16(&mut out, 0);
    push_u32(&mut out, 44);
    let offset_names_pos = out.len();
    push_u32(&mut out, 0);
    let offset_strings_pos = out.len();
    push_u32(&mut out, 0);
    let offset_strings_data_pos = out.len();
    push_u32(&mut out, 0);
    let offset_chunk_offsets_pos = out.len();
    push_u32(&mut out, 0);
    let offset_chunk_lengths_pos = out.len();
    push_u32(&mut out, 0);
    let offset_chunk_data_pos = out.len();
    push_u32(&mut out, 0);
    let offset_entries_pos = out.len();
    push_u32(&mut out, 0);
    push_u32(&mut out, 0);

    let offset_names = out.len();
    push_array(&mut out, &[0]);
    push_array(&mut out, &[0]);
    push_array(&mut out, &[]);

    let offset_strings = out.len();
    push_array(&mut out, &[]);

    let offset_strings_data = out.len();
    out.push(0);

    let offset_chunk_offsets = out.len();
    push_array(&mut out, &[0]);

    let offset_chunk_lengths = out.len();
    push_array(&mut out, &[3]);

    let offset_entries = out.len();
    out.push(0x01);

    let offset_chunk_data = out.len();
    out.extend_from_slice(b"res");

    patch_u32(&mut out, offset_names_pos, offset_names);
    patch_u32(&mut out, offset_strings_pos, offset_strings);
    patch_u32(&mut out, offset_strings_data_pos, offset_strings_data);
    patch_u32(&mut out, offset_chunk_offsets_pos, offset_chunk_offsets);
    patch_u32(&mut out, offset_chunk_lengths_pos, offset_chunk_lengths);
    patch_u32(&mut out, offset_chunk_data_pos, offset_chunk_data);
    patch_u32(&mut out, offset_entries_pos, offset_entries);
    out
}

fn push_array(out: &mut Vec<u8>, values: &[u32]) {
    out.push(0x0D);
    out.push(u8::try_from(values.len()).unwrap());
    out.push(0x0D);
    for &value in values {
        out.push(u8::try_from(value).unwrap());
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    let mut bytes = [0u8; 2];
    BinaryWriter::u16_le(value, &mut bytes);
    out.extend_from_slice(&bytes);
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    let mut bytes = [0u8; 4];
    BinaryWriter::u32_le(value, &mut bytes);
    out.extend_from_slice(&bytes);
}

fn patch_u32(out: &mut [u8], offset: usize, value: usize) {
    BinaryWriter::u32_le_at(u32::try_from(value).unwrap(), out, offset);
}

fn unique_temp_dir() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("vnlens-psb-resource-test-{nanos}"))
}

#[test]
fn psz_catalog_and_encrypted_index_keep_resources_lazy() {
    use std::io::Write;
    use vnlens_crypto::cipher::psb_stream::PsbStream;
    let mut data = minimal_resource_psb();
    let start = BinaryReader::u32_le(&data[12..]) as usize;
    let end = BinaryReader::u32_le(&data[24..]) as usize;
    PsbStream::new(0x1234_5678).apply(&mut data[start..end]);
    struct IndexOnly {
        data: Vec<u8>,
        resource: u64,
    }
    impl ReadAt for IndexOnly {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, at: u64, size: usize) -> std::io::Result<std::borrow::Cow<'_, [u8]>> {
            assert!(
                at + size as u64 <= self.resource,
                "mounting read a resource"
            );
            Ok(std::borrow::Cow::Borrowed(
                &self.data[at as usize..at as usize + size],
            ))
        }
    }
    let resource = u64::from(BinaryReader::u32_le(&data[32..]));
    let source = Arc::new(IndexOnly { data, resource });
    let mut options = ArchiveOptions::default();
    let mut key = [0; 4];
    BinaryWriter::u32_le(0x1234_5678, &mut key);
    options.keys.insert("psb", vnlens_core::Secret::new(key));
    let mounted = PsbContainer
        .open_source(source, "resource.psb", &options)
        .unwrap()
        .unwrap();
    assert_eq!(mounted.entries().len(), 2);
    assert_eq!(mounted.entries()[0].offset, resource);
    drop(mounted);

    let data = minimal_resource_psb();
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&data).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut shell = b"PSZ\0".to_vec();
    for value in [compressed.len() as u32, data.len() as u32, 0] {
        push_u32(&mut shell, value);
    }
    shell.extend(compressed);
    crate::init();
    let dir = unique_temp_dir();
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("resource.psz");
    fs::write(&path, shell).unwrap();
    let opened = Catalog::load()
        .open(&path, &vnlens_core::ArchiveRoute::new(PsbContainer.tag()))
        .unwrap();
    assert_eq!(
        &*opened
            .archive
            .open_entry(&opened.archive.entries()[0])
            .unwrap(),
        b"res"
    );
    drop(opened);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn psb_container_keeps_metadata_for_all_supported_shells() -> Result<()> {
    use std::io::Write;
    let mut psb = vec![0; 44];
    psb[..4].copy_from_slice(b"PSB\0");
    BinaryWriter::u16_le(3, &mut psb[4..]);
    BinaryWriter::u32_le(44, &mut psb[8..]);
    let names = psb.len();
    psb.extend([0x0d, 0, 0x0d].repeat(3));
    let strings = psb.len();
    psb.extend([0x0d, 0, 0x0d]);
    let entries = psb.len();
    psb.push(2);
    let offsets = psb.len();
    psb.extend([0x0d, 0, 0x0d]);
    let lengths = psb.len();
    psb.extend([0x0d, 0, 0x0d]);
    let end = psb.len();
    for (at, value) in [
        (12, names),
        (16, strings),
        (20, end),
        (24, offsets),
        (28, lengths),
        (32, end),
        (36, entries),
    ] {
        BinaryWriter::u32_le(value as u32, &mut psb[at..]);
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&psb)?;
    let payload = encoder.finish()?;
    let mut mdf = b"mdf\0".to_vec();
    let mut word = [0; 4];
    BinaryWriter::u32_le(psb.len() as u32, &mut word);
    mdf.extend(word);
    mdf.extend(&payload);
    let mut psz = b"PSZ\0".to_vec();
    for value in [payload.len() as u32, psb.len() as u32, 0] {
        BinaryWriter::u32_le(value, &mut word);
        psz.extend(word);
    }
    psz.extend(payload);
    let mut mzs = b"mzs\0".to_vec();
    BinaryWriter::u32_le(psb.len() as u32, &mut word);
    mzs.extend(word);
    mzs.extend([0x28, 0xb5, 0x2f, 0xfd, 0xa0]);
    mzs.extend(word);
    BinaryWriter::u32_le(((psb.len() as u32) << 3) | 1, &mut word);
    mzs.extend(&word[..3]);
    mzs.extend(&psb);
    for tag in ["psb"] {
        for data in [&psb, &mdf, &mzs, &psz] {
            let bytes: Arc<[u8]> = data.as_slice().into();
            let opened = Catalog::load()
                .open_source(
                    Arc::new(bytes),
                    "scene.scn",
                    &vnlens_core::ArchiveRoute::new(tag),
                )?
                .ok_or(Error::InvalidFormat)?;
            let parsed = opened
                .archive
                .metadata()
                .ok_or(Error::InvalidFormat)?
                .downcast::<vnlens_middleware::psb::Psb>()
                .map_err(|_| Error::InvalidFormat)?;
            assert_eq!(parsed.root, vnlens_middleware::psb::PsbValue::Bool(true));
            assert_eq!(opened.archive.entries().len(), 1);
            let value = &opened.archive.entries()[0];
            assert_eq!(value.name, "root");
            assert_eq!(opened.archive.open_entry(value)?.as_ref(), &[2]);
        }
        let mut malformed = psz.clone();
        let last = malformed.len() - 1;
        malformed[last] ^= 1;
        let bytes: Arc<[u8]> = malformed.into();
        assert!(
            Catalog::load()
                .open_source(
                    Arc::new(bytes),
                    "scene.psz",
                    &vnlens_core::ArchiveRoute::new(tag)
                )
                .is_err()
        );
    }
    Ok(())
}
