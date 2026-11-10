#![allow(clippy::unwrap_used)]

use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use vnlens_core::Catalog;
use vnlens_io::BinaryWriter;

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
            &vnlens_core::ArchiveRoute::new(EmotePsbResources.tag()),
        )
        .unwrap();
    assert_eq!(opened.format_tag, EmotePsbResources.tag());
    assert_eq!(opened.archive.entries()[0].name, "resources/0000.bin");
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
