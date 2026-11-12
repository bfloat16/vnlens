#![allow(clippy::unwrap_used)]

use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use vnlens_core::Catalog;
use vnlens_io::BinaryWriter;

#[test]
fn catalog_opens_info_psb_with_sibling_body() {
    crate::init();
    let dir = unique_temp_dir();
    fs::create_dir_all(&dir).unwrap();
    let info_path = dir.join("sample_info.psb.m");
    let body_path = dir.join("sample_body.bin");
    let info = minimal_archive_info_psb();
    let parsed = psb::parse_source(&info.as_slice(), None).unwrap();
    let (_, parsed_entries) = psb::archive_info_entries(&parsed).unwrap();
    assert_eq!(parsed_entries[0].name, "dir/file.bin");
    fs::write(&info_path, info).unwrap();
    fs::write(&body_path, b"abcdef").unwrap();

    let catalog = Catalog::load();
    let opened = catalog
        .open(
            &info_path,
            &vnlens_core::ArchiveRoute::new("psb/archive-info"),
        )
        .unwrap();
    assert_eq!(opened.format_tag, "psb/archive-info");
    let entries = opened.archive.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "dir/file.bin");
    assert_eq!(entries[0].offset, 1);
    assert_eq!(entries[1].name, "index/file_info");
    // A mapped body would prevent replacement on Windows. Mounting must
    // leave it unopened until an entry is actually requested.
    fs::rename(&body_path, dir.join("unused_body.bin")).unwrap();
    let metadata = opened
        .archive
        .entry_metadata(&entries[1])
        .unwrap()
        .unwrap()
        .downcast::<psb::PsbValueFile>()
        .unwrap();
    assert!(metadata.value().unwrap().as_object().is_some());
    assert!(!opened.archive.open_entry(&entries[1]).unwrap().is_empty());
    fs::write(&body_path, b"ABCDEF").unwrap();
    assert_eq!(
        opened.archive.open_entry_raw(&entries[0]).unwrap().as_ref(),
        b"BCD"
    );
    assert_eq!(
        opened.archive.open_entry(&entries[0]).unwrap().as_ref(),
        b"BCD"
    );
    drop(opened);
    fs::remove_dir_all(&dir).unwrap();
}

fn minimal_archive_info_psb() -> Vec<u8> {
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

    let names = ["file_info", "dir/file.bin"];
    let (charset, names_data, name_indexes) = build_names(&names);

    let offset_names = out.len();
    push_array(&mut out, &charset);
    push_array(&mut out, &names_data);
    push_array(&mut out, &name_indexes);

    let offset_strings = out.len();
    push_array(&mut out, &[]);

    let offset_strings_data = out.len();
    out.push(0);

    let offset_chunk_offsets = out.len();
    push_array(&mut out, &[]);

    let offset_chunk_lengths = out.len();
    push_array(&mut out, &[]);

    let offset_chunk_data = out.len();

    let offset_entries = out.len();
    push_object(&mut out, &[0], &[0], |out| {
        push_object(out, &[1], &[0], |out| {
            push_list(out, &[0, 2], |out| {
                push_number(out, 1);
                push_number(out, 3);
            });
        });
    });

    patch_u32(&mut out, offset_names_pos, offset_names);
    patch_u32(&mut out, offset_strings_pos, offset_strings);
    patch_u32(&mut out, offset_strings_data_pos, offset_strings_data);
    patch_u32(&mut out, offset_chunk_offsets_pos, offset_chunk_offsets);
    patch_u32(&mut out, offset_chunk_lengths_pos, offset_chunk_lengths);
    patch_u32(&mut out, offset_chunk_data_pos, offset_chunk_data);
    patch_u32(&mut out, offset_entries_pos, offset_entries);
    out
}

fn build_names(names: &[&str]) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    let mut charset = vec![0; 512];
    let mut names_data = vec![0; 512];
    let mut indexes = Vec::with_capacity(names.len());
    let mut next_node = 256u32;

    for name in names {
        let mut code = 0u32;
        for &byte in name.as_bytes() {
            let byte = u32::from(byte);
            let chr = if code == 0 {
                byte
            } else {
                let value = next_node;
                next_node += 1;
                value
            };
            ensure_len(&mut charset, code);
            ensure_len(&mut names_data, chr);
            charset[usize::try_from(code).unwrap()] = chr.checked_sub(byte).unwrap();
            names_data[usize::try_from(chr).unwrap()] = code;
            code = chr;
        }
        let index = next_node;
        next_node += 1;
        ensure_len(&mut names_data, index);
        names_data[usize::try_from(index).unwrap()] = code;
        indexes.push(index);
    }

    (charset, names_data, indexes)
}

fn ensure_len(values: &mut Vec<u32>, index: u32) {
    let len = usize::try_from(index).unwrap() + 1;
    if values.len() < len {
        values.resize(len, 0);
    }
}

fn push_object(
    out: &mut Vec<u8>,
    name_indexes: &[u32],
    offsets: &[u32],
    body: impl FnOnce(&mut Vec<u8>),
) {
    out.push(0x21);
    push_array(out, name_indexes);
    push_array(out, offsets);
    body(out);
}

fn push_list(out: &mut Vec<u8>, offsets: &[u32], body: impl FnOnce(&mut Vec<u8>)) {
    out.push(0x20);
    push_array(out, offsets);
    body(out);
}

fn push_number(out: &mut Vec<u8>, value: u8) {
    out.push(0x05);
    out.push(value);
}

fn push_array(out: &mut Vec<u8>, values: &[u32]) {
    let count_width = compact_width(u32::try_from(values.len()).unwrap());
    let entry_width = values.iter().copied().max().map_or(1, compact_width);
    out.push(0x0C + count_width);
    let mut count = [0u8; 4];
    BinaryWriter::u32_le(u32::try_from(values.len()).unwrap(), &mut count);
    out.extend_from_slice(&count[..usize::from(count_width)]);
    out.push(0x0C + entry_width);
    for &value in values {
        let mut bytes = [0u8; 4];
        BinaryWriter::u32_le(value, &mut bytes);
        out.extend_from_slice(&bytes[..usize::from(entry_width)]);
    }
}

fn compact_width(value: u32) -> u8 {
    if value > u32::from(u8::MAX) { 2 } else { 1 }
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

fn unique_temp_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("vnlens-archive-info-test-{nanos}"))
}
