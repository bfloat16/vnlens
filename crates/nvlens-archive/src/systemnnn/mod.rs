//! SystemNNN split indexes. GPK uses GTB name/offset tables; VPK uses VTB
//! fixed records and a terminal offset. Payload bytes remain borrowed and
//! are interpreted only by the image/audio domain when requested.
mod gpk;
mod vpk;

use nvlens_core::{Archive, Entry, Error, Result};
use nvlens_io::ArcView;
use std::{borrow::Cow, sync::Arc};

struct Package {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
}
impl Archive for Package {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
}
fn corrupt(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}
fn name(bytes: &[u8]) -> Result<String> {
    let bytes = bytes.split(|&b| b == 0).next().unwrap_or_default();
    let (name, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
    if errors {
        return Err(corrupt(0, "Invalid SystemNNN CP932 entry name"));
    }
    Ok(name.into_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_core::Catalog;
    use nvlens_io::BinaryWriter;
    use std::path::PathBuf;
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn temp() -> Temp {
        let path = std::env::temp_dir().join(format!(
            "nvlens-nnn-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Temp(path)
    }
    fn gtb(wide: bool) -> Vec<u8> {
        let names = b"../good\0bad\0";
        let mut bytes = vec![0; 20];
        for (i, word) in [2, 0, 8, 0x80000000, 0x80000003].iter().enumerate() {
            BinaryWriter::u32_le(*word, &mut bytes[i * 4..]);
        }
        bytes.extend_from_slice(names);
        if wide {
            // Extended offsets override the legacy flags and low 31 bits.
            BinaryWriter::u32_le(99, &mut bytes[12..]);
            BinaryWriter::u32_le(100, &mut bytes[16..]);
            let at = bytes.len();
            bytes.resize(at + 32, 0);
            BinaryWriter::u64_le(0, &mut bytes[at..]);
            BinaryWriter::u64_le(3, &mut bytes[at + 8..]);
            bytes[at + 24..].copy_from_slice(b"over2G!\0");
        }
        bytes
    }
    #[test]
    fn gpk_legacy_flags_and_extended_offsets_preserve_names_and_lazy_payloads() {
        crate::init();
        let dir = temp();
        let path = dir.0.join("bg0.gpk");
        std::fs::write(&path, b"ok!bad image bytes").unwrap();
        let catalog = Catalog::load();
        for wide in [false, true] {
            std::fs::write(path.with_extension("gtb"), gtb(wide)).unwrap();
            let opened = catalog
                .open(
                    &path,
                    &nvlens_core::ArchiveRoute {
                        tag: "gpk/systemnnn",
                        options: Default::default(),
                    },
                )
                .unwrap();
            let archive = opened.archive;
            assert_eq!(archive.entries().len(), 2);
            let entry = &archive.entries()[0];
            assert_eq!(entry.name, "../good.dwq");
            assert!(matches!(
                archive.open_entry(entry).unwrap(),
                Cow::Borrowed(b"ok!")
            ));
            assert_eq!(archive.open_entry_raw(entry).unwrap().as_ref(), b"ok!");
            assert_eq!(archive.entries()[1].size, 15);
        }
    }
    #[test]
    fn gpk_rejects_truncated_name_tables_and_full_width_out_of_range_offsets() {
        crate::init();
        let dir = temp();
        let path = dir.0.join("x.gpk");
        std::fs::write(&path, b"abcdef").unwrap();
        let catalog = Catalog::load();
        for n in 0..20 {
            std::fs::write(path.with_extension("gtb"), &gtb(false)[..n]).unwrap();
            assert!(
                catalog
                    .open(
                        &path,
                        &nvlens_core::ArchiveRoute {
                            tag: "gpk/systemnnn",
                            options: Default::default()
                        }
                    )
                    .is_err()
            );
        }
        let mut bytes = gtb(true);
        let at = bytes.len() - 32;
        BinaryWriter::u64_le(0x1_0000_0000, &mut bytes[at..]);
        std::fs::write(path.with_extension("gtb"), bytes).unwrap();
        assert!(
            catalog
                .open(
                    &path,
                    &nvlens_core::ArchiveRoute {
                        tag: "gpk/systemnnn",
                        options: Default::default()
                    }
                )
                .is_err()
        );
        let mut bytes = gtb(false);
        bytes.truncate(25);
        std::fs::write(path.with_extension("gtb"), bytes).unwrap();
        assert!(
            catalog
                .open(
                    &path,
                    &nvlens_core::ArchiveRoute {
                        tag: "gpk/systemnnn",
                        options: Default::default()
                    }
                )
                .is_err()
        );
    }
    #[test]
    fn vpk_fixed_names_terminal_record_and_order_checks() {
        crate::init();
        let dir = temp();
        let path = dir.0.join("aa.vpk");
        std::fs::write(&path, b"abcde").unwrap();
        let mut index = vec![0; 36];
        index[..8].copy_from_slice(b"aa000001");
        index[12..20].copy_from_slice(b"aa000002");
        BinaryWriter::u32_le(3, &mut index[20..]);
        BinaryWriter::u32_le(5, &mut index[32..]);
        std::fs::write(path.with_extension("vtb"), &index).unwrap();
        let catalog = Catalog::load();
        {
            let opened = catalog
                .open(
                    &path,
                    &nvlens_core::ArchiveRoute {
                        tag: "vpk/systemnnn",
                        options: Default::default(),
                    },
                )
                .unwrap();
            let archive = opened.archive;
            assert_eq!(archive.entries().len(), 2);
            assert_eq!(archive.entries()[0].name, "aa000001.vaw");
            assert_eq!(
                archive.open_entry(&archive.entries()[1]).unwrap().as_ref(),
                b"de"
            );
        }
        for end in [2, 6] {
            BinaryWriter::u32_le(end, &mut index[32..]);
            std::fs::write(path.with_extension("vtb"), &index).unwrap();
            assert!(
                catalog
                    .open(
                        &path,
                        &nvlens_core::ArchiveRoute {
                            tag: "vpk/systemnnn",
                            options: Default::default()
                        }
                    )
                    .is_err()
            );
        }
        index.pop();
        std::fs::write(path.with_extension("vtb"), &index).unwrap();
        assert!(
            catalog
                .open(
                    &path,
                    &nvlens_core::ArchiveRoute {
                        tag: "vpk/systemnnn",
                        options: Default::default()
                    }
                )
                .is_err()
        );
    }
}
