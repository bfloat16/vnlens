//! PE evidence precedes directory-layout evidence; no archive is opened here.

use crate::{Engine, Identification, emote};
use nvlens_core::{ArchiveOptions, Error, Result};
use nvlens_io::{ArcView, BinaryReader, pe::PeImage};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub(crate) struct Detector {
    pub pe: fn(&PeImage<'_>) -> Result<bool>,
    pub layout: fn(&Path) -> bool,
    pub engine: Engine,
    pub resolve: fn(&Path, &[PathBuf], &AtomicBool) -> Result<ArchiveOptions>,
}
nvlens_core::inventory::collect!(Detector);

/// Identifies a selected game directory or file. Only the selected directory,
/// its engine plugin directory and the parent of conventional asset directories
/// are considered; recognition never walks arbitrary ancestors or archives.
pub fn identify(path: &Path, cancelled: &AtomicBool) -> Result<Option<Identification>> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let mut root = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    if root.file_name().is_some_and(|name| {
        [
            "pac", "data", "archive", "plugin", "plugins", "g00", "gan", "bgm", "wav", "koe",
            "mov", "dat", "res", "rld",
        ]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
    }) {
        root = root.parent().unwrap_or(root);
    }
    let root = root.canonicalize()?;
    let mut executables = Vec::new();
    for directory in [root.clone(), root.join("plugin"), root.join("plugins")] {
        if !directory.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(directory)? {
            if cancelled.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().is_some_and(|ext| {
                    ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("dll")
                })
            {
                executables.push(path);
            }
        }
    }
    executables.sort();
    let mut matches = Vec::new();
    let mut has_emote = false;
    for executable in &executables {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = ArcView::open(executable)?;
        let data = view.slice(0, view.len())?;
        let Some(mut pe) = PeImage::parse(data).ok().flatten() else {
            continue;
        };
        nvlens_unpack::steamstub::unpack(&mut pe, cancelled)?;
        has_emote |= emote::pe(&pe)?;
        for detector in nvlens_core::inventory::iter::<Detector>() {
            if (detector.pe)(&pe)? {
                matches.push((
                    detector,
                    format!("PE features in {}", executable.display()),
                    Some(executable.clone()),
                ));
            }
        }
    }
    if matches.is_empty() {
        for detector in nvlens_core::inventory::iter::<Detector>() {
            if (detector.layout)(&root) {
                matches.push((detector, "Game directory layout".into(), None));
            }
        }
    }
    let Some((detector, evidence, _)) = matches.first() else {
        return Ok(None);
    };
    if matches
        .iter()
        .any(|(other, _, _)| other.engine != detector.engine)
    {
        return Err(Error::Unsupported(
            "Conflicting engine evidence in the selected game directory".into(),
        ));
    }
    let matched: Vec<_> = matches
        .iter()
        .filter_map(|(_, _, path)| path.clone())
        .collect();
    let options = (detector.resolve)(
        &root,
        if matched.is_empty() {
            &executables
        } else {
            &matched
        },
        cancelled,
    )?;
    let emote = (has_emote || emote::layout(&root))
        .then(emote::options)
        .transpose()?;
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    Ok(Some(Identification {
        root,
        engine: detector.engine,
        evidence: evidence.clone(),
        options,
        emote,
    }))
}

/// Searches file-backed PE sections for ASCII or UTF-16LE strings. The marker
/// itself is ASCII; UTF-16 code units still use the shared binary reader.
pub(crate) fn has(pe: &PeImage<'_>, marker: &[u8]) -> Result<bool> {
    for section in &pe.sections {
        let data = pe.section_data(section)?;
        if data
            .windows(marker.len())
            .any(|part| part.eq_ignore_ascii_case(marker))
        {
            return Ok(true);
        }
        if data.windows(marker.len() * 2).any(|part| {
            part.as_chunks::<2>()
                .0
                .iter()
                .zip(marker)
                .all(|(unit, byte)| {
                    let unit = BinaryReader::u16_le(unit);
                    unit <= 0x7f && (unit as u8).eq_ignore_ascii_case(byte)
                })
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn plain(_: &Path, _: &[PathBuf], _: &AtomicBool) -> Result<ArchiveOptions> {
    Ok(ArchiveOptions::default())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    use std::{fs, sync::atomic::AtomicU64};

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn temp() -> Temp {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nvlens-engine-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Temp(path)
    }
    fn pe_bytes(text: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 0x200 + text.len()];
        bytes[..2].copy_from_slice(b"MZ");
        BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        BinaryWriter::u16_le(0x14c, &mut bytes[0x84..]);
        BinaryWriter::u16_le(1, &mut bytes[0x86..]);
        BinaryWriter::u16_le(0xe0, &mut bytes[0x94..]);
        BinaryWriter::u16_le(0x10b, &mut bytes[0x98..]);
        BinaryWriter::u32_le(0x400000, &mut bytes[0xb4..]);
        BinaryWriter::u32_le(0x200, &mut bytes[0xd4..]);
        BinaryWriter::u32_le(0x1000, &mut bytes[0x184..]);
        BinaryWriter::u32_le(text.len() as u32, &mut bytes[0x188..]);
        BinaryWriter::u32_le(0x200, &mut bytes[0x18c..]);
        bytes[0x200..].copy_from_slice(text);
        bytes
    }
    #[test]
    fn pe_strings_precede_layout_and_archive_bytes_are_not_evidence() {
        let dir = temp();
        let cancel = AtomicBool::new(false);
        fs::write(dir.0.join("renamed.exe"), pe_bytes(b"AdvHD\0WillPlus\0")).unwrap();
        fs::create_dir(dir.0.join("pac")).unwrap();
        fs::write(dir.0.join("pac/Scripts.ypf"), b"broken").unwrap();
        fs::write(dir.0.join("pac/Graphics.ypf"), b"broken").unwrap();
        let game = identify(&dir.0, &cancel).unwrap().unwrap();
        assert_eq!(game.engine, Engine::Will);
        assert!(game.evidence.starts_with("PE features"));
        assert_eq!(game.route("random.arc").unwrap().tag, "arc/willv2");
        assert!(game.route("Scripts.ypf").is_none());
        fs::remove_file(dir.0.join("renamed.exe")).unwrap();
        assert!(matches!(
            identify(&dir.0, &cancel),
            Err(Error::UnknownScheme(_))
        ));
        fs::remove_dir_all(dir.0.join("pac")).unwrap();
        fs::write(dir.0.join("standalone.arc"), b"AdvHD\0WillPlus\0").unwrap();
        assert!(identify(&dir.0, &cancel).unwrap().is_none());
        cancel.store(true, Ordering::Relaxed);
        assert!(matches!(identify(&dir.0, &cancel), Err(Error::Cancelled)));
    }
    #[test]
    fn unicode_strings_conflicting_engines_and_missing_keys() {
        let dir = temp();
        let cancel = AtomicBool::new(false);
        let mut text = Vec::new();
        for unit in "AdvHD\0WillPlus\0".encode_utf16() {
            let mut bytes = [0; 2];
            BinaryWriter::u16_le(unit, &mut bytes);
            text.extend(bytes);
        }
        fs::write(dir.0.join("wide.exe"), pe_bytes(&text)).unwrap();
        assert_eq!(
            identify(&dir.0, &cancel).unwrap().unwrap().engine,
            Engine::Will
        );
        fs::write(
            dir.0.join("other.exe"),
            pe_bytes(b"ysbin\\yst%05d.ybn\0ysbin\\yst_list.ybn\0"),
        )
        .unwrap();
        assert!(matches!(
            identify(&dir.0, &cancel),
            Err(Error::Unsupported(_))
        ));
        fs::remove_file(dir.0.join("wide.exe")).unwrap();
        assert!(matches!(
            identify(&dir.0, &cancel),
            Err(Error::UnknownScheme(_))
        ));
    }
    #[test]
    fn layout_fallback_and_renamed_non_pe_are_not_confused() {
        let dir = temp();
        let cancel = AtomicBool::new(false);
        fs::write(dir.0.join("fake.exe"), b"AdvHD\0WillPlus\0").unwrap();
        assert!(identify(&dir.0, &cancel).unwrap().is_none());
        for name in ["AdvHD.exe", "Script2.arc", "Graphic.arc"] {
            fs::write(dir.0.join(name), []).unwrap();
        }
        let game = identify(&dir.0, &cancel).unwrap().unwrap();
        assert_eq!(game.engine, Engine::Will);
        assert_eq!(game.evidence, "Game directory layout");
    }
    #[test]
    fn bgi_pe_routes_arc_and_asset_directory_uses_game_context() {
        let dir = temp();
        let cancel = AtomicBool::new(false);
        fs::write(
            dir.0.join("renamed.exe"),
            pe_bytes(b"Ethornell - BURIKO General Interpreter\0BURIKO ARC20\0"),
        )
        .unwrap();
        fs::create_dir(dir.0.join("Archive")).unwrap();
        fs::write(dir.0.join("Archive/data.arc"), b"broken archive").unwrap();
        let game = identify(&dir.0.join("Archive/data.arc"), &cancel)
            .unwrap()
            .unwrap();
        assert_eq!(game.engine, Engine::Bgi);
        assert_eq!(game.route("data.arc").unwrap().tag, "arc/bgi");
        assert_eq!(game.script_format(), Some("script/bgi"));
        assert!(game.route("unrelated.ypf").is_none());
        fs::remove_file(dir.0.join("renamed.exe")).unwrap();
        for name in ["system.arc", "sysprg.arc", "sysgrp.arc"] {
            fs::write(dir.0.join(name), []).unwrap();
        }
        assert_eq!(
            identify(&dir.0, &cancel).unwrap().unwrap().engine,
            Engine::Bgi
        );
    }
    #[test]
    fn exhibit_requires_pe_identity_and_resolved_bitmap_parameters() {
        let dir = temp();
        let cancel = AtomicBool::new(false);
        fs::write(dir.0.join("resources.grp"), b"AiFS").unwrap();
        assert!(identify(&dir.0, &cancel).unwrap().is_none());
        fs::write(dir.0.join("ExHIBIT.ini"), b"[setting]\nSYSVER=1\n").unwrap();
        fs::write(
            dir.0.join("renamed.exe"),
            pe_bytes(b"ExHIBIT.ini\0RetouchSendExHIBIT\0"),
        )
        .unwrap();
        assert!(matches!(
            identify(&dir.0, &cancel),
            Err(Error::UnknownScheme(_))
        ));
        fs::create_dir(dir.0.join("res")).unwrap();
        assert!(matches!(
            identify(&dir.0.join("res"), &cancel),
            Err(Error::UnknownScheme(_))
        ));
        fs::write(dir.0.join("other.exe"), pe_bytes(b"AdvHD\0WillPlus\0")).unwrap();
        assert!(matches!(
            identify(&dir.0, &cancel),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn emote_attaches_to_host_and_never_identifies_an_engine() {
        let dir = temp();
        let cancel = AtomicBool::new(false);
        fs::create_dir(dir.0.join("plugin")).unwrap();
        fs::write(
            dir.0.join("plugin/psbfile.dll"),
            pe_bytes(b"PSBFile\0psbfile.dll\0"),
        )
        .unwrap();
        assert!(identify(&dir.0, &cancel).unwrap().is_none());
        fs::write(dir.0.join("host.exe"), pe_bytes(b"AdvHD\0WillPlus\0")).unwrap();
        let game = identify(&dir.0, &cancel).unwrap().unwrap();
        assert_eq!(game.engine, Engine::Will);
        assert_eq!(game.route("data.arc").unwrap().tag, "arc/willv2");
        assert_eq!(game.route("body.psb").unwrap().tag, "psb/emote-resources");
        assert_eq!(
            game.route("pack_info.psb.m").unwrap().tag,
            "psb/emote-archive-info"
        );
        fs::write(
            dir.0.join("hxv4.dll"),
            pe_bytes(b"Hxv4\0PARAMS\0FilterManager\0"),
        )
        .unwrap();
        assert!(matches!(
            identify(&dir.0, &cancel),
            Err(Error::Unsupported(_))
        ));
        fs::remove_file(dir.0.join("host.exe")).unwrap();
        assert!(matches!(
            identify(&dir.0, &cancel),
            Err(Error::UnknownScheme(_))
        ));
    }
}
