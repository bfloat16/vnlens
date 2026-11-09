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
            "mov", "dat", "res", "rld", "dwq", "cdvaw", "vaw", "wgq", "spt", "init2", "nya",
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
                    ext.eq_ignore_ascii_case("exe")
                        || ext.eq_ignore_ascii_case("dll")
                        || ext.eq_ignore_ascii_case("tpm")
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
    // Hxv4 is a protected KiriKiri host, so its generic host strings are not
    // conflicting evidence. Resolution must still succeed without fallback.
    if matches
        .iter()
        .any(|(d, _, _)| d.engine == Engine::KrkrzHxv4)
    {
        matches.retain(|(d, _, _)| d.engine != Engine::Krkr);
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
        if matched.is_empty() || detector.engine == Engine::Krkr {
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
#[path = "../tests/detect.rs"]
mod tests;
