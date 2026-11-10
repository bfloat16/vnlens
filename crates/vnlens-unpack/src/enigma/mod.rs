//! Static Enigma bootstrap recovery adapted from bfloat16/enigma_rs (Apache-2.0).
//! Only section decoding and embedded virtual files are retained. The Loader's
//! reached instructions are interpreted as data; target code is never executed.
mod config;
mod evb;
mod extract;
mod search;
mod x86 {
    pub(super) mod cpu;
    pub(super) mod entry;
    pub(super) mod layout;
    pub(super) mod memory;
    pub(super) mod tokens;
}
mod x64 {
    pub(super) mod cpu;
    pub(super) mod entry;
    pub(super) mod layout;
}

use anyhow::Context;
pub use search::Mode;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use vnlens_core::{Error, Result};
use vnlens_io::{ArcView, ReadAt, pe::PeImage};

struct Entry {
    loader: Option<Vec<u8>>,
    metadata: u32,
}
impl Entry {
    fn parse(pe: &PeImage<'_>, cancel: &AtomicBool) -> anyhow::Result<Self> {
        match pe.machine {
            0x14c => x86::entry::parse(pe, cancel),
            0x8664 => x64::entry::parse(pe, cancel),
            _ => anyhow::bail!("Unsupported Enigma PE architecture"),
        }
    }
}

/// One restored section, shared between engine detectors and parameter readers.
pub struct Section {
    pub rva: u32,
    pub characteristics: u32,
    pub bytes: Arc<[u8]>,
}
impl std::fmt::Debug for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Section")
            .field("rva", &self.rva)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Validates the reached bootstrap metadata and ciphertext digest. Section
/// names only select candidates; they cannot establish wrapper identity.
pub fn recognizes(image: &PeImage<'_>, cancel: &AtomicBool) -> Result<bool> {
    check(cancel)?;
    if !image.sections.iter().any(|s| s.name == [0; 8]) {
        return Ok(false);
    }
    let probe = || -> anyhow::Result<bool> {
        let entry = Entry::parse(image, cancel)?;
        let header = image.read(entry.metadata, 28)?;
        let count = vnlens_io::BinaryReader::u32_le(header) as usize;
        let size = vnlens_io::BinaryReader::u32_le(&header[4..]) as usize;
        if count == 0 || count > image.sections.len() || size == 0 {
            return Ok(false);
        }
        let rva = entry
            .metadata
            .checked_add(28)
            .context("Enigma metadata overflow")?;
        Ok(vnlens_crypto::hash::md5::digest(image.read(rva, size)?) == header[12..28])
    };
    let matched = probe().unwrap_or(false);
    check(cancel)?;
    Ok(matched)
}

/// Recovers all enabled host sections, validating every section before returning.
/// Neither the source file nor its PE headers are rewritten.
pub fn recover(
    view: Arc<ArcView>,
    mode: Mode,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Result<Recovered> {
    check(cancel)?;
    let recover = || -> anyhow::Result<_> {
        let image = PeImage::parse(view.slice(0, view.len())?)?.context("Missing protected PE")?;
        tracing::info!("Reading Enigma bootstrap and configuration");
        let config = config::parse(&image, cancel)?;
        let ctx = config
            .ctx
            .as_ref()
            .context("Unknown Enigma configuration layout")?;
        let layout = config
            .layout
            .as_ref()
            .context("Unknown Enigma Loader layout")?;
        anyhow::ensure!(
            ctx.get(layout.machine_suffix) == Some(&0),
            "Machine-bound Enigma section keys are unsupported"
        );
        let stored = extract::stored_sections(&image, &config)?;
        tracing::info!("Recovering Enigma host sections");
        let salt = search::search(&stored, mode, cancel, progress)?;
        let sections = stored
            .iter()
            .map(|section| {
                check(cancel)?;
                Ok(Section {
                    rva: section.descriptor.rva,
                    characteristics: section.descriptor.characteristics,
                    bytes: extract::decode(section, salt, true)?.into(),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let files = evb::mount(view.clone(), &image, ctx)?;
        Ok(Recovered { sections, files })
    };
    recover().map_err(|error| convert(error, cancel))
}

/// Restored host sections and lazily decoded paths relative to the host PE.
pub struct Recovered {
    pub sections: Vec<Section>,
    pub files: Vec<(std::path::PathBuf, Arc<dyn ReadAt>)>,
}
impl std::fmt::Debug for Recovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recovered")
            .field("sections", &self.sections)
            .field("files", &self.files.len())
            .finish()
    }
}

fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn convert(error: anyhow::Error, cancel: &AtomicBool) -> Error {
    if cancel.load(Ordering::Relaxed) {
        return Error::Cancelled;
    }
    if let Some(io) = error.downcast_ref::<std::io::Error>() {
        return Error::Io(std::io::Error::new(io.kind(), format!("Enigma: {error:#}")));
    }
    Error::Unsupported(format!("Enigma: {error:#}"))
}
