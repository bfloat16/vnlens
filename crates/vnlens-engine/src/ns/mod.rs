//! Nintendo Switch is a filesystem host, identified from the selected outer
//! container's metadata. It does not imply a particular game engine inside it.
use crate::{
    Engine,
    detect::{Detector, unscoped},
    routing::{Route, Router},
};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};
use vnlens_core::{ArchiveRoute, ResourceKind, ResourceOrigin, ResourceRoute, Result};
use vnlens_io::{ArcView, BinaryReader};

impl crate::Identification {
    /// Identifies a mounted NS filesystem by the same directory evidence used
    /// on disk. Sources must expose logical files lazily. Unknown engines keep
    /// the NS host and independently identified middleware for safe browsing;
    /// conflicting evidence and missing engine parameters remain errors.
    pub fn for_filesystem(
        &self,
        root: PathBuf,
        files: Arc<vnlens_io::FileSystem>,
        cancelled: &AtomicBool,
    ) -> Result<Self> {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(vnlens_core::Error::Cancelled);
        }
        let context = crate::context::Context {
            root: root.clone(),
            files: files.clone(),
            sections: Default::default(),
        };
        let mut game =
            if let Some(game) = crate::detect::identify_context(context, cancelled, &|_, _| {})? {
                game
            } else {
                let context = crate::context::Context {
                    root: root.clone(),
                    files: files.clone(),
                    sections: Default::default(),
                };
                crate::Identification {
                    root,
                    engine: Engine::NintendoSwitch,
                    evidence: "NS filesystem; game engine not identified".into(),
                    files,
                    options: self.options.clone(),
                    middleware: vnlens_core::inventory::iter::<crate::detect::Middleware>()
                        .filter(|item| {
                            (item.layout)(&context)
                                || (Arc::ptr_eq(&context.files, &self.files)
                                    && self
                                        .middleware
                                        .iter()
                                        .any(|route| std::ptr::eq(*route, &item.route)))
                        })
                        .map(|item| &item.route)
                        .collect(),
                    compose_pimg: self.compose_pimg.clone(),
                }
            };
        game.compose_pimg = self.compose_pimg.clone();
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(vnlens_core::Error::Cancelled);
        }
        Ok(game)
    }

    /// A filesystem host does not establish a game's proprietary resource
    /// formats. Recognized middleware and standard media remain available.
    #[must_use]
    pub fn warning(&self) -> Option<&'static str> {
        (self.engine == Engine::NintendoSwitch).then_some(
            "Game engine was not identified. Unknown formats use Hex preview; recognized middleware and standard formats remain available.",
        )
    }
}

const SIGNATURES: &[u32] = &[0x30534650, 0x30534648, 0x00000050];
const HEADER_SIZE: usize = 0x1104;

fn resolve(
    context: &crate::context::Context,
    _: &[PathBuf],
    cancelled: &AtomicBool,
) -> Result<vnlens_core::ArchiveOptions> {
    if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(vnlens_core::Error::Cancelled);
    }
    let mut options = vnlens_core::ArchiveOptions::default();
    options.paths.insert("ns_directory", context.root.clone());
    Ok(options)
}

fn file(view: &ArcView) -> Result<bool> {
    let ext = view
        .path()
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let result = match ext.as_str() {
        "xci" => [0x100, 0x1100].into_iter().any(|at| {
            view.len() >= at + 4 && view.slice(at, 4).is_ok_and(|bytes| bytes == b"HEAD")
        }),
        "nsp" | "pfs0" => view.len() >= 4 && view.read_u32_le(0)? == SIGNATURES[0],
        "hfs0" => view.len() >= 4 && view.read_u32_le(0)? == SIGNATURES[1],
        "romfs" => view.len() >= 8 && BinaryReader::u64_le(view.slice(0, 8)?) == 0x50,
        // NCA headers are normally encrypted and have no public magic. The
        // selected .nca declares this host; the archive reader validates its header
        // with the user's header_key before any resource processing.
        "nca" => view.len() >= 0xc00,
        "" => header_tag(view.slice(0, view.len().min(HEADER_SIZE as u64))?).is_some(),
        _ => false,
    };
    Ok(result)
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    let tag = match route.ext {
        "xci" => "ns/xci",
        "nsp" | "pfs0" => "ns/pfs0",
        "hfs0" => "ns/hfs0",
        "nca" => "ns/nca",
        "romfs" => "ns/romfs",
        _ if matches!(route.origin, ResourceOrigin::Entry(ResourceKind::Archive))
            && matches!(route.leaf, "secure" | "normal" | "update" | "logo") =>
        {
            "ns/hfs0"
        }
        _ => return None,
    };
    Some(route.archive_with(tag))
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    let tag = header_tag(route.header)?;
    Some(ResourceRoute::Archive(Box::new(route.archive_with(tag))))
}

fn header_tag(header: &[u8]) -> Option<&'static str> {
    Some(if header.starts_with(b"PFS0") {
        "ns/pfs0"
    } else if header.starts_with(b"HFS0") {
        "ns/hfs0"
    } else if header.len() >= 8 && BinaryReader::u64_le(&header[..8]) == 0x50 {
        "ns/romfs"
    } else if [0x100, 0x1100]
        .into_iter()
        .any(|at| header.get(at..at + 4) == Some(b"HEAD"))
    {
        "ns/xci"
    } else {
        return None;
    })
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::NintendoSwitch, supersedes: None, subdirs: &[],
        pe: |_| Ok(false), layout: |_| false, file, resolve, scope: unscoped,
        route: Router { filesystem_host: true, header_size: HEADER_SIZE, archive, header, ..Router::NONE },
    }
}

#[cfg(test)]
#[path = "../../tests/ns/mod.rs"]
mod tests;
