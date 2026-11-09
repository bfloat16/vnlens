//! Immutable identification results. Secret material is redacted in Debug.

use nvlens_core::{ArchiveOptions, ArchiveRoute};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Propeller,
    Rugp,
    Escude,
    SystemNnn,
    Exhibit,
    Yuris,
    Will,
    AgesMk2,
    Bgi,
    Siglus,
    Krkr,
    KrkrzHxv4,
}

#[derive(Clone, Debug)]
pub struct Identification {
    pub root: PathBuf,
    pub engine: Engine,
    pub evidence: String,
    pub(crate) options: ArchiveOptions,
    pub(crate) emote: Option<ArchiveOptions>,
}

impl Identification {
    /// Parameters shared with resource decoders; Debug redacts all keys.
    #[must_use]
    pub fn resource_options(&self) -> &ArchiveOptions {
        &self.options
    }

    /// Selects a container using the normalized name supplied by resource_route.
    /// This examines names only, never payloads or unrelated format handlers.
    #[must_use]
    pub(super) fn archive_route(&self, name: &str) -> Option<ArchiveRoute> {
        let extension = name
            .rsplit('/')
            .next()
            .unwrap_or("")
            .rsplit_once('.')
            .map_or("", |(_, extension)| extension);
        if let Some(options) = &self.emote {
            let tag = if name.ends_with("info.psb") || name.ends_with("info.psb.m") {
                Some("psb/emote-archive-info")
            } else if matches!(extension, "psb" | "m") {
                Some("psb/emote-resources")
            } else {
                None
            };
            if let Some(tag) = tag {
                return Some(ArchiveRoute {
                    tag,
                    options: options.clone(),
                });
            }
        }
        let tag = match self.engine {
            Engine::Propeller if extension == "mpk" => "mpk/propeller",
            Engine::Rugp if extension == "rio" => "rio/rugp",
            Engine::Escude if extension == "bin" => "bin/escude",
            Engine::SystemNnn if extension == "gpk" => "gpk/systemnnn",
            Engine::SystemNnn if extension == "vpk" => "vpk/systemnnn",
            Engine::Exhibit if extension == "grp" => "grp/exhibit",
            Engine::Yuris if extension == "ypf" => "ypf/yuris",
            Engine::Krkr | Engine::KrkrzHxv4 if extension == "xp3" => "xp3/krkr",
            Engine::Will if matches!(extension, "arc" | "ar2") => "arc/willv2",
            Engine::Bgi if extension == "arc" => "arc/bgi",
            Engine::Siglus if extension == "pck" => "pck/siglus",
            Engine::Siglus if matches!(extension, "ovk" | "nwk") => "voice/siglus",
            Engine::Siglus if extension == "omv" => "omv/siglus",
            Engine::Siglus if name.rsplit('/').next() == Some("gameexe.dat") => "gameexe/siglus",
            Engine::AgesMk2 if matches!(extension, "fpd" | "dat") => "fpd",
            _ => return None,
        };
        let mut options = self.options.clone();
        if self.engine == Engine::AgesMk2 {
            let key = if name.split('/').any(|part| {
                part == "obb" || part.starts_with("main.") || part.starts_with("patch.")
            }) {
                "obb"
            } else if name.split('/').any(|part| {
                part == "resident" || part.starts_with("resident.") || part.starts_with("boot.")
            }) {
                "resident"
            } else if options.keys.len() == 1 {
                *options.keys.keys().next()?
            } else {
                return None;
            };
            let secret = options.keys.get(key)?.clone();
            options.keys.insert("scramble", secret);
        }
        Some(ArchiveRoute { tag, options })
    }
}
