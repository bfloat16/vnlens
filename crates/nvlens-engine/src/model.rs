//! Immutable identification results. Secret material is redacted in Debug.

use nvlens_core::{ArchiveOptions, ArchiveRoute};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Yuris,
    Will,
    AgesMk2,
    Emote,
}

#[derive(Clone, Debug)]
pub struct Identification {
    pub root: PathBuf,
    pub engine: Engine,
    pub evidence: String,
    pub(crate) options: ArchiveOptions,
}

impl Identification {
    #[must_use]
    pub fn script_format(&self) -> Option<&'static str> {
        (self.engine == Engine::Yuris).then_some("ybn/yuris")
    }

    /// Selects a reader by the identified engine's naming conventions. This
    /// examines names only, never archive contents or unrelated format handlers.
    #[must_use]
    pub fn route(&self, name: &str) -> Option<ArchiveRoute> {
        let name = name.replace('\\', "/").to_ascii_lowercase();
        let extension = name.rsplit('.').next().unwrap_or("");
        let tag = match self.engine {
            Engine::Yuris if extension == "ypf" => "ypf/yuris",
            Engine::Will if matches!(extension, "arc" | "ar2") => "arc/willv2",
            Engine::AgesMk2 if matches!(extension, "fpd" | "dat") => "fpd",
            Engine::Emote
                if name.ends_with("_info.psb")
                    || name.ends_with("_info.psb.m")
                    || name.ends_with("info.psb")
                    || name.ends_with("info.psb.m") =>
            {
                "psb/emote-archive-info"
            }
            Engine::Emote if matches!(extension, "psb" | "m") => "psb/emote-resources",
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

    #[must_use]
    pub fn route_path(&self, path: &Path) -> Option<ArchiveRoute> {
        self.route(&path.to_string_lossy())
    }
}
