//! Immutable identification results. Secret material is redacted in Debug.

use nvlens_core::{ArchiveOptions, ArchiveRoute};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Exhibit,
    Yuris,
    Will,
    AgesMk2,
    Bgi,
    Siglus,
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
    /// Headerless scripts require a format route selected from their name.
    /// Lua is middleware and is only enabled within an identified game.
    #[must_use]
    pub fn script_format_for(&self, name: &str) -> Option<&'static str> {
        let ext = name.rsplit('.').next().unwrap_or("");
        if ext.eq_ignore_ascii_case("lua") || ext.eq_ignore_ascii_case("luac") {
            return Some("lua");
        }
        if self.engine == Engine::Will {
            return if ext.eq_ignore_ascii_case("ws2") {
                Some("ws2/will")
            } else if ext.eq_ignore_ascii_case("json") {
                Some("json/will")
            } else {
                None
            };
        }
        self.script_format()
    }
    /// Parameters shared with resource decoders; Debug redacts all keys.
    #[must_use]
    pub fn resource_options(&self) -> &ArchiveOptions {
        &self.options
    }

    #[must_use]
    pub fn script_format(&self) -> Option<&'static str> {
        match self.engine {
            Engine::Exhibit => Some("rld/exhibit"),
            Engine::Yuris => Some("ybn/yuris"),
            Engine::Bgi => Some("script/bgi"),
            Engine::Siglus => Some("script/siglus"),
            Engine::KrkrzHxv4 => Some("script/krkr"),
            _ => None,
        }
    }

    /// Selects a reader by the identified engine's naming conventions. This
    /// examines names only, never archive contents or unrelated format handlers.
    #[must_use]
    pub fn route(&self, name: &str) -> Option<ArchiveRoute> {
        let name = name.replace('\\', "/").to_ascii_lowercase();
        let extension = name.rsplit('.').next().unwrap_or("");
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
            Engine::Exhibit if extension == "grp" => "grp/exhibit",
            Engine::Yuris if extension == "ypf" => "ypf/yuris",
            Engine::KrkrzHxv4 if extension == "xp3" => "xp3/krkr",
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

    #[must_use]
    pub fn route_path(&self, path: &Path) -> Option<ArchiveRoute> {
        self.route(&path.to_string_lossy())
    }
}
