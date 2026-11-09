//! Immutable identification results. Secret material is redacted in Debug.

use nvlens_core::{ArchiveOptions, ArchiveRoute, ResourceKind};
use std::path::{Path, PathBuf};

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
        if self.engine == Engine::Propeller {
            return ext.eq_ignore_ascii_case("msc").then_some("msc/propeller");
        }
        if self.engine == Engine::SystemNnn {
            return match ext.to_ascii_lowercase().as_str() {
                "spt" => Some("spt/systemnnn"),
                "fxf" => Some("fxf/systemnnn"),
                "xtx" | "mml" => Some("text/systemnnn"),
                _ => None,
            };
        }
        if self.engine == Engine::Escude {
            return match ext.to_ascii_lowercase().as_str() {
                "c" | "h" | "inc" | "txt" | "cfg" | "001" => Some("text/escude"),
                "bin" | "lsf" | "mot" => Some("script/escude"),
                "sfx" => Some("sfx/escude"),
                _ => None,
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
            Engine::Rugp => Some("object/rugp"),
            Engine::Escude => Some("script/escude"),
            Engine::Exhibit => Some("rld/exhibit"),
            Engine::Yuris => Some("ybn/yuris"),
            Engine::Bgi => Some("script/bgi"),
            Engine::Siglus => Some("script/siglus"),
            Engine::Krkr | Engine::KrkrzHxv4 => Some("script/krkr"),
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

    #[must_use]
    pub fn route_path(&self, path: &Path) -> Option<ArchiveRoute> {
        if self.engine == Engine::Propeller
            && self.resource_kind_for_path(path) == ResourceKind::Video
        {
            return None;
        }
        self.route(&path.to_string_lossy())
    }

    /// Classifies the identified host's disk files. Stuff uses `.mpk` for both
    /// MPK archives and MPEG program streams (sub_402380's movie resources).
    /// Inspect only the start code to disambiguate that extension. Unreadable
    /// files retain their name-based route so opening reports the original error.
    #[must_use]
    pub fn resource_kind_for_path(&self, path: &Path) -> ResourceKind {
        if self.engine == Engine::Propeller
            && path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("mpk"))
            && matches!(
                nvlens_io::ArcView::open(path).and_then(|view| view.read_u32_le(0)),
                Ok(0xba01_0000)
            )
        {
            return ResourceKind::Video;
        }
        if self.engine == Engine::Propeller {
            match path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase()
                .as_str()
            {
                "ogv" => return ResourceKind::Audio,
                "mgr" => return ResourceKind::Image,
                "msc" => return ResourceKind::Script,
                _ => {}
            }
        }
        ResourceKind::guess_from_name(&path.to_string_lossy())
    }
}
