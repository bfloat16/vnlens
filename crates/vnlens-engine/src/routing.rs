//! Resource and archive routing within an already identified game. Names
//! classify listings; only an explicitly opened resource supplies header bytes.
//! Engine-specific rules live in each engine's `route` module; this module
//! selects registered names before inspecting extensionless resource headers.

use crate::Identification;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use vnlens_core::{
    ArchiveOptions, ArchiveRoute, ResourceKind, ResourceOrigin, ResourceRoute, Result,
};

pub(crate) struct Route<'a> {
    pub name: &'a str,
    pub leaf: &'a str,
    pub ext: &'a str,
    pub stored_ext: &'a str,
    pub origin: ResourceOrigin,
    pub hint: ResourceKind,
    pub header: &'a [u8],
    pub options: &'a ArchiveOptions,
    pub compose_pimg: bool,
}

impl Route<'_> {
    pub(crate) fn archive_with(&self, tag: &'static str) -> ArchiveRoute {
        ArchiveRoute {
            tag,
            options: self.options.clone(),
        }
    }
}

pub(crate) type ArchiveSetFn =
    fn(&str, &Path, &BTreeMap<String, &PathBuf>) -> Option<(PathBuf, Vec<String>)>;

#[derive(Debug)]
pub(crate) struct Router {
    /// Filesystem hosts permit identity resolution in entered virtual folders.
    pub filesystem_host: bool,
    /// Prefix covering this router's actual signature locations.
    pub header_size: usize,
    pub header: fn(&Route<'_>) -> Option<ResourceRoute>,
    pub entry: fn(&Route<'_>) -> Option<ResourceRoute>,
    pub archive: fn(&Route<'_>) -> Option<ArchiveRoute>,
    pub extension: fn(&Route<'_>) -> Option<ResourceRoute>,
    pub archive_set: ArchiveSetFn,
}

impl Router {
    pub const NONE: Self = Self {
        filesystem_host: false,
        header_size: 64,
        header: |_| None,
        entry: |_| None,
        archive: |_| None,
        extension: |_| None,
        archive_set: |_, _, _| None,
    };
}

impl Identification {
    /// Prefix length needed for extensionless resource signatures. Listings
    /// still pass an empty header and never request these bytes.
    #[must_use]
    pub fn resource_header_len(&self) -> usize {
        self.middleware
            .iter()
            .map(|m| m.header_size)
            .chain(crate::detect::detector(self.engine).map(|d| d.route.header_size))
            .max()
            .unwrap_or(64)
    }

    /// Selects one domain and format. An empty header performs metadata-only
    /// classification. Registered suffixes are authoritative, including when
    /// bytes disagree. Only extensionless names use logical header bytes;
    /// unknown suffixes stay unknown rather than probing unrelated decoders.
    #[must_use]
    pub fn resource_route(
        &self,
        name: &str,
        origin: ResourceOrigin,
        header: &[u8],
    ) -> ResourceRoute {
        let stored_ext = name
            .rsplit(['/', '\\'])
            .next()
            .and_then(|s| s.rsplit_once('.'))
            .map_or("", |(_, ext)| ext);
        let name = name.replace('\\', "/").to_ascii_lowercase();
        let leaf = name.rsplit('/').next().unwrap_or("");
        let ext = leaf.rsplit_once('.').map_or("", |(_, ext)| ext);
        let hint = match origin {
            ResourceOrigin::File => ResourceKind::Unknown,
            ResourceOrigin::Entry(kind) => kind,
        };
        let router = crate::detect::detector(self.engine).map(|d| &d.route);
        let route = Route {
            name: &name,
            leaf,
            ext,
            stored_ext,
            origin,
            hint,
            header: if ext.is_empty() { header } else { &[] },
            options: &self.options,
            compose_pimg: self.compose_pimg.load(std::sync::atomic::Ordering::Relaxed),
        };

        if let Some(archive) = router.and_then(|r| (r.archive)(&route)) {
            return ResourceRoute::Archive(Box::new(archive));
        }
        if let Some(matched) = router.and_then(|r| (r.extension)(&route)) {
            return matched;
        }
        for middleware in &self.middleware {
            if let Some(archive) = (middleware.archive)(&route) {
                return ResourceRoute::Archive(Box::new(archive));
            }
            if let Some(matched) = (middleware.extension)(&route) {
                return matched;
            }
        }
        if !ext.is_empty() {
            return standard_extension(ext, hint);
        }
        if let Some(matched) = router.and_then(|r| (r.header)(&route)) {
            return matched;
        }
        if let Some(matched) = self.middleware.iter().find_map(|m| (m.header)(&route)) {
            return matched;
        }
        if let Some(matched) = router.and_then(|r| (r.entry)(&route)) {
            return matched;
        }
        if let Some(matched) = standard_header(header) {
            return matched;
        }
        ResourceRoute::Other(hint)
    }

    /// Opens only the selected disk file's prefix. Call on access, not while
    /// listing a directory. I/O failures are retained instead of changing routes.
    pub fn route_path(&self, path: &Path) -> Result<ResourceRoute> {
        let name = path.to_string_lossy();
        if path.extension().is_some_and(|ext| !ext.is_empty()) {
            return Ok(self.resource_route(&name, ResourceOrigin::File, &[]));
        }
        let source = self.files.source(path)?;
        let header = source.read_at(
            0,
            source.len().min(self.resource_header_len() as u64) as usize,
        )?;
        Ok(self.resource_route(&name, ResourceOrigin::File, &header))
    }
}

#[cfg(test)]
#[path = "../tests/routing.rs"]
mod tests;

fn media() -> ResourceRoute {
    ResourceRoute::Media {
        audio: "audio/standard",
        video: "ffmpeg",
    }
}

fn standard_header(bytes: &[u8]) -> Option<ResourceRoute> {
    use ResourceRoute::{Audio, Image, Script, Video};
    if bytes.starts_with(b"DDS ") {
        Some(Image("dds"))
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"XWMA") {
        Some(Audio("xwma"))
    } else if bytes.starts_with(b"\x1bLua") {
        Some(Script("lua"))
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.starts_with(b"\xff\xd8\xff")
        || bytes.starts_with(b"GIF87a")
        || bytes.starts_with(b"GIF89a")
        || bytes.starts_with(b"BM")
        || bytes.starts_with(b"\0\0\x01\0")
        || (bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"))
    {
        Some(Image("image/standard"))
    } else if bytes.starts_with(b"OggS") {
        Some(media())
    } else if (bytes.starts_with(b"RIFF") || bytes.starts_with(b"RF64"))
        && bytes.get(8..12) == Some(b"WAVE")
    {
        Some(Audio("audio/standard"))
    } else if bytes.starts_with(b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c")
        || bytes.starts_with(b"\x1a\x45\xdf\xa3")
        || bytes.starts_with(b"\x00\x00\x01\xba")
        || bytes.starts_with(b"\x00\x00\x01\xb3")
        || bytes.starts_with(b"YUV4MPEG2 ")
        || (bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"AVI "))
        || bytes.get(4..8) == Some(b"ftyp")
    {
        Some(Video("ffmpeg"))
    } else {
        None
    }
}

fn standard_extension(ext: &str, hint: ResourceKind) -> ResourceRoute {
    use ResourceRoute::{Audio, Image, Other, Script, Video};
    match ext {
        "png" | "jpg" | "jpeg" | "bmp" | "gif" | "webp" | "ico" => Image("image/standard"),
        "ogg" | "opus" | "ogv" | "ogm" => media(),
        "wav" => Audio("audio/standard"),
        "dds" => Image("dds"),
        "xwma" => Audio("xwma"),
        "lua" | "luac" => Script("lua"),
        "mpg" | "mpeg" | "mpe" | "m1v" | "m2v" | "mpv" | "mp4" | "wmv" | "asf" | "avi" | "mov"
        | "mkv" | "webm" | "y4m" => Video("ffmpeg"),
        "ttf" | "otf" | "ttc" | "woff" | "woff2" | "fon" | "fnt" => Other(ResourceKind::Font),
        "txt" | "ini" | "json" | "cfg" => Other(ResourceKind::Data),
        _ => Other(hint),
    }
}
