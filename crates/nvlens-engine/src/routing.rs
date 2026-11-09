//! Resource routing within an already identified game. Names classify listings;
//! only an explicitly opened resource supplies header bytes. These selectors use
//! the markers documented by the corresponding domain readers, never invoke a
//! decoder, and never inspect another engine's proprietary formats.

use crate::{Engine, Identification};
use nvlens_core::{ResourceKind, ResourceOrigin, ResourceRoute, Result};
use nvlens_io::BinaryReader;
use std::path::Path;

impl Identification {
    /// Selects one domain and format. An empty header performs metadata-only
    /// classification. A supplied prefix is from the logical resource after
    /// archive transformations, so an extracted Ogg/WAV retains its real route.
    #[must_use]
    pub fn resource_route(
        &self,
        name: &str,
        origin: ResourceOrigin,
        header: &[u8],
    ) -> ResourceRoute {
        use ResourceRoute::{Audio, Image, Other, Script, Video};
        let name = name.replace('\\', "/").to_ascii_lowercase();
        let leaf = name.rsplit('/').next().unwrap_or("");
        let ext = leaf.rsplit_once('.').map_or("", |(_, ext)| ext);
        let hint = match origin {
            ResourceOrigin::File => ResourceKind::Unknown,
            ResourceOrigin::Entry(kind) => kind,
        };

        let headerless = match (self.engine, ext) {
            (Engine::Propeller, "mgr") => Some(Image("image/propeller-mgr")),
            (Engine::Propeller, "msc") => Some(Script("msc/propeller")),
            (Engine::Siglus, "g00") => Some(Image("g00/siglus")),
            (Engine::Siglus, "nwa") => Some(Audio("nwa/siglus")),
            (Engine::Will, "ws2") => Some(Script("ws2/will")),
            (Engine::SystemNnn, "spt") => Some(Script("spt/systemnnn")),
            (Engine::SystemNnn, "fxf") => Some(Script("fxf/systemnnn")),
            (Engine::Escude, "sfx") => Some(Script("sfx/escude")),
            _ => None,
        };
        if let Some(route) = headerless {
            return route;
        }

        // Proprietary markers take precedence over overlapping standard magic
        // (notably DWQ's "BMP "). Headerless formats require an engine name or
        // index type; they are never candidates in another engine's route.
        let native = match self.engine {
            Engine::Bgi => {
                if header.starts_with(b"CompressedBG___\0") || bgi_bitmap(header) {
                    Some(Image("image/bgi"))
                } else if matches!(header.get(4..8), Some(b"bw  " | b"hw  ")) {
                    Some(Audio("bw/bgi"))
                } else if header.starts_with(b"BurikoCompiledScriptVer1.00\0")
                    || (header.starts_with(b"\x10\0\0\0") && header.get(8..16) == Some(&[0; 8]))
                {
                    Some(Script("script/bgi"))
                } else {
                    None
                }
            }
            Engine::Exhibit => {
                if header.starts_with(b"GYU\x1a") {
                    Some(Image("gyu/exhibit"))
                } else if header.get(28..32) == Some(b"DLT\0") {
                    Some(Image("dlt/exhibit"))
                } else if header.starts_with(b"\0DLR") {
                    Some(Script("rld/exhibit"))
                } else {
                    None
                }
            }
            Engine::Yuris => match header.get(..4) {
                Some(b"YCG\0") => Some(Image("ycg/yuris")),
                Some(b"YSMV") => Some(Video("ymv/yuris")),
                Some(
                    b"YSTB" | b"YSCM" | b"YSCF" | b"YSER" | b"YSLB" | b"YSTD" | b"YSTL" | b"YSVR",
                ) => Some(Script("ybn/yuris")),
                _ => None,
            },
            Engine::SystemNnn => {
                if header.starts_with(b"PNG ")
                    || header.starts_with(b"JPEG ")
                    || header.starts_with(b"BMP ")
                    || (header.starts_with(b"IF PACKTYPE==") && header.get(44..48) == Some(b"BMP "))
                {
                    Some(Image("dwq/systemnnn"))
                } else if (header.starts_with(b"IF PACKTYPE==")
                    && matches!(header.get(44..48), Some(b"WAV " | b"OGG ")))
                    || header.starts_with(b"                OGG ")
                {
                    Some(Audio("vaw/systemnnn"))
                } else {
                    None
                }
            }
            Engine::Will if header.starts_with(b"PNAP") || header.starts_with(b"PNAS") => {
                Some(Image("pna/will"))
            }
            Engine::Siglus
                if header.starts_with(b"\x84\0\0\0")
                    || header.starts_with(b"\x10\x27\0\0\x10\x27\0\0") =>
            {
                Some(Script("script/siglus"))
            }
            Engine::Krkr | Engine::KrkrzHxv4 => {
                if matches!(header.get(..4), Some(b"TLG0" | b"TLG5" | b"TLG6")) {
                    Some(Image("tlg/krkr"))
                } else if header.starts_with(b"TJS2")
                    || header.starts_with(b"\xfe\xfe")
                    || header.starts_with(b"PSB\0")
                    || header.starts_with(b"mdf\0")
                {
                    // Configured middleware containers keep their archive route.
                    self.archive_route(&name)
                        .map(|route| ResourceRoute::Archive(Box::new(route)))
                        .or(Some(Script("script/krkr")))
                } else {
                    None
                }
            }
            Engine::Escude
                if matches!(
                    header.get(..4),
                    Some(b"@cod" | b"@mes" | b"mdb\0" | b"LSF\0" | b"MOT\0" | b"mot\0")
                ) =>
            {
                Some(Script("script/escude"))
            }
            Engine::Rugp if header.starts_with(b"NVLRSI\0\x01") => Some(Image("frame/rugp")),
            _ => None,
        };
        if let Some(route) = native {
            return route;
        }
        if let Some(route) = standard_header(header) {
            return route;
        }
        if self.engine == Engine::Rugp && matches!(hint, ResourceKind::Script | ResourceKind::Data)
        {
            return Script("object/rugp");
        }

        // ESC-ARC and its .bin script entries share an extension. The storage
        // context distinguishes name-only listings; actual container magic wins.
        let escude_script = self.engine == Engine::Escude
            && ext == "bin"
            && ((matches!(origin, ResourceOrigin::Entry(_)) && !header.is_empty())
                || header.starts_with(b"acp\0"))
            && !header.starts_with(b"ESC-ARC");
        if !escude_script && let Some(route) = self.archive_route(&name) {
            return ResourceRoute::Archive(Box::new(route));
        }
        let named = match self.engine {
            Engine::Propeller => match ext {
                "ogv" => Some(media()),
                _ => None,
            },
            Engine::Bgi => match ext {
                "bgi" | "bg" | "_bg" => Some(Image("image/bgi")),
                "bw" | "hw" | "_bw" => Some(Audio("bw/bgi")),
                "_bp" | "bss" => Some(Script("script/bgi")),
                _ => None,
            },
            Engine::Exhibit => match ext {
                "gyu" | "lvg" => Some(Image("gyu/exhibit")),
                "dlt" => Some(Image("dlt/exhibit")),
                "rld" | "rnf" | "ini" => Some(Script("rld/exhibit")),
                _ => None,
            },
            Engine::Yuris => match ext {
                "ycg" => Some(Image("ycg/yuris")),
                "ybn" => Some(Script("ybn/yuris")),
                "ymv" => Some(Video("ymv/yuris")),
                _ => None,
            },
            Engine::Siglus => match ext {
                "ss" | "gan" => Some(Script("script/siglus")),
                _ => None,
            },
            Engine::Will => match ext {
                "pna" | "mos" => Some(Image("pna/will")),
                "json" => Some(Script("json/will")),
                _ => None,
            },
            Engine::SystemNnn => match ext {
                "dwq" => Some(Image("dwq/systemnnn")),
                "vaw" | "wgq" => Some(Audio("vaw/systemnnn")),
                "xtx" | "mml" => Some(Script("text/systemnnn")),
                _ => None,
            },
            Engine::Escude => match ext {
                "c" | "h" | "inc" | "txt" | "cfg" | "001" => Some(Script("text/escude")),
                "bin" | "lsf" | "mot" => Some(Script("script/escude")),
                _ => None,
            },
            Engine::Krkr | Engine::KrkrzHxv4 => match ext {
                "tlg" | "tlg5" | "tlg6" => Some(Image("tlg/krkr")),
                "tjs" | "ks" | "scn" | "asd" | "psb" | "m" => Some(Script("script/krkr")),
                _ => None,
            },
            Engine::Rugp => match ext {
                "cr6ti" | "cr6tix" | "crmti" | "cs5i" | "csbm" | "cicon" => {
                    Some(Image("image/rugp"))
                }
                "crsi_frame" => Some(Image("frame/rugp")),
                "oor" | "coptimizedobs" | "coptimizedobsforr" => Some(Audio("oor/rugp")),
                "crsa" | "cprocessocean" | "cstdb" | "crsi" | "cs5rfont" => {
                    Some(Script("object/rugp"))
                }
                _ => None,
            },
            Engine::AgesMk2 => None,
        };
        if let Some(route) = named {
            return route;
        }
        // rUGP's serialized class decides which domain consumes an object. The
        // archive already exposes that class as an index kind when available.
        if self.engine == Engine::Rugp
            && header.len() >= 4
            && matches!(
                BinaryReader::u32_le(header),
                0x29f6_cba4 | 0x1edb_927c | 0x596e_32cd
            )
        {
            return match hint {
                ResourceKind::Image => Image("image/rugp"),
                _ => Script("object/rugp"),
            };
        }
        match ext {
            "png" | "jpg" | "jpeg" | "bmp" | "gif" | "webp" | "ico" => Image("image/standard"),
            "ogg" | "opus" | "ogv" | "ogm" => media(),
            "wav" => Audio("audio/standard"),
            "lua" | "luac" => Script("lua"),
            "mpg" | "mpeg" | "mpe" | "m1v" | "m2v" | "mpv" | "mp4" | "wmv" | "asf" | "avi"
            | "mov" | "mkv" | "webm" | "y4m" => Video("ffmpeg"),
            "ttf" | "otf" | "ttc" | "woff" | "woff2" | "fon" | "fnt" => Other(ResourceKind::Font),
            "txt" | "ini" | "json" | "cfg" => Other(ResourceKind::Data),
            _ => Other(hint),
        }
    }

    /// Opens only the selected disk file's prefix. Call on access, not while
    /// listing a directory. I/O failures are retained instead of changing routes.
    pub fn route_path(&self, path: &Path) -> Result<ResourceRoute> {
        let view = nvlens_io::ArcView::open(path)?;
        let header = view.slice(0, view.len().min(64))?;
        Ok(self.resource_route(&path.to_string_lossy(), ResourceOrigin::File, header))
    }
}

fn media() -> ResourceRoute {
    ResourceRoute::Media {
        audio: "audio/standard",
        video: "ffmpeg",
    }
}

fn standard_header(bytes: &[u8]) -> Option<ResourceRoute> {
    use ResourceRoute::{Audio, Image, Script, Video};
    if bytes.starts_with(b"\x1bLua") {
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

// Raw BGI bitmaps have no magic. These fixed header fields distinguish their
// engine-local route; the image reader validates dimensions against the payload.
fn bgi_bitmap(bytes: &[u8]) -> bool {
    bytes.len() >= 16
        && BinaryReader::u16_le(bytes) != 0
        && BinaryReader::u16_le(&bytes[2..]) != 0
        && matches!(BinaryReader::u16_le(&bytes[4..]), 8 | 24 | 32)
        && BinaryReader::u16_le(&bytes[6..]) <= 1
        && bytes[8..16] == [0; 8]
}

#[cfg(test)]
#[path = "../tests/routing.rs"]
mod tests;
