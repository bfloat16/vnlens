//! Embedded file icons selected from metadata without reading file contents.

use std::borrow::Cow;

use gpui::{AssetSource, SharedString, Styled, Svg, px, rgb, svg};
use nvlens_core::ResourceKind;

use crate::browser::Item;

#[derive(Clone, Copy, Debug)]
struct Icon {
    path: &'static str,
    source: &'static str,
    color: u32,
}

macro_rules! icon {
    ($name:literal, $color:literal) => {
        Icon {
            path: concat!("icons/", $name, ".svg"),
            source: include_str!(concat!("../assets/icons/", $name, ".svg")),
            color: $color,
        }
    };
}

const FOLDER: Icon = icon!("folder", 0x58a6f6);
const ARCHIVE: Icon = icon!("archive", 0xe5b567);
const IMAGE: Icon = icon!("image", 0x7ecf9c);
const AUDIO: Icon = icon!("audio", 0xe995bd);
const VIDEO: Icon = icon!("video", 0xb6a0ec);
const SCRIPT: Icon = icon!("script", 0xf0bf7a);
const TEXT: Icon = icon!("text", 0xb7c4d5);
const CONFIG: Icon = icon!("config", 0x9eafc5);
const CODE: Icon = icon!("code", 0x70c9c5);
const APPLICATION: Icon = icon!("application", 0x79b6f2);
const LIBRARY: Icon = icon!("library", 0xa3a6d9);
const FONT: Icon = icon!("font", 0xdaadd5);
const DOCUMENT: Icon = icon!("document", 0xe8948e);
const DATA: Icon = icon!("data", 0xc2b08c);
const FILE: Icon = icon!("file", 0xa1a1aa);

const ICONS: &[Icon] = &[
    FOLDER,
    ARCHIVE,
    IMAGE,
    AUDIO,
    VIDEO,
    SCRIPT,
    TEXT,
    CONFIG,
    CODE,
    APPLICATION,
    LIBRARY,
    FONT,
    DOCUMENT,
    DATA,
    FILE,
];

#[derive(Debug)]
pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> anyhow::Result<Option<Cow<'static, [u8]>>> {
        Ok(ICONS
            .iter()
            .find(|icon| icon.path == path)
            .map(|icon| Cow::Borrowed(icon.source.as_bytes())))
    }

    fn list(&self, path: &str) -> anyhow::Result<Vec<SharedString>> {
        let directory = path.trim_end_matches('/');
        Ok(ICONS
            .iter()
            .filter(|icon| {
                directory.is_empty()
                    || icon
                        .path
                        .strip_prefix(directory)
                        .is_some_and(|suffix| suffix.starts_with('/') || suffix.is_empty())
            })
            .map(|icon| icon.path.into())
            .collect())
    }
}

pub fn file_icon(item: &Item, selected: bool) -> Svg {
    let icon = for_item(item);
    svg()
        .path(icon.path)
        .size(px(17.))
        .flex_shrink_0()
        .text_color(rgb(if selected { 0xffffff } else { icon.color }))
}

fn for_item(item: &Item) -> Icon {
    if item.target.is_directory() {
        return FOLDER;
    }
    if item.container {
        return ARCHIVE;
    }
    let name = item.name.to_ascii_lowercase();
    let extension = name.rsplit_once('.').map_or("", |(_, extension)| extension);
    // These are display categories, not a list of supported decoders.
    match extension {
        "png" | "jpg" | "jpeg" | "jfif" | "bmp" | "gif" | "webp" | "avif" | "heic" | "heif"
        | "tif" | "tiff" | "tga" | "dds" | "ico" | "cur" | "svg" | "psd" | "ycg" | "pna"
        | "pnb" | "wip" | "g00" | "g01" | "pdt" | "gyu" | "eri" | "hg2" | "hg3" => IMAGE,
        "ogg" | "oga" | "opus" | "wav" | "wave" | "mp3" | "flac" | "aac" | "m4a" | "wma"
        | "aif" | "aiff" | "mid" | "midi" | "fcd" | "nwa" | "hca" => AUDIO,
        "mp4" | "m4v" | "mkv" | "webm" | "avi" | "mov" | "wmv" | "mpg" | "mpeg" | "ogv" | "flv"
        | "vob" | "ymv" | "omv" => VIDEO,
        "ybn" | "ws2" | "scr" | "ks" | "scn" | "spt" | "bcs" | "rpy" | "rpyc" | "tjs" | "epk"
        | "nut" | "nuc" | "ss" | "gan" => SCRIPT,
        "txt" | "md" | "markdown" | "rst" | "log" | "csv" | "tsv" | "srt" | "ass" | "vtt" => TEXT,
        "ini" | "cfg" | "conf" | "config" | "json" | "jsonc" | "json5" | "yaml" | "yml"
        | "toml" | "xml" | "properties" | "env" => CONFIG,
        "rs" | "c" | "h" | "cpp" | "hpp" | "cc" | "cs" | "go" | "java" | "kt" | "swift" | "py"
        | "js" | "jsx" | "ts" | "tsx" | "lua" | "rb" | "php" | "html" | "htm" | "css" | "scss"
        | "sh" | "bat" | "cmd" | "ps1" => CODE,
        "exe" | "com" | "msi" | "app" | "apk" => APPLICATION,
        "dll" | "so" | "dylib" | "ocx" | "lib" | "a" => LIBRARY,
        "ttf" | "otf" | "ttc" | "woff" | "woff2" | "fon" | "fnt" => FONT,
        "pdf" | "rtf" | "doc" | "docx" | "odt" | "xls" | "xlsx" | "ods" | "ppt" | "pptx"
        | "epub" | "chm" => DOCUMENT,
        "zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz" | "zst" | "cab" | "iso" | "arc"
        | "ypf" | "fpd" | "xp3" | "pak" | "pac" | "pck" | "vfs" | "cpk" | "rpa" | "nsa" | "sar" => {
            ARCHIVE
        }
        _ if matches!(
            name.as_str(),
            "license" | "licence" | "readme" | "changelog"
        ) =>
        {
            TEXT
        }
        _ => match item.kind {
            ResourceKind::Archive => ARCHIVE,
            ResourceKind::Image => IMAGE,
            ResourceKind::Audio => AUDIO,
            ResourceKind::Script => SCRIPT,
            ResourceKind::Video => VIDEO,
            ResourceKind::Unknown => match extension {
                "bin" | "dat" | "data" | "db" | "sqlite" | "sqlite3" | "sav" => DATA,
                _ => FILE,
            },
        },
    }
}
