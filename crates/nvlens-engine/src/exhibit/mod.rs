//! ExHIBIT / RetouchSystem. `liteInit` reads RT_BITMAP 152, column 31,
//! top 32 rows, then XORs the bit word with `calcIniValue`'s INI checksum.
//! `INIT_ENTRY` passes setting/SYSVER to select whether TITLE is included.
//! UxAdvSystem::createMovieFilename (sub_100C1D80) defaults to .mpg and
//! accepts an explicit extension. playVideo passes the disk path through to
//! IGraphBuilder::RenderFile (sub_48A6F0), without an engine-specific wrapper.

use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::{ArchiveOptions, Error, Result, Secret};
use nvlens_io::{ArcView, BinaryReader, BinaryWriter, pe::PeImage};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"ExHIBIT.ini")?
        && (has(image, b"RetouchSendExHIBIT")? || has(image, b"RetouchSystem@@")?))
}
fn layout(root: &Path) -> bool {
    root.join("ExHIBIT.ini").is_file()
        && root.join("resident.dll").is_file()
        && root.join("rld").is_dir()
        && root.join("res").is_dir()
}
fn resolve(root: &Path, executables: &[PathBuf], cancel: &AtomicBool) -> Result<ArchiveOptions> {
    let ini = std::fs::read(root.join("ExHIBIT.ini"))?;
    let checksum = ini_checksum(&ini)?;
    let mut seed = None;
    for path in executables {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = ArcView::open(path)?;
        let Some(image) = PeImage::parse(view.slice(0, view.len())?)? else {
            continue;
        };
        let Some(bitmap) = image.resource("#2", "#152")? else {
            continue;
        };
        let bits = bitmap_word(bitmap)?;
        let candidate = if bits == 0 { 0 } else { bits ^ checksum };
        if seed.is_some_and(|old| old != candidate) {
            return Err(Error::UnknownScheme(Some(
                "Conflicting ExHIBIT bitmap parameters".into(),
            )));
        }
        seed = Some(candidate);
    }
    let seed =
        seed.ok_or_else(|| Error::UnknownScheme(Some("ExHIBIT key bitmap is missing".into())))?;
    let mut bytes = vec![0; 4];
    BinaryWriter::u32_le(seed, &mut bytes);
    let mut options = ArchiveOptions::default();
    options.keys.insert("exhibit_rld", Secret::new(bytes));
    // RetouchSystem::liteInit's shared system-script parameter, independent
    // of the game bitmap. loadRld selects this for its system-resource flag.
    let mut system = vec![0; 4];
    BinaryWriter::u32_le(0xae85_a916, &mut system);
    options
        .keys
        .insert("exhibit_rld_system", Secret::new(system));
    Ok(options)
}
nvlens_core::inventory::submit! { Detector {pe, layout, engine: Engine::Exhibit, resolve} }

fn ini_checksum(bytes: &[u8]) -> Result<u32> {
    let mut setting = false;
    let mut fields = BTreeMap::new();
    for line in bytes.split(|&b| b == b'\n') {
        let line = line.trim_ascii();
        if line.starts_with(b"[") {
            setting = line.eq_ignore_ascii_case(b"[setting]");
        } else if setting
            && !line.starts_with(b";")
            && let Some(eq) = line.iter().position(|&b| b == b'=')
        {
            let name = line[..eq].trim_ascii().to_ascii_uppercase();
            let value = line[eq + 1..].trim_ascii();
            fields.insert(name, value);
        }
    }
    let value = |name: &str| fields.get(name.as_bytes()).copied().unwrap_or_default();
    let number = |name: &str| -> Result<u32> {
        let bytes = value(name);
        if bytes.is_empty() {
            return Ok(0);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| Error::UnknownScheme(Some("Invalid ExHIBIT numeric setting".into())))?;
        let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
        {
            u32::from_str_radix(hex, 16)
        } else {
            text.parse()
        };
        parsed.map_err(|_| Error::UnknownScheme(Some("Invalid ExHIBIT numeric setting".into())))
    };
    let mut names = vec!["CLASS"];
    if number("SYSVER")? == 0 {
        names.push("TITLE");
    }
    names.extend([
        "W_VIEW",
        "H_VIEW",
        "N_REG",
        "N_STRREG",
        "N_SYSREG",
        "N_LOCREG",
        "N_USAVE",
        "N_ASAVE",
        "N_QSAVE",
        "N_CG",
        "N_MESSAGE",
        "N_SCENE",
        "N_SOUND",
    ]);
    if number("FLAGS")? & 4 != 0 {
        names.extend(["FLAGS", "GUID", "SVDATA"]);
    }
    let mut sums = [0u8; 4];
    for (i, &byte) in names.iter().flat_map(|name| value(name)).enumerate() {
        sums[i % 4] = sums[i % 4].wrapping_add(byte);
    }
    Ok(BinaryReader::u32_le(&sums))
}

fn bitmap_word(data: &[u8]) -> Result<u32> {
    let mut r = BinaryReader::new(data);
    let header = r.read_u32_le()? as usize;
    if header < 40 {
        return Err(Error::Unsupported("ExHIBIT key DIB header".into()));
    }
    let width = r.read_u32_le()? as i32;
    let height = r.read_u32_le()? as i32;
    let planes = r.read_u16_le()?;
    let depth = r.read_u16_le()?;
    let compression = r.read_u32_le()?;
    if width < 32
        || height.unsigned_abs() < 32
        || planes != 1
        || !matches!(depth, 24 | 32)
        || compression != 0
    {
        return Err(Error::Unsupported("ExHIBIT key bitmap layout".into()));
    }
    let stride = (u64::from(width as u32) * u64::from(depth / 8) + 3) & !3;
    let mut bits = 0u32;
    for y in (0..32u32).rev() {
        let row = if height > 0 { height as u32 - 1 - y } else { y };
        let offset = header as u64 + u64::from(row) * stride + 31 * u64::from(depth / 8);
        let offset = usize::try_from(offset).map_err(|_| {
            Error::Unsupported("ExHIBIT key bitmap offset exceeds address space".into())
        })?;
        let mut pixel = BinaryReader::new_at(data, offset)?;
        bits = (bits << 1) | u32::from(pixel.read_u8()? & 1);
    }
    Ok(bits)
}

#[cfg(test)]
#[path = "../../tests/exhibit/mod.rs"]
mod tests;
