//! KiriKiri Z Hxv4 identity and static bootstrap parameter recovery.
//! BasicCryptoFilter's salt operand and PE resources establish the startup
//! chain. PARAMS/WARNING/UNIQUE are length-prefixed bootstrap records; the
//! archive seed comes from the --xopt data or the verified KDF call operands.
//! No archives are probed and no executable or script code is run.
mod native;
mod startup;
use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::{ArchiveOptions, Error, Result, Secret};
use nvlens_crypto::{cipher::hxv4, compress::zlib};
use nvlens_io::{ArcView, BinaryReader, BinaryWriter, pe::PeImage};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(
        (has(image, b"Hxv4")? && has(image, b"PARAMS")? && has(image, b"FilterManager")?)
            || (image.resource("#10", "STARTUP.TJS")?.is_some()
                && image.resource("#10", "BOOTSTRAP")?.is_some()
                && image.resource("TEXT", "#127")?.is_some()),
    )
}
fn layout(_: &Path) -> bool {
    false
}
fn missing(reason: &str) -> Error {
    Error::UnknownScheme(Some(format!("krkrz_hxv4: {reason}")))
}
fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn resolve(_: &Path, executables: &[PathBuf], cancel: &AtomicBool) -> Result<ArchiveOptions> {
    let mut resolved = None;
    for path in executables {
        check(cancel)?;
        let view = ArcView::open(path)?;
        let Some(mut image) = PeImage::parse(view.slice(0, view.len())?)? else {
            continue;
        };
        nvlens_unpack::steamstub::unpack(&mut image, cancel)?;
        let Some(encrypted) = image.resource("#10", "STARTUP.TJS")? else {
            continue;
        };
        let options = parameters(&image, encrypted, cancel)?;
        if resolved
            .as_ref()
            .is_some_and(|previous| previous != &options)
        {
            return Err(missing("Conflicting executable parameters"));
        }
        resolved = Some(options);
    }
    resolved.ok_or_else(|| missing("Startup resources were not found"))
}
fn parameters(
    image: &PeImage<'_>,
    encrypted: &[u8],
    cancel: &AtomicBool,
) -> Result<ArchiveOptions> {
    let salts = native::salts(image, cancel)?;
    let [salt] = salts.as_slice() else {
        return Err(missing(
            "Resource salt code feature is missing or ambiguous",
        ));
    };
    let text = image
        .resource("TEXT", "#127")?
        .ok_or_else(|| missing("Startup storage resource is absent"))?;
    let path = wide_string(text)?;
    let path = path
        .trim_end_matches('\0')
        .strip_prefix("bres://./")
        .and_then(|p| p.strip_suffix('/'))
        .ok_or_else(|| missing("Invalid startup storage URI"))?;
    let startup = hxv4::resource(encrypted, &wide_bytes(path), salt);
    let startup = startup::Startup::parse(&startup)?;
    let filter = startup.bootstrap_path()?;
    let input = startup.bootstrap_argument()?;
    let blob = image
        .resource("#10", "BOOTSTRAP")?
        .ok_or_else(|| missing("BOOTSTRAP resource is absent"))?;
    let packed = hxv4::resource(blob, &wide_bytes(filter), salt);
    let mut r = BinaryReader::new(&packed);
    let stored = r.read_u32_le()? as usize;
    let size = r.read_u32_le()? as usize;
    if stored != r.remaining() {
        return Err(missing("BOOTSTRAP stored length mismatch"));
    }
    let bytes = zlib::inflate_with_limit(r.read_bytes(stored)?, size)
        .map_err(|e| missing(&format!("BOOTSTRAP zlib: {e}")))?;
    if bytes.len() != size {
        return Err(missing("BOOTSTRAP decoded length mismatch"));
    }
    let boot = PeImage::parse(&bytes)?.ok_or_else(|| missing("BOOTSTRAP is not a PE image"))?;
    if !has(&boot, b"Hxv4")? {
        return Err(missing("BOOTSTRAP does not identify Hxv4"));
    }
    let params = item(&boot, b"PARAMS\0", |p| {
        p.len() >= 22
            && [(0, 8), (8, 6), (14, 3)].iter().all(|&(start, n)| {
                let mut values = p[start..start + n].to_vec();
                values.sort();
                values.iter().copied().eq(0..n as u8)
            })
    })?;
    let warning = item(&boot, b"WARNING\0", |p| {
        p.is_ascii() && p.starts_with(b"Warning!")
    })?;
    let unique = item(&boot, b"UNIQUE\0", |p| {
        wide_string(p).is_ok_and(|s| s.starts_with('{') && s.ends_with('}'))
    })?;
    let warning = std::str::from_utf8(warning).map_err(|_| missing("Invalid WARNING encoding"))?;
    let mut password = wide_bytes(&input);
    password.extend(wide_bytes(warning));
    let seed = archive_seed(&boot, cancel)?;
    check(cancel)?;
    let keys = hxv4::derive(params, &password, unique, &seed).map_err(|e| missing(&e))?;
    check(cancel)?;
    let mut options = ArchiveOptions::default();
    options.numbers.insert("hxv4", 1);
    for (name, bytes) in [
        ("hxv4_params", params),
        ("hxv4_index", keys.index.as_slice()),
        ("hxv4_nonce0", &keys.nonce0),
        ("hxv4_nonce1", &keys.nonce1),
        ("hxv4_table", &keys.table),
    ] {
        options.keys.insert(name, Secret::new(bytes));
    }
    Ok(options)
}
fn item<'a>(pe: &'a PeImage<'_>, tag: &[u8], valid: impl Fn(&[u8]) -> bool) -> Result<&'a [u8]> {
    let mut found = Vec::new();
    for section in &pe.sections {
        let data = pe.section_data(section)?;
        for (i, part) in data.windows(tag.len()).enumerate() {
            if part != tag {
                continue;
            }
            let mut r = BinaryReader::new(&data[i + tag.len()..]);
            if let Ok(size) = r.read_u16_le()
                && let Ok(value) = r.read_bytes(usize::from(size))
                && valid(value)
            {
                found.push(value);
            }
        }
    }
    found.sort();
    found.dedup();
    match found.as_slice() {
        [value] => Ok(value),
        _ => Err(missing(
            "Bootstrap parameter record is missing or ambiguous",
        )),
    }
}
fn archive_seed(pe: &PeImage<'_>, cancel: &AtomicBool) -> Result<[u8; 8]> {
    let mut found = native::seeds(pe, cancel)?;
    let marker = wide_bytes("--xopt--no\0\0");
    for section in &pe.sections {
        let data = pe.section_data(section)?;
        for (i, p) in data.windows(marker.len()).enumerate() {
            if p == marker
                && let Some(bytes) = data.get(i + marker.len()..i + marker.len() + 8)
            {
                let mut seed = [0; 8];
                seed.copy_from_slice(bytes);
                found.push(seed);
            }
        }
    }
    found.sort();
    found.dedup();
    match found.as_slice() {
        [seed] => Ok(*seed),
        _ => Err(missing("Archive unique seed is missing or ambiguous")),
    }
}
fn wide_string(bytes: &[u8]) -> Result<String> {
    let mut r = BinaryReader::new(bytes);
    let mut units = Vec::new();
    while r.remaining() != 0 {
        units.push(r.read_u16_le()?);
    }
    String::from_utf16(&units).map_err(|_| missing("Invalid bootstrap UTF-16"))
}
fn wide_bytes(s: &str) -> Vec<u8> {
    let mut out = vec![0; s.encode_utf16().count() * 2];
    for (word, bytes) in s.encode_utf16().zip(out.as_chunks_mut::<2>().0.iter_mut()) {
        BinaryWriter::u16_le(word, bytes)
    }
    out
}
nvlens_core::inventory::submit! { Detector {pe,layout,engine:Engine::KrkrzHxv4,resolve} }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Requires NVLENS_HXV4_EXE; resolves only the original executable without a sidecar or writing a PE"]
    fn resolves_local_protected_executable() -> Result<()> {
        let path = PathBuf::from(std::env::var_os("NVLENS_HXV4_EXE").ok_or(Error::InvalidFormat)?);
        let root = path.parent().ok_or(Error::InvalidFormat)?;
        let options = resolve(root, std::slice::from_ref(&path), &AtomicBool::new(false))?;
        assert_eq!(options.numbers.get("hxv4"), Some(&1));
        assert_eq!(options.keys.len(), 5);
        Ok(())
    }
}
