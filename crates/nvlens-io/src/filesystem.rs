//! Portable relative-path validation and contained, atomic file output.
#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Checks archive paths against traversal, alternate streams and device names.
#[must_use]
pub fn is_safe_relative_path(name: &str) -> bool {
    !name.is_empty()
        && name.split(['/', '\\']).all(|part| {
            if part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with(['.', ' '])
                || part
                    .chars()
                    .any(|c| c.is_control() || matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*'))
            {
                return false;
            }
            let stem = part.split('.').next().unwrap_or("");
            !["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
                .iter()
                .any(|device| stem.eq_ignore_ascii_case(device))
                && !((stem.get(..3).is_some_and(|prefix| {
                    prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT")
                })) && matches!(
                    stem.get(3..),
                    Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")
                ))
        })
}

/// Writes under `root`, rejecting existing links and replacing files atomically.
/// The caller must exclusively own the output tree while extraction is running.
pub fn write_under(root: &Path, name: &str, data: &[u8]) -> io::Result<PathBuf> {
    write_under_with(root, name, |file| file.write_all(data))
}

/// Streams into the same contained, atomic output path as write_under.
/// A failed producer leaves the destination unchanged and removes its temporary.
pub fn write_under_with(
    root: &Path,
    name: &str,
    write: impl FnOnce(&mut fs::File) -> io::Result<()>,
) -> io::Result<PathBuf> {
    fs::create_dir_all(root)?;
    let root = root.canonicalize()?;
    let mut parent = root.clone();
    let mut parts = name.split(['/', '\\']).peekable();
    while let Some(part) = parts.next() {
        let next = parent.join(output_component(part));
        if parts.peek().is_none() {
            match fs::symlink_metadata(&next) {
                Ok(meta) if is_link(&meta) || !meta.is_file() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "output is a link or not a regular file",
                    ));
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            write_atomic(&next, write)?;
            return Ok(next);
        }
        match fs::create_dir(&next) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let meta = fs::symlink_metadata(&next)?;
        if is_link(&meta) || !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "output directory is a link or not a directory",
            ));
        }
        parent = next.canonicalize()?;
        if !parent.starts_with(&root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "output escapes root directory",
            ));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "empty output path",
    ))
}

/// Percent-encodes characters that cannot be represented as a portable path.
/// Empty components use `%`; literal percent signs are always escaped.
fn output_component(part: &str) -> String {
    use std::fmt::Write;
    if part.is_empty() {
        return "%".into();
    }
    let trailing = part.trim_end_matches(['.', ' ']).len();
    let mut out = String::new();
    for (index, ch) in part.char_indices() {
        if ch == '%'
            || ch.is_control()
            || matches!(ch, ':' | '<' | '>' | '"' | '|' | '?' | '*')
            || index >= trailing
        {
            let mut bytes = [0; 4];
            for byte in ch.encode_utf8(&mut bytes).bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        } else {
            out.push(ch);
        }
    }
    if !is_safe_relative_path(&out) {
        // Reserved DOS device names always begin with an ASCII letter.
        let first = out.remove(0);
        out.insert_str(0, &format!("%{:02X}", first as u32));
    }
    out
}

fn is_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT, including junctions.
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

fn write_atomic(
    destination: &Path,
    write: impl FnOnce(&mut fs::File) -> io::Result<()>,
) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..100 {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let temporary =
            destination.with_file_name(format!(".nvlens-{}-{id}.tmp", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary);
        let mut file = match file {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        let written = write(&mut file);
        drop(file);
        let result = written.and_then(|()| fs::rename(&temporary, destination));
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return result;
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot reserve temporary output file",
    ))
}

#[cfg(test)]
#[path = "../tests/filesystem.rs"]
mod tests;
