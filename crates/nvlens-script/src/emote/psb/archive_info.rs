//! PSB file_info/umd_root index interpretation and MDF filename candidates.
use super::{Psb, PsbValue, corrupt};
use nvlens_core::{Error, Result};

/// Archive-info index style.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveInfoKind {
    FileInfo,
    UmdRoot,
}

/// One entry declared by an archive-info PSB.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveInfoEntry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

/// Extracts archive-info entries from a parsed PSB.
///
/// # Errors
///
/// Returns `InvalidFormat` when the PSB is not an archive-info object, and
/// corrupt-data errors for malformed range lists.
pub fn archive_info_entries(psb: &Psb) -> Result<(ArchiveInfoKind, Vec<ArchiveInfoEntry>)> {
    let root = psb.root.as_object().ok_or(Error::InvalidFormat)?;
    let (kind, key) = if root.contains_key("umd_root") {
        (ArchiveInfoKind::UmdRoot, "umd_root")
    } else if root.contains_key("file_info") {
        (ArchiveInfoKind::FileInfo, "file_info")
    } else {
        return Err(Error::InvalidFormat);
    };

    if matches!(root.get(key), Some(PsbValue::Null)) {
        return Ok((kind, Vec::new()));
    }
    let table = root
        .get(key)
        .and_then(PsbValue::as_object)
        .ok_or_else(|| corrupt(0, "archive-info root is not an object"))?;
    let mut entries = Vec::with_capacity(table.len());
    for (name, range) in table {
        let range = range
            .as_list()
            .ok_or_else(|| corrupt(0, "archive-info range is not a list"))?;
        let (offset, size) = archive_info_range(range, kind)?;
        entries.push(ArchiveInfoEntry {
            name: name.clone(),
            offset,
            size,
        });
    }
    Ok((kind, entries))
}

/// Returns the archive-info suffix, usually from `expire_suffix_list[0]`.
#[must_use]
pub fn archive_info_suffix(psb: &Psb) -> Option<&str> {
    let root = psb.root.as_object()?;
    let suffixes = root.get("expire_suffix_list")?.as_list()?;
    suffixes.first()?.as_str()
}

/// Returns likely MDF key filenames for an archive entry.
#[must_use]
pub fn archive_info_possible_file_names(name: &str, suffix: &str) -> Vec<String> {
    let mut results = Vec::new();
    collect_possible_file_names(name, suffix, &mut results);
    results.dedup();
    results
}

fn archive_info_range(range: &[PsbValue], kind: ArchiveInfoKind) -> Result<(u64, u64)> {
    let (start_value, len_value) = match kind {
        ArchiveInfoKind::FileInfo => (range.first(), range.get(1)),
        ArchiveInfoKind::UmdRoot => {
            if range.len() < 2 {
                return Err(corrupt(0, "umd_root range is too short"));
            }
            (range.last(), range.get(range.len() - 2))
        }
    };
    let start = start_value
        .and_then(PsbValue::as_i64)
        .ok_or_else(|| corrupt(0, "archive-info offset is missing"))?;
    let len = len_value
        .and_then(PsbValue::as_i64)
        .ok_or_else(|| corrupt(0, "archive-info length is missing"))?;
    if start < 0 || len < 0 {
        return Err(corrupt(0, "archive-info range is negative"));
    }
    Ok((
        u64::try_from(start).map_err(|_| corrupt(0, "archive-info offset does not fit u64"))?,
        u64::try_from(len).map_err(|_| corrupt(0, "archive-info length does not fit u64"))?,
    ))
}

fn collect_possible_file_names(name: &str, suffix: &str, results: &mut Vec<String>) {
    if name.trim().is_empty() {
        return;
    }

    if let Some((_, file_name)) = name.rsplit_once('/') {
        collect_possible_file_names(file_name, suffix, results);
    }

    let lower = name.to_ascii_lowercase();
    if lower != name {
        collect_possible_file_names(&lower, suffix, results);
    }

    let exts = extensions(name);
    if exts.is_empty() {
        results.push(format!("{name}{suffix}"));
        results.push(name.to_string());
    } else if exts
        .first()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(".m"))
        && exts.len() == 1
    {
        results.push(format!("{name}{suffix}"));
        results.push(name.to_string());
        if let Some(stem) = strip_extension(name) {
            results.push(stem.to_string());
        }
    } else {
        if (name.ends_with(".txt") || name.ends_with(".ks")) && suffix.starts_with(".scn") {
            results.push(format!("{name}{suffix}"));
            results.push(name.to_string());
        } else {
            results.push(name.to_string());
            results.push(format!("{name}{suffix}"));
        }

        let mut name2 = name;
        while let Some(stem) = strip_extension(name2) {
            name2 = stem;
            results.push(name2.to_string());
            results.push(format!("{name2}{suffix}"));
        }
    }
}

fn extensions(mut name: &str) -> Vec<&str> {
    let mut exts = Vec::new();
    while let Some(ext) = extension(name) {
        exts.push(ext);
        if let Some(stem) = strip_extension(name) {
            name = stem;
        } else {
            break;
        }
    }
    exts
}

fn extension(name: &str) -> Option<&str> {
    let slash = name.rfind('/').map_or(0, |pos| pos + 1);
    let dot = name[slash..].rfind('.')? + slash;
    if dot + 1 >= name.len() {
        return None;
    }
    Some(&name[dot..])
}

fn strip_extension(name: &str) -> Option<&str> {
    let slash = name.rfind('/').map_or(0, |pos| pos + 1);
    let dot = name[slash..].rfind('.')? + slash;
    if dot == slash {
        return None;
    }
    Some(&name[..dot])
}

#[cfg(test)]
#[path = "../../../tests/emote/psb/archive_info.rs"]
mod tests;
