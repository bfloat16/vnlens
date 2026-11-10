// Adapted from bfloat16/enigma_rs (Apache-2.0), commit 18fae558.
//! Enigma's encrypted Virtual Box container. Its PRGA starts from arbitrary
//! stored byte tables; they are not necessarily permutations produced by RC4 KSA.
use anyhow::{Context, Result, bail, ensure};
use nvlens_crypto::{cipher::enigma::Rc4, compress::enigma as codec};
use nvlens_io::{ArcView, BinaryReader, ReadAt};
use std::{borrow::Cow, path::PathBuf, sync::Arc};

fn decipher(data: &[u8], initial: &[u8; 256]) -> Vec<u8> {
    let mut output = data.to_vec();
    Rc4::from_state(*initial).apply(&mut output);
    output
}

fn name(reader: &mut BinaryReader<'_>) -> Result<String> {
    let mut units = Vec::new();
    loop {
        let unit = reader.read_u16_le()?;
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    Ok(String::from_utf16(&units)?)
}

#[derive(Clone, Debug)]
struct Node {
    path: PathBuf,
    size: usize,
    offset: usize,
    stored: usize,
}

fn path(parent: &std::path::Path, name: &str) -> Result<PathBuf> {
    if name.is_empty() || name == "%DEFAULT FOLDER%" {
        return Ok(parent.to_path_buf());
    }
    ensure!(!name.starts_with(['/', '\\']), "Absolute EVB path");
    let mut result = parent.to_path_buf();
    for part in name.split(['/', '\\']) {
        ensure!(
            !matches!(part, "" | "." | "..")
                && !part.contains(':')
                && !(part.starts_with('%') && part.ends_with('%')),
            "Unsupported EVB root or path traversal"
        );
        result.push(part);
    }
    Ok(result)
}

fn directory(tree: &[u8]) -> Result<Vec<Node>> {
    let mut c = BinaryReader::new(tree);
    // Iterative traversal avoids a host stack overflow on deep directory trees.
    let mut pending = vec![(PathBuf::new(), 1u32)];
    let mut files = Vec::new();
    while let Some((parent, remaining)) = pending.pop() {
        if remaining == 0 {
            continue;
        }
        pending.push((parent.clone(), remaining - 1));
        c.read_u32_le()?; // Node identifier.
        c.read_u32_le()?; // Node index.
        let children = c.read_u32_le()?;
        ensure!(
            children as usize <= tree.len() / 15,
            "invalid EVB child count"
        );
        let label = name(&mut c)?;
        let kind = c.read_u8()?;
        let path = path(&parent, &label)?;
        match kind {
            0 | 1 => {} // Main node or logical root.
            3 => {
                c.read_bytes(30)?;
            } // Policy, three Delphi dates, attributes, flag.
            2 => {
                ensure!(
                    !path.as_os_str().is_empty() && children == 0,
                    "invalid EVB file node"
                );
                c.read_bytes(2)?; // File flags and extraction policy.
                let size = usize::try_from(c.read_u64_le()?)?;
                c.read_bytes(29)?; // Dates, attributes, flag.
                name(&mut c)?; // Optional alternate name.
                c.read_u8()?;
                let offset = usize::try_from(c.read_u64_le()?)?;
                let stored = usize::try_from(c.read_u64_le()?)?;
                files.push(Node {
                    path: path.clone(),
                    size,
                    offset,
                    stored,
                });
            }
            _ => bail!("unknown EVB node kind {kind}"),
        }
        if children != 0 {
            pending.push((path, children));
        }
    }
    ensure!(c.position() == tree.len(), "unparsed EVB directory bytes");
    Ok(files)
}

fn interleaved_directory(container: &[u8], state: &[u8; 256]) -> Result<Vec<Node>> {
    let mut at = 120usize;
    let mut pending = vec![(PathBuf::new(), 1u32)];
    let mut files = Vec::new();
    while let Some((parent, remaining)) = pending.pop() {
        if remaining == 0 {
            continue;
        }
        pending.push((parent.clone(), remaining - 1));
        let size = BinaryReader::u32_le_at(
            &decipher(BinaryReader::bytes_at(container, at, 4)?, state),
            0,
        )? as usize;
        at += 4;
        let record = decipher(BinaryReader::bytes_at(container, at, size)?, state);
        at += size;
        let mut c = BinaryReader::new(&record);
        c.read_u32_le()?;
        c.read_u32_le()?;
        let children = c.read_u32_le()?;
        ensure!(
            children as usize <= container.len() / 15,
            "invalid EVB child count"
        );
        let label = name(&mut c)?;
        let kind = c.read_u8()?;
        let item = path(&parent, &label)?;
        match kind {
            0 | 1 | 3 => {}
            2 => {
                ensure!(
                    !item.as_os_str().is_empty() && children == 0,
                    "invalid EVB file node"
                );
                c.read_bytes(2)?;
                let size = usize::try_from(c.read_u64_le()?)?;
                c.read_bytes(29)?;
                name(&mut c)?;
                let stored = usize::try_from(c.read_u64_le()?)?;
                ensure!(
                    c.position() == record.len(),
                    "unparsed interleaved EVB file record"
                );
                BinaryReader::bytes_at(container, at, stored)?;
                files.push(Node {
                    path: item.clone(),
                    size,
                    offset: at,
                    stored,
                });
                at += stored;
            }
            _ => bail!("unknown EVB node kind {kind}"),
        }
        if children != 0 {
            pending.push((item, children));
        }
    }
    ensure!(
        at == container.len(),
        "unparsed interleaved EVB container bytes"
    );
    Ok(files)
}

#[derive(PartialEq, Eq)]
struct Located {
    table: usize,
    base: usize,
    length: usize,
    version: u32,
}

/// Derive the embedded container from the recovered configuration image.
/// The four 256-byte PRGA state tables are consecutive. The length/bias pair
/// consists of two u32 fields aligned to four bytes after those tables. The
/// decrypted 64-byte header validates the candidate table, length and
/// section-relative offset: it repeats the total length at +48, places the
/// directory at +120, and length(+32) + 120 equals the total length.
fn locate(pe: &nvlens_io::pe::PeImage<'_>, ctx: &[u8]) -> Result<Option<Located>> {
    let mut found = Vec::new();
    for table in 0..ctx.len() {
        let length_at = (table + 0x400).next_multiple_of(4);
        let Some(fields) = ctx.get(length_at..length_at + 8) else {
            continue;
        };
        let length = BinaryReader::u32_le_at(fields, 0)? as usize;
        let bias = BinaryReader::u32_le_at(fields, 4)? as usize;
        if length < 120 {
            continue;
        }
        for section in &pe.sections {
            if bias
                .checked_add(length)
                .is_none_or(|end| end > section.raw_size as usize)
            {
                continue;
            }
            let Some(base) = (section.raw_offset as usize).checked_add(bias) else {
                continue;
            };
            let Some(header_at) = base.checked_add(56) else {
                continue;
            };
            if header_at
                .checked_add(64)
                .is_none_or(|end| end > pe.file_bytes().len())
            {
                continue;
            }
            let metadata: &[u8; 256] = BinaryReader::bytes_at(ctx, table, 256)?.try_into()?;
            let header = decipher(
                BinaryReader::bytes_at(pe.file_bytes(), header_at, 64)?,
                metadata,
            );
            if BinaryReader::u32_le_at(&header, 4)? != 64
                || BinaryReader::u64_le_at(&header, 48)? != length as u64
                || BinaryReader::u64_le_at(&header, 24)? != 120
                || BinaryReader::u64_le_at(&header, 32)?.checked_add(120) != Some(length as u64)
            {
                continue;
            }
            let version = BinaryReader::u32_le_at(&header, 20)?;
            ensure!(
                matches!(version, 1 | 3),
                "unsupported EVB directory version {version}"
            );
            found.push(Located {
                table,
                base,
                length,
                version,
            });
        }
    }
    found.sort_by_key(|c| (c.table, c.base, c.length, c.version));
    found.dedup();
    ensure!(
        found.len() <= 1,
        "expected one embedded EVB container, found {}",
        found.len()
    );
    Ok(found.pop())
}

/// An EVB entry retains its PE mapping and decrypts only requested blocks.
pub(super) struct File {
    view: Arc<ArcView>,
    offset: u64,
    size: u64,
    stored: u64,
    state: [u8; 256],
    mode: Arc<std::sync::OnceLock<bool>>,
}
impl File {
    fn block(&self, index: u64, compressed: bool) -> std::io::Result<Vec<u8>> {
        let width = if compressed { 65536 } else { 8192 };
        let start = index
            .checked_mul(width)
            .ok_or_else(|| nvlens_io::BinaryIo::unexpected_eof("EVB block overflow"))?;
        let size = self.size.saturating_sub(start).min(width) as usize;
        if !compressed {
            return Ok(decipher(
                self.view.slice(self.offset + start, size as u64)?,
                &self.state,
            ));
        }
        let count = self.size.div_ceil(65536);
        if index
            .checked_mul(12)
            .and_then(|at| at.checked_add(12))
            .is_none_or(|end| end > self.stored)
        {
            return Err(nvlens_io::BinaryIo::unexpected_eof(
                "EVB block index exceeds file storage",
            ));
        }
        let record = decipher(self.view.slice(self.offset + index * 12, 12)?, &self.state);
        let mut reader = BinaryReader::new(&record);
        let offset = reader.read_u64_le()?;
        let packed = u64::from(reader.read_u32_le()?);
        if offset < count * 12
            || packed == 0
            || offset
                .checked_add(packed)
                .is_none_or(|end| end > self.stored)
        {
            return Err(nvlens_io::BinaryIo::unexpected_eof(
                "EVB block exceeds file storage",
            ));
        }
        let expected = if index + 1 == count {
            self.stored
        } else {
            let next = decipher(
                self.view.slice(self.offset + (index + 1) * 12, 12)?,
                &self.state,
            );
            BinaryReader::u64_le(&next)
        };
        if offset + packed != expected || (index == 0 && offset != count * 12) {
            return Err(nvlens_io::BinaryIo::invalid_input(
                "Invalid EVB block extent",
            ));
        }
        let plain = decipher(self.view.slice(self.offset + offset, packed)?, &self.state);
        codec::decompress(&plain, size, false)
    }
}
impl ReadAt for File {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
        let end = offset
            .checked_add(size as u64)
            .filter(|&end| end <= self.size)
            .ok_or_else(|| nvlens_io::BinaryIo::unexpected_eof("EVB read exceeds file"))?;
        if size == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        let compressed = if let Some(&mode) = self.mode.get() {
            mode
        } else if self.size == 0 {
            false
        } else {
            // No unequal stored extent established a mode at mount time. Check
            // only this requested file before selecting the plain encoding.
            if (0..self.size.div_ceil(65536)).all(|i| self.block(i, true).is_ok()) {
                return Err(nvlens_io::BinaryIo::invalid_input(
                    "Ambiguous EVB storage: plain and compressed layouts are both valid",
                ));
            }
            let _ = self.mode.set(false);
            false
        };
        let width = if compressed { 65536 } else { 8192 };
        let mut output = Vec::with_capacity(size);
        let mut at = offset;
        while at < end {
            let block = self.block(at / width, compressed)?;
            let begin = (at % width) as usize;
            let length = (end - at).min(block.len() as u64 - begin as u64) as usize;
            output.extend_from_slice(&block[begin..begin + length]);
            at += length as u64;
        }
        Ok(Cow::Owned(output))
    }
}

/// Reads only the EVB directory. Content decryption remains in each file source.
pub(super) fn mount(
    view: Arc<ArcView>,
    pe: &nvlens_io::pe::PeImage<'_>,
    ctx: &[u8],
) -> Result<Vec<(PathBuf, Arc<dyn ReadAt>)>> {
    let Some(container) = locate(pe, ctx)? else {
        return Ok(Vec::new());
    };
    let metadata: &[u8; 256] = BinaryReader::bytes_at(ctx, container.table, 256)?.try_into()?;
    let state: [u8; 256] = BinaryReader::bytes_at(ctx, container.table + 256, 256)?.try_into()?;
    let bytes = pe.file_bytes();
    let data = BinaryReader::bytes_at(bytes, container.base, container.length)?;
    let (nodes, base) = if container.version == 1 {
        (interleaved_directory(data, metadata)?, container.base)
    } else {
        let packed =
            BinaryReader::u32_le(&decipher(BinaryReader::bytes_at(data, 120, 4)?, metadata))
                as usize;
        let expected =
            BinaryReader::u32_le(&decipher(BinaryReader::bytes_at(data, 124, 4)?, metadata))
                as usize;
        let tree = codec::decompress(
            &decipher(BinaryReader::bytes_at(data, 128, packed)?, metadata),
            expected,
            true,
        )?;
        (directory(&tree)?, container.base + 128 + packed)
    };
    // Unequal extents establish compressed storage without touching payloads.
    // Equal extents are resolved on the first accessed file, preserving lazy mount.
    let compressed = nodes.iter().any(|node| node.size != node.stored);
    let mode = Arc::new(std::sync::OnceLock::new());
    if compressed {
        let _ = mode.set(true);
    }
    let mut paths = std::collections::HashSet::new();
    let mut files = Vec::new();
    for node in nodes {
        ensure!(
            paths.insert(node.path.to_string_lossy().to_lowercase()),
            "Duplicate EVB file path"
        );
        let offset = base
            .checked_add(node.offset)
            .context("EVB file offset overflow")?;
        ensure!(
            offset
                .checked_add(node.stored)
                .is_some_and(|end| end <= container.base + container.length),
            "EVB file exceeds container"
        );
        let source = File {
            view: view.clone(),
            offset: offset as u64,
            size: node.size as u64,
            stored: node.stored as u64,
            state,
            mode: mode.clone(),
        };
        files.push((node.path, Arc::new(source) as Arc<dyn ReadAt>));
    }
    Ok(files)
}

#[cfg(test)]
#[path = "../../tests/enigma/evb.rs"]
mod tests;
