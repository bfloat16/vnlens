//! NCA2/NCA3: 0xc00 header, four media-unit section records and authenticated
//! 0x200 filesystem headers. Header XTS uses 0x200 units (NCA2 resets each FS
//! header tweak); section CTR uses the absolute NCA byte offset. Patch,
//! BKTR/AES-CTR-Ex layers map base and update bytes before hash verification.
//! Compression follows authentication; sparse layers remain unsupported.
use super::integrity::HashLevel;
use super::{Keys, bounds, corrupt, range};
use std::{
    borrow::Cow,
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use vnlens_core::{Entry, Error, ResourceKind, Result};
use vnlens_crypto::{
    cipher::aes::{apply_ctr128, decrypt_block128, decrypt_xts_sector},
    hash::sha256::Sha256,
};
use vnlens_io::{BinaryIo, BinaryReader, ReadAt};

pub struct Nca {
    pub entries: Vec<Entry>,
    source: Arc<dyn ReadAt>,
    header: Vec<u8>,
    sections: Vec<usize>,
    keys: Option<Arc<Keys>>,
    directory: Option<PathBuf>,
    name: String,
    catalog: Mutex<Option<Arc<super::package::Catalog>>>,
}
impl std::fmt::Debug for Nca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nca")
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

struct DecryptedSection {
    data: Arc<dyn ReadAt>,
    metadata: Option<Arc<dyn ReadAt>>,
}

impl Nca {
    /// Decrypts and validates metadata only. Content keys and section payloads
    /// are requested when the caller enters that particular filesystem.
    pub fn open(source: Arc<dyn ReadAt>) -> Result<Self> {
        let mut header = source.read_at(0, 0xc00)?.into_owned();
        if &header[0x200..0x203] == b"NCA" && !matches!(header[0x203], b'2' | b'3') {
            return Err(Error::Unsupported(
                "Only NCA2 and NCA3 filesystems are implemented".into(),
            ));
        }
        let encrypted = !matches!(&header[0x200..0x204], b"NCA2" | b"NCA3");
        let keys = if encrypted {
            Some(Arc::new(Keys::load_user()?))
        } else {
            None
        };
        if let Some(keys) = &keys {
            let key = keys.get("header_key")?;
            for (sector, bytes) in header[..0x400]
                .as_chunks_mut::<512>()
                .0
                .iter_mut()
                .enumerate()
            {
                decrypt_xts_sector(&key, sector as u64, bytes);
            }
            let version = header[0x203];
            if &header[0x200..0x203] == b"NCA" && !matches!(version, b'2' | b'3') {
                return Err(Error::Unsupported(
                    "Only NCA2 and NCA3 filesystems are implemented".into(),
                ));
            }
            if !matches!(&header[0x200..0x204], b"NCA2" | b"NCA3") {
                return Err(Error::UnknownScheme(Some("NCA header could not be decrypted; check your own ~/.switch/prod.keys (NCA2/NCA3 required)".into())));
            }
            for (index, bytes) in header[0x400..]
                .as_chunks_mut::<512>()
                .0
                .iter_mut()
                .enumerate()
            {
                decrypt_xts_sector(
                    &key,
                    if version == b'2' { 0 } else { index as u64 + 2 },
                    bytes,
                );
            }
        }
        let size = BinaryReader::u64_le(&header[0x208..0x210]);
        bounds(source.as_ref(), 0, size)?;
        if size < 0xc00 {
            return Err(corrupt(0x208, "NCA size is smaller than its header"));
        }
        let mut entries = Vec::new();
        let mut sections = Vec::new();
        let mut ranges = Vec::new();
        for index in 0..4 {
            let at = 0x240 + index * 16;
            let start = u64::from(BinaryReader::u32_le(&header[at..at + 4])) * 512;
            let end = u64::from(BinaryReader::u32_le(&header[at + 4..at + 8])) * 512;
            if start == 0 && end == 0 {
                continue;
            }
            if start < 0xc00 || end < start || end > size {
                return Err(corrupt(at as u64, "Invalid NCA section range"));
            }
            if ranges.iter().any(|&(a, b)| start < b && a < end) {
                return Err(corrupt(at as u64, "Overlapping NCA sections"));
            }
            ranges.push((start, end));
            let fs = &header[0x400 + index * 512..0x600 + index * 512];
            let hash = &header[0x280 + index * 32..0x2a0 + index * 32];
            if Sha256::digest(fs).as_slice() != hash {
                return Err(corrupt(
                    0x400 + index as u64 * 512,
                    "NCA filesystem header SHA-256 mismatch",
                ));
            }
            let ext = match fs[2] {
                0 => "romfs",
                1 => "pfs0",
                other => return Err(Error::Unsupported(format!("NCA filesystem type {other}"))),
            };
            entries.push(Entry {
                name: format!("section{index}.{ext}"),
                kind: ResourceKind::Archive,
                offset: start,
                size: end - start,
                packed: None,
            });
            sections.push(index);
        }
        Ok(Self {
            entries,
            source,
            header,
            sections,
            keys,
            directory: None,
            name: String::new(),
            catalog: Mutex::new(None),
        })
    }

    fn section(&self, entry: &Entry) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| e.name == entry.name && e.offset == entry.offset && e.size == entry.size)
            .map(|i| self.sections[i])
            .ok_or_else(|| corrupt(entry.offset, "Entry does not belong to this NCA"))
    }

    pub fn raw_source(&self, entry: &Entry) -> Result<Arc<dyn ReadAt>> {
        self.section(entry)?;
        range(self.source.clone(), entry.offset, entry.size)
    }

    /// Borrows unchanged storage when the underlying source is mapped.
    pub fn read_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        self.section(entry)?;
        Ok(self
            .source
            .read_at(entry.offset, super::memory(entry.size)?)?)
    }

    pub(super) fn with_context(
        mut self,
        name: &str,
        options: &vnlens_core::ArchiveOptions,
    ) -> Self {
        self.name = name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(name)
            .to_ascii_lowercase();
        self.directory = options.paths.get("ns_directory").cloned();
        self
    }
    pub(super) fn content_type(&self) -> u8 {
        self.header[0x205]
    }
    pub(super) fn identity(&self) -> &[u8] {
        &self.header
    }
    pub(super) fn set_keys(&mut self, keys: Arc<Keys>) {
        self.keys = Some(keys);
    }
    pub(super) fn keys(&self) -> Option<&Arc<Keys>> {
        self.keys.as_ref()
    }
    pub(super) fn has_section(&self, index: usize) -> bool {
        self.sections.contains(&index)
    }

    /// Resolves the latest CNMT-associated update only when a filesystem is
    /// entered. The decrypted and patched source stays random-access and lazy.
    pub fn source(
        &self,
        entry: &Entry,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Arc<dyn ReadAt>> {
        super::check_cancel(cancelled)?;
        let index = self.section(entry)?;
        if self.content_type() != 1
            && let Some(directory) = &self.directory
        {
            let mut cached = self
                .catalog
                .lock()
                .map_err(|_| std::io::Error::other("NS package index is unavailable"))?;
            if cached.is_none() {
                *cached = Some(Arc::new(super::package::Catalog::load(
                    directory, cancelled,
                )?));
            }
            if let Some(catalog) = cached.as_ref()
                && let Some(source) = catalog.resolve(&self.name, &self.header, index, cancelled)?
            {
                return Ok(source);
            }
        }
        self.source_with_base(index, None, cancelled)
    }

    pub(super) fn source_with_base(
        &self,
        index: usize,
        base: Option<&Nca>,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Arc<dyn ReadAt>> {
        let fs = &self.header[0x400 + index * 512..0x600 + index * 512];
        let DecryptedSection {
            data: mut decrypted,
            metadata,
        } = self.decrypted(index, cancelled)?;
        if BinaryReader::u64_le(&fs[0x108..]) != 0 {
            let original = base
                .filter(|base| base.has_section(index))
                .map(|base| base.decrypted(index, cancelled).map(|section| section.data))
                .transpose()?;
            decrypted = super::patch::indirect(decrypted, original, fs, metadata, cancelled)?;
        }
        super::compression::open(self.authenticated(index, decrypted)?, fs, cancelled)
    }

    fn decrypted(
        &self,
        index: usize,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<DecryptedSection> {
        let entry = self
            .sections
            .iter()
            .position(|stored| *stored == index)
            .and_then(|position| self.entries.get(position))
            .ok_or_else(|| {
                Error::Unsupported("NCA filesystem section is absent in associated content".into())
            })?;
        let fs = &self.header[0x400 + index * 512..0x600 + index * 512];
        if BinaryReader::u16_le(&fs[0x170..0x172]) != 0 {
            return Err(Error::Unsupported("NCA sparse filesystem layer".into()));
        }
        let raw = self.raw_source(entry)?;
        let mode = fs[4];
        if !matches!(mode, 1..=6) {
            return Err(Error::Unsupported(format!("NCA section encryption {mode}")));
        }
        let mut key = [0; 32];
        if mode != 1 {
            let keys = match &self.keys {
                Some(keys) => keys.clone(),
                None => Arc::new(Keys::load_user()?),
            };
            let generation = self.header[0x206].max(self.header[0x220]);
            if self.header[0x230..0x240].iter().any(|&b| b != 0) {
                if mode == 2 {
                    return Err(Error::Unsupported("Rights-managed NCA XTS section".into()));
                }
                key[..16].copy_from_slice(&keys.title_key(generation, &self.header[0x230..0x240])?);
            } else {
                let area = keys.area_key(generation, self.header[0x207])?;
                let first = if mode == 2 { 0 } else { 2 };
                for block in 0..if mode == 2 { 2 } else { 1 } {
                    let at = 0x300 + (first + block) * 16;
                    let mut decoded: [u8; 16] = self.header[at..at + 16]
                        .try_into()
                        .map_err(|_| Error::InvalidFormat)?;
                    decrypt_block128(&area, &mut decoded);
                    key[block * 16..block * 16 + 16].copy_from_slice(&decoded);
                }
            }
        }
        let clear_prefix = if matches!(mode, 5 | 6) {
            hash_target(fs)?
        } else {
            0
        };
        if BinaryReader::u64_le(&fs[0x128..]) != 0 {
            if !matches!(mode, 1 | 4 | 6) {
                return Err(corrupt(
                    4,
                    "NCA counter table conflicts with encryption type",
                ));
            }
            let metadata: Arc<dyn ReadAt> = if mode == 1 {
                raw.clone()
            } else {
                Arc::new(Decrypted {
                    source: raw.clone(),
                    mode: 3,
                    key,
                    upper: BinaryReader::u64_le(&fs[0x140..]),
                    absolute: entry.offset,
                    clear_prefix: 0,
                })
            };
            let authenticated = super::patch::metadata(metadata.clone(), fs, cancelled)?;
            let ctr_key = key[..16].try_into().map_err(|_| Error::InvalidFormat)?;
            let data = super::patch::counter(
                raw,
                authenticated.clone().unwrap_or(metadata),
                fs,
                ctr_key,
                entry.offset,
                clear_prefix,
                cancelled,
            )?;
            return Ok(DecryptedSection {
                data,
                metadata: authenticated,
            });
        }
        if matches!(mode, 4 | 6) {
            return Err(corrupt(0x128, "NCA CTR-Ex section has no counter table"));
        }
        if mode == 1 {
            return Ok(DecryptedSection {
                data: raw,
                metadata: None,
            });
        }
        Ok(DecryptedSection {
            data: Arc::new(Decrypted {
                source: raw,
                mode,
                key,
                upper: BinaryReader::u64_le(&fs[0x140..]),
                absolute: entry.offset,
                clear_prefix,
            }),
            metadata: None,
        })
    }

    fn authenticated(&self, index: usize, decrypted: Arc<dyn ReadAt>) -> Result<Arc<dyn ReadAt>> {
        let fs = &self.header[0x400 + index * 512..0x600 + index * 512];
        match fs[3] {
            1 => Ok(decrypted),
            2 => {
                let block_size = u64::from(BinaryReader::u32_le(&fs[0x28..0x2c]));
                let count = BinaryReader::u32_le(&fs[0x2c..0x30]) as usize;
                // NcaFsHeader.HashData.HierarchicalSha256Data.Verify requires
                // two layers: the hash table and the filesystem data.
                if count != 2 || !block_size.is_power_of_two() {
                    return Err(corrupt(0x28, "Invalid NCA SHA-256 level layout"));
                }
                let mut hashes: Arc<dyn ReadAt> = Arc::new(Arc::<[u8]>::from(&fs[8..40]));
                for level in 0..count {
                    let at = 0x30 + level * 16;
                    let offset = BinaryReader::u64_le(&fs[at..at + 8]);
                    let size = BinaryReader::u64_le(&fs[at + 8..at + 16]);
                    hashes =
                        hash_level(decrypted.clone(), hashes, offset, size, block_size, false)?;
                }
                Ok(hashes)
            }
            3 => {
                if &fs[8..12] != b"IVFC" || BinaryReader::u32_le(&fs[12..16]) != 0x20000 {
                    return Err(corrupt(8, "Invalid NCA IVFC header"));
                }
                let count = BinaryReader::u32_le(&fs[20..24]) as usize;
                let master_size = BinaryReader::u32_le(&fs[16..20]) as usize;
                if !(2..=7).contains(&count) || master_size == 0 || master_size > 0x100 - 0xc8 {
                    return Err(corrupt(16, "Invalid NCA IVFC level layout"));
                }
                let mut hashes: Arc<dyn ReadAt> =
                    Arc::new(Arc::<[u8]>::from(&fs[0xc8..0xc8 + master_size]));
                for level in 0..count - 1 {
                    let at = 0x18 + level * 24;
                    let offset = BinaryReader::u64_le(&fs[at..at + 8]);
                    let size = BinaryReader::u64_le(&fs[at + 8..at + 16]);
                    let exponent = BinaryReader::u32_le(&fs[at + 16..at + 20]);
                    let block_size = 1u64
                        .checked_shl(exponent)
                        .ok_or_else(|| corrupt(at as u64, "Invalid IVFC block exponent"))?;
                    hashes = hash_level(decrypted.clone(), hashes, offset, size, block_size, true)?;
                }
                Ok(hashes)
            }
            kind => Err(Error::Unsupported(format!("NCA hash type {kind}"))),
        }
    }
}

pub(super) fn hash_level(
    source: Arc<dyn ReadAt>,
    hashes: Arc<dyn ReadAt>,
    offset: u64,
    size: u64,
    block_size: u64,
    padded: bool,
) -> Result<Arc<dyn ReadAt>> {
    let count = size.div_ceil(block_size);
    let needed = count
        .checked_mul(32)
        .ok_or_else(|| corrupt(offset, "NCA hash count overflow"))?;
    bounds(hashes.as_ref(), 0, needed)?;
    Ok(Arc::new(HashLevel {
        source: range(source, offset, size)?,
        hashes,
        block_size,
        padded,
        verified: Default::default(),
    }))
}

struct Decrypted {
    source: Arc<dyn ReadAt>,
    mode: u8,
    key: [u8; 32],
    upper: u64,
    absolute: u64,
    clear_prefix: u64,
}
impl ReadAt for Decrypted {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        if offset > self.len() || size as u64 > self.len() - offset {
            return Err(BinaryIo::unexpected_eof("NCA read exceeds section"));
        }
        if size == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        if matches!(self.mode, 3 | 5) {
            let mut bytes = self.source.read_at(offset, size)?.into_owned();
            let key = self.key[..16]
                .try_into()
                .map_err(|_| io::Error::other("Invalid AES key state"))?;
            let position = self
                .absolute
                .checked_add(offset)
                .ok_or_else(|| BinaryIo::unexpected_eof("NCA counter offset overflow"))?;
            let skip = usize::try_from(self.clear_prefix.saturating_sub(offset).min(size as u64))
                .map_err(io::Error::other)?;
            let position = position
                .checked_add(skip as u64)
                .ok_or_else(|| BinaryIo::unexpected_eof("NCA counter offset overflow"))?;
            apply_ctr128(&key, self.upper, position, &mut bytes[skip..]);
            return Ok(Cow::Owned(bytes));
        }
        let first = offset / 512;
        let end = offset + size as u64;
        let stop = end
            .div_ceil(512)
            .checked_mul(512)
            .ok_or_else(|| BinaryIo::unexpected_eof("NCA XTS range overflow"))?;
        let length = usize::try_from(stop - first * 512).map_err(io::Error::other)?;
        let mut bytes = self.source.read_at(first * 512, length)?.into_owned();
        for (index, sector) in bytes.as_chunks_mut::<512>().0.iter_mut().enumerate() {
            decrypt_xts_sector(&self.key, first + index as u64, sector);
        }
        let start = (offset % 512) as usize;
        Ok(Cow::Owned(bytes[start..start + size].to_vec()))
    }
}

fn hash_target(fs: &[u8]) -> Result<u64> {
    let at = match fs[3] {
        2 => {
            let count = BinaryReader::u32_le(&fs[0x2c..]);
            if count != 2 {
                return Err(corrupt(0x2c, "Invalid NCA hash layer count"));
            }
            0x30 + 16
        }
        3 => {
            let count = BinaryReader::u32_le(&fs[20..]);
            if !(2..=7).contains(&count) {
                return Err(corrupt(20, "Invalid NCA integrity layer count"));
            }
            0x18 + (count as usize - 2) * 24
        }
        _ => {
            return Err(Error::Unsupported(
                "NCA skip-hash encryption requires a hash hierarchy".into(),
            ));
        }
    };
    Ok(BinaryReader::u64_le(&fs[at..]))
}
