//! ESC-ARC1/2 indexes (GARbro Escude.IndexReader; native OpenFastFile 0x441900).
//! LE u32 seed/count, then v1 encrypted 0x88-byte records or v2 encrypted
//! 12-byte records and a plain CP932 name pool. Counts and records consume a
//! continuous XOR stream. ACP payloads are inspected only on entry access.
use nvlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use nvlens_crypto::cipher::escude::IndexCipher;
use nvlens_io::{ArcView, BinaryReader, BinaryWriter, ReadAt};
use std::{borrow::Cow, cell::RefCell, path::PathBuf, sync::Arc};

const SIGNATURES: &[u32] = &[0x2d43_5345];
#[derive(Debug, Default)]
struct Bin;
impl Format for Bin {
    fn tag(&self) -> &'static str {
        "bin/escude"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bin"]
    }
    fn description(&self) -> &'static str {
        "Escu:de ESC-ARC resources"
    }
}
impl ArchiveFormat for Bin {
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let entries = read_index(view.as_ref())?;
        Ok(Box::new(Package {
            view: view.clone(),
            entries,
            companion: options
                .paths
                .get("escude_source")
                .filter(|path| path.as_path() != view.path())
                .cloned(),
            companion_archive: RefCell::new(None),
        }))
    }
}
fn read_index(view: &dyn ReadAt) -> Result<Vec<Entry>> {
    let header_bytes = view.read_at(0, 16)?;
    let mut header = BinaryReader::new(&header_bytes);
    let signature = header.read_bytes(8)?;
    let version = match signature {
        b"ESC-ARC1" => 1,
        b"ESC-ARC2" => 2,
        _ => return Err(Error::InvalidFormat),
    };
    let mut cipher = IndexCipher::new(header.read_u32_le()?);
    let count = u64::from(cipher.decode_word(header.read_u32_le()?));
    let (start, record_size, names_size) = if version == 1 {
        (16, 136, 0)
    } else {
        (
            20,
            12,
            u64::from(cipher.decode_word(BinaryReader::u32_le(&view.read_at(16, 4)?))),
        )
    };
    let index_size = count * record_size;
    let mut index = view
        .read_at(
            start,
            usize::try_from(index_size)
                .map_err(|_| bad(start, "ESC-ARC index exceeds address space"))?,
        )?
        .into_owned();
    let names = view.read_at(
        start + index_size,
        usize::try_from(names_size)
            .map_err(|_| bad(start, "ESC-ARC names exceed address space"))?,
    )?;
    for word in index.as_chunks_mut::<4>().0 {
        BinaryWriter::u32_le(cipher.decode_word(BinaryReader::u32_le(word)), word);
    }
    let mut r = BinaryReader::new(&index);
    let mut entries = Vec::new();
    for _ in 0..count {
        let name_bytes = if version == 1 {
            let field = r.read_bytes(128)?;
            field.split(|&b| b == 0).next().unwrap_or_default()
        } else {
            let offset = r.read_u32_le()? as usize;
            let mut text = BinaryReader::new_at(&names, offset)?;
            while text.read_u8()? != 0 {}
            &names[offset..text.position() - 1]
        };
        let (name, _, errors) = encoding_rs::SHIFT_JIS.decode(name_bytes);
        if errors {
            return Err(bad(
                start + r.position() as u64,
                "Invalid ESC-ARC CP932 name",
            ));
        }
        let name = name.into_owned();
        let entry = Entry {
            kind: ResourceKind::Unknown,
            name,
            offset: u64::from(r.read_u32_le()?),
            size: u64::from(r.read_u32_le()?),
            packed: None,
        };
        if !entry.check_placement(view.len()) {
            return Err(bad(entry.offset, "ESC-ARC entry exceeds file"));
        }
        entries.push(entry);
    }
    Ok(entries)
}
nvlens_core::register_archive!(Bin);

struct Package {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
    companion: Option<PathBuf>,
    companion_archive: RefCell<Option<Box<dyn Archive>>>,
}
impl Archive for Package {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let bytes = self.view.slice(entry.offset, entry.size)?;
        nvlens_script::escude::decode_envelope(bytes).map_err(|error| match error {
            Error::Corrupt { reason, .. } => bad(entry.offset, &reason),
            error => error,
        })
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
    fn read_companion(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let Some(path) = &self.companion else {
            return Ok(None);
        };
        let mut cached = self.companion_archive.borrow_mut();
        if cached.is_none() {
            let view = match ArcView::open(path) {
                Ok(view) => Arc::new(view),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            *cached = Some(Bin.open(&view, &ArchiveOptions::default())?);
        }
        let Some(archive) = cached.as_ref() else {
            return Ok(None);
        };
        archive
            .entries()
            .iter()
            .find(|entry| entry.name.replace('\\', "/").eq_ignore_ascii_case(name))
            .map(|entry| archive.open_entry(entry).map(Cow::into_owned))
            .transpose()
    }
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/escude/mod.rs"]
mod tests;
