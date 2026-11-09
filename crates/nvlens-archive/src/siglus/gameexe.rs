//! Gameexe.dat loader sub_68EA00: two LE u32 flags, encrypted LZ block,
//! then UTF-16LE configuration text. The wrapper is decoded on access only.
use nvlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use nvlens_io::{ArcView, BinaryReader};
use std::{borrow::Cow, sync::Arc};
const SIGNATURES: &[u32] = &[0];

#[derive(Debug, Default)]
struct GameexeFormat;
impl Format for GameexeFormat {
    fn tag(&self) -> &'static str {
        "gameexe/siglus"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dat"]
    }
    fn description(&self) -> &'static str {
        "SiglusEngine configuration container"
    }
}
impl ArchiveFormat for GameexeFormat {
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let mut r = BinaryReader::new(view.slice(0, 8)?);
        if r.read_u32_le()? != 0 {
            return Err(Error::InvalidFormat);
        }
        let encrypted = r.read_u32_le()? != 0;
        Ok(Box::new(Gameexe {
            view: view.clone(),
            options: options.clone(),
            encrypted,
            entries: vec![Entry {
                name: "Gameexe.txt".into(),
                kind: ResourceKind::Script,
                offset: 8,
                size: view.len() - 8,
                packed: None,
            }],
        }))
    }
}
#[derive(Debug)]
struct Gameexe {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
    options: ArchiveOptions,
    encrypted: bool,
}
impl Archive for Gameexe {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let bytes = super::decode(
            self.view.slice(entry.offset, entry.size)?,
            &self.options,
            "siglus_gameexe",
            self.encrypted,
        )?;
        let mut r = BinaryReader::new(&bytes);
        let mut units = Vec::new();
        while r.remaining() > 0 {
            units.push(r.read_u16_le()?);
        }
        let text = String::from_utf16(&units).map_err(|_| Error::Corrupt {
            offset: entry.offset,
            reason: "Invalid UTF-16 Gameexe configuration".into(),
        })?;
        Ok(Cow::Owned(text.into_bytes()))
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
}
nvlens_core::register_archive!(GameexeFormat);
