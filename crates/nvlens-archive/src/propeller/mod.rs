//! Stuff MPK, sub_406490/sub_414190: LE index offset and entry count, then
//! XORed 40-byte records (CP932 name[32], absolute offset:u32, size:u32).
//! Payloads are stored verbatim. MSC encryption belongs to the script domain.
use nvlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use nvlens_io::{ArcView, BinaryReader};
use std::{borrow::Cow, sync::Arc};

const SIGNATURES: &[u32] = &[0];

#[derive(Debug, Default)]
struct Mpk;
impl Format for Mpk {
    fn tag(&self) -> &'static str {
        "mpk/propeller"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mpk"]
    }
    fn description(&self) -> &'static str {
        "Propeller Stuff MPK archive"
    }
}
impl ArchiveFormat for Mpk {
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let key = options.keys.get("propeller_mpk").ok_or_else(|| {
            Error::UnknownScheme(Some("Missing identified Propeller MPK parameters".into()))
        })?;
        let mut header = BinaryReader::new(view.slice(0, 8)?);
        let offset = u64::from(header.read_u32_le()?);
        let count = header.read_u32_le()?;
        if offset < 8 {
            return Err(corrupt(0, "MPK index overlaps header"));
        }
        let mut index = view.slice(offset, u64::from(count) * 40)?.to_vec();
        nvlens_crypto::cipher::xor::apply(&mut index, key.bytes())
            .map_err(|e| corrupt(offset, &e.to_string()))?;
        let mut reader = BinaryReader::new(&index);
        let mut entries = Vec::new();
        for _ in 0..count {
            let at = offset + reader.position() as u64;
            let raw = reader.read_bytes(32)?;
            let end = raw
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| corrupt(at, "Unterminated MPK name"))?;
            let (name, _, invalid) = encoding_rs::SHIFT_JIS.decode(&raw[..end]);
            if invalid {
                return Err(corrupt(at, "Invalid MPK CP932 name"));
            }
            let name = name.into_owned();
            let kind = match name
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase()
                .as_str()
            {
                "mgr" => ResourceKind::Image,
                "msc" => ResourceKind::Script,
                "ogv" => ResourceKind::Audio,
                _ => ResourceKind::guess_from_name(&name),
            };
            let entry = Entry {
                name,
                kind,
                offset: u64::from(reader.read_u32_le()?),
                size: u64::from(reader.read_u32_le()?),
                packed: None,
            };
            if !entry.check_placement(view.len()) {
                return Err(corrupt(at + 32, "MPK payload exceeds file storage"));
            }
            entries.push(entry);
        }
        Ok(Box::new(Pack {
            view: view.clone(),
            entries,
            options: options.clone(),
        }))
    }
}
#[derive(Debug)]
struct Pack {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
    options: ArchiveOptions,
}
impl Archive for Pack {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let bytes = self.view.slice(entry.offset, entry.size)?;
        if entry
            .name
            .rsplit('.')
            .next()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("msc"))
        {
            return nvlens_script::decode_as("msc/propeller", bytes, &self.options);
        }
        Ok(Cow::Borrowed(bytes))
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
}
fn corrupt(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}
nvlens_core::register_archive!(Mpk);

#[cfg(test)]
#[path = "../../tests/propeller/mod.rs"]
mod tests;
