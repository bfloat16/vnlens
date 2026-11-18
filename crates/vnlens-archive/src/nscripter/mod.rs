//! Classic NSA, verified in NScripter 2.82 sub_4466D0/sub_444880:
//! BE count:u16, data_base:u32; NUL CP932 name, codec:u8, relative_offset:u32,
//! stored_size:u32, logical_size:u32. SAR's original layout omits codec and
//! logical size (also documented by ONScripter SarReader::readArchive).
//! Only the header and directory are read at mount time. Codec 1 reconstructs
//! a BMP from SPB planes; codec 2 is bit LZSS; codec 4 is length-prefixed bzip2.
mod read;
use std::{borrow::Cow, sync::Arc};
use vnlens_core::{Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, Result};
use vnlens_io::{ArcView, RangeSource, ReadAt};

#[derive(Debug, Default)]
struct Nsa;
#[derive(Debug, Default)]
struct Sar;
macro_rules! format {
    ($ty:ty, $tag:literal, $ext:literal, $nsa:literal) => {
        impl Format for $ty {
            fn tag(&self) -> &'static str {
                $tag
            }
            fn signatures(&self) -> &'static [u32] {
                &[0]
            }
            fn extensions(&self) -> &'static [&'static str] {
                &[$ext]
            }
            fn description(&self) -> &'static str {
                "NScripter resource archive"
            }
        }
        impl ArchiveFormat for $ty {
            fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
                let (entries, codecs) = read::index(view.as_ref(), $nsa)?;
                Ok(Box::new(Package {
                    view: view.clone(),
                    entries,
                    codecs,
                }))
            }
        }
        vnlens_core::register_archive!($ty);
    };
}
format!(Nsa, "nsa/nscripter", "nsa", true);
format!(Sar, "sar/nscripter", "sar", false);

#[derive(Debug)]
struct Package {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
    codecs: Vec<u8>,
}
impl Package {
    fn codec(&self, entry: &Entry) -> Result<u8> {
        self.entries
            .iter()
            .position(|e| e.offset == entry.offset && e.size == entry.size && e.name == entry.name)
            .map(|i| self.codecs[i])
            .ok_or_else(|| {
                bad(
                    entry.offset,
                    "Entry does not belong to this NScripter archive",
                )
            })
    }
}
impl Archive for Package {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let codec = self.codec(entry)?;
        let data = self.view.slice(entry.offset, entry.size)?;
        let data = if codec == 0 {
            Cow::Borrowed(data)
        } else {
            let size = entry
                .packed
                .map(|p| p.unpacked_size)
                .ok_or_else(|| bad(entry.offset, "Missing NSA output size"))?;
            Cow::Owned(read::unpack(data, codec, size, entry.offset)?)
        };
        if codec != 4 && nbz(entry) {
            return vnlens_audio::nscripter::decode_envelope(&data).map(Cow::Owned);
        }
        if let Some(tag) = script_tag(entry) {
            return Ok(Cow::Owned(
                vnlens_script::decode_as(tag, &data, &ArchiveOptions::default())?.into_owned(),
            ));
        }
        Ok(data)
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        if self.codec(entry)? != 0 || nbz(entry) || script_tag(entry).is_some() {
            return Ok(None);
        }
        Ok(Some(Arc::new(RangeSource::new(
            self.view.clone(),
            entry.offset,
            entry.size,
        )?)))
    }
}
fn nbz(entry: &Entry) -> bool {
    entry
        .name
        .rsplit('.')
        .next()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("nbz"))
}
fn script_tag(entry: &Entry) -> Option<&'static str> {
    let leaf = entry.name.rsplit(['/', '\\']).next()?;
    if leaf.eq_ignore_ascii_case("nscript.dat") {
        Some("nscript/nscripter")
    } else if leaf.eq_ignore_ascii_case("nscript.zat") {
        Some("zat/nscripter")
    } else {
        None
    }
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/nscripter/mod.rs"]
mod tests;
