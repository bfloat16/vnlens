//! Tamlib CAT: endian flag bit 0, named-record flag bit 1, then group count
//! and a reserved word. Three u32 arrays at 12 contain group offsets, sizes
//! and IDs. Each group has a 20-byte header followed by record offsets, sizes
//! and optional name offsets, all relative to the group (not the file).
//! Verified against ToHeart sub_140592100/220/250/2C0/430/510.
//! DataTexture arrays (sub_14059B160) are LE: base, count, total size, offsets;
//! each DDS starts at base + offset. EMOJIPCK v1 embeds such an array after
//! its 28-byte glyph records (EmojiDataV1, sub_1405A8B90/sub_1405A8830).
mod read;

use std::{borrow::Cow, sync::Arc};
use vnlens_core::{Archive, ArchiveFormat, ArchiveOptions, Entry, Format, Result};
use vnlens_io::{ArcView, RangeSource, ReadAt};

#[derive(Debug, Default)]
struct Cat;
#[derive(Debug, Default)]
struct Textures;
#[derive(Debug, Default)]
struct Semb;

macro_rules! format {
    ($ty:ty, $tag:literal, $signatures:expr, $ext:expr, $description:literal, $index:ident) => {
        impl Format for $ty {
            fn tag(&self) -> &'static str {
                $tag
            }
            fn signatures(&self) -> &'static [u32] {
                $signatures
            }
            fn extensions(&self) -> &'static [&'static str] {
                $ext
            }
            fn description(&self) -> &'static str {
                $description
            }
        }
        impl ArchiveFormat for $ty {
            fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
                Ok(Box::new(Collection {
                    source: view.clone(),
                    entries: read::$index(view.as_ref())?,
                }))
            }
            fn open_source(
                &self,
                source: Arc<dyn ReadAt>,
                _: &str,
                _: &ArchiveOptions,
            ) -> Result<Option<Box<dyn Archive>>> {
                let entries = read::$index(source.as_ref())?;
                Ok(Some(Box::new(Collection { source, entries })))
            }
        }
        vnlens_core::register_archive!($ty);
    };
}
format!(
    Cat,
    "cat/tamsoft",
    &[0],
    &["cat"],
    "Tamsoft CAT collection",
    cat
);
format!(
    Textures,
    "textures/tamsoft",
    &[0],
    &[],
    "Tamsoft DDS texture array",
    textures
);
format!(
    Semb,
    "semb/tamsoft",
    &[0x4a4f_4d45],
    &["semb"],
    "Tamsoft emoji font collection",
    semb
);

struct Collection {
    source: Arc<dyn ReadAt>,
    entries: Vec<Entry>,
}
impl Archive for Collection {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(self.source.read_at(
            entry.offset,
            usize::try_from(entry.size).map_err(|_| {
                vnlens_core::Error::Unsupported("Tamsoft entry exceeds address space".into())
            })?,
        )?)
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        Ok(Some(Arc::new(RangeSource::new(
            self.source.clone(),
            entry.offset,
            entry.size,
        )?)))
    }
}

#[cfg(test)]
#[path = "../../tests/tamsoft/mod.rs"]
mod tests;
