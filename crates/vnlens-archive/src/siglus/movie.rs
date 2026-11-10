//! OMV 1.1 wrapper, verified against sub_6E3990: 0xa8-byte LE header,
//! header[0x4c] records of 28 bytes and header[0x50] records of 32 bytes,
//! followed by the original Ogg Theora stream. Mounting never reads the stream.
use std::{borrow::Cow, sync::Arc};
use vnlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use vnlens_io::{ArcView, BinaryReader};
const SIGNATURES: &[u32] = &[0xa8];

#[derive(Debug, Default)]
struct MovieFormat;
impl Format for MovieFormat {
    fn tag(&self) -> &'static str {
        "omv/siglus"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["omv"]
    }
    fn description(&self) -> &'static str {
        "SiglusEngine OMV video container"
    }
}
impl ArchiveFormat for MovieFormat {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let mut r = BinaryReader::new(view.slice(0, 168)?);
        if r.read_u32_le()? != 168 {
            return Err(Error::InvalidFormat);
        }
        let version = r.read_u16_le()?;
        if version != 0x101 {
            return Err(Error::Unsupported(format!("OMV version {version:#x}")));
        }
        r.set_position(76)?;
        let index_size = u64::from(r.read_u32_le()?)
            .checked_mul(28)
            .and_then(|a| {
                u64::from(r.read_u32_le().ok()?)
                    .checked_mul(32)
                    .and_then(|b| a.checked_add(b))
            })
            .ok_or_else(|| Error::Corrupt {
                offset: 76,
                reason: "OMV index size overflow".into(),
            })?;
        let offset = 168u64
            .checked_add(index_size)
            .ok_or_else(|| Error::Corrupt {
                offset: 76,
                reason: "OMV data offset overflow".into(),
            })?;
        view.slice(168, index_size)?;
        let name = format!(
            "{}.ogv",
            view.path()
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
        );
        Ok(Box::new(Movie {
            view: view.clone(),
            entries: vec![Entry {
                name,
                kind: ResourceKind::Video,
                offset,
                size: view.len() - offset,
                packed: None,
            }],
        }))
    }
}
#[derive(Debug)]
struct Movie {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
}
impl Archive for Movie {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn vnlens_io::ReadAt>>> {
        Ok(Some(Arc::new(vnlens_io::RangeSource::new(
            self.view.clone(),
            entry.offset,
            entry.size,
        )?)))
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
}
vnlens_core::register_archive!(MovieFormat);
