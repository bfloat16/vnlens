//! Scene.pck, verified against sub_6984D0: LE 0x5c-byte header, UTF-16LE
//! name ranges and scene ranges. Scene offsets are relative to header[19].
//! header[21] enables the 16-byte game key; header[22] enables compression.
use nvlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use nvlens_io::{ArcView, BinaryReader};
use std::{borrow::Cow, sync::Arc};

#[derive(Debug, Default)]
struct SceneFormat;
impl Format for SceneFormat {
    fn tag(&self) -> &'static str {
        "pck/siglus"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x5c]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pck"]
    }
    fn description(&self) -> &'static str {
        "SiglusEngine scene archive"
    }
}
#[derive(Debug)]
struct Header {
    name_index: u32,
    names: u32,
    data_index: u32,
    data: u32,
    count: u32,
    encrypted: bool,
    compressed: bool,
}
impl Header {
    fn parse(view: &ArcView) -> Result<Self> {
        let mut r = BinaryReader::new(view.slice(0, 0x5c)?);
        if r.read_u32_le()? != 0x5c {
            return Err(Error::InvalidFormat);
        }
        r.set_position(0x34)?;
        let name_index = r.read_u32_le()?;
        let name_count = r.read_u32_le()?;
        let names = r.read_u32_le()?;
        let text_count = r.read_u32_le()?;
        let data_index = r.read_u32_le()?;
        let index_count = r.read_u32_le()?;
        let data = r.read_u32_le()?;
        let count = r.read_u32_le()?;
        if [name_count, text_count, index_count]
            .iter()
            .any(|&n| n != count)
            || u64::from(data) > view.len()
        {
            return Err(Error::Corrupt {
                offset: 0x34,
                reason: "Inconsistent Siglus scene index".into(),
            });
        }
        Ok(Self {
            name_index,
            names,
            data_index,
            data,
            count,
            encrypted: r.read_u32_le()? != 0,
            compressed: r.read_u32_le()? != 0,
        })
    }
}
impl ArchiveFormat for SceneFormat {
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let header = Header::parse(view)?;
        let length = u64::from(header.count) * 8;
        if [header.name_index, header.data_index]
            .iter()
            .any(|&offset| u64::from(offset) + length > u64::from(header.data))
        {
            return Err(Error::Corrupt {
                offset: 0x34,
                reason: "Siglus index overlaps scene payload".into(),
            });
        }
        let mut names = BinaryReader::new(view.slice(u64::from(header.name_index), length)?);
        let mut ranges = BinaryReader::new(view.slice(u64::from(header.data_index), length)?);
        let mut entries = Vec::new();
        for _ in 0..header.count {
            let offset = u64::from(header.names) + u64::from(names.read_u32_le()?) * 2;
            let size = u64::from(names.read_u32_le()?) * 2;
            if offset + size > u64::from(header.data) {
                return Err(Error::Corrupt {
                    offset,
                    reason: "Siglus name overlaps payload".into(),
                });
            }
            let mut text = BinaryReader::new(view.slice(offset, size)?);
            let mut units = Vec::new();
            while text.remaining() > 0 {
                units.push(text.read_u16_le()?);
            }
            let name = String::from_utf16(&units).map_err(|_| Error::Corrupt {
                offset,
                reason: "Invalid UTF-16 scene name".into(),
            })?;
            let entry = Entry {
                name: format!("{name}.ss"),
                kind: ResourceKind::Script,
                offset: u64::from(header.data) + u64::from(ranges.read_u32_le()?),
                size: u64::from(ranges.read_u32_le()?),
                packed: None,
            };
            if !entry.check_placement(view.len()) {
                return Err(Error::Corrupt {
                    offset: entry.offset,
                    reason: "Siglus scene exceeds archive".into(),
                });
            }
            entries.push(entry);
        }
        Ok(Box::new(Scene {
            view: view.clone(),
            entries,
            header,
            options: options.clone(),
        }))
    }
}
#[derive(Debug)]
struct Scene {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
    header: Header,
    options: ArchiveOptions,
}
impl Archive for Scene {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let data = self.view.slice(entry.offset, entry.size)?;
        if !self.header.compressed || data.is_empty() {
            return Ok(Cow::Borrowed(data));
        }
        super::decode(data, &self.options, "siglus_scene", self.header.encrypted).map(Cow::Owned)
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
}
nvlens_core::register_archive!(SceneFormat);
