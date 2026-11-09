//! CRsi frame extents remain borrowed from the owning RIO volume. Opening
//! the frame list parses only its index and does not decode or copy frames.
use super::*;

#[derive(Debug)]
pub(super) struct Frames {
    sources: Arc<Sources>,
    object: Object,
    entries: Vec<Entry>,
    base: u64,
    index: nvlens_script::rugp::Animation,
}

impl Frames {
    pub(super) fn open(sources: Arc<Sources>, object: Object) -> Result<Self> {
        let (_, base, _) = sources.placement(&object)?;
        let data = sources.read(&object)?;
        let index = nvlens_script::rugp::animation_index(&data)?;
        let name = nvlens_script::rugp::object_name(&object);
        let entries = index
            .frames
            .iter()
            .enumerate()
            .map(|(i, frame)| Entry {
                name: format!("{name}@{i:08X}.crsi_frame"),
                kind: ResourceKind::Image,
                offset: base + frame.span.offset,
                size: frame.span.size,
                packed: None,
            })
            .collect();
        drop(data);
        Ok(Self {
            sources,
            object,
            entries,
            base,
            index,
        })
    }
}

impl Archive for Frames {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let target = self
            .entries
            .iter()
            .position(|e| e.name == entry.name && e.offset == entry.offset && e.size == entry.size)
            .ok_or_else(|| wire::corrupt(0, "Entry does not belong to this CRsi frame index"))?;
        let start = self.index.frames[..=target]
            .iter()
            .rposition(|f| f.mode & 1 != 0)
            .ok_or_else(|| wire::corrupt(0, "CRsi delta frame has no preceding key frame"))?;
        // nvlens frame transport, not a native RIO class: shared geometry plus
        // the exact encoded key/delta dependency chain. The image domain owns
        // pixel reconstruction; raw extraction below retains just this frame.
        let mut out = b"NVLRSI\0\x01".to_vec();
        out.resize(16, 0);
        nvlens_io::BinaryWriter::u16_le(self.index.width, &mut out[8..]);
        nvlens_io::BinaryWriter::u16_le(self.index.height, &mut out[10..]);
        nvlens_io::BinaryWriter::u32_le(
            u32::try_from(target - start + 1)
                .map_err(|_| wire::corrupt(0, "CRsi frame count exceeds u32"))?,
            &mut out[12..],
        );
        for (entry, frame) in self.entries[start..=target]
            .iter()
            .zip(&self.index.frames[start..=target])
        {
            let at = out.len();
            out.resize(at + 9, 0);
            out[at] = frame.mode;
            nvlens_io::BinaryWriter::u16_le(frame.flags, &mut out[at + 1..]);
            nvlens_io::BinaryWriter::u16_le(frame.threshold, &mut out[at + 3..]);
            nvlens_io::BinaryWriter::u32_le(
                u32::try_from(entry.size)
                    .map_err(|_| wire::corrupt(0, "CRsi frame length exceeds u32"))?,
                &mut out[at + 5..],
            );
            out.extend_from_slice(&self.open_entry_raw(entry)?);
        }
        Ok(Cow::Owned(out))
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.name == entry.name && e.offset == entry.offset && e.size == entry.size)
            .ok_or_else(|| wire::corrupt(0, "Entry does not belong to this CRsi frame index"))?;
        let start = usize::try_from(entry.offset - self.base)
            .map_err(|_| wire::corrupt(0, "CRsi frame offset exceeds address space"))?;
        let length = usize::try_from(entry.size)
            .map_err(|_| wire::corrupt(0, "CRsi frame length exceeds address space"))?;
        match self.sources.read(&self.object)? {
            Cow::Borrowed(data) => Ok(Cow::Borrowed(&data[start..start + length])),
            Cow::Owned(data) => Ok(Cow::Owned(data[start..start + length].to_vec())),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/rugp/animation.rs"]
mod tests;
