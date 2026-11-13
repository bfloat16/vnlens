//! ERISA frame dependencies. A flagged DiffeFrm is bidirectional; its nearest
//! preceding and following reference frames are decoded on demand. Only those
//! two reference images are cached. Based on SGLMovieFilePlayer sub_621C70.
use super::{ImageInfo, MediaFile, Section, bad, decode_frame};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use vnlens_core::{Error, Result};
use vnlens_io::ReadAt;

#[derive(Debug)]
pub struct RasterDecoder {
    info: ImageInfo,
    frames: Vec<Section>,
    palettes: Vec<Section>,
    previous: Option<(usize, Arc<[u8]>)>,
    following: Option<(usize, Arc<[u8]>)>,
}
impl RasterDecoder {
    pub fn new(file: &MediaFile) -> Result<Self> {
        let info = file
            .image
            .clone()
            .ok_or_else(|| bad(64, "Missing ERISA ImageInf"))?;
        let frames = file
            .stream
            .iter()
            .filter(|s| matches!(&s.id, b"ImageFrm" | b"DiffeFrm"))
            .cloned()
            .collect();
        let palettes = file
            .stream
            .iter()
            .filter(|s| s.id == *b"Palette ")
            .cloned()
            .collect();
        Ok(Self {
            info,
            frames,
            palettes,
            previous: None,
            following: None,
        })
    }
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }
    pub fn clear(&mut self) {
        self.previous = None;
        self.following = None;
    }
    fn bidirectional(&self, index: usize, source: &dyn ReadAt) -> Result<bool> {
        let section = &self.frames[index];
        if section.id != *b"DiffeFrm" {
            return Ok(false);
        }
        let prefix = source.read_at(section.offset, 2)?;
        Ok(prefix[0] == 0x28 && prefix[1] & 2 != 0)
    }
    fn read(
        &self,
        index: usize,
        source: &dyn ReadAt,
        previous: Option<&[u8]>,
        following: Option<&[u8]>,
        cancel: &AtomicBool,
    ) -> Result<Arc<[u8]>> {
        let section = &self.frames[index];
        let bytes = source.read_at(
            section.offset,
            usize::try_from(section.size).map_err(std::io::Error::other)?,
        )?;
        let palette = self
            .palettes
            .iter()
            .rfind(|s| s.offset < section.offset)
            .map(|s| {
                source.read_at(
                    s.offset,
                    usize::try_from(s.size).map_err(std::io::Error::other)?,
                )
            })
            .transpose()?;
        let pixels = decode_frame(
            &self.info,
            &bytes,
            palette.as_deref(),
            previous,
            following,
            cancel,
        );
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let pixels = pixels.map_err(|error| match error {
            Error::Corrupt { offset, reason } => Error::Corrupt {
                offset: section.offset.saturating_add(offset),
                reason,
            },
            error => error,
        })?;
        Ok(pixels.into())
    }
    fn preceding(
        &mut self,
        index: usize,
        source: &dyn ReadAt,
        cancel: &AtomicBool,
    ) -> Result<Arc<[u8]>> {
        if let Some((cached, bytes)) = &self.previous
            && *cached == index
        {
            return Ok(bytes.clone());
        }
        if let Some((cached, bytes)) = &self.following
            && *cached == index
        {
            let bytes = bytes.clone();
            self.previous = Some((index, bytes.clone()));
            self.following = None;
            return Ok(bytes);
        }
        let mut key = index;
        while key > 0 && self.frames[key].id != *b"ImageFrm" {
            key -= 1;
        }
        if self.frames[key].id != *b"ImageFrm" {
            return Err(bad(
                self.frames[key].offset,
                "ERISA frame lacks a preceding key frame",
            ));
        }
        let mut pixels = self.read(key, source, None, None, cancel)?;
        for i in key + 1..=index {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            if !self.bidirectional(i, source)? {
                pixels = self.read(i, source, Some(&pixels), None, cancel)?;
            }
        }
        self.previous = Some((index, pixels.clone()));
        self.following = None;
        Ok(pixels)
    }
    pub fn decode_at(
        &mut self,
        index: usize,
        source: &dyn ReadAt,
        cancel: &AtomicBool,
    ) -> Result<Vec<u8>> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let section = self
            .frames
            .get(index)
            .ok_or_else(|| Error::Unsupported("ERISA image frame is out of range".into()))?;
        if section.id == *b"ImageFrm" {
            return Ok(self.preceding(index, source, cancel)?.to_vec());
        }
        let mut before = index
            .checked_sub(1)
            .ok_or_else(|| bad(section.offset, "ERISA delta frame has no preceding image"))?;
        while before > 0 && self.bidirectional(before, source)? {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            before -= 1;
        }
        let previous = self.preceding(before, source, cancel)?;
        if !self.bidirectional(index, source)? {
            let pixels = self.read(index, source, Some(&previous), None, cancel)?;
            self.previous = Some((index, pixels.clone()));
            self.following = None;
            return Ok(pixels.to_vec());
        }
        let mut after = index + 1;
        while after < self.frames.len() && self.bidirectional(after, source)? {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            after += 1;
        }
        if after == self.frames.len() {
            return Err(bad(
                self.frames[index].offset,
                "ERISA bidirectional frame has no following reference",
            ));
        }
        let following = if let Some((cached, pixels)) = &self.following
            && *cached == after
        {
            pixels.clone()
        } else {
            let base = (self.frames[after].id == *b"DiffeFrm").then_some(previous.as_ref());
            let pixels = self.read(after, source, base, None, cancel)?;
            self.following = Some((after, pixels.clone()));
            pixels
        };
        Ok(self
            .read(index, source, Some(&previous), Some(&following), cancel)?
            .to_vec())
    }
}
