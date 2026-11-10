//! YU-RIS YSMV frame sequences, based on sub_45994C, sub_459C04,
//! sub_459CAC and sub_45A21C. The 0x20-byte LE header contains two identifying
//! words, frame count, alpha mode, nominal width/height, frame rate and a spare
//! word. Three parallel u32 tables contain absolute offsets, color JPEG sizes
//! and alpha JPEG sizes. Each JPEG independently XORs with `(i & 15) + 0x10`.
//! The native player decodes color first, then copies grayscale JPEG samples
//! into alpha. Frames can have dimensions different from the nominal header.

use crate::{
    Picture, VideoDecoder, VideoFormat, VideoMeta, VideoRegistration, VideoStream,
    decoder::{error, picture},
};
use ffmpeg_next::{Packet, codec, decoder, format::Pixel, frame, software::scaling};
use std::{
    fmt,
    io::{self, Read, Seek, SeekFrom},
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use vnlens_core::{Error, Format, Result};
use vnlens_crypto::cipher::xor;
use vnlens_io::{BinaryIo, BinaryReader, ReadAt, ReadSeek};

const SIGNATURES: &[u32] = &[0x564d_5359];
const MAGIC: &[u8; 4] = b"YSMV";
// sub_45994C restarts this 16-byte sequence separately for color and alpha.
const KEY: &[u8; 16] = &[
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[derive(Debug, Default)]
struct YmvFormat;

impl Format for YmvFormat {
    fn tag(&self) -> &'static str {
        "ymv/yuris"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ymv"]
    }
    fn description(&self) -> &'static str {
        "YU-RIS YSMV frame sequence"
    }
}

impl VideoFormat for YmvFormat {
    fn open(
        &self,
        source: Arc<dyn ReadAt>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Box<dyn VideoDecoder>> {
        Ok(Box::new(Ymv::open(source, cancelled)?))
    }
}

vnlens_core::inventory::submit! { VideoRegistration(|| Box::new(YmvFormat)) }

pub(super) struct Ymv {
    reader: Box<dyn ReadSeek>,
    frames: Vec<(Range<u64>, Range<u64>)>,
    alpha: bool,
    rate: u32,
    meta: VideoMeta,
    next: usize,
    jpeg: decoder::Video,
    frame: frame::Video,
    scaler: Option<(scaling::Context, frame::Video)>,
}

impl fmt::Debug for Ymv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ymv")
            .field("meta", &self.meta)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

fn corrupt(offset: u64, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

impl Ymv {
    pub(super) fn open(source: Arc<dyn ReadAt>, cancelled: Arc<AtomicBool>) -> Result<Self> {
        let mut stream = source.clone().reader(cancelled.clone())?;
        let mut header = [0; 32];
        stream.read_exact(&mut header)?;
        let mut reader = BinaryReader::new(&header);
        if reader.read_bytes(4)? != MAGIC {
            return Err(Error::InvalidFormat);
        }
        // The native loader skips the second identifying word and spare word.
        reader.read_u32_le()?;
        let count = usize::try_from(reader.read_u32_le()?).map_err(io::Error::other)?;
        let alpha = reader.read_u32_le()? != 0;
        let width = reader.read_u32_le()?;
        let height = reader.read_u32_le()?;
        let rate = reader.read_u32_le()?;
        reader.read_u32_le()?;
        if rate == 0 {
            return Err(Error::Unsupported(
                "YMV playback requires a declared frame rate".into(),
            ));
        }
        let table_size = count
            .checked_mul(4)
            .ok_or_else(|| corrupt(8, "YMV index size overflow"))?;
        let size = table_size
            .checked_mul(3)
            .ok_or_else(|| corrupt(8, "YMV index size overflow"))?;
        let index_end = 32u64
            .checked_add(size as u64)
            .ok_or_else(|| corrupt(8, "YMV index size overflow"))?;
        if index_end > source.len() {
            return Err(BinaryIo::unexpected_eof("YMV index exceeds resource").into());
        }
        let mut index = vec![0; size];
        stream.read_exact(&mut index)?;
        let mut reader = BinaryReader::new(&index);
        let mut offsets = BinaryReader::new(reader.read_bytes(table_size)?);
        let mut colors = BinaryReader::new(reader.read_bytes(table_size)?);
        let mut alphas = BinaryReader::new(reader.read_bytes(table_size)?);
        let mut frames = Vec::with_capacity(count);
        for index in 0..count {
            if index.is_multiple_of(4096) && cancelled.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let offset = u64::from(offsets.read_u32_le()?);
            let color = u64::from(colors.read_u32_le()?);
            let alpha = u64::from(alphas.read_u32_le()?);
            let color_end = offset
                .checked_add(color)
                .ok_or_else(|| corrupt(offset, "YMV color range overflow"))?;
            let alpha_end = color_end
                .checked_add(alpha)
                .ok_or_else(|| corrupt(offset, "YMV alpha range overflow"))?;
            if offset < index_end && alpha_end != offset {
                return Err(corrupt(offset, "YMV frame points into the index"));
            }
            if alpha_end > source.len() {
                return Err(BinaryIo::unexpected_eof("YMV frame exceeds resource").into());
            }
            frames.push((offset..color_end, color_end..alpha_end));
        }
        let codec = decoder::find(codec::Id::MJPEG)
            .ok_or_else(|| Error::Unsupported("FFmpeg MJPEG decoder is unavailable".into()))?;
        let jpeg = codec::Context::new_with_codec(codec)
            .decoder()
            .video()
            .map_err(error)?;
        let meta = VideoMeta {
            container: "YSMV".into(),
            duration: Some(count as f64 / f64::from(rate)),
            video: VideoStream {
                codec: "mjpeg",
                width,
                height,
                frame_rate: Some(f64::from(rate)),
            },
            audio: None,
        };
        Ok(Self {
            reader: stream,
            frames,
            alpha,
            rate,
            meta,
            next: 0,
            jpeg,
            frame: frame::Video::empty(),
            scaler: None,
        })
    }

    fn decode_jpeg(&mut self, range: Range<u64>, time: f64) -> Result<Picture> {
        let offset = range.start;
        let mut data = vec![0; usize::try_from(range.end - range.start).map_err(io::Error::other)?];
        self.reader.seek(SeekFrom::Start(range.start))?;
        self.reader.read_exact(&mut data)?;
        xor::apply(&mut data, KEY).map_err(|error| corrupt(offset, format!("YMV XOR: {error}")))?;
        self.jpeg.flush();
        self.jpeg
            .send_packet(&Packet::copy(&data))
            .map_err(|error| corrupt(offset, format!("YMV JPEG: {error}")))?;
        self.jpeg
            .receive_frame(&mut self.frame)
            .map_err(|error| corrupt(offset, format!("YMV JPEG: {error}")))?;
        picture(&self.frame, &mut self.scaler, time)?
            .ok_or_else(|| corrupt(offset, "YMV JPEG has no picture dimensions"))
    }
}

impl VideoDecoder for Ymv {
    fn meta(&self) -> &VideoMeta {
        &self.meta
    }

    fn seek(&mut self, seconds: f64) -> Result<()> {
        if !seconds.is_finite() {
            return Err(BinaryIo::invalid_input("YMV seek time must be finite").into());
        }
        self.next = (seconds.max(0.) * f64::from(self.rate)).floor() as usize;
        self.next = self.next.min(self.frames.len());
        Ok(())
    }

    fn next_picture(&mut self) -> Result<Option<Picture>> {
        let Some((color, alpha)) = self.frames.get(self.next) else {
            return Ok(None);
        };
        let (color, alpha) = (color.clone(), alpha.clone());
        let time = self.next as f64 / f64::from(self.rate);
        let mut output = self.decode_jpeg(color, time)?;
        if self.alpha && !alpha.is_empty() {
            let offset = alpha.start;
            let plane = self.decode_jpeg(alpha, time)?;
            // sub_45A21C only applies a one-component JPEG to the alpha bytes.
            if self.frame.format() == Pixel::GRAY8 {
                if (plane.width, plane.height) != (output.width, output.height) {
                    return Err(corrupt(offset, "YMV color and alpha dimensions differ"));
                }
                for (pixel, alpha) in output
                    .bgra
                    .as_chunks_mut::<4>()
                    .0
                    .iter_mut()
                    .zip(plane.bgra.as_chunks::<4>().0)
                {
                    pixel[3] = alpha[0];
                }
            }
        }
        self.next += 1;
        Ok(Some(output))
    }
}

#[cfg(test)]
#[path = "../../tests/yuris/mod.rs"]
mod tests;
