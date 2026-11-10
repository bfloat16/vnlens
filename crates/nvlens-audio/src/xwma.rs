//! RIFF xWMA (fmt/dpds/data), as stored in M2 sound_archive PSBs.
//! FFmpeg handles WMA packet decoding; output retains the original rate/channels.
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm};
use ffmpeg_next::{
    self as ffmpeg, ChannelLayout, codec, format, frame, media,
    software::resampling,
    util::{error::EAGAIN, format::Sample},
};
use nvlens_core::{Error, Format, Result};
use nvlens_io::BinaryReader;
use std::{
    io::Cursor,
    sync::atomic::{AtomicBool, Ordering},
};
#[derive(Debug, Default)]
struct Xwma;
impl Format for Xwma {
    fn tag(&self) -> &'static str {
        "xwma"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x4646_4952]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["xwma"]
    }
    fn description(&self) -> &'static str {
        "RIFF xWMA audio"
    }
}
impl AudioFormat for Xwma {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        if !data.starts_with(b"RIFF") || data.get(8..12) != Some(b"XWMA") {
            return Ok(None);
        }
        let mut r = BinaryReader::new(data);
        r.read_bytes(4)?;
        if u64::from(r.read_u32_le()?) + 8 != data.len() as u64 {
            return Err(bad("xWMA RIFF size mismatch"));
        }
        r.read_bytes(4)?;
        let mut meta = None;
        while r.remaining() != 0 {
            let name = r.read_bytes(4)?;
            let size = r.read_u32_le()? as usize;
            let chunk = r.read_bytes(size)?;
            if !size.is_multiple_of(2) {
                r.read_u8()?;
            }
            if name == b"fmt " {
                let mut f = BinaryReader::new(chunk);
                let codec = f.read_u16_le()?;
                let channels = f.read_u16_le()?;
                let sample_rate = f.read_u32_le()?;
                if channels == 0 || sample_rate == 0 {
                    return Err(bad("Invalid xWMA channel/rate fields"));
                }
                if !matches!(codec, 0x161 | 0x162) {
                    return Err(Error::Unsupported(format!("xWMA codec {codec:#x}")));
                }
                meta = Some(AudioMeta {
                    codec: "xWMA",
                    channels,
                    sample_rate,
                    frames: None,
                });
            }
        }
        meta.map(Some)
            .ok_or_else(|| bad("Missing xWMA format chunk"))
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancel: &AtomicBool) -> Result<Pcm> {
        check(cancel)?;
        let mut meta = self.metadata(data)?.ok_or(Error::InvalidFormat)?;
        ffmpeg::init().map_err(error)?;
        let io =
            format::context::StreamIo::from_read_seek(Cursor::new(data.to_vec())).map_err(error)?;
        let mut input = format::input_from_stream(io, Some("sound.xwma"), None).map_err(error)?;
        let stream = input
            .streams()
            .best(media::Type::Audio)
            .ok_or_else(|| bad("xWMA contains no audio stream"))?;
        let index = stream.index();
        let mut decoder = codec::Context::from_parameters(stream.parameters())
            .map_err(error)?
            .decoder()
            .audio()
            .map_err(error)?;
        let mut samples = Vec::new();
        let mut converter = None;
        loop {
            check(cancel)?;
            let mut packet = ffmpeg::Packet::empty();
            match packet.read(&mut input) {
                Ok(()) => {
                    if packet.stream() != index {
                        continue;
                    }
                    decoder.send_packet(&packet).map_err(error)?;
                }
                Err(ffmpeg::Error::Eof) => {
                    decoder.send_eof().map_err(error)?;
                    drain(&mut decoder, &mut converter, &meta, &mut samples, cancel)?;
                    break;
                }
                Err(cause) => return Err(error(cause)),
            }
            drain(&mut decoder, &mut converter, &meta, &mut samples, cancel)?;
        }
        meta.frames = Some(samples.len() as u64 / u64::from(meta.channels));
        Ok(Pcm {
            meta,
            samples: samples.into(),
        })
    }
}
fn drain(
    decoder: &mut ffmpeg::decoder::Audio,
    converter: &mut Option<resampling::Context>,
    meta: &AudioMeta,
    samples: &mut Vec<f32>,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut frame = frame::Audio::empty();
    loop {
        check(cancel)?;
        match decoder.receive_frame(&mut frame) {
            Ok(()) => {}
            Err(ffmpeg::Error::Eof | ffmpeg::Error::Other { errno: EAGAIN }) => return Ok(()),
            Err(cause) => return Err(error(cause)),
        }
        if frame.samples() == 0 {
            continue;
        }
        if frame.rate() != meta.sample_rate || frame.channels() != meta.channels {
            return Err(bad("xWMA frame format differs from its header"));
        }
        if frame.channel_layout().is_empty() {
            frame.set_channel_layout(ChannelLayout::default(i32::from(meta.channels)));
        }
        if converter.is_none() {
            *converter = Some(
                resampling::Context::get(
                    frame.format(),
                    frame.channel_layout(),
                    frame.rate(),
                    Sample::F32(format::sample::Type::Packed),
                    frame.channel_layout(),
                    frame.rate(),
                )
                .map_err(error)?,
            );
        }
        let Some(converter) = converter else {
            return Err(bad("Missing xWMA sample converter"));
        };
        let mut output = frame::Audio::new(
            Sample::F32(format::sample::Type::Packed),
            frame.samples(),
            frame.channel_layout(),
        );
        converter.run(&frame, &mut output).map_err(error)?;
        if output.planes() != 0 {
            samples.extend_from_slice(output.plane::<f32>(0));
        }
    }
}
fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn bad(reason: &str) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: reason.into(),
    }
}
fn error(cause: ffmpeg::Error) -> Error {
    bad(&format!("xWMA decoding failed: {cause}"))
}
nvlens_core::inventory::submit! {AudioRegistration(||Box::new(Xwma))}

#[cfg(test)]
#[path = "../tests/xwma.rs"]
mod tests;
