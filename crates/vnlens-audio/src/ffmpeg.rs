//! Shared FFmpeg packet decoding for explicitly selected audio formats.
use crate::{AudioMeta, Pcm};
use ffmpeg_next::{
    self as ffmpeg, ChannelLayout, codec, format, frame, media,
    software::resampling,
    util::{error::EAGAIN, format::Sample},
};
use std::{
    io::Cursor,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{Error, Result};

pub(crate) fn decode(
    data: &[u8],
    name: &str,
    mut meta: AudioMeta,
    cancel: &AtomicBool,
) -> Result<Pcm> {
    check(cancel)?;
    ffmpeg::init().map_err(error)?;
    let io =
        format::context::StreamIo::from_read_seek(Cursor::new(data.to_vec())).map_err(error)?;
    let mut input = format::input_from_stream(io, Some(name), None).map_err(error)?;
    let stream = input
        .streams()
        .best(media::Type::Audio)
        .ok_or_else(|| bad("FFmpeg audio contains no audio stream"))?;
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
            return Err(bad("FFmpeg audio frame format differs from its header"));
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
            return Err(bad("Missing FFmpeg audio sample converter"));
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
    bad(&format!("FFmpeg audio decoding failed: {cause}"))
}
