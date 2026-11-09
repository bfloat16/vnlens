//! Container, stream and decoded-output models independent of FFmpeg types.

/// Container-level facts read while opening a video resource.
#[derive(Clone, Debug)]
pub struct VideoMeta {
    /// FFmpeg demuxer short name, e.g. `ogg` or `mpeg`.
    pub container: String,
    /// Presentation length in seconds, when the container or stream records it.
    pub duration: Option<f64>,
    pub video: VideoStream,
    pub audio: Option<AudioStream>,
}

#[derive(Clone, Debug)]
pub struct VideoStream {
    pub codec: &'static str,
    pub width: u32,
    pub height: u32,
    /// Average frame rate, when the stream declares one.
    pub frame_rate: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct AudioStream {
    pub codec: &'static str,
    pub channels: u16,
    pub sample_rate: u32,
}

/// One decoded frame as tightly packed top-down BGRA rows.
#[derive(Clone, Debug)]
pub struct Picture {
    /// Seconds from the start of the video stream.
    pub time: f64,
    pub width: u32,
    pub height: u32,
    pub bgra: Vec<u8>,
}

/// One timed PCM block. Only codec/resampler working buffers are retained.
#[derive(Clone, Debug)]
pub struct AudioFrame {
    pub time: f64,
    pub channels: u16,
    pub sample_rate: u32,
    pub samples: Vec<f32>,
}
