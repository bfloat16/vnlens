//! Video presentation and transport. Pictures come from the decoder thread in
//! crate::video; the clock follows audio output while it plays and otherwise
//! runs on wall time from the last known position.

use super::*;
use crate::resource::VideoInput;
use crate::video::{Decoder, Output};

#[derive(Clone, Copy)]
enum Clock {
    Paused(f64),
    Playing(Instant, f64),
}
impl Clock {
    fn position(self) -> f64 {
        match self {
            Self::Paused(position) => position,
            Self::Playing(start, from) => from + start.elapsed().as_secs_f64(),
        }
    }
}

pub(super) struct VideoPreview {
    decoder: Decoder,
    input: VideoInput,
    output: Option<crate::video::AudioOutput>,
    picture: Option<Arc<RenderImage>>,
    next: Option<vnlens_video::Picture>,
    /// After opening or seeking, the next picture is shown regardless of the clock.
    awaiting: bool,
    ended: bool,
    clock: Clock,
    /// Declared container duration; zero when it is unknown.
    duration: f64,
    dragging: Arc<AtomicBool>,
}

impl VideoPreview {
    /// Returns `Ok(None)` when FFmpeg finds no video stream in `bytes`.
    pub(super) fn new(
        input: VideoInput,
        cancelled: Arc<AtomicBool>,
    ) -> anyhow::Result<Option<Self>> {
        let Some(decoder) = Decoder::open(input.clone(), cancelled)? else {
            return Ok(None);
        };
        let duration = decoder.meta.duration.unwrap_or(0.);
        Ok(Some(Self {
            decoder,
            input,
            output: None,
            picture: None,
            next: None,
            awaiting: true,
            ended: false,
            clock: Clock::Paused(0.),
            duration,
            dragging: Arc::default(),
        }))
    }

    pub(super) fn release(self, cx: &mut App) {
        if let Some(image) = self.picture {
            cx.defer(move |cx| cx.drop_image(image, None));
        }
    }

    pub(super) fn playing(&self) -> bool {
        matches!(self.clock, Clock::Playing(..))
    }

    fn clamp(&self, position: f64) -> f64 {
        if self.duration > 0. {
            position.min(self.duration)
        } else {
            position
        }
    }

    /// Current presentation time; re-anchors the wall clock to audio output.
    fn position(&mut self) -> f64 {
        if self.playing()
            && let Some(output) = &self.output
            && !output.finished()
        {
            self.clock = Clock::Playing(Instant::now(), output.position());
        }
        self.clamp(self.clock.position())
    }

    fn seek(&mut self, position: f64) {
        self.decoder.seek(position);
        if let Some(output) = &self.output {
            output.seek(position);
        }
        self.next = None;
        self.awaiting = true;
        self.ended = false;
        self.clock = if self.playing() {
            Clock::Playing(Instant::now(), position)
        } else {
            Clock::Paused(position)
        };
    }
}

impl Workspace {
    fn video_mut(&mut self) -> Option<&mut VideoPreview> {
        self.preview
            .as_mut()
            .and_then(|preview| preview.video.as_deref_mut())
    }

    pub(super) fn video_playing(&self) -> bool {
        self.preview
            .as_ref()
            .and_then(|preview| preview.video.as_deref())
            .is_some_and(VideoPreview::playing)
    }

    /// Presents the latest picture due at the clock and stops at the end.
    pub(super) fn tick_video(&mut self, cx: &mut Context<Self>) {
        let Some(video) = self.video_mut() else {
            return;
        };
        let position = video.position();
        let mut shown = None;
        let mut error = None;
        loop {
            if video.next.is_none() {
                match video.decoder.poll() {
                    Some(Output::Picture(picture)) => video.next = Some(picture),
                    Some(Output::End) => video.ended = true,
                    Some(Output::Error(message)) => {
                        video.ended = true;
                        error = Some(message);
                    }
                    None => {}
                }
            }
            let Some(next) = &video.next else {
                break;
            };
            if !video.awaiting && next.time > position {
                break;
            }
            video.awaiting = false;
            // Late pictures are skipped; only the newest due one is uploaded.
            shown = video.next.take();
        }
        let mut changed = false;
        if let Some(output) = &video.output
            && let Some(message) = output.error()
        {
            error = Some(message);
        }
        if let Some(picture) = shown {
            match image::RgbaImage::from_raw(picture.width, picture.height, picture.bgra) {
                Some(pixels) => {
                    let image = Arc::new(RenderImage::new([image::Frame::new(pixels)]));
                    if let Some(old) = video.picture.replace(image) {
                        cx.defer(move |cx| cx.drop_image(old, None));
                    }
                    changed = true;
                }
                None => error = Some("Invalid video picture dimensions".into()),
            }
        }
        if video.playing()
            && ((video.duration > 0. && position >= video.duration)
                || (video.duration == 0. && video.ended && video.next.is_none()))
        {
            video.clock = Clock::Paused(position);
            if let Some(output) = &video.output {
                output.player.pause();
            }
            changed = true;
        }
        if let Some(error) = error {
            self.error(error);
            changed = true;
        }
        if changed {
            cx.notify();
        }
    }

    pub(super) fn toggle_video(&mut self, cx: &mut Context<Self>) {
        let Some(video) = self.video_mut() else {
            return;
        };
        let mut error = None;
        if video.playing() {
            video.clock = Clock::Paused(video.position());
            if let Some(output) = &video.output {
                output.player.pause();
            }
        } else {
            let mut position = video.clock.position();
            if (video.duration > 0. && position >= video.duration)
                || (video.duration == 0. && video.ended)
            {
                position = 0.;
                video.seek(0.);
                video.output = None;
            }
            video.clock = Clock::Playing(Instant::now(), position);
            if let Some(output) = &video.output {
                output.player.play();
            } else if let Some(meta) = &video.decoder.meta.audio {
                // Opening the output device stays a user-initiated action.
                match crate::video::AudioOutput::new(video.input.clone(), meta, position) {
                    Ok(output) => video.output = Some(output),
                    Err(error_) => error = Some(format!("Video audio playback: {error_:#}")),
                }
            }
        }
        if let Some(error) = error {
            self.error(error);
        }
        cx.notify();
    }

    fn seek_video(&mut self, fraction: f64, cx: &mut Context<Self>) {
        let Some(video) = self.video_mut() else {
            return;
        };
        if video.duration <= 0. {
            return;
        }
        // Demuxers may reject the end timestamp itself; aim at the last frame.
        let period = video
            .decoder
            .meta
            .video
            .frame_rate
            .map_or(0., |rate| 1. / rate);
        let position = (video.duration * fraction.clamp(0., 1.))
            .min(video.duration - period)
            .max(0.);
        video.seek(position);
        let mut error = None;
        if video.output.is_none()
            && video.playing()
            && let Some(meta) = &video.decoder.meta.audio
        {
            match crate::video::AudioOutput::new(video.input.clone(), meta, position) {
                Ok(output) => video.output = Some(output),
                Err(error_) => error = Some(format!("Video audio playback: {error_:#}")),
            }
        }
        if let Some(error) = error {
            self.error(error);
        }
        cx.notify();
    }
    pub(super) fn video_view(
        &self,
        video: &VideoPreview,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let duration = video.duration;
        let position = video.clamp(video.clock.position());
        let playing = video.playing();
        let picture = video.picture.clone();
        let meta = &video.decoder.meta;
        let mut details = vec![format!(
            "{}×{} · {}",
            meta.video.width, meta.video.height, meta.video.codec
        )];
        details.extend(meta.video.frame_rate.map(|rate| format!("{rate:.3} fps")));
        details.extend(meta.audio.as_ref().map(|audio| {
            format!(
                "{} {} Hz {}",
                audio.codec,
                audio.sample_rate,
                match audio.channels {
                    1 => "Mono".to_owned(),
                    2 => "Stereo".to_owned(),
                    channels => format!("{channels} ch"),
                }
            )
        }));
        details.push(meta.container.clone());
        let entity = cx.entity().downgrade();
        let dragging = video.dragging.clone();
        let seekable = duration > 0.;
        div()
            .size_full()
            .flex()
            .flex_col()
            .min_h_0()
            .min_w_0()
            .px_2()
            .child(
                canvas(
                    |_, _, _| {},
                    move |bounds, _, window, _| {
                        window.paint_quad(fill(bounds, rgb(0x000000)));
                        let Some(image) = picture else {
                            return;
                        };
                        let source = image.size(0);
                        let (width, height) = (
                            u32::from(source.width) as f32,
                            u32::from(source.height) as f32,
                        );
                        if width == 0. || height == 0. {
                            return;
                        }
                        let scale = (f32::from(bounds.size.width) / width)
                            .min(f32::from(bounds.size.height) / height);
                        let fitted = size(px(width * scale), px(height * scale));
                        let draw = Bounds::new(
                            bounds.origin
                                + point(
                                    (bounds.size.width - fitted.width) / 2.,
                                    (bounds.size.height - fitted.height) / 2.,
                                ),
                            fitted,
                        );
                        if let Err(error) =
                            window.paint_image(draw, Corners::default(), image, 0, false)
                        {
                            tracing::error!(%error, "Cannot paint video picture");
                        }
                    },
                )
                .w_full()
                .flex_1()
                .min_h_0()
                .rounded(px(4.)),
            )
            .child(
                div()
                    .h(px(46.))
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_2()
                    .child(
                        div()
                            .id("video-play")
                            .size(px(32.))
                            .flex_shrink_0()
                            .rounded_full()
                            .flex()
                            .items_center()
                            .justify_center()
                            .bg(rgb(ACCENT))
                            .cursor_pointer()
                            .hover(|style| style.bg(rgb(ACCENT_HOVER)))
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_video(cx)))
                            .tooltip(super::view::tooltip(if playing {
                                "Pause (Space)"
                            } else {
                                "Play (Space)"
                            }))
                            .child(crate::icons::glyph(
                                if playing {
                                    "icons/pause.svg"
                                } else {
                                    "icons/play.svg"
                                },
                                14.,
                                TEXT,
                            )),
                    )
                    .child(
                        div()
                            .flex_shrink_0()
                            .font_family(MONO_FONT)
                            .text_size(px(11.))
                            .child(super::audio_view::time(position))
                            .child(
                                div()
                                    .text_color(rgb(SECONDARY))
                                    .child(format!(" / {}", super::audio_view::time(duration))),
                            )
                            .flex(),
                    )
                    .child(
                        canvas(
                            |bounds, window, _| {
                                window.insert_hitbox(bounds, HitboxBehavior::Normal)
                            },
                            move |bounds, hitbox, window, _| {
                                let track = Bounds::new(
                                    point(bounds.left(), bounds.center().y - px(2.)),
                                    size(bounds.size.width, px(4.)),
                                );
                                window.paint_quad(fill(track, rgb(CONTROL)).corner_radii(px(2.)));
                                let fraction = if seekable {
                                    (position / duration).clamp(0., 1.) as f32
                                } else {
                                    0.
                                };
                                let x = track.left() + track.size.width * fraction;
                                window.paint_quad(
                                    fill(
                                        Bounds::new(
                                            track.origin,
                                            size(x - track.left(), track.size.height),
                                        ),
                                        rgb(ACCENT),
                                    )
                                    .corner_radii(px(2.)),
                                );
                                if !seekable {
                                    return;
                                }
                                window.paint_quad(
                                    fill(
                                        Bounds::new(
                                            point(x - px(6.), bounds.center().y - px(6.)),
                                            size(px(12.), px(12.)),
                                        ),
                                        rgb(TEXT),
                                    )
                                    .corner_radii(px(6.)),
                                );
                                window.set_cursor_style(CursorStyle::PointingHand, &hitbox);
                                let fraction_at = move |position: Point<Pixels>| {
                                    f64::from((position.x - track.left()) / track.size.width)
                                };
                                let down_entity = entity.clone();
                                let down_dragging = dragging.clone();
                                window.on_mouse_event(
                                    move |event: &MouseDownEvent, phase, window, cx| {
                                        if phase == DispatchPhase::Bubble
                                            && event.button == MouseButton::Left
                                            && hitbox.is_hovered(window)
                                        {
                                            down_dragging.store(true, Ordering::Relaxed);
                                            let fraction = fraction_at(event.position);
                                            let _ = down_entity.update(cx, |this, cx| {
                                                this.seek_video(fraction, cx)
                                            });
                                        }
                                    },
                                );
                                let move_entity = entity.clone();
                                let move_dragging = dragging.clone();
                                window.on_mouse_event(
                                    move |event: &MouseMoveEvent, phase, _, cx| {
                                        if phase == DispatchPhase::Bubble
                                            && move_dragging.load(Ordering::Relaxed)
                                        {
                                            if event.pressed_button == Some(MouseButton::Left) {
                                                let fraction = fraction_at(event.position);
                                                let _ = move_entity.update(cx, |this, cx| {
                                                    this.seek_video(fraction, cx)
                                                });
                                            } else {
                                                move_dragging.store(false, Ordering::Relaxed);
                                            }
                                        }
                                    },
                                );
                                let up_dragging = dragging.clone();
                                window.on_mouse_event(move |event: &MouseUpEvent, _, _, _| {
                                    if event.button == MouseButton::Left {
                                        up_dragging.store(false, Ordering::Relaxed);
                                    }
                                });
                            },
                        )
                        .flex_1()
                        .min_w(px(40.))
                        .h(px(20.)),
                    )
                    .child(
                        div()
                            .flex_shrink_0()
                            .text_size(px(11.))
                            .text_color(rgb(SECONDARY))
                            .child(details.join(" · ")),
                    ),
            )
    }
}
