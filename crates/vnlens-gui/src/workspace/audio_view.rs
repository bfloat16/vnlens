//! Mel spectrogram presentation and transport. Analysis and decoding stay in
//! vnlens-audio; textures are prepared off the UI thread without font access.

use super::*;
use vnlens_audio::{
    Pcm,
    levels::LevelEnvelope,
    spectrogram::{MelSpectrogram, hz_to_mel},
};

const RANGE_DB: f32 = 100.;
const LEFT: f32 = 28.;
const RIGHT: f32 = 94.;
const TOP: f32 = 16.;
const BOTTOM: f32 = 28.;
const GAP: f32 = 10.;

pub(super) struct AudioPreview {
    pcm: Pcm,
    levels: LevelEnvelope,
    channels: Vec<Arc<RenderImage>>,
}

impl AudioPreview {
    pub(super) fn new(tag: &str, bytes: &[u8], cancelled: &AtomicBool) -> anyhow::Result<Self> {
        let pcm = vnlens_audio::decode_cancellable_as(tag, bytes, cancelled)?;
        // These are texture resolution, not limits on duration or channel count.
        let mel = MelSpectrogram::new(&pcm, 1536, 192, cancelled)?;
        let mut channels = Vec::with_capacity(mel.channels.len());
        if mel.columns != 0 {
            for channel in mel.channels {
                let mut pixels = Vec::with_capacity(channel.len() * 4);
                for band in (0..mel.bands).rev() {
                    if cancelled.load(Ordering::Relaxed) {
                        return Err(vnlens_core::Error::Cancelled.into());
                    }
                    for column in 0..mel.columns {
                        let [r, g, b] = color(channel[column * mel.bands + band]);
                        // GPUI RenderImage expects BGRA bytes.
                        pixels.extend([b, g, r, 255]);
                    }
                }
                let pixels = image::RgbaImage::from_raw(
                    u32::try_from(mel.columns)?,
                    u32::try_from(mel.bands)?,
                    pixels,
                )
                .ok_or_else(|| anyhow::anyhow!("Invalid spectrogram texture dimensions"))?;
                channels.push(Arc::new(RenderImage::new([image::Frame::new(pixels)])));
            }
        }
        let levels = LevelEnvelope::new(&pcm, cancelled)?;
        Ok(Self {
            pcm,
            levels,
            channels,
        })
    }

    pub(super) fn release(self, cx: &mut App) {
        // Defer until the active window has returned to App.windows so its
        // atlas is included; dropping CPU textures alone leaves GPU entries.
        cx.defer(move |cx| {
            for image in self.channels {
                cx.drop_image(image, None);
            }
        });
    }

    pub(super) fn duration(&self) -> f64 {
        self.pcm.samples.len() as f64
            / f64::from(self.pcm.meta.channels)
            / f64::from(self.pcm.meta.sample_rate)
    }
}

// Black/navy shadows, orange midtones and pale yellow highlights, matching the
// reference's spectral heat map. All channels share the same dB reference.
fn color(db: f32) -> [u8; 3] {
    const STOPS: [[f32; 3]; 6] = [
        [0., 0., 0.],
        [16., 30., 49.],
        [119., 54., 24.],
        [235., 112., 22.],
        [255., 202., 65.],
        [255., 255., 210.],
    ];
    let position = ((db + RANGE_DB) / RANGE_DB).clamp(0., 1.) * (STOPS.len() - 1) as f32;
    let index = (position as usize).min(STOPS.len() - 2);
    let fraction = position - index as f32;
    std::array::from_fn(|i| {
        (STOPS[index][i] + (STOPS[index + 1][i] - STOPS[index][i]) * fraction).round() as u8
    })
}

impl Workspace {
    pub(super) fn tick_audio(&mut self, cx: &mut Context<Self>) {
        let mut levels = Vec::new();
        let mut position = self.audio_position;
        if let Some(playback) = &self.playback
            && let Some(audio) = self
                .preview
                .as_ref()
                .and_then(|preview| preview.audio.as_ref())
        {
            position = if playback.player.empty() {
                audio.duration()
            } else {
                playback
                    .player
                    .get_pos()
                    .as_secs_f64()
                    .min(audio.duration())
            };
            if !playback.player.empty() && !playback.player.is_paused() {
                let end = Duration::from_secs_f64(position);
                // Include all blocks since the last tick so delayed UI frames
                // cannot discard a transient. A 100ms window steadies RMS.
                let start = Duration::from_secs_f64(self.audio_position.min(position))
                    .min(end.saturating_sub(Duration::from_millis(100)));
                levels = audio.levels.read(start, end);
            }
        }
        let changed = self.audio_meter.update(&levels, Instant::now());
        if position != self.audio_position || changed {
            self.audio_position = position;
            cx.notify();
        }
    }

    pub(super) fn toggle_audio(&mut self, cx: &mut Context<Self>) {
        if let Some(playback) = &self.playback
            && !playback.player.empty()
        {
            if playback.player.is_paused() {
                playback.player.play();
            } else {
                playback.player.pause();
            }
        } else {
            let Some(audio) = self
                .preview
                .as_ref()
                .and_then(|preview| preview.audio.as_ref())
            else {
                return;
            };
            if audio.duration() == 0. {
                return;
            }
            if self.playback.is_some() || self.audio_position >= audio.duration() {
                self.audio_position = 0.;
                self.audio_meter = super::level_meter::Meter::default();
            }
            // Cloning PCM only shares its Arc; opening the output device remains
            // a user-initiated action, independent of spectrogram generation.
            match crate::playback::Playback::new(
                audio.pcm.clone(),
                Duration::from_secs_f64(self.audio_position),
            ) {
                Ok(playback) => self.playback = Some(playback),
                Err(error) => self.error(format!("Audio playback: {error:#}")),
            }
        }
        cx.notify();
    }

    fn seek_audio(&mut self, fraction: f64, cx: &mut Context<Self>) {
        let Some(audio) = self
            .preview
            .as_ref()
            .and_then(|preview| preview.audio.as_ref())
        else {
            return;
        };
        self.audio_position = audio.duration() * fraction.clamp(0., 1.);
        self.audio_meter = super::level_meter::Meter::default();
        if let Some(playback) = &self.playback {
            if playback.player.empty() {
                self.playback = None;
            } else if let Err(error) = playback
                .player
                .try_seek(Duration::from_secs_f64(self.audio_position))
            {
                self.error(format!("Audio seek: {error:#}"));
            }
        }
        cx.notify();
    }

    pub(super) fn audio_view(
        &self,
        audio: &AudioPreview,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let duration = audio.duration();
        let position = self
            .playback
            .as_ref()
            .map_or(self.audio_position, |playback| {
                if playback.player.empty() {
                    duration
                } else {
                    playback.player.get_pos().as_secs_f64().min(duration)
                }
            });
        let playing = self
            .playback
            .as_ref()
            .is_some_and(|p| !p.player.is_paused() && !p.player.empty());
        let channels = audio.channels.clone();
        let sample_rate = audio.pcm.meta.sample_rate;
        let count = channels.len();
        let entity = cx.entity().downgrade();
        div()
            .size_full()
            .flex()
            .flex_col()
            .min_h_0()
            .min_w_0()
            .px_2()
            .child(
                div()
                    .id("audio-spectrogram-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .track_scroll(&self.preview_scroll.0.borrow().base_handle)
                    .child(
                        div()
                            .h_full()
                            .min_h(
                                px(count.max(1) as f32 * 150. + TOP + BOTTOM)
                                    + super::level_meter::Meter::height(count),
                            )
                            .flex()
                            .flex_col()
                            .child(
                                canvas(
                                    |bounds, window, _| {
                                        window.insert_hitbox(bounds, HitboxBehavior::Normal)
                                    },
                                    move |bounds, hitbox, window, cx| {
                                        let plot = plot_bounds(bounds);
                                        if plot.size.width <= px(0.) || plot.size.height <= px(0.) {
                                            return;
                                        }
                                        paint_plot(
                                            plot,
                                            &channels,
                                            sample_rate,
                                            duration,
                                            position,
                                            window,
                                            cx,
                                        );
                                        let entity = entity.clone();
                                        window.set_cursor_style(CursorStyle::Crosshair, &hitbox);
                                        window.on_mouse_event(
                                            move |event: &MouseDownEvent, phase, window, cx| {
                                                if phase == DispatchPhase::Bubble
                                                    && event.button == MouseButton::Left
                                                    && hitbox.is_hovered(window)
                                                    && plot.contains(&event.position)
                                                {
                                                    let fraction = f64::from(
                                                        (event.position.x - plot.left())
                                                            / plot.size.width,
                                                    );
                                                    let _ = entity.update(cx, |this, cx| {
                                                        this.seek_audio(fraction, cx)
                                                    });
                                                }
                                            },
                                        );
                                    },
                                )
                                .w_full()
                                .flex_1()
                                .min_h_0(),
                            )
                            .child(self.audio_meter.render(count)),
                    ),
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
                            .id("audio-play")
                            .size(px(32.))
                            .flex_shrink_0()
                            .rounded_full()
                            .flex()
                            .items_center()
                            .justify_center()
                            .bg(rgb(if duration > 0. { ACCENT } else { CONTROL }))
                            .when(duration > 0., |button| {
                                button
                                    .cursor_pointer()
                                    .hover(|style| style.bg(rgb(ACCENT_HOVER)))
                                    .on_click(cx.listener(|this, _, _, cx| this.toggle_audio(cx)))
                            })
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
                                if duration > 0. { TEXT } else { DISABLED },
                            )),
                    )
                    .child(
                        div()
                            .font_family(MONO_FONT)
                            .text_size(px(11.))
                            .child(time(position))
                            .child(
                                div()
                                    .text_color(rgb(SECONDARY))
                                    .child(format!(" / {}", time(duration))),
                            )
                            .flex(),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(rgb(SECONDARY))
                            .child(format!(
                                "{} Hz · {} · Mel",
                                sample_rate,
                                match audio.pcm.meta.channels {
                                    1 => "Mono".to_owned(),
                                    2 => "Stereo".to_owned(),
                                    channels => format!("{channels} ch"),
                                }
                            )),
                    ),
            )
    }
}

pub(super) fn time(seconds: f64) -> String {
    let minutes = (seconds / 60.).floor() as u64;
    format!("{minutes}:{:04.1}", seconds % 60.)
}

fn plot_bounds(bounds: Bounds<Pixels>) -> Bounds<Pixels> {
    Bounds::new(
        bounds.origin + point(px(LEFT), px(TOP)),
        size(
            bounds.size.width - px(LEFT + RIGHT),
            bounds.size.height - px(TOP + BOTTOM),
        ),
    )
}

pub(super) fn label(text: String, origin: Point<Pixels>, window: &mut Window, cx: &mut App) {
    let style = TextStyle {
        font_family: UI_FONT.into(),
        color: rgb(SECONDARY).into(),
        ..Default::default()
    };
    let line = window.text_system().shape_line(
        text.clone().into(),
        px(10.),
        &[style.to_run(text.len())],
        None,
    );
    if let Err(error) = line.paint(origin, px(14.), window, cx) {
        tracing::error!(%error, "Cannot paint spectrogram label");
    }
}

pub(super) fn channel_label(index: usize, count: usize) -> String {
    match count {
        1 => "M".into(),
        2 => {
            if index == 0 {
                "L".into()
            } else {
                "R".into()
            }
        }
        _ => (index + 1).to_string(),
    }
}

fn paint_plot(
    plot: Bounds<Pixels>,
    channels: &[Arc<RenderImage>],
    rate: u32,
    duration: f64,
    position: f64,
    window: &mut Window,
    cx: &mut App,
) {
    if channels.is_empty() {
        return;
    }
    let height = (plot.size.height - px(GAP * (channels.len() - 1) as f32)) / channels.len() as f32;
    let nyquist = f64::from(rate) / 2.;
    let maximum = hz_to_mel(nyquist);
    for (index, image) in channels.iter().enumerate() {
        let bounds = Bounds::new(
            plot.origin + point(px(0.), (height + px(GAP)) * index as f32),
            size(plot.size.width, height),
        );
        if !bounds.intersects(&window.content_mask().bounds) {
            continue;
        }
        if let Err(error) = window.paint_image(bounds, Corners::default(), image.clone(), 0, false)
        {
            tracing::error!(%error, "Cannot paint Mel spectrogram");
        }
        let name = channel_label(index, channels.len());
        label(
            name,
            point(plot.left() - px(20.), bounds.top() + height / 2. - px(7.)),
            window,
            cx,
        );
        // Label spacing follows the actual panel height; every frequency maps
        // through the same Mel transform as the filter bank.
        let mut previous = bounds.top() - px(20.);
        for hz in
            std::iter::once(nyquist).chain([20000., 10000., 5000., 2000., 1000., 500., 200., 0.])
        {
            if hz > nyquist {
                continue;
            }
            let y = bounds.bottom() - height * (hz_to_mel(hz) / maximum) as f32;
            if y - previous < px(20.) {
                continue;
            }
            previous = y;
            window.paint_quad(fill(
                Bounds::new(point(bounds.right(), y), size(px(4.), px(1.))),
                rgb(BORDER),
            ));
            let text = if hz >= 1000. {
                format!("{:.1}k", hz / 1000.)
            } else {
                format!("{hz:.0}")
            };
            label(text, point(bounds.right() + px(7.), y - px(7.)), window, cx);
        }
    }
    label(
        "Hz".into(),
        point(plot.right() + px(7.), plot.bottom() + px(7.)),
        window,
        cx,
    );
    let ticks = (f32::from(plot.size.width) / 90.).floor().max(1.) as usize;
    for index in 0..=ticks {
        let fraction = index as f32 / ticks as f32;
        let x = plot.left() + plot.size.width * fraction;
        window.paint_quad(fill(
            Bounds::new(point(x, plot.bottom()), size(px(1.), px(4.))),
            rgb(BORDER),
        ));
        let text = format!("{:.1}s", duration * f64::from(fraction));
        // Keep both end labels inside the time axis.
        let offset = if index == ticks {
            text.len() as f32 * 5.5
        } else {
            0.
        };
        label(
            text,
            point(x - px(offset), plot.bottom() + px(7.)),
            window,
            cx,
        );
    }
    let x = plot.left()
        + plot.size.width
            * if duration > 0. {
                (position / duration).clamp(0., 1.) as f32
            } else {
                0.
            };
    window.paint_quad(fill(
        Bounds::new(
            point(x.min(plot.right() - px(1.)), plot.top()),
            size(px(1.), plot.size.height),
        ),
        rgb(0xffd166),
    ));
    window.paint_quad(
        fill(
            Bounds::new(point(x - px(3.), plot.top() - px(6.)), size(px(7.), px(5.))),
            rgb(0xffd166),
        )
        .corner_radii(px(2.)),
    );
    let legend_x = plot.right() + px(50.);
    let steps = 256;
    for step in 0..steps {
        let fraction = step as f32 / steps as f32;
        let [r, g, b] = color(-fraction * RANGE_DB);
        let color = gpui::Rgba {
            r: f32::from(r) / 255.,
            g: f32::from(g) / 255.,
            b: f32::from(b) / 255.,
            a: 1.,
        };
        window.paint_quad(fill(
            Bounds::new(
                point(legend_x, plot.top() + plot.size.height * fraction),
                size(px(5.), plot.size.height / steps as f32 + px(1.)),
            ),
            color,
        ));
    }
    label(
        "dB rel.".into(),
        point(legend_x, plot.top() - px(15.)),
        window,
        cx,
    );
    for db in [0, 20, 40, 60, 80, 100] {
        let y = plot.top() + plot.size.height * (db as f32 / RANGE_DB);
        label(
            if db == 0 {
                "0".into()
            } else {
                format!("−{db}")
            },
            point(legend_x + px(9.), y - px(7.)),
            window,
            cx,
        );
    }
}
