//! Transport-driven meter ballistics and themed per-channel dBFS bars.

use super::*;
use vnlens_audio::levels::Level;

const FLOOR: f32 = -60.;

#[derive(Clone, Copy, PartialEq)]
struct Channel {
    rms: f32,
    peak: f32,
    held: f32,
    hold_until: Option<Instant>,
}

impl Default for Channel {
    fn default() -> Self {
        Self {
            rms: FLOOR,
            peak: FLOOR,
            held: FLOOR,
            hold_until: None,
        }
    }
}

#[derive(Default)]
pub(super) struct Meter {
    updated: Option<Instant>,
    channels: Vec<Channel>,
}

impl Meter {
    /// Instant attack, 24 dB/s release, and a one-second peak hold. Empty input
    /// releases existing bars when the transport is paused or has ended.
    pub(super) fn update(&mut self, levels: &[Level], now: Instant) -> bool {
        let elapsed = self
            .updated
            .map_or(0., |time| now.duration_since(time).as_secs_f32());
        self.updated = Some(now);
        if !levels.is_empty() {
            self.channels.resize(levels.len(), Channel::default());
        }
        let mut changed = false;
        for (index, channel) in self.channels.iter_mut().enumerate() {
            let before = *channel;
            let level = levels.get(index).copied().unwrap_or_default();
            channel.rms = level.rms_dbfs.max(FLOOR).max(channel.rms - 24. * elapsed);
            channel.peak = level.peak_dbfs.max(FLOOR).max(channel.peak - 24. * elapsed);
            if level.peak_dbfs >= channel.held && level.peak_dbfs > FLOOR {
                channel.held = level.peak_dbfs;
                channel.hold_until = Some(now + Duration::from_secs(1));
            } else if channel.hold_until.is_none_or(|time| now >= time) {
                let release = channel.hold_until.map_or(elapsed, |time| {
                    elapsed.min(now.duration_since(time).as_secs_f32())
                });
                channel.held = channel.peak.max(channel.held - 12. * release);
            }
            changed |= channel.rms != before.rms
                || channel.peak != before.peak
                || channel.held != before.held;
        }
        changed
    }

    pub(super) fn height(channels: usize) -> Pixels {
        px(24. + channels as f32 * 24.)
    }

    pub(super) fn render(&self, count: usize) -> impl IntoElement {
        let channels = self.channels.clone();
        canvas(
            |_, _, _| (),
            move |bounds, _, window, cx| {
                let left = bounds.left() + px(28.);
                let right = bounds.right() - px(94.);
                let width = right - left;
                if width <= px(0.) {
                    return;
                }
                let mut previous = left - px(40.);
                for db in [-60., -48., -36., -24., -12., 0.] {
                    let x = left + width * fraction(db);
                    if x - previous < px(34.) {
                        continue;
                    }
                    previous = x;
                    super::audio_view::label(
                        format!("{db:.0}"),
                        point(x - px(5.), bounds.top()),
                        window,
                        cx,
                    );
                }
                super::audio_view::label(
                    "RMS/Peak dBFS".into(),
                    point(right + px(7.), bounds.top()),
                    window,
                    cx,
                );
                for index in 0..count {
                    let channel = channels.get(index).copied().unwrap_or_default();
                    let top = bounds.top() + px(20. + index as f32 * 24.);
                    let bar = Bounds::new(point(left, top), size(width, px(10.)));
                    if !bar.intersects(&window.content_mask().bounds) {
                        continue;
                    }
                    super::audio_view::label(
                        super::audio_view::channel_label(index, count),
                        point(bounds.left() + px(8.), top - px(2.)),
                        window,
                        cx,
                    );
                    window.paint_quad(fill(bar, rgb(BORDER)).corner_radii(px(2.)));
                    for (start, end, color) in [
                        (FLOOR, -12_f32, 0x34c759),
                        (-12., -3., 0xffcc00),
                        (-3., 0., 0xff453a),
                    ] {
                        for (level, opacity) in [(channel.peak, 0.3), (channel.rms, 1.)] {
                            let end = end.min(level);
                            if end <= start {
                                continue;
                            }
                            let color = Rgba {
                                a: opacity,
                                ..rgb(color)
                            };
                            window.paint_quad(fill(
                                Bounds::new(
                                    point(left + width * fraction(start), top),
                                    size(width * (fraction(end) - fraction(start)), px(10.)),
                                ),
                                color,
                            ));
                        }
                    }
                    if channel.peak > FLOOR {
                        window.paint_quad(fill(
                            Bounds::new(
                                point(
                                    (left + width * fraction(channel.peak)).min(right - px(1.)),
                                    top,
                                ),
                                size(px(1.), px(10.)),
                            ),
                            rgb(super::TEXT),
                        ));
                    }
                    if channel.held > FLOOR {
                        window.paint_quad(fill(
                            Bounds::new(
                                point(
                                    (left + width * fraction(channel.held)).min(right - px(2.)),
                                    top - px(2.),
                                ),
                                size(px(2.), px(14.)),
                            ),
                            rgb(if channel.held >= 0. {
                                0xff453a
                            } else {
                                0xffd166
                            }),
                        ));
                    }
                    super::audio_view::label(
                        format!("{} / {}", reading(channel.rms), reading(channel.peak)),
                        point(right + px(7.), top - px(2.)),
                        window,
                        cx,
                    );
                }
            },
        )
        .w_full()
        .h(Self::height(count))
        .flex_shrink_0()
    }
}

fn fraction(db: f32) -> f32 {
    ((db - FLOOR) / -FLOOR).clamp(0., 1.)
}

fn reading(db: f32) -> String {
    if db <= FLOOR {
        "≤−60".into()
    } else {
        format!("{db:.1}")
    }
}
