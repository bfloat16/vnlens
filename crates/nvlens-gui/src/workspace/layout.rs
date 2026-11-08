//! Coordinated preview resizing and column scrolling, driven by window frames.

use std::time::{Duration, Instant};

use gpui::{Pixels, Window, ease_in_out, point, px};

use super::Workspace;

const DURATION: Duration = Duration::from_millis(220);

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct Layout {
    pub inset: Pixels,
    pub scroll: Pixels,
}

#[derive(Debug, Default)]
pub(super) struct Motion {
    from: Layout,
    target: Layout,
    started: Option<Instant>,
}

impl Motion {
    fn retarget(&mut self, from: Layout, target: Layout, now: Instant, animate: bool) {
        self.from = from;
        self.target = target;
        self.started = (animate && from != target).then_some(now);
    }

    fn sample(&mut self, now: Instant) -> (Layout, bool) {
        let Some(started) = self.started else {
            return (self.target, false);
        };
        let elapsed = now.saturating_duration_since(started);
        if elapsed >= DURATION {
            self.started = None;
            return (self.target, false);
        }
        let progress = ease_in_out(elapsed.as_secs_f32() / DURATION.as_secs_f32());
        (
            Layout {
                inset: self.from.inset + (self.target.inset - self.from.inset) * progress,
                scroll: self.from.scroll + (self.target.scroll - self.from.scroll) * progress,
            },
            true,
        )
    }
}

fn target_layout(
    viewport: Pixels,
    left: Pixels,
    column_width: Pixels,
    content_width: Pixels,
    scroll: Pixels,
    preview: bool,
    manual_width: Option<Pixels>,
) -> Layout {
    let inset = if preview {
        manual_width
            .unwrap_or(viewport - column_width)
            .clamp(px(180.), (viewport - px(180.)).max(px(180.)))
    } else {
        px(0.)
    };
    let browser_width = viewport - inset;
    let right = left + column_width;
    let scroll = if (preview && manual_width.is_none())
        || left + scroll < px(0.)
        || column_width > browser_width
    {
        -left
    } else if right + scroll > browser_width {
        browser_width - right
    } else {
        scroll
    };
    Layout {
        inset,
        scroll: scroll.clamp(-(content_width - browser_width).max(px(0.)), px(0.)),
    }
}

impl Workspace {
    pub(super) fn animate_layout(&mut self, window: &Window) -> Pixels {
        let viewport = window.viewport_size().width;
        let resized = self.viewport_width != viewport;
        self.viewport_width = viewport;
        let reveal = self.reveal_column.take();
        let preview = self.show_inspector && self.selection.is_some() && self.preview.is_some();
        let depth = self.selection.map(|(depth, _)| depth).unwrap_or_else(|| {
            reveal.unwrap_or_else(|| {
                if self.active + 1 < self.columns.len() {
                    self.active + 1
                } else {
                    self.active
                }
            })
        });
        let depth = depth.min(self.columns.len() - 1);
        let left = self
            .columns
            .iter()
            .take(depth)
            .fold(px(0.), |sum, column| sum + column.width);
        // The browser has a small trailing spacer after its last column.
        let content_width = self
            .columns
            .iter()
            .fold(px(24.), |sum, column| sum + column.width);
        let offset = self.strip_scroll.offset();
        let target = target_layout(
            viewport,
            left,
            self.columns[depth].width,
            content_width,
            offset.x,
            preview,
            self.inspector_width,
        );
        let now = Instant::now();
        let moving = self.layout.started.is_some();
        let (current, _) = self.layout.sample(now);
        let changed = resized
            || reveal.is_some()
            || target.inset != self.layout.target.inset
            || self.resizing.is_some();
        if changed {
            self.layout.retarget(
                Layout {
                    inset: current.inset,
                    scroll: offset.x,
                },
                target,
                now,
                !resized && self.resizing.is_none(),
            );
        }
        let (current, animating) = self.layout.sample(now);
        if changed || moving {
            let maximum = (content_width - (viewport - current.inset)).max(px(0.));
            self.strip_scroll
                .set_offset(point(current.scroll.clamp(-maximum, px(0.)), offset.y));
        }
        if animating {
            window.request_animation_frame();
        }
        current.inset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_reserves_one_column_and_closing_reveals_parents() {
        let opened = target_layout(px(1280.), px(880.), px(220.), px(1124.), px(0.), true, None);
        assert_eq!(
            opened,
            Layout {
                inset: px(1060.),
                scroll: px(-880.)
            }
        );
        let closed = target_layout(
            px(1280.),
            px(880.),
            px(220.),
            px(1124.),
            opened.scroll,
            false,
            None,
        );
        assert_eq!(closed, Layout::default());
        let dragged = target_layout(
            px(1280.),
            px(880.),
            px(220.),
            px(1124.),
            px(-500.),
            true,
            Some(px(1000.)),
        );
        assert_eq!(
            dragged,
            Layout {
                inset: px(1000.),
                scroll: px(-820.)
            }
        );
    }

    #[test]
    fn interrupted_motion_continues_from_displayed_position_and_stops() {
        let now = Instant::now();
        let target = Layout {
            inset: px(1000.),
            scroll: px(-800.),
        };
        let mut motion = Motion::default();
        motion.retarget(Layout::default(), target, now, true);
        let (halfway, running) = motion.sample(now + DURATION / 2);
        assert!(running);
        assert_eq!(
            halfway,
            Layout {
                inset: px(500.),
                scroll: px(-400.)
            }
        );
        motion.retarget(halfway, Layout::default(), now + DURATION / 2, true);
        assert_eq!(motion.sample(now + DURATION / 2), (halfway, true));
        assert_eq!(
            motion.sample(now + DURATION * 2),
            (Layout::default(), false)
        );
        assert!(motion.started.is_none());
        motion.retarget(Layout::default(), target, now, false);
        assert_eq!(motion.sample(now), (target, false));
    }
}
