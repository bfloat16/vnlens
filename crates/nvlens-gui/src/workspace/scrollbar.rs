//! Themed scrollbars for columns and previews, using current bounds on either axis.

use std::{cell::Cell, rc::Rc};

use gpui::{prelude::*, *};

#[derive(Default)]
pub(super) struct Scrollbar {
    grab: Rc<Cell<Option<f32>>>,
}

#[derive(Clone, Copy, Debug)]
struct Thumb {
    start: Pixels,
    length: Pixels,
    travel: Pixels,
    maximum: Pixels,
}

impl Thumb {
    fn new(track: Pixels, viewport: Pixels, maximum: Pixels, offset: Pixels) -> Option<Self> {
        if track <= px(0.) || viewport <= px(0.) || maximum <= px(0.) {
            return None;
        }
        let length = (track * (viewport / (viewport + maximum)))
            .max(px(24.))
            .min(track);
        let travel = track - length;
        if travel <= px(0.) {
            return None;
        }
        Some(Self {
            start: travel * (-offset / maximum).clamp(0., 1.),
            length,
            travel,
            maximum,
        })
    }

    fn offset(self, pointer: Pixels, grab: f32) -> Pixels {
        -self.maximum * ((pointer - self.length * grab) / self.travel).clamp(0., 1.)
    }

    fn bounds(self, track: Bounds<Pixels>, axis: Axis) -> Bounds<Pixels> {
        Bounds::new(
            track
                .origin
                .apply_along(axis, |origin| origin + self.start)
                .apply_along(axis.invert(), |origin| origin + px(2.)),
            track
                .size
                .apply_along(axis, |_| self.length)
                .apply_along(axis.invert(), |length| length - px(4.)),
        )
    }
}

impl Scrollbar {
    pub(super) fn render(
        &self,
        handle: ScrollHandle,
        visible: bool,
        axis: Axis,
    ) -> impl IntoElement + Styled {
        let measure_handle = handle.clone();
        let measure_grab = self.grab.clone();
        let grab = self.grab.clone();
        canvas(
            move |bounds, window, _| {
                if !visible && measure_grab.get().is_none() {
                    return None;
                }
                // This runs after the list's prepaint, so filtering, window
                // resizing and scrolling use the same frame's geometry.
                let thumb = Thumb::new(
                    bounds.size.along(axis),
                    measure_handle.bounds().size.along(axis),
                    measure_handle.max_offset().along(axis),
                    measure_handle.offset().along(axis),
                )?;
                let hitbox = window.insert_hitbox(bounds, HitboxBehavior::Normal);
                Some((thumb, hitbox))
            },
            move |bounds, state, window, _| {
                let Some((thumb, hitbox)) = state else {
                    grab.set(None);
                    return;
                };
                let dragging = grab.get().is_some();
                let hovered = hitbox.is_hovered(window);
                window.set_cursor_style(CursorStyle::Arrow, &hitbox);
                let thumb_bounds = thumb.bounds(bounds, axis);
                window.paint_quad(fill(bounds, rgba(0xffffff0a)).corner_radii(px(5.)));
                window.paint_quad(
                    fill(
                        thumb_bounds,
                        rgb(if dragging {
                            super::ACCENT
                        } else if hovered {
                            super::SECONDARY
                        } else {
                            0x6b6b73
                        }),
                    )
                    .corner_radii(px(3.)),
                );
                let view = window.current_view();
                let down_grab = grab.clone();
                let down_handle = handle.clone();
                let down_hitbox = hitbox.clone();
                window.on_mouse_event(move |event: &MouseDownEvent, phase, window, cx| {
                    if phase != DispatchPhase::Bubble
                        || event.button != MouseButton::Left
                        || !down_hitbox.is_hovered(window)
                    {
                        return;
                    }
                    let fraction = if thumb_bounds.contains(&event.position) {
                        (event.position.along(axis) - thumb_bounds.origin.along(axis))
                            / thumb.length
                    } else {
                        0.5
                    };
                    down_grab.set(Some(fraction));
                    down_handle.set_offset(down_handle.offset().apply_along(axis, |_| {
                        thumb.offset((event.position - bounds.origin).along(axis), fraction)
                    }));
                    cx.notify(view);
                    cx.stop_propagation();
                });
                let move_grab = grab.clone();
                window.on_mouse_event(move |event: &MouseMoveEvent, phase, window, cx| {
                    if phase != DispatchPhase::Bubble {
                        return;
                    }
                    if let Some(fraction) = move_grab.get() {
                        if event.dragging() {
                            handle.set_offset(handle.offset().apply_along(axis, |_| {
                                thumb.offset((event.position - bounds.origin).along(axis), fraction)
                            }));
                        } else {
                            move_grab.set(None);
                        }
                        cx.notify(view);
                    } else if hovered != hitbox.is_hovered(window) {
                        cx.notify(view);
                    }
                });
                window.on_mouse_event(move |event: &MouseUpEvent, phase, _, cx| {
                    if phase == DispatchPhase::Capture
                        && event.button == MouseButton::Left
                        && grab.take().is_some()
                    {
                        cx.notify(view);
                    }
                });
            },
        )
        .absolute()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::rust_2024::test;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn thumb_tracks_scroll_limits_and_drag_position() {
        let thumb = Thumb::new(px(400.), px(500.), px(1500.), px(-750.)).unwrap();
        assert_eq!(thumb.length, px(100.));
        assert_eq!(thumb.start, px(150.));
        assert_eq!(
            thumb.offset(thumb.start + thumb.length * 0.25, 0.25),
            px(-750.)
        );
        assert_eq!(thumb.offset(px(-100.), 0.5), px(0.));
        assert_eq!(thumb.offset(px(1000.), 0.5), px(-1500.));
        let long = Thumb::new(px(400.), px(500.), px(1_000_000.), px(-1_000_000.)).unwrap();
        assert_eq!(long.length, px(24.));
        assert_eq!(long.start + long.length, px(400.));
        assert!(Thumb::new(px(400.), px(500.), px(0.), px(0.)).is_none());
        assert!(Thumb::new(px(10.), px(500.), px(100.), px(0.)).is_none());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn both_axes_position_the_thumb_and_preserve_the_other_scroll_offset() {
        for axis in [Axis::Vertical, Axis::Horizontal] {
            let track = Bounds::new(
                point(px(30.), px(60.)),
                size(px(10.), px(10.)).apply_along(axis, |_| px(400.)),
            );
            let thumb = Thumb::new(track.size.along(axis), px(500.), px(1500.), px(-750.)).unwrap();
            let bounds = thumb.bounds(track, axis);
            assert_eq!((bounds.origin - track.origin).along(axis), px(150.));
            assert_eq!(bounds.size.along(axis), px(100.));
            assert_eq!(bounds.size.along(axis.invert()), px(6.));
            let offset = point(px(-50.), px(-80.));
            let dragged = offset.apply_along(axis, |_| thumb.offset(px(400.), 0.5));
            assert_eq!(dragged.along(axis), px(-1500.));
            assert_eq!(dragged.along(axis.invert()), offset.along(axis.invert()));
        }
    }
}
