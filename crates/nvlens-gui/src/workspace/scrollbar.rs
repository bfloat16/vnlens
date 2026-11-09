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
                // This runs after the list's prepaint, so item loading, window
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
                            super::TERTIARY
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
