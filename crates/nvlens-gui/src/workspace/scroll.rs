//! Wheel scrolling with Ctrl selecting the horizontal axis.

use gpui::{prelude::*, *};

pub(super) fn wheel(
    child: impl IntoElement,
    vertical: Option<ScrollHandle>,
    horizontal: Option<ScrollHandle>,
) -> WheelScroll {
    WheelScroll {
        child: child.into_any_element(),
        vertical,
        horizontal,
    }
}

pub(super) struct WheelScroll {
    child: AnyElement,
    vertical: Option<ScrollHandle>,
    horizontal: Option<ScrollHandle>,
}

impl IntoElement for WheelScroll {
    type Element = Self;

    fn into_element(self) -> Self {
        self
    }
}

impl Element for WheelScroll {
    type RequestLayoutState = ();
    type PrepaintState = Hitbox;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static std::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _: Option<&GlobalElementId>,
        _: Option<&InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, ()) {
        (self.child.request_layout(window, cx), ())
    }

    fn prepaint(
        &mut self,
        _: Option<&GlobalElementId>,
        _: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        _: &mut (),
        window: &mut Window,
        cx: &mut App,
    ) -> Hitbox {
        self.child.prepaint(window, cx);
        window.insert_hitbox(bounds, HitboxBehavior::Normal)
    }

    fn paint(
        &mut self,
        _: Option<&GlobalElementId>,
        _: Option<&InspectorElementId>,
        _: Bounds<Pixels>,
        _: &mut (),
        hitbox: &mut Hitbox,
        window: &mut Window,
        cx: &mut App,
    ) {
        let hitbox = hitbox.clone();
        let vertical = self.vertical.clone();
        let horizontal = self.horizontal.clone();
        let line_height = window.line_height();
        let view = window.current_view();
        self.child.paint(window, cx);
        // Capture runs before native scroll handlers; hit testing excludes overlays.
        // Register after children so the innermost scroll region handles the event first.
        window.on_mouse_event(move |event: &ScrollWheelEvent, phase, window, cx| {
            if phase != DispatchPhase::Capture || !hitbox.should_handle_scroll(window) {
                return;
            }
            let handle = if event.modifiers.control {
                &horizontal
            } else {
                &vertical
            };
            if let Some(handle) = handle {
                let delta = event.delta.pixel_delta(line_height);
                let mut offset = handle.offset();
                let maximum = handle.max_offset();
                if event.modifiers.control {
                    let delta = if delta.x.abs() > delta.y.abs() {
                        delta.x
                    } else {
                        delta.y
                    };
                    offset.x = (offset.x + delta).clamp(-maximum.width, px(0.));
                } else {
                    offset.y = (offset.y + delta.y).clamp(-maximum.height, px(0.));
                }
                if offset != handle.offset() {
                    handle.set_offset(offset);
                    cx.notify(view);
                }
            }
            cx.stop_propagation();
        });
    }
}
