//! Model inspector with orbit, pan, zoom, fit and wireframe controls.
use super::view::{button, tooltip};
use super::*;
use crate::model::{Camera, Worker};
use std::sync::Mutex;

type Drag = Option<(Point<Pixels>, Camera, bool)>;
pub(super) struct ModelPreview {
    model: Arc<vnlens_model::Model>,
    worker: Worker,
    image: Option<Arc<RenderImage>>,
    drag: Arc<Mutex<Drag>>,
}
impl ModelPreview {
    pub(super) fn new(model: vnlens_model::Model) -> anyhow::Result<Self> {
        let model = Arc::new(model);
        Ok(Self {
            worker: Worker::new(model.clone())?,
            model,
            image: None,
            drag: Arc::default(),
        })
    }
    pub(super) fn release(self, cx: &mut App) {
        if let Some(image) = self.image {
            cx.defer(move |cx| cx.drop_image(image, None));
        }
    }
}

impl Workspace {
    pub(super) fn tick_model(&mut self, cx: &mut Context<Self>) {
        let Some(model) = self.preview.as_mut().and_then(|p| p.model.as_mut()) else {
            return;
        };
        let mut error = None;
        for result in model.worker.frames.try_iter() {
            match result {
                Ok(image) => {
                    if let Some(old) = model.image.replace(image) {
                        cx.defer(move |cx| cx.drop_image(old, None));
                    }
                    self.preview_failed = false;
                    cx.notify();
                }
                Err(e) => error = Some(e),
            }
        }
        if let Some(error) = error {
            self.preview_failed = true;
            self.error(format!("Model preview: {error:#}"));
            cx.notify();
        }
    }

    pub(super) fn model_preview(&self, cx: &mut Context<Self>) -> AnyElement {
        let Some(model) = self.preview.as_ref().and_then(|p| p.model.as_ref()) else {
            return div().into_any_element();
        };
        let control = model.worker.control.clone();
        let measure = control.clone();
        let image = model.image.clone();
        let drag = model.drag.clone();
        let canvas = canvas(
            move |bounds, window, _| {
                let scale = window.scale_factor();
                measure.change(|view| {
                    view.size = [
                        (f32::from(bounds.size.width) * scale).round().max(0.) as u32,
                        (f32::from(bounds.size.height) * scale).round().max(0.) as u32,
                    ]
                });
                window.insert_hitbox(bounds, HitboxBehavior::Normal)
            },
            move |bounds, hitbox, window, _| {
                if let Some(image) = image.clone() {
                    window.with_content_mask(Some(ContentMask { bounds }), |window| {
                        if let Err(error) =
                            window.paint_image(bounds, Corners::default(), image, 0, false)
                        {
                            tracing::error!(%error,"Cannot paint model preview");
                        }
                    });
                }
                let view = window.current_view();
                let wheel_control = control.clone();
                let wheel_hitbox = hitbox.clone();
                window.on_mouse_event(move |event: &ScrollWheelEvent, phase, window, cx| {
                    if phase != DispatchPhase::Capture || !wheel_hitbox.should_handle_scroll(window)
                    {
                        return;
                    }
                    let delta = f32::from(event.delta.pixel_delta(window.line_height()).y);
                    wheel_control.change(|v| {
                        v.camera.distance =
                            (v.camera.distance * (-delta * 0.006).exp()).clamp(0.05, 100_000.)
                    });
                    cx.notify(view);
                    cx.stop_propagation();
                });
                let down_control = control.clone();
                let down_drag = drag.clone();
                let down_hitbox = hitbox.clone();
                window.on_mouse_event(move |event: &MouseDownEvent, phase, window, cx| {
                    if phase != DispatchPhase::Bubble
                        || !down_hitbox.is_hovered(window)
                        || !matches!(
                            event.button,
                            MouseButton::Left | MouseButton::Right | MouseButton::Middle
                        )
                    {
                        return;
                    }
                    if let (Ok(view), Ok(mut drag)) = (down_control.view.lock(), down_drag.lock()) {
                        *drag = Some((
                            event.position,
                            view.camera,
                            event.button != MouseButton::Left || event.modifiers.shift,
                        ));
                    }
                    cx.stop_propagation();
                });
                let move_control = control.clone();
                let move_drag = drag.clone();
                window.on_mouse_event(move |event: &MouseMoveEvent, phase, _, cx| {
                    if phase != DispatchPhase::Bubble {
                        return;
                    }
                    let Some((start, camera, pan)) = move_drag.lock().ok().and_then(|d| *d) else {
                        return;
                    };
                    if !event.dragging() {
                        if let Ok(mut drag) = move_drag.lock() {
                            *drag = None;
                        }
                        return;
                    }
                    let delta = event.position - start;
                    move_control.change(|v| {
                        v.camera = camera;
                        if pan {
                            let aspect = (f32::from(bounds.size.height)
                                / f32::from(bounds.size.width).max(1.))
                            .max(1.);
                            let scale =
                                camera.distance * aspect * 2. * std::f32::consts::FRAC_PI_8.tan()
                                    / f32::from(bounds.size.height).max(1.);
                            v.camera.pan = [
                                camera.pan[0] + f32::from(delta.x) * scale,
                                camera.pan[1] - f32::from(delta.y) * scale,
                            ];
                        } else {
                            v.camera.yaw = camera.yaw + f32::from(delta.x) * 0.008;
                            v.camera.pitch =
                                (camera.pitch + f32::from(delta.y) * 0.008).clamp(-1.55, 1.55);
                        }
                    });
                    cx.notify(view);
                    cx.stop_propagation();
                });
                let up_drag = drag.clone();
                window.on_mouse_event(move |_: &MouseUpEvent, phase, _, _| {
                    if phase == DispatchPhase::Bubble
                        && let Ok(mut drag) = up_drag.lock()
                    {
                        *drag = None;
                    }
                });
            },
        )
        .absolute()
        .inset_0();
        let wireframe = model
            .worker
            .control
            .view
            .lock()
            .is_ok_and(|v| v.camera.wireframe);
        let wire = model.worker.control.clone();
        let colors = model.worker.control.clone();
        let vertex_colors = colors.view.lock().is_ok_and(|v| v.camera.vertex_colors);
        let fit = model.worker.control.clone();
        let triangles = model
            .model
            .meshes
            .iter()
            .map(|m| m.indices.len() / 3)
            .sum::<usize>();
        div()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .flex()
            .flex_col()
            .child(
                div()
                    .px_3()
                    .py_1()
                    .text_size(px(11.))
                    .text_color(rgb(SECONDARY))
                    .child(format!(
                        "{} vertices · {triangles} triangles",
                        model.model.vertices.len()
                    )),
            )
            .child(div().relative().flex_1().min_h_0().child(canvas))
            .child(
                div()
                    .h(px(40.))
                    .px_3()
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().flex_1())
                    .child(
                        button("model-colors", "Colors", vertex_colors, true)
                            .tooltip(tooltip("Show native vertex colors"))
                            .on_click(cx.listener(move |_, _, _, cx| {
                                colors.change(|v| v.camera.vertex_colors = !v.camera.vertex_colors);
                                cx.notify();
                            })),
                    )
                    .child(
                        button(
                            "model-wireframe",
                            if wireframe { "Solid" } else { "Wireframe" },
                            false,
                            true,
                        )
                        .tooltip(tooltip("Switch shaded and wireframe rendering"))
                        .on_click(cx.listener(move |_, _, _, cx| {
                            wire.change(|v| v.camera.wireframe = !v.camera.wireframe);
                            cx.notify();
                        })),
                    )
                    .child(
                        button("model-fit", "Fit", false, true)
                            .tooltip(tooltip(
                                "Reset camera · drag to orbit · right-drag to pan · scroll to zoom",
                            ))
                            .on_click(cx.listener(move |_, _, _, cx| {
                                fit.change(|v| {
                                    v.camera = Camera {
                                        wireframe: v.camera.wireframe,
                                        vertex_colors: v.camera.vertex_colors,
                                        ..Default::default()
                                    }
                                });
                                cx.notify();
                            })),
                    ),
            )
            .into_any_element()
    }
}
