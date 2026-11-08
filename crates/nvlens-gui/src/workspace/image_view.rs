//! Image frame selection and a viewport camera. Pixel decoding stays in image;
//! frame tasks retain the displayed texture until the requested frame is ready.
use super::view::button;
use super::*;
use std::{cell::Cell, rc::Rc};

mod frames;

const ZOOM_DURATION: Duration = Duration::from_millis(180);

#[derive(Clone, Copy, Debug)]
struct ZoomMotion {
    from_scale: f32,
    to_scale: f32,
    from_origin: Point<Pixels>,
    to_origin: Point<Pixels>,
    started: Instant,
}

#[derive(Clone, Copy, Debug, Default)]
struct Camera {
    zoom: Option<f32>,
    pan: Point<Pixels>,
    viewport: Size<Pixels>,
    image: Size<Pixels>,
    motion: Option<ZoomMotion>,
}
impl Camera {
    fn scale(self) -> f32 {
        self.zoom.unwrap_or_else(|| {
            if self.image.width <= px(0.) || self.image.height <= px(0.) {
                1.
            } else {
                (self.viewport.width / self.image.width)
                    .min(self.viewport.height / self.image.height)
                    .clamp(f32::EPSILON, 1.)
            }
        })
    }
    fn maximum(self) -> Size<Pixels> {
        size(
            (self.image.width * self.scale() - self.viewport.width).max(px(0.)),
            (self.image.height * self.scale() - self.viewport.height).max(px(0.)),
        )
    }
    fn clamp(&mut self) {
        let maximum = self.maximum();
        self.pan.x = self.pan.x.clamp(-maximum.width, px(0.));
        self.pan.y = self.pan.y.clamp(-maximum.height, px(0.));
    }
    fn origin(self) -> Point<Pixels> {
        point(
            (self.viewport.width - self.image.width * self.scale()).max(px(0.)) / 2. + self.pan.x,
            (self.viewport.height - self.image.height * self.scale()).max(px(0.)) / 2. + self.pan.y,
        )
    }
    fn zoom_at(&mut self, scale: f32, anchor: Point<Pixels>) {
        let old = self.scale();
        let origin = self.origin();
        let scale = scale.clamp(1. / 64., 64.);
        self.zoom = Some(scale);
        self.pan = point(
            anchor.x
                - (anchor.x - origin.x) * (scale / old)
                - (self.viewport.width - self.image.width * scale).max(px(0.)) / 2.,
            anchor.y
                - (anchor.y - origin.y) * (scale / old)
                - (self.viewport.height - self.image.height * scale).max(px(0.)) / 2.,
        );
        self.clamp();
    }

    fn target_scale(self) -> f32 {
        self.motion
            .map_or_else(|| self.scale(), |motion| motion.to_scale)
    }

    fn animate_zoom(&mut self, scale: f32, anchor: Point<Pixels>, now: Instant) {
        self.sample(now);
        let mut target = *self;
        target.zoom_at(scale, anchor);
        self.motion = Some(ZoomMotion {
            from_scale: self.scale(),
            to_scale: target.scale(),
            from_origin: self.origin(),
            to_origin: target.origin(),
            started: now,
        });
    }

    fn sample(&mut self, now: Instant) -> bool {
        let Some(motion) = self.motion else {
            return false;
        };
        let elapsed = now.saturating_duration_since(motion.started);
        if elapsed >= ZOOM_DURATION {
            self.zoom = Some(motion.to_scale);
            self.pan = Point::default();
            self.pan = motion.to_origin - self.origin();
            self.motion = None;
            self.clamp();
            return false;
        }
        let t = ease_in_out(elapsed.as_secs_f32() / ZOOM_DURATION.as_secs_f32());
        self.zoom = Some(motion.from_scale + (motion.to_scale - motion.from_scale) * t);
        self.pan = Point::default();
        self.pan = motion.from_origin + (motion.to_origin - motion.from_origin) * t - self.origin();
        self.clamp();
        true
    }
}
#[derive(Clone, Copy)]
enum Drag {
    Pan(Point<Pixels>, Point<Pixels>),
    Bar(Axis, Pixels, Pixels),
}
pub(super) struct State {
    camera: Rc<Cell<Camera>>,
    drag: Rc<Cell<Option<Drag>>>,
    pub pending: Option<usize>,
    pub frames: frames::Frames,
}
impl Default for State {
    fn default() -> Self {
        Self {
            camera: Rc::new(Cell::new(Camera::default())),
            drag: Rc::new(Cell::new(None)),
            pending: None,
            frames: frames::Frames::default(),
        }
    }
}

impl Workspace {
    fn choose_frame(&mut self, frame: usize, cx: &mut Context<Self>) {
        if !self.show_inspector || (self.preview_loading && self.image_view.pending.is_none()) {
            return;
        }
        let Some(preview) = &self.preview else { return };
        if frame >= preview.image_frames
            || frame == preview.image_frame && self.image_view.pending.is_none()
        {
            return;
        }
        self.request.store(true, Ordering::Relaxed);
        self.request = Arc::new(AtomicBool::new(false));
        self.preview_loading = true;
        self.preview_error = None;
        self.image_view.pending = Some(frame);
        self.image_view.frames.reveal = Some(frame);
        let request = self.request.clone();
        let sender = self.sender.clone();
        let bytes = preview.bytes.clone();
        cx.background_executor()
            .spawn(async move {
                let result = (|| -> anyhow::Result<Arc<RenderImage>> {
                    if request.load(Ordering::Relaxed) {
                        return Err(nvlens_core::Error::Cancelled.into());
                    }
                    let image = nvlens_image::decode_frame(&bytes, frame)?
                        .ok_or_else(|| anyhow::anyhow!("Image format is unavailable"))?;
                    if request.load(Ordering::Relaxed) {
                        return Err(nvlens_core::Error::Cancelled.into());
                    }
                    Preview::render_image(image, None)
                })();
                let _ = sender.send(Event::ImageFrame(request, frame, result));
            })
            .detach();
        cx.notify();
    }
    fn change_image_zoom(&mut self, factor: f32, cx: &mut Context<Self>) {
        let mut camera = self.image_view.camera.get();
        camera.animate_zoom(
            camera.target_scale() * factor,
            point(camera.viewport.width / 2., camera.viewport.height / 2.),
            Instant::now(),
        );
        self.image_view.camera.set(camera);
        cx.notify();
    }
    pub(super) fn image_preview(&self, cx: &mut Context<Self>) -> AnyElement {
        let Some(preview) = &self.preview else {
            return div().into_any_element();
        };
        let Some(image) = &preview.image else {
            return div().into_any_element();
        };
        let count = preview.image_frames;
        let frame = self.image_view.pending.unwrap_or(preview.image_frame);
        let scale = self.image_view.camera.get().scale();
        let image = image.clone();
        let measure = self.image_view.camera.clone();
        let camera = self.image_view.camera.clone();
        let drag = self.image_view.drag.clone();
        let canvas = canvas(
            move |bounds, window, _| {
                let mut state = measure.get();
                let old_viewport = state.viewport;
                let old_image = state.image;
                let old_scale = state.scale();
                state.viewport = size(
                    (bounds.size.width - px(16.)).max(px(0.)),
                    (bounds.size.height - px(16.)).max(px(0.)),
                );
                let dimensions = image.size(0);
                // At 100%, each source pixel occupies one physical display pixel.
                state.image = size(
                    px(u32::from(dimensions.width) as f32 / window.scale_factor()),
                    px(u32::from(dimensions.height) as f32 / window.scale_factor()),
                );
                let animating = state.sample(Instant::now());
                state.clamp();
                measure.set(state);
                if animating
                    || state.viewport != old_viewport
                    || state.image != old_image
                    || state.scale() != old_scale
                {
                    // Notifications during prepaint do not schedule another draw.
                    // Refresh next frame so the label catches up with layout and
                    // the final animation sample without waiting for mouse input.
                    window.request_animation_frame();
                }
                (
                    window.insert_hitbox(bounds, HitboxBehavior::Normal),
                    image.clone(),
                )
            },
            move |bounds, (hitbox, image), window, _| {
                let state = camera.get();
                if state.viewport.width <= px(0.) || state.viewport.height <= px(0.) {
                    return;
                }
                let viewport = Bounds::new(bounds.origin, state.viewport);
                let draw = Bounds::new(
                    bounds.origin + state.origin(),
                    state.image.map(|v| v * state.scale()),
                );
                window.with_content_mask(Some(ContentMask { bounds: viewport }), |window| {
                    if let Err(error) =
                        window.paint_image(draw, Corners::default(), image, 0, false)
                    {
                        tracing::error!(%error,"Cannot paint image preview");
                    }
                });
                let mut bars = Vec::new();
                for axis in [Axis::Horizontal, Axis::Vertical] {
                    let maximum = state.maximum().along(axis);
                    if maximum <= px(0.) {
                        continue;
                    }
                    let track_length = state.viewport.along(axis);
                    let length = (track_length * (track_length / (track_length + maximum)))
                        .max(px(24.))
                        .min(track_length);
                    let travel = track_length - length;
                    let start = if travel > px(0.) {
                        -state.pan.along(axis) / maximum * travel
                    } else {
                        px(0.)
                    };
                    let track = match axis {
                        Axis::Horizontal => Bounds::new(
                            point(bounds.left(), viewport.bottom() + px(4.)),
                            size(track_length, px(8.)),
                        ),
                        Axis::Vertical => Bounds::new(
                            point(viewport.right() + px(4.), bounds.top()),
                            size(px(8.), track_length),
                        ),
                    };
                    let thumb = Bounds::new(
                        track.origin.apply_along(axis, |v| v + start),
                        track.size.apply_along(axis, |_| length),
                    );
                    window.paint_quad(fill(track, rgba(0xffffff0a)).corner_radii(px(4.)));
                    window.paint_quad(fill(thumb, rgb(0x6b6b73)).corner_radii(px(4.)));
                    bars.push((axis, track, thumb, travel));
                }
                let view = window.current_view();
                let wheel_camera = camera.clone();
                let wheel_hitbox = hitbox.clone();
                window.on_mouse_event(move |event: &ScrollWheelEvent, phase, window, cx| {
                    if phase != DispatchPhase::Capture || !wheel_hitbox.should_handle_scroll(window)
                    {
                        return;
                    }
                    let mut state = wheel_camera.get();
                    let delta = event.delta.pixel_delta(window.line_height());
                    if event.modifiers.control {
                        let scale = state.target_scale() * (f32::from(delta.y) * 0.006).exp();
                        state.animate_zoom(scale, event.position - bounds.origin, Instant::now());
                    } else {
                        state.sample(Instant::now());
                        state.motion = None;
                        state.pan.y += delta.y;
                        state.clamp();
                    }
                    wheel_camera.set(state);
                    cx.notify(view);
                    cx.stop_propagation();
                });
                let down_drag = drag.clone();
                let down_camera = camera.clone();
                let down_hitbox = hitbox.clone();
                window.on_mouse_event(move |event: &MouseDownEvent, phase, window, cx| {
                    if phase != DispatchPhase::Bubble
                        || event.button != MouseButton::Left
                        || !down_hitbox.is_hovered(window)
                    {
                        return;
                    }
                    let mut state = down_camera.get();
                    state.sample(Instant::now());
                    state.motion = None;
                    down_camera.set(state);
                    let mut selected = Drag::Pan(event.position, state.pan);
                    for (axis, track, thumb, travel) in &bars {
                        if track.contains(&event.position) {
                            let grab = if thumb.contains(&event.position) {
                                (event.position - thumb.origin).along(*axis)
                            } else {
                                thumb.size.along(*axis) / 2.
                            };
                            selected = Drag::Bar(*axis, track.origin.along(*axis) + grab, *travel);
                            break;
                        }
                    }
                    down_drag.set(Some(selected));
                    cx.stop_propagation();
                });
                let move_camera = camera.clone();
                let move_drag = drag.clone();
                window.on_mouse_event(move |event: &MouseMoveEvent, phase, _, cx| {
                    if phase != DispatchPhase::Bubble {
                        return;
                    }
                    let Some(drag) = move_drag.get() else { return };
                    if !event.dragging() {
                        move_drag.set(None);
                        return;
                    }
                    let mut state = move_camera.get();
                    match drag {
                        Drag::Pan(start, pan) => state.pan = pan + (event.position - start),
                        Drag::Bar(axis, origin, travel) if travel > px(0.) => {
                            state.pan = state.pan.apply_along(axis, |_| {
                                -state.maximum().along(axis)
                                    * ((event.position.along(axis) - origin) / travel)
                            })
                        }
                        _ => {}
                    }
                    state.clamp();
                    move_camera.set(state);
                    cx.notify(view);
                    cx.stop_propagation();
                });
                let up_drag = drag.clone();
                window.on_mouse_event(move |_: &MouseUpEvent, phase, _, _| {
                    if phase == DispatchPhase::Bubble {
                        up_drag.set(None);
                    }
                });
            },
        )
        .absolute()
        .inset_0();
        div()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .flex()
            .flex_col()
            .relative()
            .child(div().relative().flex_1().min_h_0().m_3().child(canvas))
            .when(count > 1, |view| view.child(self.image_frames(cx)))
            .child(
                div()
                    .h(px(40.))
                    .px_3()
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .gap_2()
                    .when(count > 1, |bar| {
                        bar.child(button("frame-previous", "‹", false, frame > 0).on_click(
                            cx.listener(move |this, _, _, cx| {
                                this.choose_frame(frame.saturating_sub(1), cx)
                            }),
                        ))
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(SECONDARY))
                                .child(format!("{} / {count}", frame + 1)),
                        )
                        .child(
                            button("frame-next", "›", false, frame + 1 < count).on_click(
                                cx.listener(move |this, _, _, cx| this.choose_frame(frame + 1, cx)),
                            ),
                        )
                    })
                    .child(div().flex_1())
                    .child(button("zoom-out", "−", false, true).on_click(
                        cx.listener(|this, _, _, cx| this.change_image_zoom(1. / 1.25, cx)),
                    ))
                    .child(
                        button("zoom-actual", format!("{:.0}%", scale * 100.), false, true)
                            .on_click(cx.listener(|this, _, _, cx| {
                                let mut camera = this.image_view.camera.get();
                                camera.animate_zoom(
                                    1.,
                                    point(camera.viewport.width / 2., camera.viewport.height / 2.),
                                    Instant::now(),
                                );
                                this.image_view.camera.set(camera);
                                cx.notify();
                            })),
                    )
                    .child(
                        button("zoom-in", "+", false, true).on_click(
                            cx.listener(|this, _, _, cx| this.change_image_zoom(1.25, cx)),
                        ),
                    ),
            )
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::rust_2024::test;

    #[test]
    fn automatic_zoom_keeps_small_images_at_actual_size_and_fits_large_images() {
        let mut camera = Camera {
            viewport: size(px(800.), px(600.)),
            image: size(px(10.), px(10.)),
            ..Camera::default()
        };
        assert_eq!(camera.scale(), 1.);
        assert_eq!(camera.origin(), point(px(395.), px(295.)));
        camera.image = size(px(1600.), px(900.));
        assert_eq!(camera.scale(), 0.5);
        camera.image = size(px(400.), px(1200.));
        assert_eq!(camera.scale(), 0.5);
        camera.image = size(px(800.), px(600.));
        assert_eq!(camera.scale(), 1.);
    }

    #[test]
    fn zoom_interpolates_keeps_pointer_anchor_and_retargets_without_jumping() {
        let now = Instant::now();
        let mut camera = Camera {
            viewport: size(px(800.), px(600.)),
            image: size(px(1600.), px(1200.)),
            ..Camera::default()
        };
        let anchor = point(px(300.), px(200.));
        let image_point = (anchor - camera.origin()) / camera.scale();
        camera.animate_zoom(1., anchor, now);
        assert_eq!(camera.scale(), 0.5);
        assert!(camera.sample(now + ZOOM_DURATION / 2));
        assert_eq!(camera.scale(), 0.75);
        assert_eq!((anchor - camera.origin()) / camera.scale(), image_point);
        let origin = camera.origin();
        camera.animate_zoom(2., anchor, now + ZOOM_DURATION / 2);
        assert_eq!(camera.scale(), 0.75);
        assert_eq!(camera.origin(), origin);
        assert!(!camera.sample(now + ZOOM_DURATION * 2));
        assert_eq!(camera.scale(), 2.);
        assert_eq!((anchor - camera.origin()) / camera.scale(), image_point);
        assert!(camera.motion.is_none());
    }

    #[test]
    fn actual_size_animation_finishes_at_one_and_survives_viewport_changes() {
        let now = Instant::now();
        let mut camera = Camera {
            viewport: size(px(800.), px(600.)),
            image: size(px(1600.), px(900.)),
            zoom: Some(2.),
            pan: point(px(-1000.), px(-600.)),
            ..Camera::default()
        };
        camera.animate_zoom(1., point(px(400.), px(300.)), now);
        assert!(camera.sample(now + ZOOM_DURATION / 2));
        assert!(camera.scale() > 1. && camera.scale() < 2.);
        assert!(!camera.sample(now + ZOOM_DURATION));
        assert_eq!(camera.scale(), 1.);
        assert!(camera.motion.is_none());
        camera.viewport = size(px(400.), px(300.));
        assert_eq!(camera.scale(), 1.);
        camera.viewport = size(px(3200.), px(1800.));
        camera.clamp();
        assert_eq!(camera.scale(), 1.);
        assert_eq!(camera.pan, Point::default());
    }
}
