//! A horizontal filmstrip with viewport-sized decoding and texture residency.
use super::*;
use std::collections::BTreeMap;

const STEP: f32 = 112.;
const HEIGHT: f32 = 90.;

pub(in crate::workspace) struct Frames {
    scroll: ScrollHandle,
    bar: scrollbar::Scrollbar,
    visible: Range<usize>,
    // `None` marks a failed frame so it is not decoded again while visible.
    images: BTreeMap<usize, Option<Arc<RenderImage>>>,
    request: Arc<AtomicBool>,
    pub(super) reveal: Option<usize>,
}

impl Default for Frames {
    fn default() -> Self {
        Self {
            scroll: ScrollHandle::new(),
            bar: scrollbar::Scrollbar::default(),
            visible: 0..0,
            images: BTreeMap::new(),
            request: Arc::new(AtomicBool::new(false)),
            reveal: None,
        }
    }
}

impl Drop for Frames {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl Frames {
    pub(in crate::workspace) fn pending_count(&self) -> usize {
        if self.request.load(Ordering::Relaxed) {
            return 0;
        }
        self.visible
            .clone()
            .filter(|frame| !self.images.contains_key(frame))
            .count()
    }

    pub(in crate::workspace) fn cancel(&self) {
        self.request.store(true, Ordering::Relaxed);
    }

    pub(in crate::workspace) fn clear(&mut self, cx: &mut App) {
        self.cancel();
        for image in std::mem::take(&mut self.images).into_values().flatten() {
            cx.defer(move |cx| cx.drop_image(image, None));
        }
    }

    /// Stores a current thumbnail and returns its decode failure for reporting.
    pub(in crate::workspace) fn receive(
        &mut self,
        request: Arc<AtomicBool>,
        frame: usize,
        result: anyhow::Result<Arc<RenderImage>>,
        cx: &mut App,
    ) -> Option<anyhow::Error> {
        if Arc::ptr_eq(&request, &self.request)
            && !request.load(Ordering::Relaxed)
            && self.visible.contains(&frame)
        {
            match result {
                Ok(image) => {
                    self.images.insert(frame, Some(image));
                }
                Err(error) => {
                    self.images.insert(frame, None);
                    return Some(error);
                }
            }
        } else if let Ok(image) = result {
            cx.defer(move |cx| cx.drop_image(image, None));
        }
        None
    }
}

fn visible_range(count: usize, offset: f32, width: f32) -> Range<usize> {
    let start = ((-offset / STEP).floor() as usize).min(count);
    let end = (((-offset + width) / STEP).ceil() as usize).min(count);
    start..end.max(start)
}

impl Workspace {
    fn load_image_thumbnails(&mut self, visible: Range<usize>, cx: &mut Context<Self>) {
        if !self.show_inspector
            || self.preview_failed
            || (self.preview_loading && self.image_view.pending.is_none())
        {
            return;
        }
        let Some(preview) = &self.preview else { return };
        let frames = &mut self.image_view.frames;
        if visible == frames.visible && !frames.request.load(Ordering::Relaxed) {
            return;
        }
        frames.cancel();
        frames.request = Arc::new(AtomicBool::new(false));
        frames.visible = visible.clone();
        frames.images.retain(|frame, image| {
            if visible.contains(frame) {
                true
            } else {
                if let Some(image) = image {
                    let image = image.clone();
                    cx.defer(move |cx| cx.drop_image(image, None));
                }
                false
            }
        });
        let missing: Vec<_> = visible
            .filter(|frame| !frames.images.contains_key(frame))
            .collect();
        if missing.is_empty() {
            return;
        }
        let vnlens_core::ResourceRoute::Image(tag) = preview.route else {
            return;
        };
        let bytes = preview.bytes.clone();
        let request = frames.request.clone();
        let sender = self.sender.clone();
        cx.background_executor()
            .spawn(async move {
                for frame in missing {
                    if request.load(Ordering::Relaxed) {
                        break;
                    }
                    let result = (|| {
                        let image = vnlens_image::decode_frame_as(tag, &bytes, frame)?;
                        if request.load(Ordering::Relaxed) {
                            return Err(vnlens_core::Error::Cancelled.into());
                        }
                        // Texture resolution only; source pixels and exports retain their size.
                        Preview::render_image(image, Some((208, 120)))
                    })();
                    if request.load(Ordering::Relaxed) {
                        break;
                    }
                    if sender
                        .send(Event::ImageThumbnail(request.clone(), frame, result))
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .detach();
    }

    pub(super) fn image_frames(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let scroll = self.image_view.frames.scroll.clone();
        let wheel_scroll = scroll.clone();
        let strip = canvas(
            cx.processor(|this, bounds: Bounds<Pixels>, window, cx| {
                let count = this
                    .preview
                    .as_ref()
                    .map_or(0, |preview| preview.image_frames);
                let width = f32::from(bounds.size.width).max(0.);
                let total = count as f32 * STEP;
                let scroll = this.image_view.frames.scroll.clone();
                let mut offset = f32::from(scroll.offset().x);
                if let Some(frame) = this.image_view.frames.reveal.take() {
                    let left = frame as f32 * STEP;
                    if left + offset < 0. {
                        offset = -left;
                    } else if left + STEP + offset > width {
                        offset = width - left - STEP;
                    }
                }
                offset = offset.clamp(-(total - width).max(0.), 0.);
                scroll.set_offset(point(px(offset), px(0.)));
                let range = visible_range(count, offset, width);
                this.load_image_thumbnails(range.clone(), cx);
                let selected = this.image_view.pending.unwrap_or_else(|| {
                    this.preview
                        .as_ref()
                        .map_or(0, |preview| preview.image_frame)
                });
                let cards = range.map(|frame| {
                    let thumbnail = this.image_view.frames.images.get(&frame);
                    div()
                        .id(("image-frame", frame))
                        .absolute()
                        .left(px(frame as f32 * STEP + 4.))
                        .top(px(4.))
                        .w(px(STEP - 8.))
                        .h(px(HEIGHT - 8.))
                        .p_1()
                        .rounded(px(6.))
                        .border_2()
                        .border_color(rgb(if selected == frame { ACCENT } else { BORDER }))
                        .bg(rgb(BACKGROUND))
                        .cursor_pointer()
                        .hover(|style| style.bg(rgb(BORDER)))
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .flex_1()
                                .min_h_0()
                                .flex()
                                .items_center()
                                .justify_center()
                                .child(match thumbnail {
                                    Some(Some(image)) => img(image.clone())
                                        .size_full()
                                        .object_fit(ObjectFit::Contain)
                                        .into_any_element(),
                                    _ => div().into_any_element(),
                                }),
                        )
                        .child(
                            div()
                                .text_size(px(10.))
                                .text_center()
                                .child((frame + 1).to_string()),
                        )
                        .on_click(cx.listener(move |this, _, _, cx| this.choose_frame(frame, cx)))
                });
                let mut content = div()
                    .id("image-frames-scroll")
                    .w(bounds.size.width)
                    .h(px(HEIGHT))
                    .overflow_x_scroll()
                    .track_scroll(&scroll)
                    .child(
                        div()
                            .relative()
                            .w(px(total))
                            .h(px(HEIGHT))
                            .ml(px((width - total).max(0.) / 2.))
                            .children(cards),
                    )
                    .into_any_element();
                content.layout_as_root(bounds.size.map(AvailableSpace::Definite), window, cx);
                content.prepaint_at(bounds.origin, window, cx);
                let hitbox = window.insert_hitbox(bounds, HitboxBehavior::Normal);
                (content, hitbox)
            }),
            move |_, (mut content, hitbox), window, cx| {
                content.paint(window, cx);
                let view = window.current_view();
                window.on_mouse_event(move |event: &ScrollWheelEvent, phase, window, cx| {
                    if phase != DispatchPhase::Capture || !hitbox.should_handle_scroll(window) {
                        return;
                    }
                    let delta = event.delta.pixel_delta(window.line_height());
                    let delta = if delta.x.abs() > delta.y.abs() {
                        delta.x
                    } else {
                        delta.y
                    };
                    let offset = wheel_scroll.offset().x + delta;
                    wheel_scroll.set_offset(point(
                        offset.clamp(-wheel_scroll.max_offset().width, px(0.)),
                        px(0.),
                    ));
                    cx.notify(view);
                    cx.stop_propagation();
                });
            },
        )
        .w_full()
        .h(px(HEIGHT));
        div()
            .relative()
            .mx_3()
            .h(px(HEIGHT + 12.))
            .flex_shrink_0()
            .overflow_hidden()
            .child(strip)
            .child(
                self.image_view
                    .frames
                    .bar
                    .render(scroll, true, Axis::Horizontal)
                    .left(px(4.))
                    .right(px(4.))
                    .bottom(px(1.))
                    .h(px(8.)),
            )
    }
}
