//! Single-line names with measured middle ellipsis at grapheme boundaries.

use gpui::{prelude::*, *};
use unicode_segmentation::UnicodeSegmentation;

pub(super) fn filename(name: &str) -> Filename {
    let text = if name.is_empty() {
        "(empty name)".to_owned()
    } else {
        name.chars()
            .map(|ch| if ch.is_control() { '�' } else { ch })
            .collect()
    };
    Filename(text.into())
}

pub(super) struct Filename(SharedString);

impl Filename {
    /// Measures the full sanitized name before flex layout can constrain it.
    pub(super) fn natural_width(&self, style: &TextStyle, window: &Window) -> Pixels {
        window
            .text_system()
            .shape_line(
                self.0.clone(),
                style.font_size.to_pixels(window.rem_size()),
                &[style.to_run(self.0.len())],
                None,
            )
            .width
            .ceil()
    }
}

impl IntoElement for Filename {
    type Element = Self;

    fn into_element(self) -> Self {
        self
    }
}

impl Element for Filename {
    type RequestLayoutState = (ShapedLine, TextStyle, Pixels);
    type PrepaintState = ShapedLine;

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
        _: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let style = window.text_style();
        let font_size = style.font_size.to_pixels(window.rem_size());
        let line_height = window.line_height();
        let line = window.text_system().shape_line(
            self.0.clone(),
            font_size,
            &[style.to_run(self.0.len())],
            None,
        );
        let width = line.width;
        let layout =
            window.request_measured_layout(Style::default(), move |known, available, _, _| {
                let available_width = known.width.unwrap_or(match available.width {
                    AvailableSpace::Definite(width) => width,
                    _ => width,
                });
                size(width.min(available_width).max(px(0.)), line_height)
            });
        (layout, (line, style, line_height))
    }

    fn prepaint(
        &mut self,
        _: Option<&GlobalElementId>,
        _: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        (full, style, _): &mut Self::RequestLayoutState,
        window: &mut Window,
        _: &mut App,
    ) -> ShapedLine {
        if full.width <= bounds.size.width {
            return full.clone();
        }
        let font_size = style.font_size.to_pixels(window.rem_size());
        let shape = |text: SharedString| {
            window.text_system().shape_line(
                text.clone(),
                font_size,
                &[style.to_run(text.len())],
                None,
            )
        };
        let mut best = shape("…".into());
        if best.width > bounds.size.width {
            return shape("".into());
        }
        let boundaries: Vec<usize> = self
            .0
            .grapheme_indices(true)
            .map(|(index, _)| index)
            .chain(std::iter::once(self.0.len()))
            .collect();
        let count = boundaries.len() - 1;
        let mut low = 0;
        let mut high = count;
        while low + 1 < high {
            let keep = low + (high - low) / 2;
            let left = boundaries[keep.div_ceil(2)];
            let right = boundaries[count - keep / 2];
            let line = shape(format!("{}…{}", &self.0[..left], &self.0[right..]).into());
            if line.width <= bounds.size.width {
                low = keep;
                best = line;
            } else {
                high = keep;
            }
        }
        best
    }

    fn paint(
        &mut self,
        _: Option<&GlobalElementId>,
        _: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        (_, _, line_height): &mut Self::RequestLayoutState,
        line: &mut ShapedLine,
        window: &mut Window,
        cx: &mut App,
    ) {
        if let Err(error) = line.paint(bounds.origin, *line_height, window, cx) {
            tracing::error!(%error, "Cannot paint filename");
        }
    }
}
