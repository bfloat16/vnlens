//! Platform window chrome inside the application toolbar. AppKit owns the
//! traffic lights; Windows hit regions preserve snap layouts while explicit
//! GPUI actions handle clicks. Linux follows the compositor's decorations.
use gpui::{prelude::*, *};
#[cfg(target_os = "windows")]
mod windows;

pub const HEIGHT: f32 = 40.;

pub fn options() -> TitlebarOptions {
    TitlebarOptions {
        title: Some("vnlens".into()),
        appears_transparent: true,
        traffic_light_position: if cfg!(target_os = "macos") {
            Some(point(px(12.), px((HEIGHT - 14.) / 2.)))
        } else {
            None
        },
    }
}

pub fn bar(window: &Window) -> Stateful<Div> {
    div()
        .id("application-titlebar")
        .h(px(HEIGHT))
        .flex_shrink_0()
        .flex()
        .items_center()
        .gap_2()
        .pl(px(
            if cfg!(target_os = "macos") && !window.is_fullscreen() {
                84.
            } else {
                12.
            },
        ))
        .border_b_1()
        .border_color(rgb(crate::workspace::BORDER))
        // A focusable ancestor calls prevent_default on mouse-down, suppressing
        // Windows' HTCAPTION move loop. Isolate caption presses from it while
        // leaving native propagation intact. Interactive children occlude this.
        .occlude()
        .window_control_area(WindowControlArea::Drag)
        .on_mouse_down(MouseButton::Left, |event, window, cx| {
            // GPUI counts consecutive clicks beyond two. Each complete pair
            // must toggle, including a second double-click without a pause.
            if event.click_count > 1 && event.click_count.is_multiple_of(2) {
                #[cfg(target_os = "macos")]
                window.titlebar_double_click();
                #[cfg(not(target_os = "macos"))]
                toggle_zoom(window);
                // Prevent the Windows caption handler from toggling again.
                cx.stop_propagation();
            } else {
                #[cfg(any(target_os = "linux", target_os = "freebsd"))]
                window.start_window_move();
            }
        })
        .map(|view| {
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            let view = view.on_mouse_down(MouseButton::Right, |event, window, _| {
                window.show_window_menu(event.position)
            });
            view
        })
}

pub fn drag_space() -> Div {
    div().flex_1().min_w(px(20.)).h_full()
}

pub fn controls(window: &Window) -> Div {
    let view = div().flex().h_full().flex_shrink_0();
    #[cfg(target_os = "macos")]
    {
        let _ = window;
        view.w(px(12.))
    }
    #[cfg(not(target_os = "macos"))]
    {
        if window.is_fullscreen()
            || (!cfg!(target_os = "windows")
                && matches!(window.window_decorations(), Decorations::Server))
        {
            return view.w(px(12.));
        }
        let controls = window.window_controls();
        view.when(controls.minimize, |view| {
            view.child(control(
                "window-minimize",
                "icons/window-minimize.svg",
                WindowControlArea::Min,
            ))
        })
        .when(controls.maximize, |view| {
            view.child(control(
                "window-maximize",
                if window.is_maximized() {
                    "icons/window-restore.svg"
                } else {
                    "icons/window-maximize.svg"
                },
                WindowControlArea::Max,
            ))
        })
        .child(control(
            "window-close",
            "icons/window-close.svg",
            WindowControlArea::Close,
        ))
    }
}

#[cfg(not(target_os = "macos"))]
fn control(id: &'static str, icon: &'static str, action: WindowControlArea) -> Stateful<Div> {
    div()
        .id(id)
        .w(px(46.))
        .h_full()
        .flex()
        .items_center()
        .justify_center()
        .occlude()
        .window_control_area(action)
        .on_mouse_down(MouseButton::Left, |_, window, _| {
            // GPUI dispatches caption mouse events to the element first.
            // Suppress the native fallback while allowing GPUI's own click
            // tracker to see the press and fire on mouse release.
            window.prevent_default();
        })
        .hover(move |style| {
            style.bg(if action == WindowControlArea::Close {
                rgba(0xc42b1cff)
            } else {
                rgba(0xffffff1a)
            })
        })
        .child(
            svg()
                .path(icon)
                .size(px(12.))
                .text_color(rgb(crate::workspace::TEXT)),
        )
        .on_click(move |_, window, cx| {
            match action {
                WindowControlArea::Min => window.minimize_window(),
                WindowControlArea::Max => toggle_zoom(window),
                WindowControlArea::Close => window.remove_window(),
                WindowControlArea::Drag => {}
            }
            cx.stop_propagation();
        })
}

#[cfg(not(target_os = "macos"))]
fn toggle_zoom(window: &Window) {
    #[cfg(target_os = "windows")]
    if window.is_maximized() {
        if let Err(error) = windows::restore(window) {
            tracing::error!(%error, "Cannot restore maximized window");
        }
        return;
    }
    window.zoom_window();
}
