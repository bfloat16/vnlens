//! Native desktop entry point.
#![deny(unsafe_code)]
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod archive;
mod browser;
mod icons;
mod playback;
mod preferences;
mod resource;
mod titlebar;
mod video;
mod workspace;

use gpui::{App, AppContext, Application, Bounds, WindowBounds, WindowOptions, px, size};

fn main() {
    nvlens_io::log::init(0);
    nvlens_engine::init();
    nvlens_archive::init();
    nvlens_image::init();
    nvlens_audio::init();
    nvlens_script::init();
    nvlens_video::init();
    let preferences = preferences::Preferences::load();

    Application::new()
        .with_assets(icons::Assets)
        .run(move |cx: &mut App| {
            workspace::bind_keys(cx);
            cx.on_window_closed(|cx| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            let bounds = Bounds::centered(None, size(px(1280.), px(800.)), cx);
            if let Err(error) = cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    window_min_size: Some(size(px(960.), px(600.))),
                    titlebar: Some(titlebar::options()),
                    ..Default::default()
                },
                |window, cx| cx.new(|cx| workspace::Workspace::new(window, cx, preferences)),
            ) {
                tracing::error!(%error, "Cannot create the application window");
                cx.quit();
            }
            cx.activate(true);
        });
}
