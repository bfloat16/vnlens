//! Offscreen model rendering worker. The GUI sends camera/size changes; GPU
//! work and readback stay on this worker, with only completed frames published.
mod render;

use anyhow::{Result, anyhow};
use gpui::RenderImage;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Camera {
    pub yaw: f32,
    pub pitch: f32,
    pub distance: f32,
    pub pan: [f32; 2],
    pub wireframe: bool,
    pub vertex_colors: bool,
}
impl Default for Camera {
    fn default() -> Self {
        Self {
            yaw: 0.4,
            pitch: 0.15,
            distance: 3.2,
            pan: [0.; 2],
            wireframe: false,
            vertex_colors: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct View {
    pub camera: Camera,
    pub size: [u32; 2],
}

#[derive(Clone, Debug)]
pub struct Control {
    pub view: Arc<Mutex<View>>,
    wake: mpsc::Sender<()>,
}
impl Control {
    pub fn change(&self, update: impl FnOnce(&mut View)) {
        if let Ok(mut view) = self.view.lock() {
            let old = *view;
            update(&mut view);
            if view.camera != old.camera || view.size != old.size {
                let _ = self.wake.send(());
            }
        }
    }
}

pub struct Worker {
    pub control: Control,
    pub frames: mpsc::Receiver<Result<Arc<RenderImage>>>,
    cancelled: Arc<AtomicBool>,
}
impl Worker {
    pub fn new(model: Arc<vnlens_model::Model>) -> Result<Self> {
        let (wake, receiver) = mpsc::channel();
        let (sender, frames) = mpsc::channel();
        let view = Arc::new(Mutex::new(View::default()));
        let control = Control {
            view: view.clone(),
            wake,
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = cancelled.clone();
        std::thread::Builder::new()
            .name("model-preview".into())
            .spawn(move || {
                let mut renderer = None;
                while !stop.load(Ordering::Relaxed) {
                    match receiver.recv_timeout(Duration::from_millis(50)) {
                        Ok(()) => {}
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    for _ in receiver.try_iter() {}
                    let Ok(view) = view.lock().map(|v| *v) else {
                        break;
                    };
                    if view.size.contains(&0) {
                        continue;
                    }
                    let result = (|| {
                        if renderer.is_none() {
                            renderer =
                                Some(pollster::block_on(render::Renderer::new(&model, &stop))?);
                        }
                        let mut pixels = renderer
                            .as_ref()
                            .ok_or_else(|| anyhow!("Model renderer is unavailable"))?
                            .draw(view, &stop)?;
                        // GPUI's decoded frame upload uses BGRA channel order.
                        vnlens_image::swap_red_blue(pixels.as_mut());
                        Ok(Arc::new(RenderImage::new([image::Frame::new(pixels)])))
                    })();
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    if sender.send(result).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            control,
            frames,
            cancelled,
        })
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}
