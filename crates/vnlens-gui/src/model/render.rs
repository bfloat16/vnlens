//! GPU mesh buffers, depth-tested shaded/wireframe rendering and padded readback.
use super::View;
use anyhow::{Result, anyhow, bail};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use vnlens_io::BinaryWriter;
use wgpu::util::DeviceExt;

pub(super) struct Renderer {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::RenderPipeline,
    vertices: wgpu::Buffer,
    count: u32,
    uniform: wgpu::Buffer,
    group: wgpu::BindGroup,
}

#[cfg(test)]
#[path = "../../tests/model/render.rs"]
mod tests;

fn cancelled(flag: &AtomicBool) -> Result<()> {
    if flag.load(Ordering::Relaxed) {
        return Err(vnlens_core::Error::Cancelled.into());
    }
    Ok(())
}

impl Renderer {
    pub async fn new(model: &vnlens_model::Model, stop: &AtomicBool) -> Result<Self> {
        cancelled(stop)?;
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::new_without_display_handle());
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                ..Default::default()
            })
            .await?;
        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("model-preview"),
                required_limits: adapter.limits(),
                ..Default::default()
            })
            .await?;
        let center: [f64; 3] = std::array::from_fn(|i| {
            (f64::from(model.bounds[0][i]) + f64::from(model.bounds[1][i])) * 0.5
        });
        let radius = (0..3)
            .map(|i| (f64::from(model.bounds[1][i]) - center[i]).powi(2))
            .sum::<f64>()
            .sqrt();
        let scale = if radius > 0. { 1. / radius } else { 1. };
        let vertex_count = model
            .meshes
            .iter()
            .try_fold(0u64, |n, m| n.checked_add(m.indices.len() as u64))
            .ok_or_else(|| anyhow!("Model vertex count overflow"))?;
        let count = u32::try_from(vertex_count)
            .map_err(|_| anyhow!("Model exceeds GPU draw vertex count"))?;
        let size = vertex_count
            .checked_mul(40)
            .ok_or_else(|| anyhow!("Model GPU buffer size overflow"))?;
        if size > device.limits().max_buffer_size {
            bail!("Model exceeds GPU buffer capacity");
        }
        let mut bytes = vec![0; usize::try_from(size)?];
        let mut output = bytes.as_chunks_mut::<40>().0.iter_mut();
        for mesh in &model.meshes {
            for triangle in mesh.indices.as_chunks::<3>().0 {
                cancelled(stop)?;
                let positions = triangle.map(|index| {
                    std::array::from_fn::<_, 3, _>(|i| {
                        ((f64::from(model.vertices[index as usize].position[i]) - center[i])
                            * scale) as f32
                    })
                });
                let [a, b, c] = positions;
                let ab = std::array::from_fn::<_, 3, _>(|i| b[i] - a[i]);
                let ac = std::array::from_fn::<_, 3, _>(|i| c[i] - a[i]);
                let flat = [
                    ab[1] * ac[2] - ab[2] * ac[1],
                    ab[2] * ac[0] - ab[0] * ac[2],
                    ab[0] * ac[1] - ab[1] * ac[0],
                ];
                for (index, position) in triangle.iter().zip(positions) {
                    let vertex = &model.vertices[*index as usize];
                    let normal = vertex.normal.unwrap_or(flat);
                    let length = normal.iter().map(|v| v * v).sum::<f32>().sqrt();
                    let normal = if length > 0. {
                        normal.map(|v| v / length)
                    } else {
                        [0., 1., 0.]
                    };
                    let row = output
                        .next()
                        .ok_or_else(|| anyhow!("Model GPU vertex count mismatch"))?;
                    for (value, chunk) in position
                        .into_iter()
                        .chain(normal)
                        .chain(vertex.color)
                        .zip(row.as_chunks_mut::<4>().0.iter_mut())
                    {
                        BinaryWriter::f32_le(value, chunk);
                    }
                }
            }
        }
        let vertices = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("model-vertices"),
            contents: &bytes,
            usage: wgpu::BufferUsages::VERTEX,
        });
        let uniform = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("model-camera"),
            size: 80,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("model-mesh"),
            source: wgpu::ShaderSource::Wgsl(include_str!("mesh.wgsl").into()),
        });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("model-preview"),
            layout: None,
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: Some("vertex_main"),
                compilation_options: Default::default(),
                buffers: &[wgpu::VertexBufferLayout {
                    array_stride: 40,
                    step_mode: wgpu::VertexStepMode::Vertex,
                    attributes: &wgpu::vertex_attr_array![0=>Float32x3,1=>Float32x3,2=>Float32x4],
                }],
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: Some("fragment_main"),
                compilation_options: Default::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format: wgpu::TextureFormat::Rgba8UnormSrgb,
                    blend: None,
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            primitive: wgpu::PrimitiveState {
                cull_mode: None,
                ..Default::default()
            },
            depth_stencil: Some(wgpu::DepthStencilState {
                format: wgpu::TextureFormat::Depth32Float,
                depth_write_enabled: Some(true),
                depth_compare: Some(wgpu::CompareFunction::Less),
                stencil: Default::default(),
                bias: Default::default(),
            }),
            multisample: Default::default(),
            multiview_mask: None,
            cache: None,
        });
        let group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("model-camera"),
            layout: &pipeline.get_bind_group_layout(0),
            entries: &[wgpu::BindGroupEntry {
                binding: 0,
                resource: uniform.as_entire_binding(),
            }],
        });
        Ok(Self {
            device,
            queue,
            pipeline,
            vertices,
            count,
            uniform,
            group,
        })
    }

    pub fn draw(&self, view: View, stop: &AtomicBool) -> Result<image::RgbaImage> {
        cancelled(stop)?;
        let [width, height] = view.size;
        let limit = self.device.limits().max_texture_dimension_2d;
        if width == 0 || height == 0 || width > limit || height > limit {
            bail!("Model viewport exceeds GPU texture dimensions");
        }
        let camera = view.camera;
        let (sy, cy) = camera.yaw.sin_cos();
        let (sp, cp) = camera.pitch.sin_cos();
        let right = [cy, 0., -sy, camera.pan[0]];
        let up = [-sy * sp, cp, -cy * sp, camera.pan[1]];
        let distance = camera.distance * (height as f32 / width as f32).max(1.);
        let back = [sy * cp, sp, cy * cp, distance];
        let near = 0.01;
        let far = distance + 4.;
        let f = 1. / (std::f32::consts::FRAC_PI_8).tan();
        let projection = [
            f * height as f32 / width as f32,
            f,
            far / (far - near),
            -far * near / (far - near),
        ];
        let mut uniform = [0; 80];
        for (value, chunk) in right
            .into_iter()
            .chain(up)
            .chain(back)
            .chain(projection)
            .chain([
                f32::from(camera.wireframe),
                f32::from(camera.vertex_colors),
                0.,
                0.,
            ])
            .zip(uniform.as_chunks_mut::<4>().0.iter_mut())
        {
            BinaryWriter::f32_le(value, chunk);
        }
        self.queue.write_buffer(&self.uniform, 0, &uniform);
        let texture = |format, usage| {
            self.device.create_texture(&wgpu::TextureDescriptor {
                label: Some("model-viewport"),
                size: wgpu::Extent3d {
                    width,
                    height,
                    depth_or_array_layers: 1,
                },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format,
                usage,
                view_formats: &[],
            })
        };
        let color = texture(
            wgpu::TextureFormat::Rgba8UnormSrgb,
            wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
        );
        let depth = texture(
            wgpu::TextureFormat::Depth32Float,
            wgpu::TextureUsages::RENDER_ATTACHMENT,
        );
        let color_view = color.create_view(&Default::default());
        let depth_view = depth.create_view(&Default::default());
        let pitch = (u64::from(width) * 4).div_ceil(256) * 256;
        let size = pitch * u64::from(height);
        if size > self.device.limits().max_buffer_size {
            bail!("Model viewport exceeds GPU readback capacity");
        }
        let readback = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("model-frame"),
            size,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let mut encoder = self.device.create_command_encoder(&Default::default());
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("model-preview"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &color_view,
                    resolve_target: None,
                    depth_slice: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color {
                            r: 0.012,
                            g: 0.012,
                            b: 0.015,
                            a: 1.,
                        }),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: Some(wgpu::RenderPassDepthStencilAttachment {
                    view: &depth_view,
                    depth_ops: Some(wgpu::Operations {
                        load: wgpu::LoadOp::Clear(1.),
                        store: wgpu::StoreOp::Discard,
                    }),
                    stencil_ops: None,
                }),
                ..Default::default()
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &self.group, &[]);
            pass.set_vertex_buffer(0, self.vertices.slice(..));
            pass.draw(0..self.count, 0..1);
        }
        encoder.copy_texture_to_buffer(
            wgpu::TexelCopyTextureInfo {
                texture: &color,
                mip_level: 0,
                origin: wgpu::Origin3d::ZERO,
                aspect: wgpu::TextureAspect::All,
            },
            wgpu::TexelCopyBufferInfo {
                buffer: &readback,
                layout: wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: Some(u32::try_from(pitch)?),
                    rows_per_image: Some(height),
                },
            },
            wgpu::Extent3d {
                width,
                height,
                depth_or_array_layers: 1,
            },
        );
        self.queue.submit([encoder.finish()]);
        let (sender, receiver) = mpsc::channel();
        readback
            .slice(..)
            .map_async(wgpu::MapMode::Read, move |result| {
                let _ = sender.send(result);
            });
        self.device.poll(wgpu::PollType::wait_indefinitely())?;
        receiver.recv()??;
        cancelled(stop)?;
        let mapped = readback.slice(..).get_mapped_range();
        let mut pixels = Vec::new();
        for row in mapped.chunks_exact(usize::try_from(pitch)?) {
            pixels.extend_from_slice(&row[..width as usize * 4]);
        }
        drop(mapped);
        readback.unmap();
        image::RgbaImage::from_raw(width, height, pixels)
            .ok_or_else(|| anyhow!("Invalid model frame dimensions"))
    }
}
