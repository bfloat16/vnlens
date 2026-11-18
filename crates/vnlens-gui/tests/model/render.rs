use super::*;
use crate::model::Camera;
use vnlens_model::{Mesh, Model, Vertex};

#[test]
#[ignore = "Requires a GPU adapter; renders offscreen without starting the GUI"]
fn shaded_triangle_depth_wireframe_resize_and_cancellation() -> Result<()> {
    let mut model = Model {
        vertices: [[-1., -1., 0.], [1., -1., 0.], [0., 1., 0.]]
            .map(|position| Vertex {
                position,
                normal: None,
                color: [1., 0., 0., 1.],
                uv: None,
            })
            .to_vec(),
        meshes: vec![Mesh {
            indices: vec![0, 1, 2],
            material: None,
        }],
        materials: Vec::new(),
        bounds: [[-1., -1., 0.], [1., 1., 0.]],
        source: std::sync::Arc::from([]),
    };
    let back = model
        .vertices
        .iter()
        .map(|v| Vertex {
            position: [v.position[0], v.position[1], -0.6],
            color: [0., 0., 1., 1.],
            ..*v
        })
        .collect::<Vec<_>>();
    model.vertices.extend(back);
    model.meshes[0].indices.extend([3, 4, 5]);
    model.bounds[0][2] = -0.6;
    let stop = AtomicBool::new(false);
    let renderer = pollster::block_on(Renderer::new(&model, &stop))?;
    let view = View {
        camera: Camera {
            yaw: 0.,
            pitch: 0.,
            vertex_colors: true,
            ..Default::default()
        },
        size: [128, 128],
    };
    let solid = renderer.draw(view, &stop)?;
    assert!(solid.get_pixel(64, 64).0[0] > 100);
    assert!(
        solid.get_pixel(64, 64).0[2] < 10,
        "The farther blue triangle must not overwrite the nearer red one"
    );
    let wire = renderer.draw(
        View {
            camera: Camera {
                wireframe: true,
                ..view.camera
            },
            ..view
        },
        &stop,
    )?;
    let count = |image: &image::RgbaImage| image.pixels().filter(|p| p[0] > 80).count();
    assert!(count(&solid) > count(&wire) && count(&wire) > 0);
    let resized = renderer.draw(
        View {
            size: [127, 65],
            ..view
        },
        &stop,
    )?;
    assert_eq!(resized.dimensions(), (127, 65));
    assert!(
        renderer
            .draw(
                View {
                    size: [0, 128],
                    ..view
                },
                &stop
            )
            .is_err()
    );
    stop.store(true, Ordering::Relaxed);
    assert!(renderer.draw(view, &stop).is_err());
    Ok(())
}
