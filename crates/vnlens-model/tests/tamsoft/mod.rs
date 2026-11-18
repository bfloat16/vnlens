use super::*;
use vnlens_core::Error;
use vnlens_io::BinaryWriter;

mod local;

fn triangle() -> Arc<[u8]> {
    let mut data = vec![0; 0xde];
    data[..4].copy_from_slice(b"tmd0");
    BinaryWriter::u16_le(0x13, &mut data[6..]);
    BinaryWriter::u16_le(0x209, &mut data[10..]);
    for (at, value) in [
        (0x48, 0xd0),
        (0x4c, 0xd8),
        (0x5c, 0xa0),
        (0x88, 1),
        (0x8c, 1),
        (0x9c, 3),
        (0xd0, 1),
    ] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    for (i, p) in [[0., 0., 0.], [1., 0., 0.], [0., 1., 0.]]
        .into_iter()
        .enumerate()
    {
        for (axis, v) in p.into_iter().enumerate() {
            BinaryWriter::f32_le(v, &mut data[0xa0 + i * 16 + axis * 4..]);
        }
        BinaryWriter::u16_le(1024, &mut data[0xac + i * 16..]);
    }
    for (i, index) in [0, 1, 2].into_iter().enumerate() {
        BinaryWriter::u16_le(index, &mut data[0xd8 + i * 2..]);
    }
    data.into()
}

#[test]
fn registered_triangle_positions_uv_bounds_and_source() -> Result<()> {
    let source = triangle();
    let model = crate::decode_as(
        "tmd/tamsoft",
        source.clone(),
        &Default::default(),
        &AtomicBool::new(false),
    )?;
    assert_eq!(model.vertices.len(), 3);
    assert_eq!(model.vertices[1].position, [1., 0., 0.]);
    assert_eq!(model.vertices[2].uv, Some([1., 0.]));
    assert_eq!(model.bounds, [[0., 0., 0.], [1., 1., 0.]]);
    assert_eq!(model.meshes[0].indices, [0, 1, 2]);
    assert!(Arc::ptr_eq(&source, &model.source));
    assert!(
        crate::decode_as(
            "wrong",
            source,
            &Default::default(),
            &AtomicBool::new(false)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn truncation_vertex_index_and_cancel_are_retained() {
    for end in [0, 159, 0xa0, 0xdd] {
        assert!(
            matches!(Tmd.decode(triangle()[..end].to_vec().into(),&Default::default(),&AtomicBool::new(false)),Err(Error::Io(e)) if e.kind()==std::io::ErrorKind::UnexpectedEof)
        );
    }
    let mut data = triangle().to_vec();
    BinaryWriter::u16_le(3, &mut data[0xd8..]);
    assert!(matches!(
        Tmd.decode(data.into(), &Default::default(), &AtomicBool::new(false)),
        Err(Error::Corrupt { .. })
    ));
    assert!(matches!(
        Tmd.decode(triangle(), &Default::default(), &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
}

#[test]
fn packed_normals_color_float_uv_and_wide_indices() -> Result<()> {
    let mut data = vec![0; 0x108];
    data[..0xa0].copy_from_slice(&triangle()[..0xa0]);
    BinaryWriter::u16_le(0x1897, &mut data[6..]);
    for (at, value) in [(0x48, 0xf4), (0x4c, 0xfc), (0xf4, 1)] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    for i in 0..3 {
        let at = 0xa0 + i * 28;
        BinaryWriter::f32_le(i as f32, &mut data[at..]);
        data[at + 12..at + 20].copy_from_slice(&[255, 127, 0, 0, 10, 20, 30, 255]);
        BinaryWriter::f32_le(0.25, &mut data[at + 20..]);
        BinaryWriter::f32_le(-0.5, &mut data[at + 24..]);
        BinaryWriter::u32_le(i as u32, &mut data[0xfc + i * 4..]);
    }
    let model = Tmd.decode(
        data.clone().into(),
        &Default::default(),
        &AtomicBool::new(false),
    )?;
    assert_eq!(model.meshes[0].indices, [0, 1, 2]);
    assert_eq!(model.vertices[0].uv, Some([0.25, -0.5]));
    assert_eq!(
        model.vertices[0].color,
        [10. / 255., 20. / 255., 30. / 255., 1.]
    );
    let normal = model.vertices[0].normal.ok_or(Error::InvalidFormat)?;
    assert_eq!((normal[0], normal[2]), (1., -1.));
    BinaryWriter::f32_le(f32::NAN, &mut data[0xa0..]);
    assert!(matches!(
        Tmd.decode(data.into(), &Default::default(), &AtomicBool::new(false)),
        Err(Error::Corrupt { .. })
    ));
    Ok(())
}

#[test]
fn separate_vertex_attributes_and_empty_geometry() -> Result<()> {
    let mut data = vec![0; 0xee];
    data[..0xa0].copy_from_slice(&triangle()[..0xa0]);
    BinaryWriter::u16_le(0x12, &mut data[6..]);
    for (at, value) in [
        (0x48, 0xe0),
        (0x4c, 0xe8),
        (0x5c, 0xb0),
        (0xac, 0xd4),
        (0xe0, 1),
    ] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    BinaryWriter::f32_le(1., &mut data[0xbc..]);
    BinaryWriter::f32_le(1., &mut data[0xcc..]);
    BinaryWriter::u16_le(1024, &mut data[0xd4..]);
    for (i, index) in [0, 1, 2].into_iter().enumerate() {
        BinaryWriter::u16_le(index, &mut data[0xe8 + i * 2..]);
    }
    let model = Tmd.decode(data.into(), &Default::default(), &AtomicBool::new(false))?;
    assert_eq!(model.vertices[1].position, [1., 0., 0.]);
    assert_eq!(model.vertices[2].position, [0., 1., 0.]);
    assert_eq!(model.vertices[0].uv, Some([1., 0.]));
    let mut data = vec![0; 0xa0];
    data[..4].copy_from_slice(b"tmd0");
    BinaryWriter::u16_le(0x209, &mut data[10..]);
    BinaryWriter::u16_le(1, &mut data[6..]);
    let model = Tmd.decode(
        data.clone().into(),
        &Default::default(),
        &AtomicBool::new(false),
    )?;
    assert!(model.vertices.is_empty() && model.meshes.is_empty());
    BinaryWriter::u16_le(0x300, &mut data[10..]);
    assert!(matches!(
        Tmd.decode(data.into(), &Default::default(), &AtomicBool::new(false)),
        Err(Error::Unsupported(_))
    ));
    Ok(())
}
