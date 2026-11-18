//! Range validation and native TMD0 attribute/command decoding.
use crate::{Material, Mesh, Model, TextureBinding, Vertex};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use vnlens_core::{Error, Result};
use vnlens_io::{BinaryIo, BinaryReader};

fn bad(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
fn cancel(flag: &AtomicBool) -> Result<()> {
    if flag.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn bytes(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .filter(|&end| end <= data.len() as u64)
        .ok_or_else(|| BinaryIo::unexpected_eof("TMD range exceeds source"))?;
    Ok(&data[usize::try_from(offset)
        .map_err(|_| BinaryIo::unexpected_eof("TMD offset exceeds address space"))?
        ..usize::try_from(end)
            .map_err(|_| BinaryIo::unexpected_eof("TMD range exceeds address space"))?])
}
fn table(data: &[u8], at: usize, count: u32, stride: u64) -> Result<&[u8]> {
    let offset = u64::from(BinaryReader::u32_le(bytes(data, at as u64, 4)?));
    if count != 0 && offset == 0 {
        return Err(bad(at, "Missing TMD table"));
    }
    bytes(data, offset, u64::from(count) * stride)
}

#[derive(Clone, Copy)]
enum Attribute {
    Position,
    Normal,
    Skip,
    Color(bool),
    Uv(bool),
}

pub(super) fn decode(source: Arc<[u8]>, cancelled: &AtomicBool) -> Result<Model> {
    cancel(cancelled)?;
    let data = source.as_ref();
    let header = bytes(data, 0, 0xa0)?;
    if &header[..4] != b"tmd0" {
        return Err(Error::InvalidFormat);
    }
    let flags = BinaryReader::u16_le(&header[6..]);
    let version = BinaryReader::u16_le(&header[10..]);
    if version >> 8 != 2 {
        return Err(Error::Unsupported(format!("TMD version 0x{version:04x}")));
    }
    let count = BinaryReader::u32_le(&header[0x9c..]);
    if count != 0 && flags & 2 == 0 {
        return Err(Error::Unsupported(
            "TMD vertices without position attributes".into(),
        ));
    }
    let float_uv = flags & 0x1000 != 0 && version >= 0x202;
    let mut attributes = Vec::new();
    if flags & 2 != 0 {
        attributes.push((Attribute::Position, 12, None));
    }
    if flags & 0x400 != 0 {
        attributes.push((Attribute::Skip, 8, Some(9)));
    }
    if flags & 0x8000 != 0 {
        if flags & 1 == 0 {
            return Err(Error::Unsupported(
                "TMD separate eight-weight attributes".into(),
            ));
        }
        attributes.push((Attribute::Skip, 8, None));
    }
    if flags & 4 != 0 {
        attributes.push((Attribute::Normal, 4, Some(0)));
    }
    if flags & 8 != 0 {
        attributes.push((Attribute::Skip, 8, Some(1)));
    }
    for (i, bit) in [0x80, 0x100, 0x200].into_iter().enumerate() {
        if flags & bit == 0 {
            break;
        }
        attributes.push((Attribute::Color(i == 0), 4, Some(6 + i)));
    }
    for (i, bit) in [0x10, 0x20, 0x40].into_iter().enumerate() {
        if flags & bit == 0 {
            break;
        }
        attributes.push((
            Attribute::Uv(i == 0),
            if float_uv { 8 } else { 4 },
            Some(3 + i),
        ));
    }
    let stride: usize = attributes.iter().map(|a| a.1).sum();
    let packed = if flags & 1 != 0 {
        table(data, 0x5c, count, stride as u64)?
    } else {
        &[]
    };
    let extra = if flags & 0x2000 != 0 { 0xc8 } else { 0xa0 };
    let mut streams = Vec::new();
    if flags & 1 == 0 {
        for (attribute, width, slot) in &attributes {
            if let Some(slot) = slot {
                if matches!(attribute, Attribute::Skip) {
                    // Bone/tangent records occupy two parallel four-byte streams.
                    streams.push((
                        table(data, extra + slot * 4, count, (*width / 2) as u64)?,
                        *width / 2,
                    ));
                    table(data, extra + (slot + 1) * 4, count, (*width / 2) as u64)?;
                } else {
                    streams.push((table(data, extra + slot * 4, count, *width as u64)?, *width));
                }
            } else {
                streams.push((table(data, 0x5c, count, *width as u64)?, *width));
            }
        }
    }
    let vertex_count =
        usize::try_from(count).map_err(|_| bad(0x9c, "TMD vertex count exceeds address space"))?;
    let mut vertices = Vec::new();
    let mut bounds = [[f32::INFINITY; 3], [f32::NEG_INFINITY; 3]];
    for i in 0..vertex_count {
        cancel(cancelled)?;
        let mut vertex = Vertex {
            position: [0.; 3],
            normal: None,
            color: [1.; 4],
            uv: None,
        };
        let mut at = i * stride;
        for (j, (attribute, width, _)) in attributes.iter().enumerate() {
            let value = if flags & 1 != 0 {
                let v = &packed[at..at + width];
                at += width;
                v
            } else {
                let (stream, width) = streams[j];
                &stream[i * width..(i + 1) * width]
            };
            match attribute {
                Attribute::Position => {
                    for (axis, chunk) in value.as_chunks::<4>().0.iter().enumerate() {
                        let p = BinaryReader::f32_le(chunk);
                        if !p.is_finite() {
                            return Err(bad(0x5c, "Non-finite TMD vertex position"));
                        }
                        vertex.position[axis] = p;
                        bounds[0][axis] = bounds[0][axis].min(p);
                        bounds[1][axis] = bounds[1][axis].max(p);
                    }
                }
                Attribute::Normal => {
                    vertex.normal = Some(std::array::from_fn(|axis| {
                        f32::from(value[axis]) / 255. * 2. - 1.
                    }));
                }
                Attribute::Color(true) => {
                    vertex.color = std::array::from_fn(|axis| f32::from(value[axis]) / 255.);
                }
                Attribute::Uv(true) => {
                    vertex.uv = Some(if float_uv {
                        [
                            BinaryReader::f32_le(value),
                            BinaryReader::f32_le(&value[4..]),
                        ]
                    } else {
                        [
                            f32::from(BinaryReader::i16_le(value)) / 1024.,
                            f32::from(BinaryReader::i16_le(&value[2..])) / 1024.,
                        ]
                    });
                }
                _ => {}
            }
        }
        vertices.push(vertex);
    }
    if vertices.is_empty() {
        bounds = [[0.; 3]; 2];
    }
    let material_count = BinaryReader::u32_le(&header[0x78..]);
    let material_rows = table(data, 0x38, material_count, 20)?;
    let binding_count = BinaryReader::u32_le(&header[0x98..]);
    let bindings = table(data, 0x58, binding_count, 12)?;
    let mut materials = Vec::new();
    for row in material_rows.as_chunks::<20>().0 {
        cancel(cancelled)?;
        let first = usize::from(BinaryReader::u16_le(&row[8..]));
        let count = usize::from(BinaryReader::u16_le(&row[10..]));
        let rows = if count == 0 {
            &[][..]
        } else {
            bindings
                .get(first * 12..(first + count) * 12)
                .ok_or_else(|| bad(0x38, "TMD material texture bindings exceed table"))?
        };
        materials.push(Material {
            name_hash: BinaryReader::u32_le(row),
            shader: BinaryReader::u32_le(&row[4..]),
            raw: row.to_vec(),
            textures: rows
                .as_chunks::<12>()
                .0
                .iter()
                .map(|r| TextureBinding {
                    parameter_hash: BinaryReader::u32_le(r),
                    texture: BinaryReader::u16_le(&r[4..]),
                    raw: r.to_vec(),
                })
                .collect(),
        });
    }
    let primitive_count = BinaryReader::u32_le(&header[0x88..]);
    let primitive_rows = table(data, 0x48, primitive_count, 8)?;
    let triangle_count = BinaryReader::u32_le(&header[0x8c..]);
    let index_width = if flags & 0x800 != 0 { 4 } else { 2 };
    let indices = table(data, 0x4c, triangle_count, index_width * 3)?;
    let mut meshes = Vec::new();
    for row in primitive_rows.as_chunks::<8>().0 {
        cancel(cancelled)?;
        let count = u64::from(BinaryReader::u32_le(row));
        let first = u64::from(BinaryReader::u32_le(&row[4..]));
        let bytes = bytes(indices, first * 3 * index_width, count * 3 * index_width)?;
        let mut decoded = Vec::new();
        for raw in bytes.chunks_exact(index_width as usize) {
            cancel(cancelled)?;
            let index = if index_width == 4 {
                BinaryReader::u32_le(raw)
            } else {
                u32::from(BinaryReader::u16_le(raw))
            };
            if u64::from(index) >= vertices.len() as u64 {
                return Err(bad(0x4c, "TMD triangle vertex index is out of range"));
            }
            decoded.push(index);
        }
        meshes.push(Mesh {
            indices: decoded,
            material: None,
        });
    }
    let objects = table(data, 0x28, BinaryReader::u32_le(&header[0x68..]), 44)?;
    let commands = table(data, 0x34, BinaryReader::u32_le(&header[0x74..]), 2)?;
    for object in objects.as_chunks::<44>().0 {
        cancel(cancelled)?;
        let count = u64::from(BinaryReader::u16_le(&object[24..]));
        let start = u64::from(BinaryReader::u32_le(&object[28..]));
        let mut material = None;
        for raw in bytes(commands, start * 2, count * 2)?.as_chunks::<2>().0 {
            cancel(cancelled)?;
            let cmd = BinaryReader::u16_le(raw);
            let index = usize::from(cmd & 0xfff);
            match cmd >> 12 {
                2 | 5 | 6 => {
                    if index >= materials.len() {
                        return Err(bad(0x34, "TMD material command is out of range"));
                    }
                    material = Some(index);
                }
                3 => {
                    let mesh = meshes
                        .get_mut(index)
                        .ok_or_else(|| bad(0x34, "TMD primitive command is out of range"))?;
                    mesh.material = material;
                }
                _ => {}
            }
        }
    }
    Ok(Model {
        vertices,
        meshes,
        materials,
        bounds,
        source,
    })
}
