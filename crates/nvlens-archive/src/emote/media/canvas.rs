//! Lossless placement of BC7 blocks for M2 imageList canvases. Only unscaled,
//! block-aligned, non-overlapping tiles can be assembled without decoding.
use super::{Encoding, bad, bc7_size, resource};
use nvlens_core::{Entry, ResourceKind, Result};
use nvlens_io::ReadAt;
use nvlens_script::psb::{Psb, PsbNumber, PsbResource, PsbValue};
#[derive(Clone, Debug)]
struct Tile {
    resource: PsbResource,
    width: u32,
    height: u32,
    x: u32,
    y: u32,
}
#[derive(Clone, Debug)]
pub(in crate::emote) struct Canvas {
    width: u32,
    height: u32,
    tiles: Vec<Tile>,
}
fn integer(value: Option<&PsbValue>) -> Option<u32> {
    match value? {
        PsbValue::Number(PsbNumber::Integer(value)) => u32::try_from(*value).ok(),
        PsbValue::Number(PsbNumber::Float(value))
            if value.is_finite()
                && *value >= 0.
                && f64::from(*value) <= f64::from(u32::MAX)
                && value.fract() == 0. =>
        {
            Some(*value as u32)
        }
        PsbValue::Number(PsbNumber::Double(value))
            if value.is_finite()
                && *value >= 0.
                && *value <= f64::from(u32::MAX)
                && value.fract() == 0. =>
        {
            Some(*value as u32)
        }
        _ => None,
    }
}
pub(in crate::emote) fn entries(psb: &Psb) -> Result<Vec<(Entry, Canvas)>> {
    let mut entries = Vec::new();
    let Some(list) = psb
        .root
        .as_object()
        .and_then(|root| root.get("imageList"))
        .and_then(PsbValue::as_list)
    else {
        return Ok(entries);
    };
    'image: for (index, value) in list.iter().enumerate() {
        let Some(image) = value.as_object() else {
            continue;
        };
        let (Some(width), Some(height), Some(textures)) = (
            integer(image.get("width")),
            integer(image.get("height")),
            image.get("texture").and_then(PsbValue::as_list),
        ) else {
            continue;
        };
        if width == 0 || height == 0 {
            continue;
        }
        let mut tiles: Vec<Tile> = Vec::new();
        for value in textures {
            let Some(texture) = value.as_object() else {
                continue 'image;
            };
            let Some(pixels) = texture.get("image").and_then(PsbValue::as_object) else {
                continue 'image;
            };
            if pixels.get("type").and_then(PsbValue::as_str) != Some("BC7") {
                continue 'image;
            }
            let (Some(x), Some(y), Some(w), Some(h), Some(data)) = (
                integer(texture.get("left")),
                integer(texture.get("top")),
                integer(pixels.get("width")),
                integer(pixels.get("height")),
                pixels.get("pixel").and_then(|v| resource(psb, v)),
            ) else {
                continue 'image;
            };
            if !x.is_multiple_of(4)
                || !y.is_multiple_of(4)
                || w == 0
                || h == 0
                || integer(texture.get("width")) != Some(w)
                || integer(texture.get("height")) != Some(h)
            {
                continue 'image;
            }
            if x >= width || y >= height {
                continue;
            }
            if tiles.iter().any(|tile| {
                u64::from(x) < u64::from(tile.x) + u64::from(tile.width)
                    && u64::from(tile.x) < u64::from(x) + u64::from(w)
                    && u64::from(y) < u64::from(tile.y) + u64::from(tile.height)
                    && u64::from(tile.y) < u64::from(y) + u64::from(h)
            }) {
                continue 'image;
            }
            tiles.push(Tile {
                resource: data.clone(),
                width: w,
                height: h,
                x,
                y,
            });
        }
        let Some(start) = tiles.iter().map(|tile| tile.resource.offset).min() else {
            continue;
        };
        let end = tiles.iter().try_fold(start, |end, tile| {
            tile.resource
                .offset
                .checked_add(tile.resource.size)
                .map(|limit| end.max(limit))
                .ok_or_else(|| bad("PSB tile range overflow"))
        })?;
        let label = image
            .get("label")
            .and_then(PsbValue::as_str)
            .unwrap_or("image");
        let entry = Entry {
            name: format!("images/{index:04}_{label}.dds"),
            offset: start,
            size: end - start,
            kind: ResourceKind::Image,
            packed: None,
        };
        entries.push((
            entry,
            Canvas {
                width,
                height,
                tiles,
            },
        ));
    }
    Ok(entries)
}
impl Canvas {
    pub(super) fn wrap(&self, source: &dyn ReadAt) -> Result<Vec<u8>> {
        let width = self.width.div_ceil(4) as usize;
        let height = self.height.div_ceil(4) as usize;
        let length = width
            .checked_mul(height)
            .and_then(|n| n.checked_mul(16))
            .ok_or_else(|| bad("BC7 canvas exceeds address space"))?;
        let mut blocks = vec![0; length];
        for block in blocks.as_chunks_mut::<16>().0 {
            block[0] = 0x40;
        }
        for tile in &self.tiles {
            let stride = tile.width.div_ceil(4) as usize * 16;
            let expected = bc7_size(tile.width, tile.height)?;
            if tile.resource.size != expected {
                return Err(bad("BC7 tile length differs from dimensions"));
            }
            let x = (tile.x / 4) as usize;
            let y = (tile.y / 4) as usize;
            let rows = (tile.height.div_ceil(4) as usize).min(height - y);
            let bytes = stride.min((width - x) * 16);
            for row in 0..rows {
                let source_offset = tile.resource.offset + (row * stride) as u64;
                let destination = ((y + row) * width + x) * 16;
                blocks[destination..destination + bytes]
                    .copy_from_slice(&source.read_at(source_offset, bytes)?);
            }
        }
        Encoding::Bc7 {
            width: self.width,
            height: self.height,
        }
        .wrap(source, &blocks)
    }
}

#[cfg(test)]
#[path = "../../../tests/emote/media/canvas.rs"]
mod tests;
