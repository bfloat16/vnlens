//! PSB-backed PIMG composites follow PSDInfo.loadPIMG: root width/height and
//! layers, numeric `<same_image or layer_id>.tlg` resources, non-paint markers
//! and group visibility. PSDLayer.redrawRect draws normal layers in reverse
//! stored order. The PSB middleware owns framing, decryption and resource reads;
//! this module owns image decoding, placement and KiriKiri layer blending.
mod blend;

use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use vnlens_core::{Archive, ArchiveOptions, Error, Format, ResourceResolver, Result};
use vnlens_middleware::psb::{PsbFile, PsbValue};

const SIGNATURES: &[u32] = &[0x0042_5350, 0x0066_646d, 0x0073_7a6d, 0x005a_5350];

#[derive(Debug, Default)]
struct Pimg;

impl Format for Pimg {
    fn tag(&self) -> &'static str {
        "pimg/krkr"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pimg"]
    }
    fn description(&self) -> &'static str {
        "KiriKiri PIMG layer composite"
    }
}

impl ImageFormat for Pimg {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        let file = open(data, "", &ArchiveOptions::default(), None)?;
        metadata(&file).map(Some)
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        self.decode_with_options(data, None, &ArchiveOptions::default(), None)
    }
    fn decode_with_options(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
        options: &ArchiveOptions,
        cancelled: Option<&AtomicBool>,
    ) -> Result<Image> {
        let file = open(
            data,
            resources
                .and_then(ResourceResolver::resource_name)
                .unwrap_or(""),
            options,
            cancelled,
        )?;
        compose(&file, cancelled)
    }
}

fn open(
    data: &[u8],
    name: &str,
    options: &ArchiveOptions,
    cancelled: Option<&AtomicBool>,
) -> Result<PsbFile> {
    let bytes: Arc<[u8]> = data.into();
    PsbFile::open_configured(Arc::new(bytes), name, options, cancelled)
}

fn bad(reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: reason.into(),
    }
}

fn check(cancelled: Option<&AtomicBool>) -> Result<()> {
    if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

fn object(value: &PsbValue) -> Result<&BTreeMap<String, PsbValue>> {
    value
        .as_object()
        .ok_or_else(|| bad("PIMG value is not an object"))
}

fn integer(fields: &BTreeMap<String, PsbValue>, name: &str) -> Result<i64> {
    fields
        .get(name)
        .and_then(PsbValue::as_i64)
        .ok_or_else(|| bad(format!("Missing or invalid PIMG {name}")))
}

fn dimension(fields: &BTreeMap<String, PsbValue>, name: &str) -> Result<u32> {
    u32::try_from(integer(fields, name)?).map_err(|_| bad(format!("Invalid PIMG {name}")))
}

fn visible(fields: &BTreeMap<String, PsbValue>) -> Result<bool> {
    match fields.get("visible") {
        Some(PsbValue::Bool(value)) => Ok(*value),
        Some(value) => value
            .as_i64()
            .map(|v| v != 0)
            .ok_or_else(|| bad("Invalid PIMG visibility")),
        None => Ok(false),
    }
}

fn metadata(file: &PsbFile) -> Result<ImageMeta> {
    let fields = object(&file.document.root)?;
    let width = dimension(fields, "width")?;
    let height = dimension(fields, "height")?;
    if width == 0 || height == 0 {
        return Err(bad("Zero PIMG canvas dimensions"));
    }
    let meta = ImageMeta {
        width,
        height,
        offset_x: 0,
        offset_y: 0,
        offset_unit: OffsetUnit::Pixels,
        bpp: 32,
    };
    meta.rgba_size()?;
    Ok(meta)
}

fn compose(file: &PsbFile, cancelled: Option<&AtomicBool>) -> Result<Image> {
    check(cancelled)?;
    let meta = metadata(file)?;
    let root = object(&file.document.root)?;
    let layers = root
        .get("layers")
        .and_then(PsbValue::as_list)
        .ok_or_else(|| bad("Missing PIMG layer list"))?;
    let mut groups = BTreeMap::new();
    for layer in layers {
        check(cancelled)?;
        let layer = object(layer)?;
        if integer(layer, "layer_type")? == 2 {
            groups.insert(integer(layer, "layer_id")?, layer);
        }
    }
    let mut pixels = vec![0; meta.rgba_size()?];
    for value in layers.iter().rev() {
        check(cancelled)?;
        let layer = object(value)?;
        if integer(layer, "layer_type")? != 0 || !is_visible(layer, &groups, cancelled)? {
            continue;
        }
        let id = layer
            .get("same_image")
            .and_then(|value| (!matches!(value, PsbValue::Void | PsbValue::Null)).then_some(value))
            .map_or_else(
                || integer(layer, "layer_id"),
                |value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                        .ok_or_else(|| bad("Invalid PIMG shared image ID"))
                },
            )?;
        // Negative IDs identify layout/control rectangles, not pixel resources.
        if id <= 0 {
            continue;
        }
        let opacity =
            u8::try_from(integer(layer, "opacity")?).map_err(|_| bad("Invalid PIMG opacity"))?;
        if opacity == 0 {
            continue;
        }
        let mode = blend::Mode::new(integer(layer, "type")?)?;
        let name = format!("{id}.tlg");
        let entry = file
            .entries()
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| bad(format!("Missing PIMG layer resource {name}")))?;
        let bytes = file.open_entry(entry)?;
        check(cancelled)?;
        let image = crate::decode_as("tlg/krkr", &bytes)?;
        paint(&mut pixels, &meta, &image, layer, mode, opacity, cancelled)?;
    }
    Ok(Image {
        meta,
        pixels: PixelBuffer::Rgba8(pixels),
    })
}

fn is_visible(
    layer: &BTreeMap<String, PsbValue>,
    groups: &BTreeMap<i64, &BTreeMap<String, PsbValue>>,
    cancelled: Option<&AtomicBool>,
) -> Result<bool> {
    let mut current = Some(layer);
    let mut seen = BTreeSet::new();
    while let Some(layer) = current {
        check(cancelled)?;
        if !visible(layer)? {
            return Ok(false);
        }
        current = match layer.get("group_layer_id") {
            None | Some(PsbValue::Void | PsbValue::Null) => None,
            Some(value) => {
                let id = value
                    .as_i64()
                    .ok_or_else(|| bad("Invalid PIMG parent group ID"))?;
                if !seen.insert(id) {
                    return Err(bad("Cyclic PIMG group references"));
                }
                groups.get(&id).copied()
            }
        };
    }
    Ok(true)
}

fn paint(
    output: &mut [u8],
    canvas: &ImageMeta,
    image: &Image,
    layer: &BTreeMap<String, PsbValue>,
    mode: blend::Mode,
    opacity: u8,
    cancelled: Option<&AtomicBool>,
) -> Result<()> {
    let left = i128::from(integer(layer, "left")?);
    let top = i128::from(integer(layer, "top")?);
    let width = dimension(layer, "width")?.min(image.meta.width);
    let height = dimension(layer, "height")?.min(image.meta.height);
    let x0 = left.clamp(0, i128::from(canvas.width));
    let y0 = top.clamp(0, i128::from(canvas.height));
    let x1 = (left + i128::from(width)).clamp(0, i128::from(canvas.width));
    let y1 = (top + i128::from(height)).clamp(0, i128::from(canvas.height));
    if x1 <= x0 || y1 <= y0 {
        return Ok(());
    }
    let (source, bgra) = match &image.pixels {
        PixelBuffer::Rgba8(bytes) => (bytes.as_slice(), false),
        PixelBuffer::Bgra8(bytes) => (bytes.as_slice(), true),
        _ => return Err(Error::Unsupported("PIMG layer pixel representation".into())),
    };
    let canvas_width = canvas.width as usize;
    let source_width = image.meta.width as usize;
    for y in y0..y1 {
        check(cancelled)?;
        let from = ((y - top) as usize * source_width + (x0 - left) as usize) * 4;
        let to = (y as usize * canvas_width + x0 as usize) * 4;
        let count = (x1 - x0) as usize * 4;
        for (dest, source) in output[to..to + count]
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(source[from..from + count].as_chunks::<4>().0)
        {
            let mut pixel = *source;
            if bgra {
                pixel.swap(0, 2);
            }
            mode.apply(dest, pixel, opacity);
        }
    }
    Ok(())
}

vnlens_core::inventory::submit! { ImageRegistration(|| Box::new(Pimg)) }
