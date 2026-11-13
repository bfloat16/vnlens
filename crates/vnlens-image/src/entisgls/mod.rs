//! ERI adapter to the shared ERISA raster decoder. Header descriptions retain
//! hot-spot offsets; reference-file images are requested only when needed.
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, PixelBuffer};
use std::{collections::HashSet, sync::atomic::AtomicBool};
use vnlens_core::{ArchiveOptions, Error, Format, ResourceResolver, Result};
use vnlens_middleware::erisa::{MediaFile, RasterDecoder};

#[derive(Debug, Default)]
struct Eri;
impl Format for Eri {
    fn tag(&self) -> &'static str {
        "eri/entisgls"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x6974_6e45, 0x5453_4956]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["eri", "emi"]
    }
    fn description(&self) -> &'static str {
        "Entis rasterized image"
    }
}

fn meta(file: &MediaFile) -> Result<ImageMeta> {
    let info = file.image.as_ref().ok_or_else(|| Error::Corrupt {
        offset: 64,
        reason: "Missing ERISA ImageInf".into(),
    })?;
    let mut offset_x = 0;
    let mut offset_y = 0;
    if let Some(hotspot) = file.tags.get("hot-spot") {
        let (x, y) = hotspot
            .trim()
            .split_once(',')
            .ok_or_else(|| Error::Corrupt {
                offset: 64,
                reason: "Invalid ERISA hot-spot".into(),
            })?;
        offset_x = x.trim().parse().map_err(|_| Error::Corrupt {
            offset: 64,
            reason: "Invalid ERISA hot-spot X".into(),
        })?;
        offset_y = y.trim().parse().map_err(|_| Error::Corrupt {
            offset: 64,
            reason: "Invalid ERISA hot-spot Y".into(),
        })?;
    }
    Ok(ImageMeta {
        width: info.width,
        height: info.height,
        bpp: u16::try_from(info.bpp).map_err(std::io::Error::other)?,
        offset_x,
        offset_y,
        offset_unit: Default::default(),
    })
}

fn decode(file: &MediaFile, data: &[u8], frame: usize, cancel: &AtomicBool) -> Result<Image> {
    let mut decoder = RasterDecoder::new(file)?;
    let pixels = decoder.decode_at(frame, &data, cancel)?;
    Ok(Image {
        meta: meta(file)?,
        pixels: PixelBuffer::Bgra8(pixels),
    })
}
impl ImageFormat for Eri {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        Ok(Some(meta(&MediaFile::open(&data)?)?))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        self.decode_with_options(data, None, &Default::default(), None)
    }
    fn decode_with_resources(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Image> {
        self.decode_with_options(data, resources, &Default::default(), None)
    }
    fn frame_count(&self, data: &[u8]) -> Result<usize> {
        Ok(MediaFile::open(&data)?
            .stream
            .iter()
            .filter(|s| matches!(&s.id, b"ImageFrm" | b"DiffeFrm"))
            .count())
    }
    fn decode_frame(&self, data: &[u8], frame: usize) -> Result<Image> {
        decode(
            &MediaFile::open(&data)?,
            data,
            frame,
            &AtomicBool::new(false),
        )
    }
    fn decode_with_options(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
        _: &ArchiveOptions,
        cancel: Option<&AtomicBool>,
    ) -> Result<Image> {
        let default = AtomicBool::new(false);
        let cancel = cancel.unwrap_or(&default);
        let mut file = MediaFile::open(&data)?;
        let mut result = decode(&file, data, 0, cancel)?;
        let mut visited = HashSet::new();
        while let Some(name) = file
            .tags
            .get("reference-file")
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
        {
            if !visited.insert(name.clone()) {
                return Err(Error::Corrupt {
                    offset: 64,
                    reason: "Cyclic ERISA reference-file".into(),
                });
            }
            let bytes = resources
                .ok_or_else(|| {
                    Error::Unsupported("ERISA reference image requires resolver".into())
                })?
                .read_resource(&name)?
                .ok_or_else(|| {
                    Error::Unsupported(format!("ERISA reference image is missing: {name}"))
                })?;
            let slice = bytes.as_slice();
            file = MediaFile::open(&slice)?;
            let base = decode(&file, &bytes, 0, cancel)?;
            if base.meta.width < result.meta.width || base.meta.height < result.meta.height {
                return Err(Error::Corrupt {
                    offset: 64,
                    reason: "ERISA reference image does not cover the target image".into(),
                });
            }
            let base_width = base.meta.width as usize;
            if let (PixelBuffer::Bgra8(target), PixelBuffer::Bgra8(base)) =
                (&mut result.pixels, base.pixels)
            {
                for y in 0..result.meta.height as usize {
                    for x in 0..result.meta.width as usize {
                        let target_at = (y * result.meta.width as usize + x) * 4;
                        let base_at = (y * base_width + x) * 4;
                        for ch in 0..if result.meta.bpp == 32
                            && file
                                .image
                                .as_ref()
                                .is_some_and(|i| i.format & 0x0400_0000 != 0)
                        {
                            4
                        } else {
                            3
                        } {
                            target[target_at + ch] =
                                target[target_at + ch].wrapping_add(base[base_at + ch]);
                        }
                    }
                }
            }
        }
        Ok(result)
    }
}
vnlens_core::inventory::submit! { ImageRegistration(|| Box::new(Eri)) }

#[cfg(test)]
#[path = "../../tests/entisgls/mod.rs"]
mod tests;
