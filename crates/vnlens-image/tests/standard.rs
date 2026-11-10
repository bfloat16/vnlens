#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn gif_frame_count_and_selected_frame_export() -> Result<()> {
    let mut data = Vec::new();
    {
        let mut encoder = image::codecs::gif::GifEncoder::new(&mut data);
        for color in [[255, 0, 0, 255], [0, 255, 0, 255]] {
            let buffer = image::RgbaImage::from_pixel(2, 1, image::Rgba(color));
            encoder
                .encode_frame(image::Frame::new(buffer))
                .map_err(error)?;
        }
    }
    assert_eq!(Raster.frame_count(&data)?, 2);
    let second = Raster.decode_frame(&data, 1)?;
    assert!(matches!(second.pixels,PixelBuffer::Rgba8(ref p) if p==&[0,255,0,255,0,255,0,255]));
    assert!(Raster.decode_frame(&data, 2).is_err());
    assert!(Raster.frame_count(&data[..data.len() - 1]).is_err());
    Ok(())
}

#[test]
fn decodes_png_with_offsets_and_rejects_invalid_offset_unit() {
    let img = Image {
        meta: ImageMeta {
            width: 1,
            height: 1,
            offset_x: -4,
            offset_y: 8,
            offset_unit: OffsetUnit::Micrometers,
            bpp: 32,
        },
        pixels: PixelBuffer::Rgba8(vec![10, 20, 30, 255]),
    };
    let mut png = img.to_png().unwrap();
    assert!(Raster.metadata(b"not an image").unwrap().is_none());
    let decoded = Raster.decode(&png).unwrap();
    assert_eq!(decoded.meta.width, 1);
    assert_eq!(decoded.meta.height, 1);
    assert_eq!(decoded.meta.offset_x, -4);
    assert_eq!(decoded.meta.offset_y, 8);
    assert_eq!(decoded.meta.offset_unit, OffsetUnit::Micrometers);
    assert!(matches!(
        decoded.pixels,
        PixelBuffer::Rgba8(ref pixels) if pixels == &[10, 20, 30, 255]
    ));

    let offs_pos = png.windows(4).position(|window| window == b"oFFs").unwrap();
    png[offs_pos + 4 + 8] = 2;
    assert!(matches!(Raster.metadata(&png), Err(Error::Corrupt { .. })));
}
