use super::*;
use crate::Video;
use image::{ColorType, codecs::jpeg::JpegEncoder};
use nvlens_io::BinaryWriter;

fn encode_jpeg(width: u32, height: u32, color: ColorType, pixels: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    JpegEncoder::new_with_quality(&mut out, 100)
        .encode(pixels, width, height, color.into())
        .map_err(io::Error::other)?;
    xor::apply(&mut out, KEY).map_err(|e| corrupt(0, e.to_string()))?;
    Ok(out)
}

fn fixture(frames: &[(&[u8], &[u8])], alpha: bool, rate: u32) -> Vec<u8> {
    let count = frames.len();
    let index_end = 32 + count * 12;
    let mut bytes = vec![0; index_end];
    bytes[..4].copy_from_slice(MAGIC);
    BinaryWriter::u32_le(1, &mut bytes[4..]);
    BinaryWriter::u32_le(count as u32, &mut bytes[8..]);
    BinaryWriter::u32_le(u32::from(alpha), &mut bytes[12..]);
    BinaryWriter::u32_le(1, &mut bytes[16..]);
    BinaryWriter::u32_le(1, &mut bytes[20..]);
    BinaryWriter::u32_le(rate, &mut bytes[24..]);
    let mut offset = index_end as u32;
    for (i, (color, mask)) in frames.iter().enumerate() {
        BinaryWriter::u32_le(offset, &mut bytes[32 + i * 4..]);
        BinaryWriter::u32_le(color.len() as u32, &mut bytes[32 + (count + i) * 4..]);
        BinaryWriter::u32_le(mask.len() as u32, &mut bytes[32 + (count * 2 + i) * 4..]);
        bytes.extend_from_slice(color);
        bytes.extend_from_slice(mask);
        offset += (color.len() + mask.len()) as u32;
    }
    bytes
}

#[test]
fn decodes_xored_jpeg_frames_alpha_plane_and_keeps_frames_lazy() -> Result<()> {
    assert_eq!(YmvFormat.tag(), "ymv/yuris");
    assert_eq!(YmvFormat.signatures(), SIGNATURES);
    assert_eq!(YmvFormat.extensions(), &["ymv"]);

    let color0 = encode_jpeg(1, 1, ColorType::Rgb8, &[200, 100, 50])?;
    let alpha0 = encode_jpeg(1, 1, ColorType::L8, &[128])?;
    let color1 = encode_jpeg(1, 1, ColorType::Rgb8, &[10, 20, 240])?;
    let alpha1 = encode_jpeg(1, 1, ColorType::L8, &[64])?;
    // Frame 1 has corrupt payload bytes; mounting and reading frame 0 must succeed.
    let bytes: Arc<[u8]> = fixture(
        &[(&color0, &alpha0), (b"broken", b""), (&color1, &alpha1)],
        true,
        10,
    )
    .into();
    let source: Arc<dyn ReadAt> = Arc::new(bytes);

    let mut video = Video::open_source_as(
        "ymv/yuris",
        source,
        Some("op.ymv"),
        Arc::new(AtomicBool::new(false)),
    )?
    .ok_or(Error::InvalidFormat)?;
    assert_eq!(video.meta().container, "YSMV");
    assert_eq!(video.meta().video.frame_rate, Some(10.));

    let first = video.next_picture()?.ok_or(Error::InvalidFormat)?;
    assert_eq!((first.width, first.height), (1, 1));
    assert!((f64::from(first.bgra[3]) - 128.).abs() <= 2.);

    assert!(matches!(video.next_picture(), Err(Error::Corrupt { .. })));

    video.seek(0.2)?;
    let third = video.next_picture()?.ok_or(Error::InvalidFormat)?;
    assert!((third.time - 0.2).abs() < 1e-6);
    assert!((f64::from(third.bgra[3]) - 64.).abs() <= 2.);
    assert!(video.next_picture()?.is_none());
    Ok(())
}

#[test]
fn rejects_zero_rate_bad_ranges_and_truncation() {
    let zero_rate: Arc<[u8]> = fixture(&[], false, 0).into();
    assert!(matches!(
        Ymv::open(Arc::new(zero_rate), Arc::new(AtomicBool::new(false))),
        Err(Error::Unsupported(_))
    ));

    let mut bad = fixture(&[(b"abcd", b"")], false, 10);
    BinaryWriter::u32_le(16, &mut bad[32..]);
    let bad_source: Arc<[u8]> = bad.clone().into();
    assert!(matches!(
        Ymv::open(Arc::new(bad_source), Arc::new(AtomicBool::new(false))),
        Err(Error::Corrupt { .. })
    ));

    let truncated: Arc<[u8]> = bad[..20].to_vec().into();
    assert!(matches!(
        Ymv::open(Arc::new(truncated), Arc::new(AtomicBool::new(false))),
        Err(Error::Io(_))
    ));
}
