use super::*;
use crate::{decode_cancellable_as, metadata_as};
use nvlens_io::BinaryWriter;

fn build_xwma(codec: u16, channels: u16, sample_rate: u32, include_fmt: bool) -> Vec<u8> {
    let mut chunks = Vec::new();
    if include_fmt {
        let mut fmt = [0u8; 26];
        fmt[..4].copy_from_slice(b"fmt ");
        BinaryWriter::u32_le(18, &mut fmt[4..8]);
        BinaryWriter::u16_le(codec, &mut fmt[8..10]);
        BinaryWriter::u16_le(channels, &mut fmt[10..12]);
        BinaryWriter::u32_le(sample_rate, &mut fmt[12..16]);
        BinaryWriter::u32_le(4000, &mut fmt[16..20]); // avg bytes/sec
        BinaryWriter::u16_le(4, &mut fmt[20..22]); // block align
        BinaryWriter::u16_le(16, &mut fmt[22..24]); // bits/sample
        chunks.extend_from_slice(&fmt);
    }
    let mut junk = [0u8; 12];
    junk[..4].copy_from_slice(b"JUNK");
    BinaryWriter::u32_le(3, &mut junk[4..8]);
    junk[8..12].copy_from_slice(&[1, 2, 3, 0]); // odd-sized chunk + pad byte
    chunks.extend_from_slice(&junk);

    let mut data = vec![0u8; 12 + chunks.len()];
    data[..4].copy_from_slice(b"RIFF");
    BinaryWriter::u32_le((4 + chunks.len()) as u32, &mut data[4..8]);
    data[8..12].copy_from_slice(b"XWMA");
    data[12..].copy_from_slice(&chunks);
    data
}

#[test]
fn parses_xwma_metadata_and_validates_chunks() -> Result<()> {
    assert!(metadata_as("xwma", b"RIFF\x04\0\0\0WAVE")?.is_none());

    for codec in [0x161, 0x162] {
        let data = build_xwma(codec, 2, 44_100, true);
        let meta = metadata_as("xwma", &data)?.ok_or(Error::InvalidFormat)?;
        assert_eq!(meta.codec, "xWMA");
        assert_eq!(meta.channels, 2);
        assert_eq!(meta.sample_rate, 44_100);
        assert_eq!(meta.frames, None);
    }

    let unsupported = build_xwma(0x0001, 2, 44_100, true);
    assert!(matches!(
        metadata_as("xwma", &unsupported),
        Err(Error::Unsupported(_))
    ));

    let zero_channels = build_xwma(0x161, 0, 44_100, true);
    assert!(matches!(
        metadata_as("xwma", &zero_channels),
        Err(Error::Corrupt { .. })
    ));

    let missing_fmt = build_xwma(0x161, 2, 44_100, false);
    assert!(matches!(
        metadata_as("xwma", &missing_fmt),
        Err(Error::Corrupt { .. })
    ));

    let mut bad_size = build_xwma(0x161, 2, 44_100, true);
    bad_size.push(0);
    assert!(matches!(
        metadata_as("xwma", &bad_size),
        Err(Error::Corrupt { .. })
    ));

    let cancel = AtomicBool::new(true);
    assert!(matches!(
        decode_cancellable_as("xwma", &unsupported, &cancel),
        Err(Error::Cancelled)
    ));
    Ok(())
}
