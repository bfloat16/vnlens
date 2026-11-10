use super::*;
use ogg::writing::{PacketWriteEndInfo, PacketWriter};
use vnlens_io::BinaryWriter;
fn sample() -> Result<Vec<u8>> {
    let mut head = b"OpusHead".to_vec();
    head.extend([1, 1]);
    head.resize(19, 0);
    BinaryWriter::u16_le(120, &mut head[10..]);
    BinaryWriter::u32_le(48000, &mut head[12..]);
    let mut tags = b"OpusTags".to_vec();
    tags.resize(16, 0);
    let mut w = PacketWriter::new(Vec::new());
    w.write_packet(head.into_boxed_slice(), 1, PacketWriteEndInfo::EndPage, 0)?;
    w.write_packet(tags.into_boxed_slice(), 1, PacketWriteEndInfo::EndPage, 0)?;
    // RFC 6716 CELT silence, three 20 ms packets; omit the last 240 frames.
    for i in 0..3 {
        w.write_packet(
            vec![0xf8, 0xff, 0xfe].into_boxed_slice(),
            1,
            if i == 2 {
                PacketWriteEndInfo::EndStream
            } else {
                PacketWriteEndInfo::EndPage
            },
            if i == 2 { 2640 } else { (i + 1) * 960 },
        )?;
    }
    Ok(w.into_inner())
}
#[test]
fn silence_preskip_final_trim_crc_and_cancellation() -> Result<()> {
    let data = sample()?;
    let meta = metadata(&data)?;
    assert_eq!(
        (meta.channels, meta.sample_rate, meta.frames),
        (1, 48000, Some(2520))
    );
    let pcm = decode(&data, &AtomicBool::new(false))?;
    assert_eq!(pcm.samples.len(), 2520);
    assert!(pcm.samples.iter().all(|v| v.abs() < 1e-8));
    assert!(matches!(
        decode(&data, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    let mut bad = data;
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(metadata(&bad).is_err());
    Ok(())
}
