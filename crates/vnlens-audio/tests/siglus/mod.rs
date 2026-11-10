use super::*;
use vnlens_io::BinaryWriter;
fn stream(samples: u32, rle: bool, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 50];
    BinaryWriter::u16_le(1, &mut data);
    BinaryWriter::u16_le(16, &mut data[2..]);
    for (at, value) in [
        (4, 44100),
        (12, u32::from(rle)),
        (16, 1),
        (20, samples * 2),
        (24, 50 + payload.len() as u32),
        (28, samples),
        (32, samples),
        (36, samples),
        (44, 48),
    ] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    BinaryWriter::u16_le(100, &mut data[48..]);
    data.extend(payload);
    data
}
#[test]
fn signed_deltas_zero_reset_runs_and_truncation() -> Result<()> {
    let bytes = stream(3, false, &[0x09, 0x89, 0x0f]);
    let pcm = Nwa.decode(&bytes)?;
    assert_eq!(&*pcm.samples, &[108. / 32768., 100. / 32768., 0.]);
    assert!(Nwa.decode(&bytes[..bytes.len() - 1]).is_err());
    let run = stream(4, true, &[0xe8, 3]);
    assert_eq!(
        &*Nwa.decode(&run)?.samples,
        &[100. / 32768., 100. / 32768., 100. / 32768., 0.]
    );
    assert!(matches!(
        Nwa.decode_cancellable(&run, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}
