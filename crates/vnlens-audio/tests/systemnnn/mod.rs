#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;
fn wrapped(wav: &[u8], kind: u8) -> Vec<u8> {
    let mut data = b"IF PACKTYPE==0  CUT THIS 64 BYTETHEN REMAKE WAV PACKTYPE=0      ".to_vec();
    data[13] = b'0' + kind;
    data[57] = b'0' + kind;
    data.extend_from_slice(wav);
    data
}
#[test]
fn wrapped_pcm_matches_standard_decoder_and_cancels() {
    let pcm = Pcm {
        meta: AudioMeta {
            codec: "WAV PCM",
            channels: 1,
            sample_rate: 22050,
            frames: Some(3),
        },
        samples: vec![0.0, 0.5, -0.5].into(),
    };
    let wav = pcm.to_wav().unwrap();
    let bytes = wrapped(&wav, 0);
    let decoded = Vaw.decode(&bytes).unwrap();
    assert_eq!(&*decoded.samples, &*pcm.samples);
    assert_eq!(decoded.meta.frames, Some(3));
    for len in 0..bytes.len() {
        assert!(Vaw.decode(&bytes[..len]).is_err());
    }
    assert!(matches!(
        Vaw.decode_cancellable(&bytes, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
}
#[test]
fn ogg_prefix_uses_declared_format_size_not_a_fixed_offset() {
    for fmt_size in [16usize, 40, 64] {
        let mut wav = vec![0; 20 + fmt_size + 8];
        wav[..4].copy_from_slice(b"RIFF");
        wav[8..16].copy_from_slice(b"WAVEfmt ");
        BinaryWriter::u32_le(fmt_size as u32, &mut wav[16..]);
        wav[20 + fmt_size..24 + fmt_size].copy_from_slice(b"data");
        wav.extend_from_slice(b"OggSsynthetic packet");
        let bytes = wrapped(&wav, 2);
        assert_eq!(payload(&bytes).unwrap().unwrap(), b"OggSsynthetic packet");
        for len in 0..bytes.len() - 16 {
            assert!(payload(&bytes[..len]).is_err() || payload(&bytes[..len]).unwrap().is_none());
        }
    }
    let mut direct = vec![b' '; 64];
    direct[16..20].copy_from_slice(b"OGG ");
    direct[48..58].copy_from_slice(b"PACKTYPE=6");
    direct.extend_from_slice(b"OggS");
    assert_eq!(payload(&direct).unwrap().unwrap(), b"OggS");
    assert!(payload(b"OggS").unwrap().is_none());
}
