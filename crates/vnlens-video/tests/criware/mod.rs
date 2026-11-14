use super::*;
use crate::{AudioDecoder, Video};

#[test]
fn directed_usm_dispatch_rejects_non_usm_streams_without_ffmpeg_fallback() {
    let y4m: Arc<dyn ReadAt> = Arc::new(Arc::<[u8]>::from(
        b"YUV4MPEG2 W2 H2 F10:1 Ip A1:1 C444\nFRAME\n\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
            .as_slice(),
    ));
    assert!(matches!(
        Video::open_source_as(
            "cri/usm",
            y4m.clone(),
            Some("movie.y4m"),
            Arc::new(AtomicBool::new(false)),
        ),
        Err(Error::InvalidFormat)
    ));
    assert!(matches!(
        AudioDecoder::open_source_as(
            "cri/usm",
            y4m,
            Some("movie.y4m"),
            Arc::new(AtomicBool::new(false)),
        ),
        Err(Error::InvalidFormat)
    ));
}
