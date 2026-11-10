//! Zstandard frame decoding (RFC 8878), using ruzstd's streaming decoder.
use ruzstd::decoding::{FrameDecoder, StreamingDecoder};
use std::io::{self, Read};

/// Opens a frame using the format's full window range. Frame checksums are
/// verified when its output is exhausted; callers enforce the container size.
pub fn decoder<R: Read>(reader: R) -> io::Result<impl Read> {
    let inner = StreamingDecoder::new_with_max_window_size(reader, u64::MAX)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(Checked { inner })
}
struct Checked<R: Read> {
    inner: StreamingDecoder<R, FrameDecoder>,
}
impl<R: Read> Read for Checked<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(bytes)?;
        if count == 0
            && !bytes.is_empty()
            && let Some(expected) = self.inner.decoder.get_checksum_from_data()
            && self.inner.decoder.get_calculated_checksum() != Some(expected)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Zstandard frame checksum mismatch",
            ));
        }
        Ok(count)
    }
}
#[cfg(test)]
#[path = "../../tests/compress/zstd.rs"]
mod tests;
