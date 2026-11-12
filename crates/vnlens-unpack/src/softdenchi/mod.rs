//! SoftDenchi concatenated executables: the first PE contains SoftDenchi strings,
//! followed by wrapper metadata and an intact host PE with relative file offsets.
//! The host starts at the next DOS/PE header beyond the wrapper's stored sections;
//! both headers and section bounds are validated by the shared PE reader.

use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Result};
use vnlens_io::{BinaryIo, BinaryReader, pe::PeImage};

/// Selects the second PE after recognizing SoftDenchi strings in the first PE.
/// Borrows the host, including its overlay, without copying, executing or saving
/// either executable. Unrecognized images are unchanged. Missing hosts are corrupt;
/// malformed host headers and sections retain their I/O errors. Cancellation leaves
/// the original image unchanged.
pub fn unpack<'a>(image: &mut PeImage<'a>, cancel: &AtomicBool) -> Result<bool> {
    check(cancel)?;
    let marker = b"SoftDenchi";
    let mut recognized = false;
    for section in &image.sections {
        for (position, bytes) in image
            .section_data(section)?
            .windows(marker.len())
            .enumerate()
        {
            if position.is_multiple_of(4096) {
                check(cancel)?;
            }
            if bytes.eq_ignore_ascii_case(marker) {
                recognized = true;
                break;
            }
        }
        if recognized {
            break;
        }
    }
    if !recognized {
        return Ok(false);
    }
    let end = image
        .sections
        .iter()
        .fold(u64::from(image.header_size), |end, section| {
            end.max(u64::from(section.raw_offset) + u64::from(section.raw_size))
        });
    let start = usize::try_from(end)
        .map_err(|_| BinaryIo::unexpected_eof("SoftDenchi wrapper extent does not fit memory"))?;
    let mut reader = BinaryReader::new_at(image.file_bytes(), start)?;
    let tail = reader.read_bytes(reader.remaining())?;
    for (position, magic) in tail.windows(2).enumerate() {
        if position.is_multiple_of(4096) {
            check(cancel)?;
        }
        if magic != b"MZ" {
            continue;
        }
        let candidate = &tail[position..];
        // Incidental MZ bytes in wrapper metadata are not PE candidates.
        let signature = (|| -> std::io::Result<&[u8]> {
            let mut dos = BinaryReader::new_at(candidate, 0x3c)?;
            let offset = usize::try_from(dos.read_u32_le()?).map_err(|_| {
                BinaryIo::unexpected_eof("SoftDenchi PE offset does not fit memory")
            })?;
            let mut pe = BinaryReader::new_at(candidate, offset)?;
            pe.read_bytes(4)
        })();
        if !matches!(signature, Ok(b"PE\0\0")) {
            continue;
        }
        let host = PeImage::parse(candidate)?.ok_or(Error::InvalidFormat)?;
        check(cancel)?;
        *image = host;
        return Ok(true);
    }
    check(cancel)?;
    Err(Error::Corrupt {
        offset: end,
        reason: "SoftDenchi host PE is missing".into(),
    })
}

fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/softdenchi/mod.rs"]
mod tests;
