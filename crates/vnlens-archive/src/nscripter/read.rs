//! Index bounds and compression framing. SPB output is a 54-byte BMP header
//! followed by bottom-up, four-byte-aligned BGR24 rows.
use super::*;
use vnlens_core::{Packed, ResourceKind};
use vnlens_io::{BinaryReader, BinaryWriter};

pub(super) fn index(source: &dyn ReadAt, nsa: bool) -> Result<(Vec<Entry>, Vec<u8>)> {
    let header = source.read_at(0, 6)?;
    let mut r = BinaryReader::new(&header);
    let count = usize::from(BinaryReader::u16_be(r.read_bytes(2)?));
    let base = u64::from(BinaryReader::u32_be(r.read_bytes(4)?));
    if base < 6 {
        return Err(bad(2, "NScripter data overlaps header"));
    }
    let directory = source.read_at(
        6,
        usize::try_from(base - 6)
            .map_err(|_| Error::Unsupported("NScripter index exceeds address space".into()))?,
    )?;
    let mut r = BinaryReader::new(&directory);
    let mut entries = Vec::new();
    let mut codecs = Vec::new();
    for _ in 0..count {
        let at = r.position();
        let name_size = directory[at..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| bad(6 + at as u64, "Unterminated NScripter entry name"))?;
        let raw_name = r.read_bytes(name_size)?;
        r.read_u8()?;
        let (name, _, invalid) = encoding_rs::SHIFT_JIS.decode(raw_name);
        if invalid {
            return Err(bad(6 + at as u64, "Invalid NScripter CP932 entry name"));
        }
        let codec = if nsa { r.read_u8()? } else { 0 };
        let offset = base + u64::from(BinaryReader::u32_be(r.read_bytes(4)?));
        let size = u64::from(BinaryReader::u32_be(r.read_bytes(4)?));
        let unpacked = if nsa {
            u64::from(BinaryReader::u32_be(r.read_bytes(4)?))
        } else {
            size
        };
        if !matches!(codec, 0 | 1 | 2 | 4) {
            return Err(Error::Unsupported(format!("NSA compression type {codec}")));
        }
        let entry = Entry {
            name: name.into_owned(),
            offset,
            size,
            kind: ResourceKind::Unknown,
            packed: (codec != 0).then_some(Packed {
                unpacked_size: unpacked,
                is_packed: true,
            }),
        };
        if !entry.check_placement(source.len()) {
            return Err(
                vnlens_io::BinaryIo::unexpected_eof("NScripter entry exceeds storage").into(),
            );
        }
        entries.push(entry);
        codecs.push(codec);
    }
    Ok((entries, codecs))
}

pub(super) fn unpack(data: &[u8], codec: u8, size: u64, offset: u64) -> Result<Vec<u8>> {
    let size = usize::try_from(size)
        .map_err(|_| Error::Unsupported("NSA output exceeds address space".into()))?;
    let decoded = match codec {
        // sub_40EB20/sub_445550 use SPB dimensions, ignoring the index's
        // original BMP file size. Original trailing padding and BMP metadata
        // are not encoded in SPB and must not become an output-size check.
        1 => return bitmap(data, offset),
        2 => vnlens_crypto::compress::nscripter::lzss(data, size)
            .map_err(|e| decode_error(offset, e))?,
        // NBZ's own prefix is authoritative, including archives whose original
        // length field is zero (ONScripter SarReader's delayed-size path).
        4 => return vnlens_audio::nscripter::decode_envelope(data),
        _ => return Err(Error::Unsupported(format!("NSA compression type {codec}"))),
    };
    if decoded.len() != size {
        return Err(bad(offset, "NSA decompressed size mismatch"));
    }
    Ok(decoded)
}

fn bitmap(data: &[u8], offset: u64) -> Result<Vec<u8>> {
    let mut r = BinaryReader::new(data);
    let width = BinaryReader::u16_be(r.read_bytes(2)?);
    let height = BinaryReader::u16_be(r.read_bytes(2)?);
    let pixels =
        vnlens_crypto::compress::nscripter::spb(r.read_bytes(r.remaining())?, width, height)
            .map_err(|e| decode_error(offset + 4, e))?;
    let row = usize::from(width) * 3;
    let stride = row.div_ceil(4) * 4;
    let pixel_size = stride
        .checked_mul(usize::from(height))
        .ok_or_else(|| Error::Unsupported("SPB bitmap exceeds address space".into()))?;
    let file_size = pixel_size
        .checked_add(54)
        .ok_or_else(|| Error::Unsupported("SPB bitmap exceeds address space".into()))?;
    let file_size_u32 = u32::try_from(file_size)
        .map_err(|_| Error::Unsupported("SPB bitmap exceeds BMP size field".into()))?;
    let mut out = vec![0; file_size];
    out[..2].copy_from_slice(b"BM");
    BinaryWriter::u32_le(file_size_u32, &mut out[2..]);
    BinaryWriter::u32_le(54, &mut out[10..]);
    BinaryWriter::u32_le(40, &mut out[14..]);
    BinaryWriter::u32_le(u32::from(width), &mut out[18..]);
    BinaryWriter::u32_le(u32::from(height), &mut out[22..]);
    BinaryWriter::u16_le(1, &mut out[26..]);
    BinaryWriter::u16_le(24, &mut out[28..]);
    BinaryWriter::u32_le(file_size_u32 - 54, &mut out[34..]);
    for (y, source) in pixels.chunks_exact(row).enumerate() {
        let start = 54 + (usize::from(height) - 1 - y) * stride;
        out[start..start + row].copy_from_slice(source);
    }
    Ok(out)
}

fn decode_error(offset: u64, error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        error.into()
    } else {
        bad(offset, &format!("NScripter decompression: {error}"))
    }
}
