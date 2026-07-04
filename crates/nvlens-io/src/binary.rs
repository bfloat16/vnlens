//! Binary read/write primitives.
//!
//! This module is the sole place in the project where raw bytes are turned into
//! integers and back. Higher layers ([`crate::ArcView`], format parsers, codecs)
//! must go through these helpers instead of decoding bytes by hand.
//!
//! Three entry points, by input shape:
//! - [`BinaryReader`]: a cursor over an in-memory `&[u8]` slice.
//! - [`BinaryWriter`]: stateless encoders writing into caller-owned buffers.
//! - [`BinaryIo`]: adapters over `std::io::Read`/`Seek` streams.
//!
//! Multi-byte values default to little-endian; big-endian variants are named
//! explicitly or selected via [`Endian`].

use std::io::{Read, Seek, SeekFrom};

/// Byte order selector for multi-byte integer decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    /// Reads a `u16` from a two-byte slice using this byte order.
    pub fn read_u16(self, data: &[u8]) -> u16 {
        match self {
            Self::Little => BinaryReader::u16_le(data),
            Self::Big => BinaryReader::u16_be(data),
        }
    }

    /// Reads a `u32` from a four-byte slice using this byte order.
    pub fn read_u32(self, data: &[u8]) -> u32 {
        match self {
            Self::Little => BinaryReader::u32_le(data),
            Self::Big => BinaryReader::u32_be(data),
        }
    }

    /// Reads a `u64` from an eight-byte slice using this byte order.
    pub fn read_u64(self, data: &[u8]) -> u64 {
        match self {
            Self::Little => BinaryReader::u64_le(data),
            Self::Big => BinaryReader::u64_be(data),
        }
    }
}

/// Cursor over an in-memory byte slice, plus stateless integer decoders.
#[derive(Debug, Clone)]
pub struct BinaryReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BinaryReader<'a> {
    /// Reads a little-endian `u16` from the first two bytes of `data`.
    pub fn u16_le(data: &[u8]) -> u16 {
        u16::from_le_bytes([data[0], data[1]])
    }

    /// Reads a big-endian `u16` from the first two bytes of `data`.
    pub fn u16_be(data: &[u8]) -> u16 {
        u16::from_be_bytes([data[0], data[1]])
    }

    /// Reads a little-endian `i16` from the first two bytes of `data`.
    pub fn i16_le(data: &[u8]) -> i16 {
        i16::from_le_bytes([data[0], data[1]])
    }

    /// Reads a little-endian `u32` from the first four bytes of `data`.
    pub fn u32_le(data: &[u8]) -> u32 {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    }

    /// Reads a big-endian `u32` from the first four bytes of `data`.
    pub fn u32_be(data: &[u8]) -> u32 {
        u32::from_be_bytes([data[0], data[1], data[2], data[3]])
    }

    /// Reads a little-endian `i32` from the first four bytes of `data`.
    pub fn i32_le(data: &[u8]) -> i32 {
        i32::from_le_bytes([data[0], data[1], data[2], data[3]])
    }

    /// Reads a little-endian `u64` from the first eight bytes of `data`.
    pub fn u64_le(data: &[u8]) -> u64 {
        u64::from_le_bytes(as_array8(data))
    }

    /// Reads a big-endian `u64` from the first eight bytes of `data`.
    pub fn u64_be(data: &[u8]) -> u64 {
        u64::from_be_bytes(as_array8(data))
    }

    /// Reads a little-endian `i64` from the first eight bytes of `data`.
    pub fn i64_le(data: &[u8]) -> i64 {
        i64::from_le_bytes(as_array8(data))
    }

    /// Reads a little-endian `u16` from `data` at a fixed offset.
    pub fn u16_le_at(data: &[u8], offset: usize) -> u16 {
        Self::u16_le(&data[offset..offset + 2])
    }

    /// Reads a little-endian `u32` from `data` at a fixed offset.
    pub fn u32_le_at(data: &[u8], offset: usize) -> u32 {
        Self::u32_le(&data[offset..offset + 4])
    }

    /// Creates a reader positioned at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Creates a reader positioned at `pos`; errors if `pos` is past the end.
    pub fn new_at(data: &'a [u8], pos: usize) -> std::io::Result<Self> {
        if pos > data.len() {
            return Err(BinaryIo::invalid_input(format!(
                "offset out of range: 0x{pos:X}"
            )));
        }
        Ok(Self { data, pos })
    }

    /// Returns the backing slice length.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether the backing slice is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the current byte position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Sets the current byte position; errors if it is past the end.
    pub fn set_position(&mut self, pos: usize) -> std::io::Result<()> {
        if pos > self.data.len() {
            return Err(BinaryIo::unexpected_eof(format!(
                "seek past end at 0x{pos:X}"
            )));
        }
        self.pos = pos;
        Ok(())
    }

    /// Returns the number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Reads a borrowed byte range of length `len` and advances the cursor.
    pub fn read_bytes(&mut self, len: usize) -> std::io::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| BinaryIo::invalid_input("read offset overflow"))?;
        if end > self.data.len() {
            return Err(BinaryIo::unexpected_eof(format!(
                "unexpected EOF at 0x{:X}, need {len} bytes",
                self.pos
            )));
        }
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    /// Reads one byte.
    pub fn read_u8(&mut self) -> std::io::Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Reads a little-endian `u16`.
    pub fn read_u16_le(&mut self) -> std::io::Result<u16> {
        Ok(Self::u16_le(self.read_bytes(2)?))
    }

    /// Reads a little-endian `i16`.
    pub fn read_i16_le(&mut self) -> std::io::Result<i16> {
        Ok(Self::i16_le(self.read_bytes(2)?))
    }

    /// Reads a little-endian `u32`.
    pub fn read_u32_le(&mut self) -> std::io::Result<u32> {
        Ok(Self::u32_le(self.read_bytes(4)?))
    }

    /// Reads a `u32` using the requested byte order.
    pub fn read_u32(&mut self, endian: Endian) -> std::io::Result<u32> {
        Ok(endian.read_u32(self.read_bytes(4)?))
    }

    /// Reads a little-endian `i32`.
    pub fn read_i32_le(&mut self) -> std::io::Result<i32> {
        Ok(Self::i32_le(self.read_bytes(4)?))
    }

    /// Reads a little-endian `u64`.
    pub fn read_u64_le(&mut self) -> std::io::Result<u64> {
        Ok(Self::u64_le(self.read_bytes(8)?))
    }

    /// Reads a `u64` using the requested byte order.
    pub fn read_u64(&mut self, endian: Endian) -> std::io::Result<u64> {
        Ok(endian.read_u64(self.read_bytes(8)?))
    }

    /// Reads a little-endian `i64`.
    pub fn read_i64_le(&mut self) -> std::io::Result<i64> {
        Ok(Self::i64_le(self.read_bytes(8)?))
    }

    /// Reads `count` little-endian UTF-16 code units.
    pub fn read_utf16_units_le(&mut self, count: usize) -> std::io::Result<Vec<u16>> {
        let mut units = Vec::with_capacity(count);
        for _ in 0..count {
            units.push(self.read_u16_le()?);
        }
        Ok(units)
    }

    /// Skips padding until the cursor is aligned to a four-byte boundary.
    pub fn align4(&mut self) -> std::io::Result<()> {
        let rem = self.pos & 3;
        if rem != 0 {
            let _ = self.read_bytes(4 - rem)?;
        }
        Ok(())
    }
}

/// Stateless little/big-endian encoders writing into caller-owned buffers.
#[derive(Debug)]
pub struct BinaryWriter;

impl BinaryWriter {
    /// Writes a little-endian `u16` into the first two bytes of `out`.
    pub fn u16_le(value: u16, out: &mut [u8]) {
        out[..2].copy_from_slice(&value.to_le_bytes());
    }

    /// Writes a little-endian `u32` into the first four bytes of `out`.
    pub fn u32_le(value: u32, out: &mut [u8]) {
        out[..4].copy_from_slice(&value.to_le_bytes());
    }

    /// Writes a little-endian `u32` into `out` at a fixed offset.
    pub fn u32_le_at(value: u32, out: &mut [u8], offset: usize) {
        Self::u32_le(value, &mut out[offset..offset + 4]);
    }

    /// Writes a big-endian `u64` into the first eight bytes of `out`.
    pub fn u64_be(value: u64, out: &mut [u8]) {
        out[..8].copy_from_slice(&value.to_be_bytes());
    }
}

/// Adapters over `std::io::Read`/`Seek` streams, plus error constructors.
#[derive(Debug)]
pub struct BinaryIo;

impl BinaryIo {
    /// Reads a little-endian `u16` from a stream.
    pub fn read_u16_le<R: Read>(reader: &mut R) -> std::io::Result<u16> {
        let mut bytes = [0u8; 2];
        reader.read_exact(&mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Reads a little-endian `u32` from a stream.
    pub fn read_u32_le<R: Read>(reader: &mut R) -> std::io::Result<u32> {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Reads a little-endian `i32` from a stream.
    pub fn read_i32_le<R: Read>(reader: &mut R) -> std::io::Result<i32> {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        Ok(i32::from_le_bytes(bytes))
    }

    /// Reads a little-endian `u32` from a seekable stream at a fixed offset.
    pub fn read_u32_le_at<R: Read + Seek>(reader: &mut R, offset: u64) -> std::io::Result<u32> {
        reader.seek(SeekFrom::Start(offset))?;
        Self::read_u32_le(reader)
    }

    /// Constructs an `InvalidInput` I/O error.
    pub fn invalid_input(message: impl Into<String>) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
    }

    /// Constructs an `UnexpectedEof` I/O error.
    pub fn unexpected_eof(message: impl Into<String>) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, message.into())
    }
}

/// Copies the first eight bytes of `data` into a fixed array for 64-bit decoding.
fn as_array8(data: &[u8]) -> [u8; 8] {
    [
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn cursor_reads_advance() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mut r = BinaryReader::new(&data);
        assert_eq!(r.read_u16_le().unwrap(), 0x0201);
        assert_eq!(r.read_u32_le().unwrap(), 0x0605_0403);
        assert_eq!(r.remaining(), 0);
        assert!(r.read_u8().is_err());
    }

    #[test]
    fn endian_selects_order() {
        let data = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(Endian::Little.read_u32(&data), 0x7856_3412);
        assert_eq!(Endian::Big.read_u32(&data), 0x1234_5678);
    }

    #[test]
    fn writer_roundtrip() {
        let mut out = [0u8; 4];
        BinaryWriter::u32_le(0xDEAD_BEEF, &mut out);
        assert_eq!(BinaryReader::u32_le(&out), 0xDEAD_BEEF);
    }
}
