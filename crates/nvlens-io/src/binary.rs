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
#![forbid(unsafe_code)]

/// Byte order selector for multi-byte integer decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    /// Reads a `u32` from a four-byte slice using this byte order.
    #[must_use]
    pub fn read_u32(self, data: &[u8]) -> u32 {
        match self {
            Self::Little => BinaryReader::u32_le(data),
            Self::Big => BinaryReader::u32_be(data),
        }
    }

    /// Reads a `u64` from an eight-byte slice using this byte order.
    #[must_use]
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

/// Bit order within each byte of a compressed stream.
#[derive(Clone, Copy, Debug)]
pub enum BitOrder {
    Msb,
    Lsb,
}

/// Bounded bit cursor. Multi-bit fields are assembled in stream order.
#[derive(Debug)]
pub struct BitReader<'a> {
    data: &'a [u8],
    byte: usize,
    cache: u64,
    available: u8,
    order: BitOrder,
}

impl<'a> BitReader<'a> {
    #[must_use]
    pub fn new(data: &'a [u8], order: BitOrder) -> Self {
        Self {
            data,
            byte: 0,
            cache: 0,
            available: 0,
            order,
        }
    }
    #[inline]
    fn refill(&mut self) -> bool {
        let Some(&byte) = self.data.get(self.byte) else {
            return false;
        };
        self.byte += 1;
        let byte = match self.order {
            BitOrder::Msb => byte,
            BitOrder::Lsb => byte.reverse_bits(),
        };
        self.cache = (self.cache << 8) | u64::from(byte);
        self.available += 8;
        true
    }
    /// Peeks eight bits without consuming them; a short final field returns None.
    #[inline]
    #[must_use]
    pub fn peek_byte(&mut self) -> Option<u8> {
        if self.available < 8 && !self.refill() {
            return None;
        }
        Some((self.cache >> (self.available - 8)) as u8)
    }
    #[inline]
    pub fn read_bit(&mut self) -> std::io::Result<u8> {
        Ok(self.read_bits(1)? as u8)
    }
    #[inline]
    pub fn read_bits(&mut self, count: u8) -> std::io::Result<u32> {
        if count > 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Bit field exceeds u32",
            ));
        }
        while self.available < count {
            if !self.refill() {
                return Err(BinaryIo::unexpected_eof("Truncated bitstream"));
            }
        }
        self.available -= count;
        let value = (self.cache >> self.available) as u32;
        self.cache &= (1u64 << self.available) - 1;
        Ok(value)
    }
    /// Reads bytes interleaved with control bits, retaining the pending bits.
    /// Used by codecs whose literal/match bytes share the control-bit stream.
    pub fn read_raw_bytes(&mut self, len: usize) -> std::io::Result<&'a [u8]> {
        let mut reader = BinaryReader::new_at(self.data, self.byte)?;
        let bytes = reader.read_bytes(len)?;
        self.byte = reader.position();
        Ok(bytes)
    }

    pub fn align_byte(&mut self) {
        self.available -= self.available % 8;
        self.cache &= (1u64 << self.available) - 1;
    }

    /// Reads a field whose first stream bit is its least significant bit.
    /// BitOrder still selects the bit traversal order within each source byte.
    pub fn read_bits_le(&mut self, count: u8) -> std::io::Result<u32> {
        let value = self.read_bits(count)?;
        Ok(if count == 0 {
            0
        } else {
            value.reverse_bits() >> (32 - count)
        })
    }
}

impl<'a> BinaryReader<'a> {
    /// Reads signed base-128 payloads, optionally separating low tag bits.
    /// BGI uses two tag bits for typed immediates. Signed payloads use i64;
    /// redundant extension groups remain legal and are checked for consistency.
    pub fn read_tagged_sleb64(&mut self, tag_bits: u8) -> std::io::Result<(u64, i64)> {
        if tag_bits > 7 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Base-128 tag exceeds first group",
            ));
        }
        let mut value = 0u64;
        let mut bits = 0u32;
        let mut tag = 0;
        let mut first = true;
        let mut extension = None;
        loop {
            let byte = self.read_u8()?;
            let skip = if first { tag_bits } else { 0 };
            if first {
                tag = u64::from(byte & ((1u8 << tag_bits) - 1));
                first = false;
            }
            for bit in skip..7 {
                let set = (byte >> bit) & 1;
                if bits < 64 {
                    value |= u64::from(set) << bits;
                    bits += 1;
                } else {
                    let sign = (value >> 63) as u8;
                    if set != sign {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Signed base-128 value exceeds i64",
                        ));
                    }
                    extension = Some(sign);
                }
            }
            if byte & 0x80 == 0 {
                let negative = byte & 0x40 != 0;
                if bits < 64 && negative {
                    value |= u64::MAX << bits;
                }
                if bits == 64
                    && (negative != (value >> 63 != 0)
                        || extension.is_some_and(|sign| (sign != 0) != negative))
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Signed base-128 sign mismatch",
                    ));
                }
                return Ok((tag, value as i64));
            }
        }
    }
    /// Reads an unsigned base-128 integer into a format-defined u32 field.
    pub fn read_uleb32(&mut self) -> std::io::Result<u32> {
        let mut value = 0u32;
        let mut shift = 0;
        loop {
            let byte = self.read_u8()?;
            let part = u32::from(byte & 0x7f);
            if shift >= 32 || part > (u32::MAX >> shift) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Base-128 integer exceeds u32",
                ));
            }
            value |= part << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }
    /// Reads a little-endian `u16` from the first two bytes of `data`.
    #[must_use]
    pub fn u16_le(data: &[u8]) -> u16 {
        u16::from_le_bytes([data[0], data[1]])
    }

    /// Reads a big-endian `u16` from the first two bytes of `data`.
    #[must_use]
    pub fn u16_be(data: &[u8]) -> u16 {
        u16::from_be_bytes([data[0], data[1]])
    }

    /// Reads a little-endian `i16` from the first two bytes of `data`.
    #[must_use]
    pub fn i16_le(data: &[u8]) -> i16 {
        i16::from_le_bytes([data[0], data[1]])
    }

    /// Reads a little-endian `u32` from the first four bytes of `data`.
    #[must_use]
    pub fn u32_le(data: &[u8]) -> u32 {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    }

    /// Reads a big-endian `u32` from the first four bytes of `data`.
    #[must_use]
    pub fn u32_be(data: &[u8]) -> u32 {
        u32::from_be_bytes([data[0], data[1], data[2], data[3]])
    }

    /// Reads a little-endian `i32` from the first four bytes of `data`.
    #[must_use]
    pub fn i32_le(data: &[u8]) -> i32 {
        i32::from_le_bytes([data[0], data[1], data[2], data[3]])
    }

    /// Reads a little-endian `u64` from the first eight bytes of `data`.
    #[must_use]
    pub fn u64_le(data: &[u8]) -> u64 {
        u64::from_le_bytes(as_array8(data))
    }

    /// Reads a big-endian `u64` from the first eight bytes of `data`.
    #[must_use]
    pub fn u64_be(data: &[u8]) -> u64 {
        u64::from_be_bytes(as_array8(data))
    }

    /// Reads a little-endian `i64` from the first eight bytes of `data`.
    #[must_use]
    pub fn i64_le(data: &[u8]) -> i64 {
        i64::from_le_bytes(as_array8(data))
    }

    /// Reads an IEEE 754 little-endian float.
    #[must_use]
    pub fn f64_le(data: &[u8]) -> f64 {
        f64::from_bits(Self::u64_le(data))
    }

    /// Reads an IEEE 754 little-endian float.
    #[must_use]
    pub fn f32_le(data: &[u8]) -> f32 {
        f32::from_bits(Self::u32_le(data))
    }

    /// Reads an unsigned little-endian integer stored in `width` bytes.
    pub fn compact_u64_le(data: &[u8]) -> std::io::Result<u64> {
        if data.len() > 8 {
            return Err(BinaryIo::invalid_input(format!(
                "compact integer width {} exceeds 8",
                data.len()
            )));
        }
        let mut value = 0u64;
        for (shift, &byte) in data.iter().enumerate() {
            value |= u64::from(byte) << (shift * 8);
        }
        Ok(value)
    }

    /// Reads a signed little-endian integer with sign extension to 64 bits.
    pub fn compact_i64_le(data: &[u8]) -> std::io::Result<i64> {
        let value = Self::compact_u64_le(data)?;
        if data.is_empty() {
            return Ok(0);
        }
        let shift = (8 - data.len()) * 8;
        Ok(((value << shift) as i64) >> shift)
    }

    /// Reads an integer stored in one to eight bytes in the selected byte order.
    pub fn read_compact_u64(&mut self, width: u8, endian: Endian) -> std::io::Result<u64> {
        if !(1..=8).contains(&width) {
            return Err(BinaryIo::invalid_input(
                "Integer storage width must be 1..=8",
            ));
        }
        let bytes = self.read_bytes(usize::from(width))?;
        match endian {
            Endian::Little => Self::compact_u64_le(bytes),
            Endian::Big => Ok(bytes
                .iter()
                .fold(0, |value, &byte| (value << 8) | u64::from(byte))),
        }
    }

    /// Reads a signed integer stored in one to eight bytes, extending its sign.
    pub fn read_compact_i64(&mut self, width: u8, endian: Endian) -> std::io::Result<i64> {
        let value = self.read_compact_u64(width, endian)?;
        let shift = (8 - width) * 8;
        Ok(((value << shift) as i64) >> shift)
    }

    /// Reads MSB-first base-128 groups. `end_bit` is the terminating high bit
    /// (set in Lua 5.4; clear in Lua 5.5). Overflow follows the u64 field width.
    pub fn read_msb_base128_u64(&mut self, end_bit: bool) -> std::io::Result<u64> {
        let mut value = 0u64;
        loop {
            let byte = self.read_u8()?;
            if value > u64::MAX >> 7 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Base-128 integer exceeds u64",
                ));
            }
            value = (value << 7) | u64::from(byte & 127);
            if (byte & 128 != 0) == end_bit {
                return Ok(value);
            }
        }
    }

    /// Creates a reader positioned at the start of `data`.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Creates a reader positioned at `pos`; errors if `pos` is past the end.
    pub fn new_at(data: &'a [u8], pos: usize) -> std::io::Result<Self> {
        if pos > data.len() {
            return Err(BinaryIo::unexpected_eof(format!(
                "offset out of range: 0x{pos:X}"
            )));
        }
        Ok(Self { data, pos })
    }

    /// Returns the current byte position.
    #[must_use]
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
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Reads a borrowed byte range of length `len` and advances the cursor.
    pub fn read_bytes(&mut self, len: usize) -> std::io::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| BinaryIo::unexpected_eof("read offset overflow"))?;
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

    /// Reads a little-endian `u32`.
    pub fn read_u32_le(&mut self) -> std::io::Result<u32> {
        Ok(Self::u32_le(self.read_bytes(4)?))
    }

    /// Reads a `u32` using the requested byte order.
    pub fn read_u32(&mut self, endian: Endian) -> std::io::Result<u32> {
        Ok(endian.read_u32(self.read_bytes(4)?))
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
}

/// Stateless little/big-endian encoders writing into caller-owned buffers.
#[derive(Debug)]
pub struct BinaryWriter;

impl BinaryWriter {
    /// Writes an IEEE 754 little-endian float.
    pub fn f32_le(value: f32, out: &mut [u8]) {
        Self::u32_le(value.to_bits(), out);
    }
    /// Writes a little-endian `u16` into the first two bytes of `out`.
    pub fn u16_le(value: u16, out: &mut [u8]) {
        out[..2].copy_from_slice(&value.to_le_bytes());
    }

    /// Writes a little-endian `u32` into the first four bytes of `out`.
    pub fn u32_le(value: u32, out: &mut [u8]) {
        out[..4].copy_from_slice(&value.to_le_bytes());
    }

    /// Writes a big-endian `u32` into the first four bytes of `out`.
    pub fn u32_be(value: u32, out: &mut [u8]) {
        out[..4].copy_from_slice(&value.to_be_bytes());
    }

    /// Writes a little-endian `u32` into `out` at a fixed offset.
    pub fn u32_le_at(value: u32, out: &mut [u8], offset: usize) {
        Self::u32_le(value, &mut out[offset..offset + 4]);
    }

    /// Writes a big-endian `u64` into the first eight bytes of `out`.
    pub fn u64_be(value: u64, out: &mut [u8]) {
        out[..8].copy_from_slice(&value.to_be_bytes());
    }

    /// Writes a little-endian `u64` into the first eight bytes of `out`.
    pub fn u64_le(value: u64, out: &mut [u8]) {
        out[..8].copy_from_slice(&value.to_le_bytes());
    }

    /// Writes the low `out.len()` bytes of `value` in little-endian order.
    pub fn compact_u64_le(value: u64, out: &mut [u8]) -> std::io::Result<()> {
        if out.len() > 8 {
            return Err(BinaryIo::invalid_input(format!(
                "compact integer width {} exceeds 8",
                out.len()
            )));
        }
        for (shift, byte) in out.iter_mut().enumerate() {
            *byte = ((value >> (shift * 8)) & 0xFF) as u8;
        }
        Ok(())
    }
}

/// Binary I/O error constructors.
#[derive(Debug)]
pub struct BinaryIo;

impl BinaryIo {
    /// Constructs an `InvalidInput` I/O error.
    #[must_use]
    pub fn invalid_input(message: impl Into<String>) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
    }

    /// Constructs an `UnexpectedEof` I/O error.
    #[must_use]
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
    fn bit_cache_orders_alignment_and_truncation() -> std::io::Result<()> {
        let mut bits = BitReader::new(&[0xab, 0xcd, 0xef], BitOrder::Msb);
        assert_eq!(bits.read_bits(3)?, 5);
        assert_eq!(bits.peek_byte(), Some(0x5e));
        bits.align_byte();
        assert_eq!(bits.read_bits(8)?, 0xcd);
        assert_eq!(bits.read_bits(4)?, 0xe);
        assert_eq!(bits.peek_byte(), None);
        assert_eq!(bits.read_bits(4)?, 0xf);
        assert_eq!(
            bits.read_bit().err().map(|e| e.kind()),
            Some(std::io::ErrorKind::UnexpectedEof)
        );
        let mut bits = BitReader::new(&[0x81, 0x02], BitOrder::Lsb);
        assert_eq!(bits.read_bits(8)?, 0x81);
        assert_eq!(bits.read_bits(8)?, 0x40);
        assert_eq!(
            BinaryReader::new(&[0xe5, 0x8e, 0x26]).read_uleb32()?,
            624485
        );
        assert_eq!(
            BinaryReader::new(&[0x9b, 0xf1, 0x59]).read_tagged_sleb64(0)?,
            (0, -624485)
        );
        assert_eq!(BinaryReader::new(&[0x7e]).read_tagged_sleb64(2)?, (2, -1));
        assert_eq!(
            BinaryReader::new(&[0x82, 0x02]).read_tagged_sleb64(2)?,
            (2, 64)
        );
        Ok(())
    }

    #[test]
    fn compact_signed_values_extend_the_highest_byte() {
        for width in 1..=8 {
            assert_eq!(
                BinaryReader::compact_i64_le(&[0xff; 8][..width]).unwrap(),
                -1
            );
        }
        assert_eq!(BinaryReader::compact_i64_le(&[0x80]).unwrap(), -128);
        assert_eq!(BinaryReader::compact_i64_le(&[0, 0x80]).unwrap(), -32768);
        assert_eq!(BinaryReader::compact_i64_le(&[0xff, 0]).unwrap(), 255);
    }

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
    fn compact_integer_reads_keep_byte_order_sign_and_bounds() {
        for (bytes, endian) in [
            ([0x80, 0x01, 0x23], Endian::Big),
            ([0x23, 0x01, 0x80], Endian::Little),
        ] {
            assert_eq!(
                BinaryReader::new(&bytes)
                    .read_compact_u64(3, endian)
                    .unwrap(),
                0x800123
            );
            assert_eq!(
                BinaryReader::new(&bytes)
                    .read_compact_i64(3, endian)
                    .unwrap(),
                -8388317
            );
            assert!(
                BinaryReader::new(&bytes)
                    .read_compact_u64(0, endian)
                    .is_err()
            );
            assert!(
                BinaryReader::new(&bytes)
                    .read_compact_u64(9, endian)
                    .is_err()
            );
            assert_eq!(
                BinaryReader::new(&bytes)
                    .read_compact_u64(4, endian)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        }
        assert_eq!(
            BinaryReader::new(&[255; 8])
                .read_compact_i64(8, Endian::Big)
                .unwrap(),
            -1
        );
    }

    #[test]
    fn msb_base128_handles_both_terminators_and_integer_overflow() {
        assert_eq!(
            BinaryReader::new(&[1, 0x82])
                .read_msb_base128_u64(true)
                .unwrap(),
            130
        );
        assert_eq!(
            BinaryReader::new(&[0x81, 2])
                .read_msb_base128_u64(false)
                .unwrap(),
            130
        );
        let mut maximum = [0x7f; 10];
        maximum[0] = 1;
        maximum[9] = 255;
        assert_eq!(
            BinaryReader::new(&maximum)
                .read_msb_base128_u64(true)
                .unwrap(),
            u64::MAX
        );
        maximum[0] = 2;
        assert_eq!(
            BinaryReader::new(&maximum)
                .read_msb_base128_u64(true)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            BinaryReader::new(&[0])
                .read_msb_base128_u64(true)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let mut zeros = [0; 20];
        zeros[19] = 0x80;
        assert_eq!(
            BinaryReader::new(&zeros)
                .read_msb_base128_u64(true)
                .unwrap(),
            0
        );
    }

    #[test]
    fn writer_roundtrip() {
        let mut out = [0u8; 4];
        BinaryWriter::u32_le(0xDEAD_BEEF, &mut out);
        assert_eq!(BinaryReader::u32_le(&out), 0xDEAD_BEEF);
    }

    #[test]
    fn compact_integer_roundtrip() {
        let mut out = [0u8; 3];
        BinaryWriter::compact_u64_le(0x00AB_CDEF, &mut out).unwrap();
        assert_eq!(out, [0xEF, 0xCD, 0xAB]);
        assert_eq!(BinaryReader::compact_u64_le(&out).unwrap(), 0x00AB_CDEF);
    }
}
