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

/// Control bits interleaved with byte payloads in one stream. Reading a byte
/// leaves the current control byte intact until all of its bits are consumed.
#[derive(Debug)]
pub struct InterleavedBits<'a> {
    reader: BinaryReader<'a>,
    bits: u8,
    remaining: u8,
    order: BitOrder,
}
impl<'a> InterleavedBits<'a> {
    #[must_use]
    pub fn new(data: &'a [u8], order: BitOrder) -> Self {
        Self {
            reader: BinaryReader::new(data),
            bits: 0,
            remaining: 0,
            order,
        }
    }
    #[must_use]
    pub fn position(&self) -> usize {
        self.reader.position()
    }
    pub fn byte(&mut self) -> std::io::Result<u8> {
        self.reader.read_u8()
    }
    pub fn bit(&mut self) -> std::io::Result<u32> {
        if self.remaining == 0 {
            self.bits = self.reader.read_u8()?;
            self.remaining = 8;
        }
        let value = match self.order {
            BitOrder::Msb => {
                let value = self.bits >> 7;
                self.bits <<= 1;
                value
            }
            BitOrder::Lsb => {
                let value = self.bits & 1;
                self.bits >>= 1;
                value
            }
        };
        self.remaining -= 1;
        Ok(u32::from(value))
    }
}

/// Growable bit writer for codecs with interleaved, variable-width fields.
#[derive(Debug)]
pub struct BitWriter {
    data: Vec<u8>,
    used: u8,
    order: BitOrder,
}
impl BitWriter {
    #[must_use]
    pub fn new(order: BitOrder) -> Self {
        Self {
            data: Vec::new(),
            used: 0,
            order,
        }
    }
    pub fn write_bits_le(&mut self, value: u32, count: u8) -> std::io::Result<()> {
        if count > 32 {
            return Err(BinaryIo::invalid_input("Bit field exceeds u32"));
        }
        for index in 0..count {
            if self.used == 0 {
                self.data.push(0);
            }
            let last = self.data.len() - 1;
            let shift = match self.order {
                BitOrder::Lsb => self.used,
                BitOrder::Msb => 7 - self.used,
            };
            self.data[last] |= (((value >> index) & 1) as u8) << shift;
            self.used = (self.used + 1) % 8;
        }
        Ok(())
    }
    /// Writes a field most significant bit first in the selected byte bit order.
    pub fn write_bits(&mut self, value: u32, count: u8) -> std::io::Result<()> {
        if count == 0 {
            return Ok(());
        }
        if count > 32 {
            return Err(BinaryIo::invalid_input("Bit field exceeds u32"));
        }
        self.write_bits_le(value.reverse_bits() >> (32 - count), count)
    }
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
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

/// Bit cursor over a sequential source. It consumes no bytes beyond the field
/// being requested; callers can wrap the source in a buffered reader.
#[derive(Debug)]
pub struct StreamBitReader<R> {
    reader: R,
    byte: u8,
    available: u8,
    order: BitOrder,
}

impl<R: std::io::Read> StreamBitReader<R> {
    #[must_use]
    pub fn new(reader: R, order: BitOrder) -> Self {
        Self {
            reader,
            byte: 0,
            available: 0,
            order,
        }
    }

    pub fn read_bit(&mut self) -> std::io::Result<u8> {
        if self.available == 0 {
            let mut byte = [0];
            self.reader.read_exact(&mut byte)?;
            self.byte = match self.order {
                BitOrder::Msb => byte[0],
                BitOrder::Lsb => byte[0].reverse_bits(),
            };
            self.available = 8;
        }
        let value = self.byte >> 7;
        self.byte <<= 1;
        self.available -= 1;
        Ok(value)
    }

    pub fn read_bits(&mut self, count: u8) -> std::io::Result<u32> {
        if count > 32 {
            return Err(BinaryIo::invalid_input("Bit field exceeds u32"));
        }
        let mut value = 0;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.read_bit()?);
        }
        Ok(value)
    }
}

impl<'a> BitReader<'a> {
    /// Returns the next byte index and bit offset, excluding buffered lookahead.
    #[must_use]
    pub fn position(&self) -> (usize, u8) {
        (
            self.byte - usize::from(self.available.div_ceil(8)),
            (8 - self.available % 8) % 8,
        )
    }

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
    /// Peeks a bounded field without consuming bits, including codec prefixes
    /// whose actual code length is determined by the returned lookahead.
    pub fn peek_bits(&mut self, count: u8) -> std::io::Result<u32> {
        if count > 32 {
            return Err(BinaryIo::invalid_input("Bit field exceeds u32"));
        }
        while self.available < count {
            if !self.refill() {
                return Err(BinaryIo::unexpected_eof("Truncated bitstream"));
            }
        }
        Ok(((self.cache >> (self.available - count)) & ((1u64 << count) - 1)) as u32)
    }
    #[inline]
    pub fn read_bits(&mut self, count: u8) -> std::io::Result<u32> {
        let value = self.peek_bits(count)?;
        self.available -= count;
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

    /// Reads an LSB-significant field up to the width of a u64.
    pub fn read_bits_le_u64(&mut self, count: u8) -> std::io::Result<u64> {
        if count > 64 {
            return Err(BinaryIo::invalid_input("Bit field exceeds u64"));
        }
        let low = u64::from(self.read_bits_le(count.min(32))?);
        if count <= 32 {
            return Ok(low);
        }
        Ok(low | (u64::from(self.read_bits_le(count - 32)?) << 32))
    }

    /// Reads an MSB-significant field up to the width of a u64.
    pub fn read_bits_u64(&mut self, count: u8) -> std::io::Result<u64> {
        if count > 64 {
            return Err(BinaryIo::invalid_input("Bit field exceeds u64"));
        }
        if count <= 32 {
            return self.read_bits(count).map(u64::from);
        }
        let high = u64::from(self.read_bits(count - 32)?);
        Ok((high << 32) | u64::from(self.read_bits(32)?))
    }
}

impl<'a> BinaryReader<'a> {
    /// Borrows a checked byte range without maintaining a cursor.
    pub fn bytes_at(data: &'a [u8], offset: usize, size: usize) -> std::io::Result<&'a [u8]> {
        Self::new_at(data, offset)?.read_bytes(size)
    }

    /// Reads a little-endian integer at a checked byte offset.
    pub fn u16_le_at(data: &[u8], offset: usize) -> std::io::Result<u16> {
        BinaryReader::new_at(data, offset)?.read_u16_le()
    }

    /// Reads a little-endian integer at a checked byte offset.
    pub fn u32_le_at(data: &[u8], offset: usize) -> std::io::Result<u32> {
        BinaryReader::new_at(data, offset)?.read_u32_le()
    }

    /// Reads a little-endian integer at a checked byte offset.
    pub fn u64_le_at(data: &[u8], offset: usize) -> std::io::Result<u64> {
        BinaryReader::new_at(data, offset)?.read_u64_le()
    }

    /// Reads MFC CString framing and returns its encoding flag and raw units.
    /// The flag is true for UTF-16; byte strings may also contain binary data.
    pub fn read_mfc_string(&mut self) -> std::io::Result<(bool, &'a [u8])> {
        let mut length = u32::from(self.read_u8()?);
        let mut wide = false;
        if length == 255 {
            length = u32::from(self.read_u16_le()?);
            if length == 0xfffe {
                wide = true;
                length = u32::from(self.read_u8()?);
                if length == 255 {
                    length = u32::from(self.read_u16_le()?);
                }
            }
            if length == 65535 {
                length = self.read_u32_le()?;
            }
        }
        let size = (length as usize)
            .checked_mul(if wide { 2 } else { 1 })
            .ok_or_else(|| BinaryIo::unexpected_eof("MFC string length exceeds address space"))?;
        Ok((wide, self.read_bytes(size)?))
    }
    /// Reads signed base-128 payloads, optionally separating low tag bits.
    /// BGI uses two tag bits for typed immediates. Signed payloads use i64;
    /// redundant extension groups remain legal and are checked for consistency.
    pub fn read_tagged_sleb64(&mut self, tag_bits: u8) -> std::io::Result<(u64, i64)> {
        if tag_bits > 7 {
            return Err(BinaryIo::invalid_input("Base-128 tag exceeds first group"));
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

    /// Reads a signed integer whose high bits were stored in a preceding tag.
    /// Remaining whole bytes are little-endian; the combined width determines
    /// the sign bit. Used by mixed-width expression immediates.
    pub fn read_signed_le_with_high_bits(
        &mut self,
        high: u8,
        high_bits: u8,
        payload_bytes: u8,
    ) -> std::io::Result<i64> {
        if high_bits == 0
            || high_bits > 8
            || payload_bytes > 7
            || u16::from(high) >= (1u16 << high_bits)
        {
            return Err(BinaryIo::invalid_input(
                "Invalid signed integer prefix width",
            ));
        }
        let low = if payload_bytes == 0 {
            0
        } else {
            self.read_compact_u64(payload_bytes, Endian::Little)?
        };
        let bits = u32::from(payload_bytes) * 8 + u32::from(high_bits);
        let value = low | (u64::from(high) << (u32::from(payload_bytes) * 8));
        Ok(((value << (64 - bits)) as i64) >> (64 - bits))
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

    /// Writes a big-endian 16-bit field into the first two output bytes.
    pub fn u16_be(value: u16, out: &mut [u8]) {
        out[..2].copy_from_slice(&value.to_be_bytes());
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
#[path = "../tests/binary.rs"]
mod tests;
