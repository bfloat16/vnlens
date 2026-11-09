//! CPmArchive class/object serialization. Based on UnivUI's ReadClass,
//! ReadRioReference and class-list readers (1001D730/1001D9C0), and GARbro's
//! documented CRioArchive layout. Integer fields are little endian. Names
//! use CP932 or the MFC Unicode string marker; class names use an LSB codec.
use nvlens_core::{Error, Result};
use nvlens_io::{BinaryReader, BinaryWriter};

pub const ENCRYPTED_SIGNATURE: u32 = 0x1edb_927c;
pub const OBJECT_SIGNATURE: u32 = 0x29f6_cba4;
pub const RIO_SIGNATURE: u32 = 0x596e_32cd;
pub const ICI_SIGNATURE: u32 = 0x673c_e92a;
pub const OFFSET_BIAS: u32 = 0xa2fb_6ad1;
pub const SIZE_BIAS: u32 = 0xe7b5_d9f8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class {
    pub name: String,
    pub schema: u16,
    /// Original compressed name, retained for standalone native serialization.
    pub encoded: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Object {
    pub class: Class,
    pub flags: u16,
    /// Logical RIO address before the installation's address-unit shift.
    pub offset: u32,
    pub size: u32,
    pub name: Option<String>,
    pub parent: Option<usize>,
}

#[derive(Clone, Debug)]
enum Slot {
    Empty,
    Class(Class),
    Object(Option<Object>),
}

#[derive(Clone, Debug)]
pub enum Reference {
    Existing(u32),
    External(Object),
    Inline(Class, u16),
}

#[derive(Debug)]
pub struct Reader<'a> {
    pub bytes: BinaryReader<'a>,
    pub encrypted: bool,
    cache: Vec<Slot>,
    references_started: bool,
    pub objects: Vec<Object>,
}

pub fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}

pub fn string(r: &mut BinaryReader<'_>) -> Result<String> {
    let at = r.position();
    let (wide, bytes) = r.read_mfc_string()?;
    if wide {
        let mut r = BinaryReader::new(bytes);
        let mut units = Vec::with_capacity(bytes.len() / 2);
        while r.remaining() != 0 {
            units.push(r.read_u16_le()?);
        }
        String::from_utf16(&units).map_err(|_| corrupt(at, "Invalid RIO UTF-16 name"))
    } else {
        cp932(bytes, at)
    }
}

fn cp932(bytes: &[u8], at: usize) -> Result<String> {
    let (value, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
    if errors {
        return Err(corrupt(at, "Invalid RIO CP932 name"));
    }
    Ok(value.into_owned())
}

pub fn count(r: &mut BinaryReader<'_>) -> Result<u32> {
    let n = r.read_u16_le()?;
    Ok(if n == 0xffff {
        r.read_u32_le()?
    } else {
        u32::from(n)
    })
}

fn short_count(r: &mut BinaryReader<'_>) -> Result<u16> {
    let n = r.read_u8()?;
    Ok(if n == 0xff {
        r.read_u16_le()?
    } else {
        u16::from(n)
    })
}

fn class_name(bytes: &[u8], at: usize) -> Result<String> {
    cp932(&nvlens_crypto::compress::rugp::class_name(bytes)?, at)
}

impl<'a> Reader<'a> {
    /// Switches an encrypted substream while retaining its enclosing tables.
    pub(super) fn with_data<'b>(self, data: &'b [u8]) -> Reader<'b> {
        Reader {
            bytes: BinaryReader::new(data),
            encrypted: self.encrypted,
            cache: self.cache,
            references_started: self.references_started,
            objects: self.objects,
        }
    }
    #[must_use]
    pub fn new(data: &'a [u8], encrypted: bool) -> Self {
        Self {
            bytes: BinaryReader::new(data),
            encrypted,
            cache: vec![Slot::Empty, Slot::Empty],
            references_started: false,
            objects: Vec::new(),
        }
    }

    pub fn class(&mut self) -> Result<(Option<Class>, u32)> {
        let at = self.bytes.position();
        let word = self.bytes.read_u16_le()?;
        let tag = if word == 0x7fff {
            self.bytes.read_u32_le()?
        } else {
            (u32::from(word & 0x8000) << 16) | u32::from(word & 0x7fff)
        };
        if tag & 0x8000_0000 == 0 {
            return Ok((None, tag));
        }
        if word == 0xffff {
            let schema = self.bytes.read_u16_le()?;
            let (name, encoded) = if self.encrypted {
                let length = usize::from(short_count(&mut self.bytes)?);
                let encoded = self.bytes.read_bytes(length)?;
                (class_name(encoded, at)?, Some(encoded.to_vec()))
            } else {
                let length = usize::from(self.bytes.read_u16_le()?);
                (cp932(self.bytes.read_bytes(length)?, at)?, None)
            };
            let class = Class {
                name,
                schema,
                encoded,
            };
            self.cache.push(Slot::Class(class.clone()));
            Ok((Some(class), tag))
        } else {
            match self.cache.get((tag & 0x7fff_ffff) as usize) {
                Some(Slot::Class(class)) => Ok((Some(class.clone()), tag)),
                _ => Err(corrupt(at, "RIO reference is not a defined class")),
            }
        }
    }

    pub fn header(&mut self) -> Result<(u32, u16, u16, Class)> {
        let signature = self.bytes.read_u32_le()?;
        if !matches!(
            signature,
            ENCRYPTED_SIGNATURE | OBJECT_SIGNATURE | RIO_SIGNATURE | ICI_SIGNATURE
        ) {
            return Err(Error::InvalidFormat);
        }
        let mut version = self.bytes.read_u16_le()?;
        let mut flags = 0;
        if (0x10..=0x3fff).contains(&version) {
            if version >= 0x11 {
                flags = self.bytes.read_u16_le()?;
            }
        } else {
            self.bytes.set_position(self.bytes.position() - 2)?;
            version = 0x10;
        }
        self.encrypted = signature == ENCRYPTED_SIGNATURE;
        let class = self
            .class()?
            .0
            .ok_or_else(|| corrupt(self.bytes.position(), "Missing RIO root class"))?;
        self.cache.push(Slot::Object(None));
        Ok((signature, version, flags, class))
    }

    /// Parses only the serialized child index, iteratively. No referenced
    /// object body is accessed, and no format-independent depth limit applies.
    pub fn children(&mut self) -> Result<Vec<Object>> {
        let mut nodes = Vec::new();
        let mut stack = vec![(count(&mut self.bytes)?, None)];
        while let Some((left, parent)) = stack.last_mut() {
            if *left == 0 {
                stack.pop();
                continue;
            }
            *left -= 1;
            let parent = *parent;
            let name = if self.encrypted {
                None
            } else {
                Some(string(&mut self.bytes)?)
            };
            if !self.encrypted {
                self.cache.push(Slot::Object(None));
            }
            let at = self.bytes.position();
            let flags = self.bytes.read_u16_le()?;
            let class = match flags & 7 {
                0 => {
                    self.bytes
                        .read_bytes(if flags & 0x8000 != 0 { 1 } else { 2 })?;
                    self.class()?
                        .0
                        .ok_or_else(|| corrupt(at, "Missing RIO child class"))?
                }
                1 => {
                    self.bytes.read_u32_le()?;
                    match self.bytes.read_u16_le()? {
                        0x1e57 => self
                            .class()?
                            .0
                            .ok_or_else(|| corrupt(at, "Missing RIO field class"))?,
                        0x2d6b | 0x2f1a => {
                            let schema = self.bytes.read_u16_le()?;
                            let len = usize::from(self.bytes.read_u16_le()?);
                            Class {
                                name: cp932(self.bytes.read_bytes(len)?, at)?,
                                schema,
                                encoded: None,
                            }
                        }
                        code => {
                            return Err(Error::Unsupported(format!(
                                "RIO field class 0x{code:04X} at 0x{at:X}"
                            )));
                        }
                    }
                }
                mode => {
                    return Err(Error::Unsupported(format!(
                        "RIO node mode {mode} at 0x{at:X}"
                    )));
                }
            };
            let (offset, size) = if flags & 8 != 0 {
                self.extent()?
            } else {
                (0, 0)
            };
            nodes.push(Object {
                class,
                flags,
                offset,
                size,
                name,
                parent,
            });
            if !self.encrypted || flags & 0x200 == 0 {
                stack.push((count(&mut self.bytes)?, Some(nodes.len() - 1)));
            }
        }
        Ok(nodes)
    }

    fn extent(&mut self) -> Result<(u32, u32)> {
        let offset = self.bytes.read_u32_le()?;
        let size = self.bytes.read_u32_le()?;
        Ok(if self.encrypted {
            (
                offset.wrapping_sub(OFFSET_BIAS),
                nvlens_crypto::cipher::rugp::decode_size(size, SIZE_BIAS),
            )
        } else {
            (offset, size)
        })
    }

    /// Reads an external-reference chain. Anonymous inline objects are returned
    /// to the class-specific reader, whose serializer defines their boundary.
    pub fn reference(&mut self) -> Result<Reference> {
        if !self.references_started {
            self.references_started = true;
            if self.encrypted {
                let padding = short_count(&mut self.bytes)?;
                self.cache.extend((0..padding).map(|_| Slot::Empty));
            }
        }
        let mut parents = Vec::new();
        let mut result;
        loop {
            let at = self.bytes.position();
            let (class, tag) = self.class()?;
            let Some(class) = class else {
                match self.cache.get(tag as usize) {
                    Some(Slot::Object(Some(object))) => {
                        result = Reference::External(object.clone())
                    }
                    Some(_) => result = Reference::Existing(tag),
                    None => return Err(corrupt(at, "RIO object reference exceeds its table")),
                }
                break;
            };
            let flags = self.bytes.read_u16_le()?;
            if flags & 0x40 != 0 {
                if !parents.is_empty() {
                    return Err(Error::Unsupported(
                        "Inline RIO object used as an external reference parent".into(),
                    ));
                }
                self.cache.push(Slot::Object(None));
                return Ok(Reference::Inline(class, flags));
            }
            let (offset, size, name) = if self.encrypted {
                let (offset, size) = self.extent()?;
                (offset, size, None)
            } else {
                (0, 0, Some(string(&mut self.bytes)?))
            };
            parents.push(Object {
                class,
                flags,
                offset,
                size,
                name,
                parent: None,
            });
        }
        while let Some(object) = parents.pop() {
            self.bytes.read_bytes(if object.flags & 7 != 0 {
                4
            } else if object.flags & 0x8000 != 0 {
                1
            } else {
                2
            })?;
            self.cache.push(Slot::Object(Some(object.clone())));
            result = Reference::External(object);
        }
        if let Reference::External(object) = &result {
            self.objects.push(object.clone());
        }
        Ok(result)
    }

    pub fn map_object(&mut self) {
        self.cache.push(Slot::Object(None));
    }

    pub fn map_class(&mut self, class: Class) {
        self.cache.push(Slot::Class(class));
    }

    pub fn cached_class(&self, tag: u32) -> Result<Class> {
        match self.cache.get((tag & 0x7fff_ffff) as usize) {
            Some(Slot::Class(class)) => Ok(class.clone()),
            _ => Err(corrupt(
                self.bytes.position(),
                "RIO message class is not defined",
            )),
        }
    }
}

/// Skips the randomised compact header using only its actual bit fields.
/// Returns the effective object schema and stored archive flags.
pub(super) fn compact_header(r: &mut BinaryReader<'_>) -> Result<(u16, u16, u16)> {
    let mode = r.read_u8()? & 3;
    let flags = r.read_u8()?;
    let third = u16::from(r.read_u8()?);
    let schema = match flags >> 6 {
        0 => third >> 6,
        1 => third >> 2,
        2 => ((third & 0xfe) << 1) | (u16::from(r.read_u8()? & 0xc0) << 1),
        _ => ((third & 0xfe) << 1) | (u16::from(r.read_u8()? & 0xfe) << 6),
    };
    if flags & 1 != 0 {
        return Err(Error::Unsupported(
            "RIO compact object with a named child list".into(),
        ));
    }
    let version = if mode == 3 { r.read_u16_le()? } else { 0x14 };
    let flags = if mode >= 2 { r.read_u16_le()? } else { 1 };
    Ok((schema, version, flags))
}

/// Restores the native standalone RIO header around a compact object. The
/// body and compressed class-name spelling are retained; raw extraction uses
/// the original compact bytes instead.
pub fn standalone(data: &[u8], class: &Class) -> Result<Vec<u8>> {
    let mut r = BinaryReader::new(data);
    let (schema, version, flags) = compact_header(&mut r)?;
    envelope(r.read_bytes(r.remaining())?, class, schema, version, flags)
}

/// Wraps an inline object body in a native standalone RIO envelope.
pub fn envelope(
    data: &[u8],
    class: &Class,
    schema: u16,
    version: u16,
    flags: u16,
) -> Result<Vec<u8>> {
    let encoded = if let Some(encoded) = &class.encoded {
        std::borrow::Cow::Borrowed(encoded.as_slice())
    } else {
        let (name, _, errors) = encoding_rs::SHIFT_JIS.encode(&class.name);
        if errors {
            return Err(corrupt(0, "Cannot encode RIO class name"));
        }
        std::borrow::Cow::Owned(nvlens_crypto::compress::rugp::encode_class_name(&name)?)
    };
    let length = u16::try_from(encoded.len())
        .map_err(|_| corrupt(0, "RIO class name exceeds its encoded length field"))?;
    let prefix_len = 12 + if length < 255 { 1 } else { 3 } + encoded.len() + 2;
    let mut out = vec![0; prefix_len];
    BinaryWriter::u32_le(ENCRYPTED_SIGNATURE, &mut out);
    BinaryWriter::u16_le(version, &mut out[4..]);
    BinaryWriter::u16_le(flags, &mut out[6..]);
    BinaryWriter::u16_le(0xffff, &mut out[8..]);
    BinaryWriter::u16_le(schema, &mut out[10..]);
    let at = if length < 255 {
        out[12] = length as u8;
        13
    } else {
        out[12] = 255;
        BinaryWriter::u16_le(length, &mut out[13..]);
        15
    };
    out[at..at + encoded.len()].copy_from_slice(&encoded);
    out.extend_from_slice(data);
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/rugp/wire.rs"]
mod tests;
