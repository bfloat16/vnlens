//! Read-only PE section mapping for executable feature discovery.
//! Virtual addresses are resolved through headers and file-backed section data.
#![forbid(unsafe_code)]

use crate::{BinaryIo, BinaryReader};
use std::collections::BTreeMap;
use std::io;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_address: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub executable: bool,
}

pub struct PeImage<'a> {
    bytes: &'a [u8],
    pub image_base: u64,
    pub machine: u16,
    pub entry_point: u32,
    pub sections: Vec<Section>,
    header_size: u32,
    pe32_plus: bool,
    resources: Option<(u32, u32)>,
    tls: Option<(u32, u32)>,
    replacements: BTreeMap<u32, Vec<u8>>,
}

impl std::fmt::Debug for PeImage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeImage")
            .field("machine", &self.machine)
            .field("image_base", &self.image_base)
            .field("entry_point", &self.entry_point)
            .field("sections", &self.sections)
            .finish_non_exhaustive()
    }
}

impl<'a> PeImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> io::Result<Option<Self>> {
        if !bytes.starts_with(b"MZ") {
            return Ok(None);
        }
        let mut dos = BinaryReader::new_at(bytes, 0x3c)?;
        let offset = usize::try_from(dos.read_u32_le()?)
            .map_err(|_| BinaryIo::invalid_input("PE offset does not fit memory"))?;
        let mut reader = BinaryReader::new_at(bytes, offset)?;
        if reader.read_bytes(4)? != b"PE\0\0" {
            return Err(BinaryIo::invalid_input("Invalid PE signature"));
        }
        let machine = reader.read_u16_le()?;
        let count = usize::from(reader.read_u16_le()?);
        reader.read_bytes(12)?;
        let optional_size = usize::from(reader.read_u16_le()?);
        reader.read_u16_le()?;
        let optional = reader.read_bytes(optional_size)?;
        let mut fields = BinaryReader::new(optional);
        let kind = fields.read_u16_le()?;
        fields.set_position(16)?;
        let entry_point = fields.read_u32_le()?;
        fields.set_position(if kind == 0x10b {
            28
        } else if kind == 0x20b {
            24
        } else {
            return Err(BinaryIo::invalid_input("Unsupported PE optional header"));
        })?;
        let image_base = if kind == 0x10b {
            u64::from(fields.read_u32_le()?)
        } else {
            fields.read_u64_le()?
        };
        fields.set_position(60)?;
        let header_size = fields.read_u32_le()?;
        let directory_count_offset = if kind == 0x10b { 92 } else { 108 };
        let (resources, tls) = if optional.len() >= directory_count_offset + 4 {
            fields.set_position(directory_count_offset)?;
            let count = fields.read_u32_le()?;
            let mut directory = |index: u32| -> io::Result<Option<(u32, u32)>> {
                if index >= count {
                    return Ok(None);
                }
                fields.set_position(directory_count_offset + 4 + index as usize * 8)?;
                let rva = fields.read_u32_le()?;
                let size = fields.read_u32_le()?;
                Ok((rva != 0 && size != 0).then_some((rva, size)))
            };
            (directory(2)?, directory(9)?)
        } else {
            (None, None)
        };
        let table_size = count
            .checked_mul(40)
            .ok_or_else(|| BinaryIo::unexpected_eof("PE section count overflow"))?;
        let mut table = BinaryReader::new(reader.read_bytes(table_size)?);
        let mut sections = Vec::with_capacity(count);
        for _ in 0..count {
            let mut name = [0; 8];
            name.copy_from_slice(table.read_bytes(8)?);
            table.read_u32_le()?;
            let virtual_address = table.read_u32_le()?;
            let raw_size = table.read_u32_le()?;
            let raw_offset = table.read_u32_le()?;
            table.read_bytes(12)?;
            let flags = table.read_u32_le()?;
            let end = u64::from(raw_offset)
                .checked_add(u64::from(raw_size))
                .ok_or_else(|| BinaryIo::unexpected_eof("PE section range overflow"))?;
            if end > bytes.len() as u64 {
                return Err(BinaryIo::unexpected_eof("PE section exceeds file"));
            }
            sections.push(Section {
                name,
                virtual_address,
                raw_offset,
                raw_size,
                executable: flags & 0x2000_0000 != 0,
            });
        }
        Ok(Some(Self {
            bytes,
            image_base,
            machine,
            entry_point,
            sections,
            header_size,
            pe32_plus: kind == 0x20b,
            resources,
            tls,
            replacements: BTreeMap::new(),
        }))
    }

    pub fn section_data(&self, section: &Section) -> io::Result<&[u8]> {
        if let Some(data) = self.replacements.get(&section.virtual_address) {
            return Ok(data);
        }
        let offset = usize::try_from(section.raw_offset)
            .map_err(|_| BinaryIo::unexpected_eof("PE section offset does not fit memory"))?;
        let size = usize::try_from(section.raw_size)
            .map_err(|_| BinaryIo::unexpected_eof("PE section size does not fit memory"))?;
        let mut reader = BinaryReader::new_at(self.bytes, offset)?;
        reader.read_bytes(size)
    }

    /// Replaces one complete file-backed section for static analysis. Header,
    /// resource and RVA mappings are preserved; this does not rebuild a PE file.
    pub fn replace_section(&mut self, rva: u32, data: Vec<u8>) -> io::Result<()> {
        let section = self
            .sections
            .iter()
            .find(|s| s.virtual_address == rva)
            .ok_or_else(|| BinaryIo::invalid_input("PE replacement section is absent"))?;
        if data.len() as u64 != u64::from(section.raw_size) {
            return Err(BinaryIo::invalid_input(
                "PE replacement section length mismatch",
            ));
        }
        self.replacements.insert(rva, data);
        Ok(())
    }

    #[must_use]
    pub fn at_rva(&self, rva: u32) -> Option<&[u8]> {
        self.at_va(self.image_base.checked_add(u64::from(rva))?)
    }

    /// Reads the first TLS callback VA, including PE32+ pointer widths. The
    /// directory and callback slot must be present in file-backed data.
    pub fn first_tls_callback(&self) -> io::Result<Option<u64>> {
        let Some((rva, size)) = self.tls else {
            return Ok(None);
        };
        let bytes = self
            .at_rva(rva)
            .and_then(|b| b.get(..size as usize))
            .ok_or_else(|| BinaryIo::unexpected_eof("PE TLS directory exceeds section"))?;
        let wide = self.pe32_plus;
        let mut reader = BinaryReader::new_at(bytes, if wide { 24 } else { 12 })?;
        let callbacks = if wide {
            reader.read_u64_le()?
        } else {
            u64::from(reader.read_u32_le()?)
        };
        if callbacks == 0 {
            return Ok(None);
        }
        let bytes = self
            .at_va(callbacks)
            .ok_or_else(|| BinaryIo::unexpected_eof("PE TLS callbacks exceed section"))?;
        let mut reader = BinaryReader::new(bytes);
        let callback = if wide {
            reader.read_u64_le()?
        } else {
            u64::from(reader.read_u32_le()?)
        };
        Ok((callback != 0).then_some(callback))
    }

    #[must_use]
    pub fn at_va(&self, address: u64) -> Option<&[u8]> {
        let rva = address.checked_sub(self.image_base)?;
        if rva < u64::from(self.header_size) {
            return self.bytes.get(
                usize::try_from(rva).ok()?
                    ..usize::try_from(self.header_size)
                        .ok()?
                        .min(self.bytes.len()),
            );
        }
        for section in &self.sections {
            let Some(offset) = rva.checked_sub(u64::from(section.virtual_address)) else {
                continue;
            };
            if offset < u64::from(section.raw_size) {
                return self
                    .section_data(section)
                    .ok()?
                    .get(usize::try_from(offset).ok()?..);
            }
        }
        None
    }

    #[must_use]
    pub fn c_string_at_va(&self, address: u64) -> Option<&[u8]> {
        let bytes = self.at_va(address)?;
        bytes.get(..bytes.iter().position(|&byte| byte == 0)?)
    }

    /// Looks up a PE resource by type and name, then selects its first language.
    /// Numeric IDs are written as `#10`. Directory offsets are relative to the
    /// resource root; payload RVAs are mapped through the image sections.
    pub fn resource(&self, kind: &str, name: &str) -> io::Result<Option<&[u8]>> {
        let Some((rva, size)) = self.resources else {
            return Ok(None);
        };
        let address = self
            .image_base
            .checked_add(u64::from(rva))
            .ok_or_else(|| BinaryIo::unexpected_eof("PE resource address overflow"))?;
        let bytes = self
            .at_va(address)
            .and_then(|b| b.get(..size as usize))
            .ok_or_else(|| BinaryIo::unexpected_eof("PE resource directory exceeds section"))?;
        let mut directory = 0usize;
        for wanted in [Some(kind), Some(name), None] {
            let mut reader = BinaryReader::new_at(bytes, directory)?;
            reader.read_bytes(12)?;
            let count = usize::from(reader.read_u16_le()?) + usize::from(reader.read_u16_le()?);
            let mut found = None;
            for _ in 0..count {
                let id = reader.read_u32_le()?;
                let target = reader.read_u32_le()?;
                let matches = if let Some(wanted) = wanted {
                    if id & 0x8000_0000 != 0 {
                        let mut string = BinaryReader::new_at(bytes, (id & 0x7fff_ffff) as usize)?;
                        let count = usize::from(string.read_u16_le()?);
                        let mut units = Vec::new();
                        for _ in 0..count {
                            units.push(string.read_u16_le()?);
                        }
                        String::from_utf16(&units)
                            .map_err(|_| BinaryIo::invalid_input("Invalid PE resource name"))?
                            == wanted
                    } else {
                        wanted.strip_prefix('#').and_then(|s| s.parse::<u32>().ok()) == Some(id)
                    }
                } else {
                    true
                };
                if matches {
                    found = Some(target);
                    break;
                }
            }
            let Some(target) = found else { return Ok(None) };
            directory = (target & 0x7fff_ffff) as usize;
            if wanted.is_some() && target & 0x8000_0000 == 0 {
                return Err(BinaryIo::invalid_input(
                    "PE resource path ends before language",
                ));
            }
            if wanted.is_none() && target & 0x8000_0000 != 0 {
                return Err(BinaryIo::invalid_input(
                    "PE resource language points to a directory",
                ));
            }
        }
        let mut record = BinaryReader::new_at(bytes, directory)?;
        let rva = record.read_u32_le()?;
        let size = record.read_u32_le()?;
        record.read_bytes(8)?;
        let address = self
            .image_base
            .checked_add(u64::from(rva))
            .ok_or_else(|| BinaryIo::unexpected_eof("PE resource address overflow"))?;
        self.at_va(address)
            .and_then(|b| b.get(..size as usize))
            .map(Some)
            .ok_or_else(|| BinaryIo::unexpected_eof("PE resource data exceeds section"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::BinaryWriter;
    fn fixture(base: u32) -> Vec<u8> {
        let mut b = vec![0; 0x600];
        b[..2].copy_from_slice(b"MZ");
        BinaryWriter::u32_le(0x80, &mut b[0x3c..]);
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        BinaryWriter::u16_le(0x14c, &mut b[0x84..]);
        BinaryWriter::u16_le(1, &mut b[0x86..]);
        BinaryWriter::u16_le(0xe0, &mut b[0x94..]);
        BinaryWriter::u16_le(0x10b, &mut b[0x98..]);
        for (at, n) in [
            (0xb4, base),
            (0xd4, 0x200),
            (0xf4, 16),
            (0x108, 0x1000),
            (0x10c, 0x180),
            (0x184, 0x1000),
            (0x188, 0x400),
            (0x18c, 0x200),
            (0x210, 10),
            (0x214, 0x80000020),
            (0x230, 0x80000080),
            (0x234, 0x80000040),
            (0x250, 1033),
            (0x254, 0x60),
            (0x260, 0x1200),
            (0x264, 3),
        ] {
            BinaryWriter::u32_le(n, &mut b[at..]);
        }
        for at in [0x20e, 0x22c, 0x24e] {
            BinaryWriter::u16_le(1, &mut b[at..]);
        }
        let name = "STARTUP.TJS";
        BinaryWriter::u16_le(name.len() as u16, &mut b[0x280..]);
        for (i, w) in name.encode_utf16().enumerate() {
            BinaryWriter::u16_le(w, &mut b[0x282 + i * 2..]);
        }
        b[0x400..0x403].copy_from_slice(b"TJS");
        b
    }
    #[test]
    fn resources_follow_named_paths_and_relocated_payload_rvas() -> io::Result<()> {
        for base in [0x400000, 0x610000] {
            let mut bytes = fixture(base);
            let image = PeImage::parse(&bytes)?.unwrap();
            assert_eq!(
                image.resource("#10", "STARTUP.TJS")?,
                Some(b"TJS".as_slice())
            );
            assert!(image.resource("#10", "BOOTSTRAP")?.is_none());
            BinaryWriter::u32_le(0x8000_0000, &mut bytes[0x254..]);
            assert!(
                PeImage::parse(&bytes)?
                    .unwrap()
                    .resource("#10", "STARTUP.TJS")
                    .is_err()
            );
            BinaryWriter::u32_le(0x60, &mut bytes[0x254..]);
            BinaryWriter::u32_le(0x1400, &mut bytes[0x260..]);
            assert_eq!(
                PeImage::parse(&bytes)?
                    .unwrap()
                    .resource("#10", "STARTUP.TJS")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        Ok(())
    }
}
