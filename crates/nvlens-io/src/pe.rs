//! Read-only PE section mapping for executable feature discovery.
//! Virtual addresses are resolved through headers and file-backed section data.
#![forbid(unsafe_code)]

use crate::{BinaryIo, BinaryReader};
use std::io;

#[derive(Clone, Debug)]
pub struct Section {
    pub virtual_address: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub executable: bool,
}

#[derive(Debug)]
pub struct PeImage<'a> {
    bytes: &'a [u8],
    pub image_base: u64,
    pub machine: u16,
    pub sections: Vec<Section>,
    header_size: u32,
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
        let table_size = count
            .checked_mul(40)
            .ok_or_else(|| BinaryIo::unexpected_eof("PE section count overflow"))?;
        let mut table = BinaryReader::new(reader.read_bytes(table_size)?);
        let mut sections = Vec::with_capacity(count);
        for _ in 0..count {
            table.read_bytes(12)?;
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
            sections,
            header_size,
        }))
    }

    pub fn section_data(&self, section: &Section) -> io::Result<&'a [u8]> {
        let offset = usize::try_from(section.raw_offset)
            .map_err(|_| BinaryIo::unexpected_eof("PE section offset does not fit memory"))?;
        let size = usize::try_from(section.raw_size)
            .map_err(|_| BinaryIo::unexpected_eof("PE section size does not fit memory"))?;
        let mut reader = BinaryReader::new_at(self.bytes, offset)?;
        reader.read_bytes(size)
    }

    #[must_use]
    pub fn at_va(&self, address: u64) -> Option<&'a [u8]> {
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
    pub fn c_string_at_va(&self, address: u64) -> Option<&'a [u8]> {
        let bytes = self.at_va(address)?;
        bytes.get(..bytes.iter().position(|&byte| byte == 0)?)
    }
}
