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
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub executable: bool,
}

#[derive(Clone, Debug)]
pub enum ImportSymbol {
    Name(Vec<u8>),
    Ordinal(u16),
}

#[derive(Clone, Debug)]
pub struct Import {
    pub library: Vec<u8>,
    pub symbol: ImportSymbol,
    pub slot: u64,
}

pub struct PeImage<'a> {
    bytes: &'a [u8],
    pub image_base: u64,
    pub machine: u16,
    pub entry_point: u32,
    pub sections: Vec<Section>,
    header_size: u32,
    pe32_plus: bool,
    exports: Option<(u32, u32)>,
    imports: Option<(u32, u32)>,
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
        let (exports, imports, resources, tls) = if optional.len() >= directory_count_offset + 4 {
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
            (directory(0)?, directory(1)?, directory(2)?, directory(9)?)
        } else {
            (None, None, None, None)
        };
        let table_size = count
            .checked_mul(40)
            .ok_or_else(|| BinaryIo::unexpected_eof("PE section count overflow"))?;
        let mut table = BinaryReader::new(reader.read_bytes(table_size)?);
        let mut sections = Vec::with_capacity(count);
        for _ in 0..count {
            let mut name = [0; 8];
            name.copy_from_slice(table.read_bytes(8)?);
            let virtual_size = table.read_u32_le()?;
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
                virtual_size,
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
            exports,
            imports,
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

    /// Reads an initial PE word, including the zero-filled tail of a section.
    /// File-backed bytes use the current section replacements when present.
    pub fn u32_at_va(&self, address: u64) -> io::Result<u32> {
        let mut word = [0; 4];
        for (i, byte) in word.iter_mut().enumerate() {
            let address = address
                .checked_add(i as u64)
                .ok_or_else(|| BinaryIo::unexpected_eof("PE word address overflow"))?;
            if let Some(value) = self.at_va(address).and_then(|b| b.first()) {
                *byte = *value;
            } else if !self.sections.iter().any(|section| {
                address
                    .checked_sub(self.image_base)
                    .and_then(|rva| rva.checked_sub(u64::from(section.virtual_address)))
                    .is_some_and(|offset| {
                        offset >= u64::from(section.raw_size)
                            && offset < u64::from(section.virtual_size)
                    })
            }) {
                return Err(BinaryIo::unexpected_eof("PE word exceeds mapped sections"));
            }
        }
        Ok(BinaryReader::u32_le(&word))
    }

    /// Resolves a named local export to its VA. Forwarded exports have no
    /// implementation in this image and return None; malformed tables fail.
    pub fn export(&self, name: &[u8]) -> io::Result<Option<u64>> {
        let Some((rva, size)) = self.exports else {
            return Ok(None);
        };
        let mapped = |rva| {
            self.at_rva(rva)
                .ok_or_else(|| BinaryIo::unexpected_eof("PE export table exceeds section"))
        };
        let mut directory = BinaryReader::new(mapped(rva)?);
        directory.read_bytes(20)?;
        let functions = directory.read_u32_le()?;
        let names = directory.read_u32_le()?;
        let addresses_rva = directory.read_u32_le()?;
        let names_rva = directory.read_u32_le()?;
        let ordinals_rva = directory.read_u32_le()?;
        if names == 0 {
            return Ok(None);
        }
        let mut addresses = BinaryReader::new(mapped(addresses_rva)?);
        let mut strings = BinaryReader::new(mapped(names_rva)?);
        let mut ordinals = BinaryReader::new(mapped(ordinals_rva)?);
        for _ in 0..names {
            let string = mapped(strings.read_u32_le()?)?;
            let end = string
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| BinaryIo::unexpected_eof("Unterminated PE export name"))?;
            let ordinal = ordinals.read_u16_le()?;
            if u32::from(ordinal) >= functions {
                return Err(BinaryIo::invalid_input(
                    "PE export ordinal exceeds address table",
                ));
            }
            if &string[..end] != name {
                continue;
            }
            addresses.set_position(usize::from(ordinal) * 4)?;
            let target = addresses.read_u32_le()?;
            if target == 0 || target.checked_sub(rva).is_some_and(|offset| offset < size) {
                return Ok(None);
            }
            mapped(target)?;
            return self
                .image_base
                .checked_add(u64::from(target))
                .map(Some)
                .ok_or_else(|| BinaryIo::invalid_input("PE export address overflow"));
        }
        Ok(None)
    }

    /// Resolves an ordinal export without loading the executable. Forwarders
    /// return None, matching `export`; all table reads remain section-bounded.
    pub fn export_ordinal(&self, ordinal: u16) -> io::Result<Option<u64>> {
        let Some((rva, size)) = self.exports else {
            return Ok(None);
        };
        let mut r = BinaryReader::new(
            self.at_rva(rva)
                .ok_or_else(|| BinaryIo::unexpected_eof("Missing PE export directory"))?,
        );
        r.read_bytes(16)?;
        let base = r.read_u32_le()?;
        let count = r.read_u32_le()?;
        r.read_u32_le()?;
        let table = r.read_u32_le()?;
        let Some(index) = u32::from(ordinal).checked_sub(base).filter(|i| *i < count) else {
            return Ok(None);
        };
        let mut r = BinaryReader::new(
            self.at_rva(table)
                .ok_or_else(|| BinaryIo::unexpected_eof("Missing PE export addresses"))?,
        );
        r.set_position(index as usize * 4)?;
        let target = r.read_u32_le()?;
        if target == 0 || target.checked_sub(rva).is_some_and(|d| d < size) {
            return Ok(None);
        }
        if !self.sections.iter().any(|section| {
            target
                .checked_sub(section.virtual_address)
                .is_some_and(|offset| offset < section.virtual_size.max(section.raw_size))
        }) {
            return Err(BinaryIo::unexpected_eof("PE export exceeds section"));
        }
        Ok(Some(self.image_base + u64::from(target)))
    }

    /// Enumerates the declared import slots, preserving names and ordinals.
    /// This only reads PE metadata and never resolves or executes a DLL.
    pub fn imports(&self) -> io::Result<Vec<Import>> {
        let Some((rva, size)) = self.imports else {
            return Ok(Vec::new());
        };
        let bytes = self
            .at_rva(rva)
            .and_then(|b| b.get(..size as usize))
            .ok_or_else(|| BinaryIo::unexpected_eof("PE import directory exceeds section"))?;
        let mut descriptors = BinaryReader::new(bytes);
        let mut imports = Vec::new();
        while descriptors.remaining() != 0 {
            let lookup = descriptors.read_u32_le()?;
            let timestamp = descriptors.read_u32_le()?;
            let forwarder = descriptors.read_u32_le()?;
            let name = descriptors.read_u32_le()?;
            let table = descriptors.read_u32_le()?;
            if lookup | timestamp | forwarder | name | table == 0 {
                return Ok(imports);
            }
            let library = self
                .c_string_at_va(self.image_base + u64::from(name))
                .ok_or_else(|| BinaryIo::unexpected_eof("Unterminated PE import library"))?;
            let mut r = BinaryReader::new(
                self.at_rva(if lookup == 0 { table } else { lookup })
                    .ok_or_else(|| BinaryIo::unexpected_eof("Missing PE import lookup"))?,
            );
            let mut slot = self.image_base + u64::from(table);
            loop {
                let value = if self.pe32_plus {
                    r.read_u64_le()?
                } else {
                    u64::from(r.read_u32_le()?)
                };
                if value == 0 {
                    break;
                }
                let ordinal_bit = if self.pe32_plus {
                    1u64 << 63
                } else {
                    1u64 << 31
                };
                let symbol = if value & ordinal_bit != 0 {
                    ImportSymbol::Ordinal(value as u16)
                } else {
                    let address = self
                        .image_base
                        .checked_add(value)
                        .and_then(|v| v.checked_add(2))
                        .ok_or_else(|| BinaryIo::invalid_input("PE import address overflow"))?;
                    ImportSymbol::Name(
                        self.c_string_at_va(address)
                            .ok_or_else(|| BinaryIo::unexpected_eof("Unterminated PE import name"))?
                            .to_vec(),
                    )
                };
                imports.push(Import {
                    library: library.to_vec(),
                    symbol,
                    slot,
                });
                slot = slot
                    .checked_add(if self.pe32_plus { 8 } else { 4 })
                    .ok_or_else(|| BinaryIo::invalid_input("PE import slot overflow"))?;
            }
        }
        Err(BinaryIo::unexpected_eof("Unterminated PE import directory"))
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
#[path = "../tests/pe.rs"]
mod tests;
