//! Siglus 0x84-byte scene header, indexed UTF-16 strings and label addresses.
use super::corrupt;
use crate::ir::Value;
use nvlens_core::Result;
use nvlens_io::{BinaryIo, BinaryReader};

#[derive(Debug)]
pub(super) struct Scene<'a> {
    data: &'a [u8],
    pub(super) fields: [u32; 33],
    strings: Vec<Option<Value>>,
}
impl<'a> Scene<'a> {
    pub(super) fn new(data: &'a [u8]) -> Result<Self> {
        let mut r = BinaryReader::new(data);
        let mut fields = [0; 33];
        for field in &mut fields {
            *field = r.read_u32_le()?;
        }
        if fields[4] != fields[6] {
            return Err(corrupt(16, "Siglus string counts differ"));
        }
        let mut s = Self {
            data,
            fields,
            strings: Vec::new(),
        };
        s.slice(fields[3], u64::from(fields[4]) * 8)?;
        s.strings.resize_with(fields[4] as usize, || None);
        Ok(s)
    }
    pub(super) fn slice(&self, offset: u32, size: u64) -> Result<&'a [u8]> {
        let size = usize::try_from(size)
            .map_err(|_| BinaryIo::unexpected_eof("Siglus section exceeds memory"))?;
        Ok(BinaryReader::new_at(self.data, offset as usize)?.read_bytes(size)?)
    }
    pub(super) fn text(&mut self, id: u32) -> Result<Value> {
        let slot = self
            .strings
            .get(id as usize)
            .ok_or_else(|| corrupt(self.fields[3] as usize, "Siglus string ID exceeds table"))?;
        if let Some(text) = slot {
            return Ok(text.clone());
        }
        let table = self.slice(self.fields[3], u64::from(self.fields[4]) * 8)?;
        let mut r = BinaryReader::new_at(table, id as usize * 8)?;
        let offset = u64::from(self.fields[5]) + u64::from(r.read_u32_le()?) * 2;
        let count = r.read_u32_le()?;
        let at = usize::try_from(offset)
            .map_err(|_| BinaryIo::unexpected_eof("Siglus text offset exceeds memory"))?;
        let mut r = BinaryReader::new_at(self.data, at)?;
        let raw = r.read_bytes(
            usize::try_from(u64::from(count) * 2)
                .map_err(|_| BinaryIo::unexpected_eof("Siglus text length exceeds memory"))?,
        )?;
        let mut r = BinaryReader::new(raw);
        let key = id.wrapping_mul(0x7087) as u16;
        let mut units = Vec::new();
        while r.remaining() > 0 {
            units.push(r.read_u16_le()? ^ key);
        }
        let value = match String::from_utf16(&units) {
            Ok(s) => Value::Text(s),
            Err(_) => Value::Bytes(raw.to_vec()),
        };
        self.strings[id as usize] = Some(value.clone());
        Ok(value)
    }
    pub(super) fn target(&self, id: u32) -> Result<u64> {
        let table = self.slice(self.fields[7], u64::from(self.fields[8]) * 4)?;
        let mut r = BinaryReader::new_at(table, id as usize * 4)?;
        let relative = r.read_u32_le()?;
        if relative > self.fields[2] {
            return Err(corrupt(
                self.fields[7] as usize,
                "Siglus label target exceeds bytecode",
            ));
        }
        Ok(u64::from(self.fields[1]) + u64::from(relative))
    }
}
