use super::*;

/// Compiler storage fields needed by the native bytecode reader.
#[derive(Clone, Debug)]
pub(super) struct Header {
    pub version: u32,
    pub code: u64,
    pub size: u64,
    pub stored: u64,
    pub kidoku: u64,
    pub kidoku_count: u32,
}
impl Header {
    /// Parses compiler fields and their ranges without decoding the bytecode.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(data);
        if r.read_u32_le()? != 0x1d0 {
            return Err(Error::InvalidFormat);
        }
        let version = r.read_u32_le()?;
        if !matches!(version % 100, 1 | 2) {
            return Err(Error::Unsupported(format!(
                "RealLive compiler storage kind {}",
                version % 100
            )));
        }
        let kidoku = u64::from(r.read_u32_le()?);
        let kidoku_count = r.read_u32_le()?;
        let kidoku_bytes = u64::from(r.read_u32_le()?);
        let names = u64::from(r.read_u32_le()?);
        let name_count = r.read_u32_le()?;
        let name_bytes = u64::from(r.read_u32_le()?);
        let code = u64::from(r.read_u32_le()?);
        let size = u64::from(r.read_u32_le()?);
        let stored = u64::from(r.read_u32_le()?);
        BinaryReader::new(data).read_bytes(0x1d0)?;
        if kidoku_bytes != u64::from(kidoku_count) * 4
            || kidoku < 0x1d0
            || kidoku.checked_add(kidoku_bytes).is_none_or(|e| e > code)
            || names.checked_add(name_bytes).is_none_or(|e| e > code)
            || code < 0x1d0
        {
            return Err(corrupt(8, "Inconsistent RealLive compiler tables"));
        }
        let mut names_reader = BinaryReader::new_at(
            data,
            usize::try_from(names)
                .map_err(|_| corrupt(0x14, "RealLive name offset exceeds memory"))?,
        )?;
        let names_data = names_reader.read_bytes(
            usize::try_from(name_bytes)
                .map_err(|_| corrupt(0x1c, "RealLive name table exceeds memory"))?,
        )?;
        let mut names_reader = BinaryReader::new(names_data);
        for _ in 0..name_count {
            let length = names_reader.read_u32_le()? as usize;
            names_reader.read_bytes(length)?;
        }
        let length = if version % 100 == 1 { size } else { stored };
        let mut payload = BinaryReader::new_at(
            data,
            usize::try_from(code)
                .map_err(|_| corrupt(0x20, "RealLive code offset exceeds memory"))?,
        )?;
        payload.read_bytes(
            usize::try_from(length)
                .map_err(|_| corrupt(0x24, "RealLive code size exceeds memory"))?,
        )?;
        Ok(Self {
            version,
            code,
            size,
            stored,
            kidoku,
            kidoku_count,
        })
    }
}
