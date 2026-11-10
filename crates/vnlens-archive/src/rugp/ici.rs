//! CObjectArcMan and CInstallSource installation metadata, as serialized by
//! UnivUI (10015F90/100132A0). File bases use the declared address-unit shift;
//! byte lengths do not. The installation bitmap has one bit per 64 KiB block.
use vnlens_core::{Error, Result};
use vnlens_io::BinaryReader;
use vnlens_script::rugp::wire::{self, Reader, count, string};

#[derive(Debug)]
pub(super) struct Volume {
    pub name: String,
    pub base: u64,
    pub size: u64,
}

#[derive(Debug)]
pub(super) struct Index {
    pub shift: u32,
    pub toc_offset: u64,
    pub toc_size: u64,
    pub volumes: Vec<Volume>,
}

pub(super) fn parse(data: &[u8]) -> Result<Index> {
    let chunk =
        vnlens_crypto::cipher::rugp::decrypt_chunk(&mut BinaryReader::new(data), 0xb29d_5a0c)
            .map_err(super::cipher_error)?;
    let decoded = vnlens_crypto::cipher::rugp::decode_ici(&chunk);
    let mut archive = Reader::new(&decoded, false);
    let (signature, _, _, class) = archive.header()?;
    if signature != wire::ICI_SIGNATURE || class.name != "CObjectArcMan" {
        return Err(Error::InvalidFormat);
    }
    if !archive.children()?.is_empty() {
        return Err(Error::Unsupported("ICI manager with child objects".into()));
    }
    let r = &mut archive.bytes;
    let version = r.read_u32_le()?;
    r.read_u32_le()?;
    r.read_bytes(2)?;
    let shift = if version >= 10 {
        let shift = r.read_u32_le()?;
        r.read_u32_le()?;
        shift
    } else {
        0
    };
    r.read_bytes(12)?;
    if version < 6 {
        return Err(Error::Unsupported(format!(
            "ICI manager version {version} has no root extent"
        )));
    }
    let offset = u64::from(r.read_u32_le()?);
    let size = u64::from(r.read_u32_le()?);
    r.read_u32_le()?;
    if version >= 8 {
        r.read_u32_le()?;
    }
    r.read_mfc_string()?;
    r.read_u32_le()?;
    r.read_mfc_string()?;
    r.read_u32_le()?;
    // Includes the binary installation identifier, serialized as a CString.
    for _ in 0..3 {
        r.read_mfc_string()?;
    }
    r.read_u32_le()?;
    r.read_mfc_string()?;
    for _ in 0..count(r)? {
        r.read_mfc_string()?;
    }
    r.read_u32_le()?;
    if version >= 9 {
        r.read_mfc_string()?;
    }
    if version >= 7 {
        r.read_mfc_string()?;
    }
    if version >= 5 {
        r.read_u32_le()?;
    }
    let mut volumes = Vec::new();
    for _ in 0..count(r)? {
        if r.read_u8()? == 0 {
            continue;
        }
        let version = r.read_u16_le()?;
        if version >= 7 {
            r.read_bytes(9)?;
            r.read_mfc_string()?;
        }
        for _ in 0..5 {
            r.read_mfc_string()?;
        }
        r.read_bytes(16)?;
        r.read_bytes(if version < 6 { 8 } else { 4 })?;
        let name = string(r)?;
        let base = r.read_u64_le()?;
        let size = r.read_u64_le()?;
        if version < 6 {
            r.read_u64_le()?;
        }
        r.read_u32_le()?;
        r.read_mfc_string()?;
        r.read_bytes(20)?;
        r.read_mfc_string()?;
        let words = count(r)? as usize;
        r.read_bytes(
            words
                .checked_mul(4)
                .ok_or_else(|| wire::corrupt(r.position(), "ICI array length overflow"))?,
        )?;
        let bitmap = size.div_ceil(65536).div_ceil(8);
        r.read_bytes(
            usize::try_from(bitmap)
                .map_err(|_| wire::corrupt(r.position(), "ICI bitmap exceeds address space"))?,
        )?;
        volumes.push(Volume {
            name,
            base: address(base, shift)?,
            size,
        });
    }
    Ok(Index {
        shift,
        toc_offset: address(offset, shift)?,
        toc_size: size,
        volumes,
    })
}

pub(super) fn address(value: u64, shift: u32) -> Result<u64> {
    let unit = 1u64
        .checked_shl(shift)
        .ok_or_else(|| wire::corrupt(0, "RIO address unit exceeds u64"))?;
    value
        .checked_mul(unit)
        .ok_or_else(|| wire::corrupt(0, "RIO byte address overflow"))
}
