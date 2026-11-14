//! CRI HCA and ADX framing. Headers retain encoding facts for shared HCA
//! spectral decoding and resource-domain adapters. HCA counts exclude its
//! encoder delay/end padding.
use super::corrupt;
use vnlens_core::{Error, Result};
use vnlens_crypto::checksum::crc16::crc16_8005;
use vnlens_io::{BinaryIo, BinaryReader};

#[derive(Clone, Debug)]
pub struct HcaHeader {
    pub version: u16,
    pub header_size: u16,
    pub channels: u16,
    pub sample_rate: u32,
    pub block_count: u32,
    pub block_size: u16,
    pub delay: u16,
    pub padding: u16,
    pub cipher: u16,
    pub frames: u64,
    pub compression: HcaCompression,
    pub ath_type: u16,
}

#[derive(Clone, Debug)]
pub struct HcaCompression {
    pub min_resolution: u8,
    pub max_resolution: u8,
    pub track_count: u8,
    pub channel_config: u8,
    pub total_bands: u16,
    pub base_bands: u16,
    pub stereo_bands: u16,
    pub bands_per_hfr_group: u8,
    pub ms_stereo: u8,
}
impl HcaHeader {
    pub fn open(data: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(data);
        if !tag(r.read_bytes(4)?, b"HCA\0") {
            return Err(Error::InvalidFormat);
        }
        let version = BinaryReader::u16_be(r.read_bytes(2)?);
        let header_size = BinaryReader::u16_be(r.read_bytes(2)?);
        let header = data
            .get(..usize::from(header_size))
            .ok_or_else(|| BinaryIo::unexpected_eof("Truncated HCA header"))?;
        if header.len() < 24 {
            return Err(corrupt(6, "HCA header is smaller than its format fields"));
        }
        if crc16_8005(header) != 0 {
            return Err(corrupt(0, "HCA header CRC-16 mismatch"));
        }
        if !tag(r.read_bytes(4)?, b"fmt\0") {
            return Err(corrupt(8, "Missing HCA format chunk"));
        }
        let format = BinaryReader::u32_be(r.read_bytes(4)?);
        let channels = (format >> 24) as u16;
        let sample_rate = format & 0xffffff;
        let block_count = BinaryReader::u32_be(r.read_bytes(4)?);
        let delay = BinaryReader::u16_be(r.read_bytes(2)?);
        let padding = BinaryReader::u16_be(r.read_bytes(2)?);
        if channels == 0 || sample_rate == 0 {
            return Err(corrupt(12, "HCA has zero channels or sample rate"));
        }
        let mut block_size = None;
        let mut cipher = 0;
        let mut compression = None;
        let mut ath_type = u16::from(version < 0x200);
        let mut at = 24;
        while at + 4 <= header.len() - 2 {
            let id = &header[at..at + 4];
            let size = if tag(id, b"comp") {
                16
            } else if tag(id, b"dec\0") {
                12
            } else if tag(id, b"vbr\0") || tag(id, b"rva\0") {
                8
            } else if tag(id, b"ath\0") || tag(id, b"ciph") {
                6
            } else if tag(id, b"loop") {
                16
            } else if tag(id, b"comm") {
                let length = *header
                    .get(at + 4)
                    .ok_or_else(|| BinaryIo::unexpected_eof("Truncated HCA comment"))?;
                5 + usize::from(length)
            } else if tag(id, b"pad\0") {
                break;
            } else {
                return Err(Error::Unsupported(format!(
                    "Unknown HCA header chunk at 0x{at:x}"
                )));
            };
            let chunk = header
                .get(at..at + size)
                .filter(|_| at + size <= header.len() - 2)
                .ok_or_else(|| BinaryIo::unexpected_eof("Truncated HCA chunk"))?;
            if tag(id, b"comp") || tag(id, b"dec\0") {
                block_size = Some(BinaryReader::u16_be(&chunk[4..6]));
                compression = Some(if tag(id, b"comp") {
                    HcaCompression {
                        min_resolution: chunk[6],
                        max_resolution: chunk[7],
                        track_count: chunk[8],
                        channel_config: chunk[9],
                        total_bands: u16::from(chunk[10]),
                        base_bands: u16::from(chunk[11]),
                        stereo_bands: u16::from(chunk[12]),
                        bands_per_hfr_group: chunk[13],
                        ms_stereo: chunk[14],
                    }
                } else {
                    let total = u16::from(chunk[8]) + 1;
                    let base = if chunk[11] == 0 {
                        total
                    } else {
                        u16::from(chunk[9]) + 1
                    };
                    HcaCompression {
                        min_resolution: chunk[6],
                        max_resolution: chunk[7],
                        track_count: chunk[10] >> 4,
                        channel_config: chunk[10] & 15,
                        total_bands: total,
                        base_bands: base,
                        stereo_bands: total.checked_sub(base).ok_or_else(|| {
                            corrupt(at as u64, "HCA base bands exceed total bands")
                        })?,
                        bands_per_hfr_group: 0,
                        ms_stereo: u8::from(chunk[11] > 1),
                    }
                });
            }
            if tag(id, b"ciph") {
                cipher = BinaryReader::u16_be(&chunk[4..6]);
            }
            if tag(id, b"ath\0") {
                ath_type = BinaryReader::u16_be(&chunk[4..6]);
            }
            at += size;
        }
        let block_size = block_size.ok_or_else(|| corrupt(24, "Missing HCA compression chunk"))?;
        if block_size == 0 {
            return Err(Error::Unsupported("Variable bitrate HCA framing".into()));
        }
        let frames = (u64::from(block_count) * 1024)
            .checked_sub(u64::from(delay) + u64::from(padding))
            .ok_or_else(|| corrupt(16, "HCA delay/padding exceeds sample count"))?;
        Ok(Self {
            version,
            header_size,
            channels,
            sample_rate,
            block_count,
            block_size,
            delay,
            padding,
            cipher,
            frames,
            compression: compression
                .ok_or_else(|| corrupt(24, "Missing HCA compression parameters"))?,
            ath_type,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AdxHeader {
    pub encoding: u8,
    pub block_size: u8,
    pub bit_depth: u8,
    pub channels: u16,
    pub sample_rate: u32,
    pub frames: u64,
    pub data_offset: u64,
    pub version: u8,
    pub cipher: u8,
}
impl AdxHeader {
    pub fn open(data: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(data);
        if r.read_bytes(2)? != [0x80, 0] {
            return Err(Error::InvalidFormat);
        }
        let data_offset = u64::from(BinaryReader::u16_be(r.read_bytes(2)?)) + 4;
        let encoding = r.read_u8()?;
        let block_size = r.read_u8()?;
        let bit_depth = r.read_u8()?;
        let channels = u16::from(r.read_u8()?);
        let sample_rate = BinaryReader::u32_be(r.read_bytes(4)?);
        let frames = u64::from(BinaryReader::u32_be(r.read_bytes(4)?));
        r.read_bytes(2)?;
        let version = r.read_u8()?;
        let cipher = r.read_u8()?;
        if data_offset < 20 || channels == 0 || sample_rate == 0 || block_size < 3 || bit_depth == 0
        {
            return Err(corrupt(2, "Invalid ADX format fields"));
        }
        let copyright = data
            .get(data_offset as usize - 6..data_offset as usize)
            .ok_or_else(|| BinaryIo::unexpected_eof("Truncated ADX copyright header"))?;
        if copyright != b"(c)CRI" {
            return Err(corrupt(data_offset - 6, "Invalid ADX copyright marker"));
        }
        Ok(Self {
            encoding,
            block_size,
            bit_depth,
            channels,
            sample_rate,
            frames,
            data_offset,
            version,
            cipher,
        })
    }
}
fn tag(bytes: &[u8], expected: &[u8; 4]) -> bool {
    bytes.iter().map(|b| b & 0x7f).eq(expected.iter().copied())
}

#[cfg(test)]
#[path = "../../tests/criware/audio.rs"]
mod tests;
