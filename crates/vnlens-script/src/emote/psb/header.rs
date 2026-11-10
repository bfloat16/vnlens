//! PSB v1-v4 headers, optional stream decryption and section offset validation.
use super::{PSB_MAGIC, PsbHeader, corrupt};
use vnlens_core::{Error, Result};
use vnlens_crypto::cipher::psb_stream::PsbStream;
use vnlens_io::{BinaryReader, BinarySourceReader, ReadAt};

impl PsbHeader {
    pub(super) fn read(data: &dyn ReadAt, psb_key: Option<u32>) -> Result<Self> {
        if data.len() < 4 || data.read_at(0, 4)?.as_ref() != PSB_MAGIC {
            return Err(Error::InvalidFormat);
        }
        let mut reader = BinarySourceReader::new(data);
        let signature = reader.read_bytes(4)?;
        if signature.as_ref() != PSB_MAGIC {
            return Err(Error::InvalidFormat);
        }
        let version = reader.read_u16_le()?;
        reader.read_u16_le()?;
        if !(1..=4).contains(&version) {
            return Err(Error::Unsupported(format!("PSB version {version}")));
        }

        if let Some(key) = psb_key {
            let mut stream = PsbStream::new(key);
            let header_length = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_names = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_strings = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_strings_data = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_chunk_offsets = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_chunk_lengths = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_chunk_data = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_entries = read_encrypted_u32(&mut reader, &mut stream)?;
            if version > 2 {
                read_encrypted_u32(&mut reader, &mut stream)?;
            }
            let (offset_extra_chunk_offsets, offset_extra_chunk_lengths, offset_extra_chunk_data) =
                if version > 3 {
                    (
                        Some(read_encrypted_u32(&mut reader, &mut stream)?),
                        Some(read_encrypted_u32(&mut reader, &mut stream)?),
                        Some(read_encrypted_u32(&mut reader, &mut stream)?),
                    )
                } else {
                    (None, None, None)
                };
            return Ok(Self {
                version,
                header_length,
                offset_names,
                offset_strings,
                offset_strings_data,
                offset_chunk_offsets,
                offset_chunk_lengths,
                offset_chunk_data,
                offset_entries,
                offset_extra_chunk_offsets,
                offset_extra_chunk_lengths,
                offset_extra_chunk_data,
            });
        }

        let header_length = reader.read_u32_le()?;
        let offset_names = reader.read_u32_le()?;
        let offset_strings = reader.read_u32_le()?;
        let offset_strings_data = reader.read_u32_le()?;
        let offset_chunk_offsets = reader.read_u32_le()?;
        let offset_chunk_lengths = reader.read_u32_le()?;
        let offset_chunk_data = reader.read_u32_le()?;
        let offset_entries = reader.read_u32_le()?;
        if version > 2 {
            reader.read_u32_le()?;
        }
        let (offset_extra_chunk_offsets, offset_extra_chunk_lengths, offset_extra_chunk_data) =
            if version > 3 {
                (
                    Some(reader.read_u32_le()?),
                    Some(reader.read_u32_le()?),
                    Some(reader.read_u32_le()?),
                )
            } else {
                (None, None, None)
            };

        Ok(Self {
            version,
            header_length,
            offset_names,
            offset_strings,
            offset_strings_data,
            offset_chunk_offsets,
            offset_chunk_lengths,
            offset_chunk_data,
            offset_entries,
            offset_extra_chunk_offsets,
            offset_extra_chunk_lengths,
            offset_extra_chunk_data,
        })
    }
}

fn read_encrypted_u32(reader: &mut BinarySourceReader<'_>, stream: &mut PsbStream) -> Result<u32> {
    let mut bytes = reader.read_bytes(4)?.to_vec();
    stream.apply(&mut bytes);
    Ok(BinaryReader::u32_le(&bytes))
}

fn expected_header_len(version: u16) -> u32 {
    if version < 3 {
        40
    } else if version > 3 {
        56
    } else {
        44
    }
}

pub(super) fn validate_header(header: &PsbHeader, len: u64) -> Result<()> {
    if !(1..=4).contains(&header.version) {
        return Err(corrupt(4, "unsupported PSB version"));
    }

    let min_header = expected_header_len(header.version);
    if header.header_length != 0 && header.header_length < min_header {
        return Err(corrupt(8, "PSB header length is too small"));
    }

    let offsets = [
        header.offset_names,
        header.offset_strings,
        header.offset_strings_data,
        header.offset_chunk_offsets,
        header.offset_chunk_lengths,
        header.offset_chunk_data,
        header.offset_entries,
    ];
    for offset in offsets {
        if u64::from(offset) > len {
            return Err(corrupt(
                u64::from(offset),
                "PSB section offset is out of range",
            ));
        }
    }
    Ok(())
}
