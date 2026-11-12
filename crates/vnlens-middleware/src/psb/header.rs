//! PSB v1-v4 little-endian headers. Native PSBObject::initialize at
//! psbfile.dll 0x1000C0E0/0x1000C150 maps these fields independently; v1 uses
//! byte 8 as a key-array offset. v3/v4 add an Adler-32 field and extra chunks.
use super::{PSB_MAGIC, PsbHeader, corrupt};
use vnlens_core::{Error, Result};
use vnlens_crypto::{checksum::adler32::Adler32, cipher::psb_stream::PsbStream};
use vnlens_io::{BinaryReader, BinaryWriter, ReadAt};

impl PsbHeader {
    pub(super) fn read(data: &dyn ReadAt, cipher: Option<&mut PsbStream>) -> Result<Self> {
        if data.len() < 4 || data.read_at(0, 4)?.as_ref() != PSB_MAGIC {
            return Err(Error::InvalidFormat);
        }
        let prefix = data.read_at(0, 8)?;
        let version = BinaryReader::u16_le(&prefix[4..]);
        if !(1..=4).contains(&version) {
            return Err(Error::Unsupported(format!("PSB version {version}")));
        }
        let mut bytes = data.read_at(8, header_len(version) - 8)?;
        if let Some(cipher) = cipher {
            cipher.apply(bytes.to_mut());
        }
        let mut reader = BinaryReader::new(&bytes);
        Ok(Self {
            version,
            flags: BinaryReader::u16_le(&prefix[6..]),
            header_length: reader.read_u32_le()?,
            offset_names: reader.read_u32_le()?,
            offset_strings: reader.read_u32_le()?,
            offset_strings_data: reader.read_u32_le()?,
            offset_chunk_offsets: reader.read_u32_le()?,
            offset_chunk_lengths: reader.read_u32_le()?,
            offset_chunk_data: reader.read_u32_le()?,
            offset_entries: reader.read_u32_le()?,
            checksum: if version >= 3 {
                Some(reader.read_u32_le()?)
            } else {
                None
            },
            offset_extra_chunk_offsets: if version >= 4 {
                Some(reader.read_u32_le()?)
            } else {
                None
            },
            offset_extra_chunk_lengths: if version >= 4 {
                Some(reader.read_u32_le()?)
            } else {
                None
            },
            offset_extra_chunk_data: if version >= 4 {
                Some(reader.read_u32_le()?)
            } else {
                None
            },
        })
    }

    /// Compares the stored checksum to the decoded header fields. v1/v2 have
    /// no checksum. Native v3 readers may ignore this field; v4 validates it.
    #[must_use]
    pub fn checksum_valid(&self) -> Option<bool> {
        let expected = self.checksum?;
        let mut checksum = Adler32::default();
        for value in [
            self.header_length,
            self.offset_names,
            self.offset_strings,
            self.offset_strings_data,
            self.offset_chunk_offsets,
            self.offset_chunk_lengths,
            self.offset_chunk_data,
            self.offset_entries,
        ]
        .into_iter()
        .chain(
            [
                self.offset_extra_chunk_offsets,
                self.offset_extra_chunk_lengths,
                self.offset_extra_chunk_data,
            ]
            .into_iter()
            .flatten(),
        ) {
            let mut bytes = [0; 4];
            BinaryWriter::u32_le(value, &mut bytes);
            checksum.update(&bytes);
        }
        Some(checksum.checksum() == expected)
    }
}

pub(super) fn header_len(version: u16) -> usize {
    match version {
        1 | 2 => 40,
        3 => 44,
        _ => 56,
    }
}

pub(super) fn validate_header(header: &PsbHeader, len: u64) -> Result<()> {
    let minimum = header_len(header.version) as u64;
    let metadata = [
        Some(header.offset_names),
        Some(header.offset_strings),
        Some(header.offset_chunk_offsets),
        Some(header.offset_chunk_lengths),
        Some(header.offset_entries),
        header.offset_extra_chunk_offsets,
        header.offset_extra_chunk_lengths,
        (header.version == 1).then_some(header.header_length),
    ];
    for offset in metadata.into_iter().flatten() {
        if u64::from(offset) < minimum || u64::from(offset) >= len {
            return Err(corrupt(
                u64::from(offset),
                "PSB metadata offset is out of range",
            ));
        }
    }
    for offset in [
        Some(header.offset_strings_data),
        Some(header.offset_chunk_data),
        header.offset_extra_chunk_data,
    ]
    .into_iter()
    .flatten()
    {
        if u64::from(offset) > len {
            return Err(corrupt(
                u64::from(offset),
                "PSB data offset is out of range",
            ));
        }
    }
    Ok(())
}
