//! OptimizedObs framing from riooor.rpo and the public-domain deoptimizeobs
//! format specification. OOR retains Vorbis packets; only page/header framing
//! changes. Bits are MSB-first here, while Vorbis packets remain untouched.
mod vorbis;
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm};
use nvlens_core::{Error, Format, Result};
use nvlens_io::{BinaryWriter, BitOrder, BitReader};
use ogg::writing::{PacketWriteEndInfo as End, PacketWriter};
use std::sync::atomic::{AtomicBool, Ordering};

fn bad(reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: format!("OptimizedObs: {}", reason.into()),
    }
}

#[derive(Debug)]
struct Info {
    channels: u8,
    rate: u32,
    small: u8,
    large: u8,
    end: Option<u64>,
}

fn page_header(bits: &mut BitReader<'_>) -> Result<(u8, u8, Option<u64>)> {
    let version = bits.read_bits(2)? as u8;
    if version > 1 {
        return Err(Error::Unsupported(format!(
            "OptimizedObs page version {version}"
        )));
    }
    let flags = bits.read_bits(4)? as u8;
    let granule = if version != 0 {
        bits.read_bits(2)?;
        let value = bits.read_bits_u64(64)?;
        bits.read_bits(6)?;
        Some(value)
    } else {
        None
    };
    Ok((version, flags, granule))
}

fn info(bits: &mut BitReader<'_>) -> Result<Info> {
    let (_, flags, _) = page_header(bits)?;
    if flags != 2 {
        return Err(bad("Missing identification page"));
    }
    bits.align_byte();
    let version = bits.read_bits(2)?;
    if version > 1 {
        return Err(Error::Unsupported(format!(
            "OptimizedObs identification version {version}"
        )));
    }
    let channels = bits.read_bits(3)? as u8;
    let selector = bits.read_bits(2)?;
    let rate = if selector < 3 {
        11025 << selector
    } else {
        match (version, bits.read_bits(8)?) {
            (0, 3) | (1, 4) => 32000,
            (0, 4) => 48000,
            (0, 5) => 96000,
            (1, 5) => 48000,
            (1, 6) => 64000,
            (1, 7) => 88200,
            (1, 8) => 96000,
            _ => return Err(bad("Unknown sample rate selector")),
        }
    };
    let end = if version != 0 {
        bits.read_bits(9)?;
        Some(bits.read_bits_u64(64)?)
    } else {
        None
    };
    let small = bits.read_bits(4)? as u8;
    let large = bits.read_bits(4)? as u8;
    if channels == 0
        || !(6..=13).contains(&small)
        || large < small
        || large > 13
        || bits.read_bit()? != 1
    {
        return Err(bad("Invalid Vorbis identification fields"));
    }
    bits.align_byte();
    Ok(Info {
        channels,
        rate,
        small,
        large,
        end,
    })
}

fn identification(info: &Info) -> Vec<u8> {
    let mut packet = vec![0; 30];
    packet[..7].copy_from_slice(b"\x01vorbis");
    packet[11] = info.channels;
    BinaryWriter::u32_le(info.rate, &mut packet[12..]);
    packet[28] = info.small | (info.large << 4);
    packet[29] = 1;
    packet
}

/// Reframes one OOR logical stream as Ogg without changing its Vorbis audio
/// packets. Setup tables load only when the stream explicitly references one.
pub fn to_ogg(data: &[u8]) -> Result<Vec<u8>> {
    convert(data, &AtomicBool::new(false))
}

fn convert(data: &[u8], cancel: &AtomicBool) -> Result<Vec<u8>> {
    let mut bits = BitReader::new(data, BitOrder::Msb);
    let info = info(&mut bits)?;
    let ident_packet = identification(&info);
    lewton::header::read_header_ident(&ident_packet).map_err(|e| bad(e.to_string()))?;
    let mut writer = PacketWriter::new(Vec::new());
    writer.write_packet(ident_packet.into_boxed_slice(), 1, End::EndPage, 0)?;
    let mut comment = vec![0; 16];
    comment[..7].copy_from_slice(b"\x03vorbis");
    comment[15] = 1;
    writer.write_packet(comment.into_boxed_slice(), 1, End::EndPage, 0)?;
    let mut setup = None;
    let mut inline_setup = false;
    let mut carry = Vec::new();
    let mut frames = 0u64;
    let mut previous_block = None;
    let mut ended = false;
    while bits.position().0 < data.len() {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let (_, flags, granule) = page_header(&mut bits)?;
        if flags & 2 != 0 || ended {
            return Err(bad("Unexpected beginning or data after stream end"));
        }
        if (flags & 8 != 0) != !carry.is_empty() {
            return Err(bad("Packet continuation does not match the previous page"));
        }
        let length_bits = bits.read_bits(4)? as u8;
        bits.read_bit()?;
        let count = bits.read_bits(8)? as usize;
        let base_bits = match bits.read_bits(2)? {
            0 => 0,
            1 => 8,
            2 => 11,
            _ => return Err(bad("Undefined packet-size selector")),
        };
        let base = bits.read_bits(base_bits)? as usize;
        let mut lengths = Vec::with_capacity(count);
        for _ in 0..count {
            lengths.push(base + bits.read_bits(length_bits)? as usize);
        }
        bits.align_byte();
        for (i, length) in lengths.into_iter().enumerate() {
            let data = bits.read_raw_bytes(length)?;
            let partial = i + 1 == count && flags & 4 != 0;
            carry.extend_from_slice(data);
            if partial {
                continue;
            }
            let packet = std::mem::take(&mut carry);
            // OOR setup pages include an empty second packet; riooor skips
            // zero-sized entries instead of feeding them to Vorbis.
            if packet.is_empty() {
                continue;
            }
            if setup.is_none() {
                let mut header = b"\x05vorbis".to_vec();
                if inline_setup {
                    header.extend_from_slice(&packet);
                } else {
                    let (&id, inline) = packet
                        .split_first()
                        .ok_or_else(|| bad("Empty setup packet"))?;
                    let id = id & 63;
                    if id == 0 {
                        inline_setup = true;
                        if inline.is_empty() {
                            continue;
                        }
                        header.extend_from_slice(inline);
                    } else {
                        if !inline.is_empty() {
                            return Err(bad("Preset setup packet has trailing bytes"));
                        }
                        let name = nvlens_bin::keys::rugp::VORBIS_SETUPS
                            .get(usize::from(id) - 1)
                            .ok_or_else(|| {
                                Error::UnknownScheme(Some(format!("OptimizedObs setup {id}")))
                            })?;
                        header.extend_from_slice(&nvlens_bin::load(name)?);
                    }
                }
                lewton::header::read_header_setup(&header, info.channels, (info.small, info.large))
                    .map_err(|e| bad(e.to_string()))?;
                setup = Some(vorbis::modes(&header, info.channels)?);
                writer.write_packet(header.into_boxed_slice(), 1, End::EndPage, 0)?;
            } else {
                let setup = setup.as_ref().ok_or_else(|| bad("Missing setup packet"))?;
                let block = vorbis::block_size(&packet, setup, info.small, info.large)?;
                if let Some(previous) = previous_block {
                    frames = frames
                        .checked_add((previous + block) / 4)
                        .ok_or_else(|| bad("Sample count overflow"))?;
                }
                previous_block = Some(block);
                let last = i + 1 == count;
                let end = if last && flags & 1 != 0 {
                    ended = true;
                    End::EndStream
                } else if last {
                    End::EndPage
                } else {
                    End::NormalPacket
                };
                let position = if ended {
                    info.end.or(granule).unwrap_or(frames)
                } else if last {
                    granule.unwrap_or(frames)
                } else {
                    frames
                };
                writer.write_packet(packet.into_boxed_slice(), 1, end, position)?;
            }
        }
        if flags & 1 != 0 && (!carry.is_empty() || !ended) {
            return Err(bad("Incomplete end page"));
        }
    }
    if !ended || !carry.is_empty() {
        return Err(nvlens_io::BinaryIo::unexpected_eof("Truncated OptimizedObs stream").into());
    }
    Ok(writer.into_inner())
}

#[derive(Debug, Default)]
struct Oor;
impl Format for Oor {
    fn tag(&self) -> &'static str {
        "oor/rugp"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["oor", "coptimizedobs"]
    }
    fn description(&self) -> &'static str {
        "rUGP OptimizedObs Vorbis audio"
    }
}
impl AudioFormat for Oor {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        if !matches!(data.first(), Some(0x08 | 0x48)) {
            return Ok(None);
        }
        let mut bits = BitReader::new(data, BitOrder::Msb);
        if info(&mut bits).is_err() {
            return Ok(None);
        }
        let mut meta = crate::standard::ogg::metadata(&to_ogg(data)?)?;
        meta.codec = "rUGP OptimizedObs";
        Ok(Some(meta))
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancel: &AtomicBool) -> Result<Pcm> {
        crate::standard::ogg::decode(&convert(data, cancel)?, cancel)
    }
}
nvlens_core::inventory::submit! {AudioRegistration(||Box::new(Oor))}

#[cfg(test)]
#[path = "../../tests/rugp/mod.rs"]
mod tests;
