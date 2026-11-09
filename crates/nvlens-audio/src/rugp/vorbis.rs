//! Vorbis setup field traversal for mode block sizes. Lewton validates the
//! complete setup but does not expose its modes; its sample-count convenience
//! function indexes modes without checking corrupt packet mode numbers.
//! This follows Vorbis I sections 4.2.4 and 4.3, without decoding audio.
use super::bad;
use nvlens_core::Result;
use nvlens_io::{BitOrder, BitReader};

fn skip(bits: &mut BitReader<'_>, mut count: u64) -> Result<()> {
    while count != 0 {
        let take = count.min(32) as u8;
        bits.read_bits(take)?;
        count -= u64::from(take);
    }
    Ok(())
}
fn ilog(n: u32) -> u8 {
    (32 - n.leading_zeros()) as u8
}

pub(super) fn modes(packet: &[u8], channels: u8) -> Result<Vec<bool>> {
    let mut b = BitReader::new(
        packet
            .get(7..)
            .ok_or_else(|| bad("Truncated Vorbis setup"))?,
        BitOrder::Lsb,
    );
    let books = b.read_bits_le(8)? + 1;
    for _ in 0..books {
        if b.read_bits_le(24)? != 0x564342 {
            return Err(bad("Invalid Vorbis codebook signature"));
        }
        let dimensions = b.read_bits_le(16)?;
        let entries = b.read_bits_le(24)?;
        if b.read_bit()? != 0 {
            b.read_bits_le(5)?;
            let mut current = 0;
            while current < entries {
                let n = b.read_bits_le(ilog(entries - current))?;
                current = current
                    .checked_add(n)
                    .filter(|&n| n <= entries)
                    .ok_or_else(|| bad("Invalid ordered codebook count"))?;
            }
        } else {
            let sparse = b.read_bit()? != 0;
            for _ in 0..entries {
                if !sparse || b.read_bit()? != 0 {
                    b.read_bits_le(5)?;
                }
            }
        }
        let lookup = b.read_bits_le(4)?;
        if lookup != 0 {
            skip(&mut b, 64)?;
            let value_bits = b.read_bits_le(4)? + 1;
            b.read_bit()?;
            let values = if lookup == 1 {
                if dimensions == 0 {
                    return Err(bad("Zero codebook dimensions"));
                }
                let (mut lo, mut hi) = (0u32, entries);
                while lo < hi {
                    let mid = lo + (hi - lo).div_ceil(2);
                    let mut product = 1u64;
                    for _ in 0..dimensions {
                        product = product.saturating_mul(u64::from(mid));
                        if product > u64::from(entries) {
                            break;
                        }
                    }
                    if product <= u64::from(entries) {
                        lo = mid;
                    } else {
                        hi = mid - 1;
                    }
                }
                u64::from(lo)
            } else if lookup == 2 {
                u64::from(entries) * u64::from(dimensions)
            } else {
                return Err(bad("Invalid codebook lookup type"));
            };
            skip(&mut b, values * u64::from(value_bits))?;
        }
    }
    let times = b.read_bits_le(6)? + 1;
    skip(&mut b, u64::from(times) * 16)?;
    for _ in 0..b.read_bits_le(6)? + 1 {
        match b.read_bits_le(16)? {
            0 => {
                skip(&mut b, 8 + 16 + 16 + 6 + 8)?;
                let books = b.read_bits_le(4)? + 1;
                skip(&mut b, u64::from(books) * 8)?;
            }
            1 => {
                let n = b.read_bits_le(5)?;
                let mut partitions = Vec::new();
                for _ in 0..n {
                    partitions.push(b.read_bits_le(4)? as usize);
                }
                let mut dimensions = Vec::new();
                if let Some(&max) = partitions.iter().max() {
                    for _ in 0..=max {
                        dimensions.push(b.read_bits_le(3)? + 1);
                        let subclasses = b.read_bits_le(2)?;
                        if subclasses != 0 {
                            b.read_bits_le(8)?;
                        }
                        skip(&mut b, (1 << subclasses) * 8)?;
                    }
                }
                b.read_bits_le(2)?;
                let range = b.read_bits_le(4)?;
                for class in partitions {
                    skip(&mut b, u64::from(dimensions[class]) * u64::from(range))?;
                }
            }
            _ => return Err(bad("Invalid Vorbis floor type")),
        }
    }
    for _ in 0..b.read_bits_le(6)? + 1 {
        skip(&mut b, 16 + 24 + 24 + 24)?;
        let classes = b.read_bits_le(6)? + 1;
        b.read_bits_le(8)?;
        let mut books = 0;
        for _ in 0..classes {
            let low = b.read_bits_le(3)?;
            let high = if b.read_bit()? != 0 {
                b.read_bits_le(5)?
            } else {
                0
            };
            books += low.count_ones() + high.count_ones();
        }
        skip(&mut b, u64::from(books) * 8)?;
    }
    for _ in 0..b.read_bits_le(6)? + 1 {
        if b.read_bits_le(16)? != 0 {
            return Err(bad("Invalid Vorbis mapping type"));
        }
        let submaps = if b.read_bit()? != 0 {
            b.read_bits_le(4)? + 1
        } else {
            1
        };
        if b.read_bit()? != 0 {
            let coupling = b.read_bits_le(8)? + 1;
            skip(
                &mut b,
                u64::from(coupling) * 2 * u64::from(ilog(u32::from(channels) - 1)),
            )?;
        }
        b.read_bits_le(2)?;
        if submaps > 1 {
            skip(&mut b, u64::from(channels) * 4)?;
        }
        skip(&mut b, u64::from(submaps) * 24)?;
    }
    let mut modes = Vec::new();
    for _ in 0..b.read_bits_le(6)? + 1 {
        modes.push(b.read_bit()? != 0);
        skip(&mut b, 40)?;
    }
    if b.read_bit()? != 1 {
        return Err(bad("Missing Vorbis setup framing bit"));
    }
    Ok(modes)
}

pub(super) fn block_size(packet: &[u8], modes: &[bool], small: u8, large: u8) -> Result<u64> {
    let mut bits = BitReader::new(packet, BitOrder::Lsb);
    if bits.read_bit()? != 0 {
        return Err(bad("Unexpected Vorbis header in audio data"));
    }
    let mode = bits.read_bits_le(ilog(modes.len() as u32 - 1))? as usize;
    let large_mode = *modes
        .get(mode)
        .ok_or_else(|| bad("Audio mode exceeds the Vorbis setup table"))?;
    Ok(1u64 << if large_mode { large } else { small })
}

#[cfg(test)]
#[path = "../../tests/rugp/vorbis.rs"]
mod tests;
