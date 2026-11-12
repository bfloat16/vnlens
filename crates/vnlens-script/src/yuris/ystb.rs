//! YSTB 0x1DF..=0x1E0 and 0x1E6..=0x22B, little-endian 32-byte header
//! followed by instruction, argument, value and source-line sections. Each
//! section restarts the same four-byte XOR key independently (0x452299).

use super::{corrupt, tables::Command};
use std::{
    collections::BTreeSet,
    ops::Range,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{Error, Result, Secret};
use vnlens_io::BinaryReader;

/// Validates framing without decrypting or interpreting native instructions.
pub(super) fn sections(data: &[u8]) -> Result<(usize, Vec<Range<usize>>)> {
    let mut reader = BinaryReader::new(data);
    if reader.read_bytes(4)? != b"YSTB" {
        return Err(Error::InvalidFormat);
    }
    let version = reader.read_u32_le()?;
    if !matches!(version, 0x1df..=0x1e0 | 0x1e6..=0x22b) {
        return Err(Error::Unsupported(format!("YSTB version 0x{version:X}")));
    }
    let count = reader.read_u32_le()? as usize;
    let mut start = 32usize;
    let mut sections = Vec::with_capacity(4);
    for _ in 0..4 {
        let size = reader.read_u32_le()? as usize;
        let end = start
            .checked_add(size)
            .filter(|&end| end <= data.len())
            .ok_or_else(|| corrupt(start, "YSTB section exceeds file"))?;
        sections.push(start..end);
        start = end;
    }
    reader.read_u32_le()?;
    if start != data.len() {
        return Err(corrupt(start, "YSTB section sizes do not cover file"));
    }
    if count.checked_mul(4) != Some(sections[0].len())
        || sections[3].len() != sections[0].len()
        || !sections[1].len().is_multiple_of(12)
    {
        return Err(corrupt(
            8,
            "YSTB instruction, operand, or source-line table size mismatch",
        ));
    }
    Ok((count, sections))
}

/// Applies the native section transform in place after validating all ranges.
pub fn decrypt(data: &mut [u8], key: &[u8; 4]) -> Result<()> {
    let (_, ranges) = sections(data)?;
    for range in ranges {
        vnlens_crypto::cipher::xor::apply_u32_key(&mut data[range], key);
    }
    Ok(())
}

/// Candidate keys use a zero data offset, as in YSTB_Coder::GetXorKey, but
/// include every argument offset and the unencrypted case. A candidate must
/// satisfy the complete instruction/argument layout and the supplied native
/// command definitions. No candidate or multiple candidates remain unresolved.
pub fn recover_key(
    data: &[u8],
    commands: &[Command],
    cancelled: &AtomicBool,
) -> Result<Option<Secret>> {
    let (_, ranges) = sections(data)?;
    let args = &data[ranges[1].clone()];
    if args.is_empty() || ranges[2].is_empty() {
        return Ok(None);
    }
    let code = &data[ranges[0].clone()];
    let mut counts = [0u64; 256];
    for inst in code.as_chunks::<4>().0 {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        counts[usize::from(inst[1])] += 1;
    }
    let mut argc_keys = [false; 256];
    for key in u8::MIN..=u8::MAX {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let total: u64 = counts
            .iter()
            .enumerate()
            .map(|(value, count)| count * u64::from(value as u8 ^ key))
            .sum();
        argc_keys[usize::from(key)] = total == (args.len() / 12) as u64;
    }
    let mut candidates = BTreeSet::from([[0; 4]]);
    for arg in args.as_chunks::<12>().0 {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        candidates.insert([arg[8], arg[9], arg[10], arg[11]]);
    }
    let mut found = None;
    for key in candidates {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if !argc_keys[usize::from(key[1])] || !validate(data, &ranges, commands, &key, cancelled)? {
            continue;
        }
        if found.is_some() {
            return Err(Error::UnknownScheme(Some(
                "Ambiguous YSTB script key".into(),
            )));
        }
        found = Some(Secret::new(key));
    }
    Ok(found)
}

fn validate(
    data: &[u8],
    ranges: &[Range<usize>],
    commands: &[Command],
    key: &[u8; 4],
    cancelled: &AtomicBool,
) -> Result<bool> {
    let args = &data[ranges[1].clone()];
    let values_len = ranges[2].len() as u64;
    let count = ranges[0].len() / 4;
    let mut argument = 0;
    let mut data_arguments = 0;
    for inst in data[ranges[0].clone()].as_chunks::<4>().0 {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let Some(command) = commands.get(usize::from(inst[0] ^ key[0])) else {
            return Ok(false);
        };
        for position in 0..(inst[1] ^ key[1]) {
            let Some(encoded) = args.get(argument..argument + 12) else {
                return Ok(false);
            };
            argument += 12;
            let mut plain = [0; 12];
            for (index, (byte, out)) in encoded.iter().zip(&mut plain).enumerate() {
                *out = *byte ^ key[index % 4];
            }
            let length = BinaryReader::u32_le(&plain[4..]);
            let offset = BinaryReader::u32_le(&plain[8..]);
            let control =
                matches!(command.name.as_str(), "ELSE" | "IF" | "IFBLEND" | "LOOP") && position > 0;
            if control {
                if u64::from(length) > count as u64 {
                    return Ok(false);
                }
            } else if command.name != "RETURNCODE" {
                if u64::from(offset) + u64::from(length) > values_len {
                    return Ok(false);
                }
                data_arguments += 1;
            }
        }
    }
    Ok(argument == args.len() && data_arguments != 0)
}

#[cfg(test)]
#[path = "../../tests/yuris/ystb.rs"]
mod tests;
