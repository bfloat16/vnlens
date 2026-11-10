//! Authenticated Hxv4 table: arrays alternate path octets and directory arrays;
//! directories alternate filename octets and [locator, key] arrays. Counts and
//! integers are big-endian. Paths expose the stored hash octets as uppercase hex.
//! Archive slots and the ordinary XP3 synthetic names identify payloads; several
//! hashed paths may reference one payload without duplicating its storage state.
use super::corrupt;
use std::collections::BTreeMap;
use vnlens_core::Result;
use vnlens_io::{BinaryReader, Endian};

#[derive(PartialEq, Eq)]
pub(super) struct Binding {
    pub path: String,
    pub filter: (u64, u16),
}
pub(super) type Index = BTreeMap<(u16, String), Vec<Binding>>;

pub(super) fn read(bytes: &[u8]) -> Result<Index> {
    let mut r = BinaryReader::new(bytes);
    let paths = array(&mut r)?;
    if paths % 2 != 0 {
        return Err(corrupt(0, "Odd Hxv4 path pair count"));
    }
    let mut out = Index::new();
    for _ in 0..paths / 2 {
        let directory = hex(octets(&mut r, 8)?);
        let files = array(&mut r)?;
        if files % 2 != 0 {
            return Err(corrupt(0, "Odd Hxv4 file pair count"));
        }
        for _ in 0..files / 2 {
            let filename = hex(octets(&mut r, 32)?);
            let fields = array(&mut r)?;
            if fields < 2 {
                return Err(corrupt(0, "Truncated Hxv4 entry metadata"));
            }
            let locator = integer(&mut r)?;
            let key = integer(&mut r)?;
            skip(&mut r, fields - 2)?;
            let name = fake_name(locator as u32);
            let binding = Binding {
                path: format!("{directory}/{filename}"),
                filter: (key, (locator >> 32) as u16),
            };
            let aliases = out.entry(((locator >> 48) as u16, name)).or_default();
            if aliases.iter().any(|old| old.filter != binding.filter) {
                return Err(corrupt(r.position() as u64, "Conflicting Hxv4 entry keys"));
            }
            if !aliases.contains(&binding) {
                aliases.push(binding);
            }
        }
    }
    if r.remaining() != 0 {
        return Err(corrupt(r.position() as u64, "Trailing Hxv4 table data"));
    }
    Ok(out)
}
use super::names::hex;
fn count(r: &mut BinaryReader<'_>) -> Result<usize> {
    let n = r.read_u32(Endian::Big)? as i32;
    usize::try_from(n).map_err(|_| corrupt(r.position() as u64, "Negative Hxv4 count"))
}
fn array(r: &mut BinaryReader<'_>) -> Result<usize> {
    if r.read_u8()? != 0x81 {
        return Err(corrupt(r.position() as u64, "Expected Hxv4 array"));
    }
    count(r)
}
fn integer(r: &mut BinaryReader<'_>) -> Result<u64> {
    if r.read_u8()? != 4 {
        return Err(corrupt(r.position() as u64, "Expected Hxv4 integer"));
    }
    Ok(r.read_u64(Endian::Big)?)
}
fn octets<'a>(r: &mut BinaryReader<'a>, len: usize) -> Result<&'a [u8]> {
    if r.read_u8()? != 3 || count(r)? != len {
        return Err(corrupt(r.position() as u64, "Invalid Hxv4 hash octets"));
    }
    Ok(r.read_bytes(len)?)
}
// Iterative traversal permits arbitrary nesting without recursive stack growth.
fn skip(r: &mut BinaryReader<'_>, n: usize) -> Result<()> {
    let mut pending = vec![(n, false)];
    while let Some((left, dict)) = pending.last_mut() {
        if *left == 0 {
            pending.pop();
            continue;
        }
        *left -= 1;
        if *dict {
            string(r)?;
        }
        match r.read_u8()? {
            0 | 1 => {}
            2 => string(r)?,
            3 => {
                let n = count(r)?;
                r.read_bytes(n)?;
            }
            4 | 5 => {
                r.read_bytes(8)?;
            }
            0x81 => {
                let n = count(r)?;
                pending.push((n, false));
            }
            0xc1 => {
                let n = count(r)?;
                pending.push((n, true));
            }
            _ => return Err(corrupt(r.position() as u64, "Unknown Hxv4 object type")),
        }
    }
    Ok(())
}
fn string(r: &mut BinaryReader<'_>) -> Result<()> {
    let n = count(r)?
        .checked_mul(2)
        .ok_or_else(|| corrupt(r.position() as u64, "Hxv4 string size overflow"))?;
    r.read_bytes(n)?;
    Ok(())
}
fn fake_name(mut id: u32) -> String {
    let mut out = String::new();
    loop {
        // Native sub_100179A0 emits 14-bit digits in U+5000..U+8FFF.
        if let Some(c) = char::from_u32(0x5000 + (id & 0x3fff)) {
            out.push(c);
        }
        id >>= 14;
        if id == 0 {
            return out;
        }
    }
}
