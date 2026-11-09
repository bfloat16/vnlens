//! Reads the embedded TJS2100 startup's constant pools and top-level object.
//! This is engine parameter analysis of the _bootStrap call, not a script
//! decoder. Constant propagation merges both sides of unknown branches and
//! reaches a fixed point; loops never execute and conflicting arguments fail.
use super::{missing, wide_string};
use nvlens_core::Result;
use nvlens_io::BinaryReader;
use std::collections::{BTreeMap, VecDeque};

pub(super) struct Startup {
    strings: Vec<String>,
    code: Vec<i16>,
    values: Vec<(i16, i16)>,
}
fn block<'a>(r: &mut BinaryReader<'a>, tag: &[u8]) -> Result<&'a [u8]> {
    if r.read_bytes(4)? != tag {
        return Err(missing("Invalid startup chunk tag"));
    }
    let size = r.read_u32_le()? as usize;
    Ok(r.read_bytes(
        size.checked_sub(8)
            .ok_or_else(|| missing("Invalid startup chunk size"))?,
    )?)
}
fn skip_array(r: &mut BinaryReader<'_>, width: usize) -> Result<()> {
    let n = r.read_u32_le()? as usize;
    r.read_bytes(
        n.checked_mul(width)
            .ok_or_else(|| missing("Startup array overflow"))?,
    )?;
    Ok(())
}
fn align(r: &mut BinaryReader<'_>) -> Result<()> {
    r.read_bytes((4 - r.position() % 4) % 4)?;
    Ok(())
}
impl Startup {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(bytes);
        if r.read_bytes(8)? != b"TJS2100\0" || r.read_u32_le()? as usize != bytes.len() {
            return Err(missing("Invalid startup TJS2100 header"));
        }
        let mut data = BinaryReader::new(block(&mut r, b"DATA")?);
        for width in [1, 2, 4, 8, 8] {
            skip_array(&mut data, width)?;
            align(&mut data)?;
        }
        let count = data.read_u32_le()?;
        let mut strings = Vec::new();
        for _ in 0..count {
            let size = (data.read_u32_le()? as usize)
                .checked_mul(2)
                .ok_or_else(|| missing("Startup string overflow"))?;
            strings.push(wide_string(data.read_bytes(size)?)?);
            align(&mut data)?;
        }
        let octets = data.read_u32_le()?;
        for _ in 0..octets {
            skip_array(&mut data, 1)?;
            align(&mut data)?;
        }
        if data.remaining() != 0 {
            return Err(missing("Trailing startup constants"));
        }
        let mut objects = BinaryReader::new(block(&mut r, b"OBJS")?);
        if r.remaining() != 0 {
            return Err(missing("Trailing startup data"));
        }
        let top = objects.read_u32_le()?;
        let count = objects.read_u32_le()?;
        let mut selected = None;
        for i in 0..count {
            if objects.read_bytes(4)? != b"TJS2" {
                return Err(missing("Invalid startup object"));
            }
            let size = objects.read_u32_le()? as usize;
            let bytes = objects.read_bytes(size)?;
            if i != top {
                continue;
            }
            let mut o = BinaryReader::new(bytes);
            o.read_bytes(48)?;
            skip_array(&mut o, 8)?;
            let n = o.read_u32_le()? as usize;
            let mut words = BinaryReader::new(
                o.read_bytes(
                    n.checked_mul(2)
                        .ok_or_else(|| missing("Startup code overflow"))?,
                )?,
            );
            let mut code = Vec::new();
            while words.remaining() != 0 {
                code.push(words.read_u16_le()? as i16);
            }
            align(&mut o)?;
            let n = o.read_u32_le()?;
            let mut values = Vec::new();
            for _ in 0..n {
                values.push((o.read_u16_le()? as i16, o.read_u16_le()? as i16));
            }
            skip_array(&mut o, 4)?;
            skip_array(&mut o, 8)?;
            if o.remaining() != 0 {
                return Err(missing("Trailing startup object data"));
            }
            selected = Some((code, values));
        }
        if objects.remaining() != 0 {
            return Err(missing("Trailing startup objects"));
        }
        let (code, values) = selected.ok_or_else(|| missing("Startup toplevel is absent"))?;
        Ok(Self {
            strings,
            code,
            values,
        })
    }
    pub(super) fn bootstrap_path(&self) -> Result<&str> {
        let mut paths = self
            .strings
            .iter()
            .filter_map(|s| s.strip_prefix("bres://./")?.strip_suffix("/bootstrap"))
            .collect::<Vec<_>>();
        paths.sort();
        paths.dedup();
        match paths.as_slice() {
            [path] if !path.is_empty() && !path.contains('/') && !path.contains(char::from(92)) => {
                Ok(path)
            }
            _ => Err(missing("Bootstrap filter URI is missing or ambiguous")),
        }
    }
    fn string(&self, index: i16) -> Option<&str> {
        let &(kind, index) = self.values.get(usize::try_from(index).ok()?)?;
        (kind == 3)
            .then(|| self.strings.get(usize::try_from(index).ok()?))
            .flatten()
            .map(String::as_str)
    }
    pub(super) fn bootstrap_argument(&self) -> Result<String> {
        let instructions = decode(&self.code)?;
        let mut iter = instructions.values();
        let first = iter.next().ok_or_else(|| missing("Empty startup code"))?;
        if first[0] != 1
            || !self
                .values
                .get(first[2] as usize)
                .is_some_and(|v| matches!(v.0, 2 | 10))
        {
            return Err(missing("Startup bootstrap registration is absent"));
        }
        let mut store = iter
            .next()
            .ok_or_else(|| missing("Truncated startup registration"))?;
        if store[0] == 123 {
            store = iter
                .next()
                .ok_or_else(|| missing("Truncated startup registration"))?;
        }
        if store[0] != 111
            || store[1] != -1
            || self.string(store[2]) != Some("_bootStrap")
            || store[3] != first[1]
        {
            return Err(missing("Startup bootstrap function is not registered"));
        }
        type Registers = BTreeMap<i16, String>;
        let mut states = BTreeMap::<usize, Registers>::from([(0, Registers::new())]);
        let mut queue = VecDeque::from([0]);
        while let Some(pc) = queue.pop_front() {
            let op = instructions
                .get(&pc)
                .ok_or_else(|| missing("Startup branch is not an instruction boundary"))?;
            let mut regs = states[&pc].clone();
            match op[0] {
                1 => {
                    regs.remove(&op[1]);
                    if let Some(s) = self.string(op[2]) {
                        regs.insert(op[1], s.into());
                    }
                }
                2 => {
                    let v = regs.get(&op[2]).cloned();
                    regs.remove(&op[1]);
                    if let Some(v) = v {
                        regs.insert(op[1], v);
                    }
                }
                58 => {
                    let b = regs.get(&op[2]).cloned();
                    let a = regs.remove(&op[1]);
                    if let (Some(mut a), Some(b)) = (a, b) {
                        a.push_str(&b);
                        regs.insert(op[1], a);
                    }
                }
                4 => {
                    let start = op[1];
                    let end = i32::from(start) + i32::from(op[2]);
                    regs.retain(|r, _| i32::from(*r) < i32::from(start) || i32::from(*r) >= end);
                }
                0
                | 5..=10
                | 14..=17
                | 104..=106
                | 108..=109
                | 111
                | 113
                | 118..=123
                | 125..=127 => {}
                _ => {
                    if let Some(dst) = op.get(1) {
                        regs.remove(dst);
                    }
                }
            }
            let next = pc + op.len();
            let mut successors = Vec::new();
            if matches!(op[0], 15..=17) {
                let target = pc
                    .checked_add_signed(isize::from(op[1]))
                    .ok_or_else(|| missing("Startup branch offset overflow"))?;
                successors.push(target);
            }
            if op[0] != 17 && op[0] != 119 {
                successors.push(next);
            }
            for to in successors {
                if to == self.code.len() {
                    continue;
                }
                if !instructions.contains_key(&to) {
                    return Err(missing("Invalid startup branch target"));
                }
                if let Some(old) = states.get_mut(&to) {
                    let n = old.len();
                    old.retain(|reg, value| regs.get(reg) == Some(value));
                    if n != old.len() {
                        queue.push_back(to);
                    }
                } else {
                    states.insert(to, regs.clone());
                    queue.push_back(to);
                }
            }
        }
        let mut inputs = Vec::new();
        for (&pc, regs) in &states {
            let op = instructions[&pc];
            if op[0] == 100 && op[2] == -2 && self.string(op[3]) == Some("_bootStrap") {
                if op[4] != 2 {
                    return Err(missing("Unsupported bootstrap call arguments"));
                }
                inputs.push(
                    regs.get(&op[5])
                        .ok_or_else(|| missing("Bootstrap argument is not a resolved constant"))?
                        .clone(),
                );
            }
        }
        inputs.sort();
        inputs.dedup();
        match inputs.as_slice() {
            [input] => Ok(input.clone()),
            _ => Err(missing("Bootstrap argument is missing or ambiguous")),
        }
    }
}
fn decode(code: &[i16]) -> Result<BTreeMap<usize, &[i16]>> {
    let mut out = BTreeMap::new();
    let mut pc = 0;
    while pc < code.len() {
        let op = code[pc];
        let n = match op {
            0 | 14 | 119 | 121 | 126 | 127 => 1,
            3 | 5 | 6 | 11..=13 | 15..=18 | 22 | 82 | 83 | 86 | 87 | 89..=98 | 118 | 122 | 124 => 2,
            1 | 2 | 4 | 7..=10 | 21 | 25 | 88 | 114 | 115 | 120 | 123 | 125 => 3,
            19 | 20 | 23 | 24 | 84 | 85 | 103..=113 | 116 | 117 => 4,
            26..=81 => match (op - 26) % 4 {
                0 => 3,
                1 | 2 => 5,
                _ => 4,
            },
            99..=102 => {
                let base = if matches!(op, 99 | 102) { 4 } else { 5 };
                let count = *code
                    .get(pc + base - 1)
                    .ok_or_else(|| missing("Truncated startup call"))?;
                match count {
                    -1 => base,
                    -2 => {
                        let count = *code
                            .get(pc + base)
                            .ok_or_else(|| missing("Truncated startup call"))?;
                        base + 1
                            + usize::try_from(count)
                                .map_err(|_| missing("Invalid startup call count"))?
                                * 2
                    }
                    n if n >= 0 => base + n as usize,
                    _ => return Err(missing("Invalid startup call count")),
                }
            }
            _ => return Err(missing("Unknown startup opcode")),
        };
        let end = pc
            .checked_add(n)
            .ok_or_else(|| missing("Startup instruction overflow"))?;
        let bytes = code
            .get(pc..end)
            .ok_or_else(|| missing("Truncated startup instruction"))?;
        out.insert(pc, bytes);
        pc = end;
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/krkrz_hxv4/startup.rs"]
mod tests;
