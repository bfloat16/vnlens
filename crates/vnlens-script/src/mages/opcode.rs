//! Operand layouts from MAGES_Tools table00/table01/table10/table20 and the
//! corresponding ExecuteScxLoop handlers. Layout letters: b=byte, w=LE u16,
//! e=expression, l=code label, d=data label, r=return-table index,
//! t=embedded-text index, m=message-bank key expression.
//! Unassigned commands retain their numeric identity, even when operandless.
use super::{Layout, arg, expression, op, semantics, span};
use crate::ir::*;
use vnlens_core::{Error, Result};
use vnlens_io::BinaryReader;

struct Operands<'a> {
    data: &'a [u8],
    reader: BinaryReader<'a>,
    args: Vec<Arg>,
    layout: Layout,
}
impl Operands<'_> {
    fn byte(&mut self) -> Result<u8> {
        let start = self.reader.position();
        let value = self.reader.read_u8()?;
        self.args.push(arg(
            ArgName::Mode,
            start,
            self.reader.position(),
            Value::Unsigned(u64::from(value)),
        ));
        Ok(value)
    }
    fn fields(&mut self, layout: &str) -> Result<()> {
        for kind in layout.bytes() {
            let start = self.reader.position();
            let name = match kind {
                b'l' => ArgName::LabelId,
                b'd' => ArgName::LabelBase,
                b'r' => ArgName::ReturnTargets,
                b't' => ArgName::StringIndex,
                b'm' => ArgName::MessageIndex,
                _ => ArgName::Unknown(self.args.len() as u64),
            };
            let value = match kind {
                b'b' => Value::Unsigned(u64::from(self.reader.read_u8()?)),
                b'w' | b'l' | b'd' | b'r' | b't' => {
                    Value::Unsigned(u64::from(self.reader.read_u16_le()?))
                }
                b'e' | b'm' => Value::Expression(expression::read(&mut self.reader, self.data, 0)?),
                _ => return Err(Error::Unsupported("Unknown SCX operand layout".into())),
            };
            self.args
                .push(arg(name, start, self.reader.position(), value));
        }
        Ok(())
    }
    fn string(&mut self) -> Result<()> {
        let start = self.reader.position();
        // ReadString scans from cursor + 1 even when the first byte is zero
        // (sub_14008E380 / sub_1800903B0). Preserve that first byte as well.
        self.reader.read_u8()?;
        while self.reader.read_u8()? != 0 {}
        let end = self.reader.position();
        let (text, _, invalid) = encoding_rs::SHIFT_JIS.decode(&self.data[start..end - 1]);
        let value = if invalid {
            Value::Bytes(self.data[start..end - 1].to_vec())
        } else {
            Value::Text(text.into_owned())
        };
        self.args.push(arg(ArgName::Name, start, end, value));
        Ok(())
    }
}

pub(super) fn read(data: &[u8], start: usize, layout: Layout) -> Result<Instruction> {
    let mut s = Operands {
        data,
        reader: BinaryReader::new_at(data, start)?,
        args: Vec::new(),
        layout,
    };
    let first = s.reader.read_u8()?;
    let code = if first == 0xfe {
        s.fields("e")?;
        0xfe
    } else {
        s.reader.set_position(start)?;
        let code = u32::from(BinaryReader::u16_be(s.reader.read_bytes(2)?) & 0x7fff);
        let second = code as u8;
        let known = match first & 0x7f {
            0 => table00(second, &mut s)?,
            1 => table01(second, &mut s)?,
            0x10 => table10(second, &mut s)?,
            0x20 => table20(second, &mut s)?,
            _ => false,
        };
        if !known {
            return Err(Error::Unsupported(format!(
                "SCX opcode 0x{code:04X} at 0x{start:X}"
            )));
        }
        code
    };
    let end = s.reader.position();
    let mut instruction = Instruction {
        id: start as u64,
        span: span(start, end),
        source_line: None,
        opcode: op("mages/scx", code, Operation::Unknown),
        args: s.args,
        attributes: vec![Attribute {
            name: "opcode_prefix".into(),
            value: u64::from(first),
        }],
    };
    semantics::annotate(&mut instruction, layout)?;
    Ok(instruction)
}

fn table00(code: u8, s: &mut Operands<'_>) -> Result<bool> {
    if s.layout.extended_context {
        match code {
            0x3d => {
                match s.byte()? {
                    0 => s.fields("ee")?,
                    1 => {
                        s.string()?;
                        s.fields("eeee")?;
                    }
                    _ => {}
                }
                return Ok(true);
            }
            0x5b => {
                if s.byte()? == 1 {
                    s.fields("ee")?;
                }
                return Ok(true);
            }
            _ => {}
        }
    }
    if s.layout.glyph_width == 2 {
        match code {
            0x50 => {
                if matches!(s.byte()?, 0 | 3 | 6) {
                    s.fields("l")?;
                }
                return Ok(true);
            }
            0x59 => return Ok(true),
            _ => {}
        }
    }
    let layout = match code {
        0x00
        | 0x03
        | 0x06
        | 0x09
        | 0x0e
        | 0x1a
        | 0x1c
        | 0x27
        | 0x32
        | 0x34
        | 0x3e..=0x40
        | 0x45
        | 0x47
        | 0x48
        | 0x51
        | 0x52
        | 0x58
        | 0x5b
        | 0x60 => "",
        0x02 | 0x05 | 0x1d | 0x1f | 0x26 | 0x2b | 0x2c | 0x42 | 0x46 | 0x4f | 0x5d => "e",
        0x04 | 0x16 | 0x37 | 0x59 => "bee",
        0x07 => "l",
        0x08 => "ed",
        0x0a | 0x10 | 0x53 => "bel",
        0x0b => "lr",
        0x0c => "el",
        0x0d => "elr",
        0x1b => "el",
        0x0f => "le",
        0x11 | 0x2e | 0x31 | 0x38 | 0x4d | 0x50 | 0x57 => "be",
        0x14 | 0x18 | 0x19 | 0x33 | 0x3d => "ee",
        0x17 => "beee",
        0x1e
        | 0x22
        | 0x24
        | 0x29
        | 0x2d
        | 0x30
        | 0x35
        | 0x36
        | 0x39
        | 0x3b
        | 0x3c
        | 0x41
        | 0x44
        | 0x49..=0x4b
        | 0x5e => "b",
        0x20 => "el",
        0x25 => "eee",
        0x28 => "eeee",
        0x54 => "belr",
        0x55 => "beel",
        0x56 => "beelr",
        0x01 => {
            let m = s.byte()?;
            s.fields("eel")?;
            if m >= 0x80 {
                s.string()?;
            }
            return Ok(true);
        }
        0x12 | 0x13 => {
            let m = s.byte()?;
            s.fields(if m == 0 { "e" } else { "ee" })?;
            return Ok(true);
        }
        0x15 => {
            let m = s.byte()?;
            s.fields(if m < 10 { "eel" } else { "el" })?;
            return Ok(true);
        }
        0x21 => {
            let m = s.byte()?;
            s.fields(if m == 2 { "ee" } else { "e" })?;
            return Ok(true);
        }
        0x23 => {
            s.fields("b")?;
            let m = s.byte()?;
            if m != 2 {
                s.fields("ee")?;
            }
            return Ok(true);
        }
        0x2f => {
            let m = s.byte()?;
            if s.layout.glyph_width == 2 || s.layout.extended_context {
                if m == 1 {
                    s.fields("e")?;
                }
                return Ok(true);
            }
            s.fields(match m {
                1 | 2 | 0x10 | 0x11 => "e",
                0x12..=0x14 => "ee",
                0x15 => "eee",
                _ => "",
            })?;
            return Ok(true);
        }
        0x2a => {
            // sub_1400942F0: language setting, shared by the checked VMs.
            let mode = s.byte()?;
            if mode == 0x97 || (mode == 0xb4 && s.layout.extended_context) {
                s.fields("e")?;
            }
            return Ok(true);
        }
        0x3a => {
            let m = s.byte()?;
            s.fields(match m {
                0 => "ee",
                2 | 3 => "e",
                _ => "",
            })?;
            return Ok(true);
        }
        0x43 => {
            let m = s.byte()?;
            if s.layout.glyph_width == 2 {
                let sub = m & 0x7f;
                let sub = if sub >= 10 { sub - 10 } else { sub };
                match sub {
                    2 | 9 => s.fields("e")?,
                    3 | 4 => s.fields(if m & 0x80 != 0 { "m" } else { "t" })?,
                    _ => {}
                }
                return Ok(true);
            }
            match m & 0x0f {
                2 => s.fields("e")?,
                3 | 4 => {
                    if s.byte()? == 1 {
                        s.fields("e")?;
                    }
                    if m & 0x80 != 0 {
                        if m & 0x40 != 0 {
                            s.fields("e")?;
                        }
                        s.fields("m")?;
                    } else {
                        s.fields("t")?;
                    }
                }
                _ => {}
            }
            return Ok(true);
        }
        0x4c => {
            if s.byte()? == 0 {
                s.fields("e")?;
            }
            return Ok(true);
        }
        0x4e => {
            let m = s.byte()?;
            s.fields(match m {
                0 => "eee",
                1 => "eeee",
                _ => "e",
            })?;
            return Ok(true);
        }
        0x5a => {
            let m = s.byte()?;
            s.fields("e")?;
            if m == 0 {
                s.fields("w")?;
            }
            return Ok(true);
        }
        0x5c => {
            if s.byte()? == 1 {
                s.string()?;
            }
            return Ok(true);
        }
        0x5f => {
            if matches!(s.byte()?, 1 | 2) {
                s.fields("e")?;
            }
            return Ok(true);
        }
        _ => return Ok(false),
    };
    s.fields(layout)?;
    Ok(true)
}

fn table01(code: u8, s: &mut Operands<'_>) -> Result<bool> {
    if s.layout.extended_context && code == 0x17 {
        s.fields("b")?;
        return Ok(true);
    }
    if code == 3 {
        s.fields(match s.layout.surface_operands {
            Some(0) => "",
            Some(1) => "e",
            Some(3) => "eee",
            _ => {
                return Err(Error::Unsupported(
                    "Unresolved SCX surface opcode layout".into(),
                ));
            }
        })?;
        return Ok(true);
    }
    if (s.layout.glyph_width == 2 && matches!(code, 0x16 | 0x1e | 0x28 | 0x30 | 0x31))
        || (s.layout.extended_context && code == 0x1e)
    {
        return Ok(true);
    }
    if code == 0x1a && s.layout.glyph_width == 2 {
        s.fields("eee")?;
        return Ok(true);
    }
    let layout = match code {
        0x00 => "beee",
        0x02 | 0x07 => "eee",
        0x04 => "eeeee",
        0x0e | 0x21 => "ed",
        0x0f => "tt",
        0x0b | 0x17..=0x1d | 0x1f | 0x24 | 0x26 | 0x29..=0x2b | 0x2e | 0x2f | 0x32..=0x40 => "",
        0x0d | 0x10 | 0x23 | 0x27 => "b",
        0x20 => "e",
        0x01 => {
            if s.byte()? == 1 {
                s.fields("e")?;
            }
            return Ok(true);
        }
        0x05 => {
            let m = s.byte()?;
            s.fields(match m {
                0 | 1 => "ee",
                2 => "eee",
                3..=6 => "eeee",
                7 => "ee",
                10 => "eeeeee",
                _ => "",
            })?;
            return Ok(true);
        }
        0x06 => {
            let m = s.byte()?;
            s.fields(match m {
                0 => "ee",
                1 => "eee",
                _ => "",
            })?;
            return Ok(true);
        }
        0x08 => {
            if s.byte()? == 10 {
                s.fields("e")?;
            }
            return Ok(true);
        }
        0x09 => {
            let m = s.byte()?;
            match m & 0x7f {
                0 => s.fields("w")?,
                1 => {
                    if m & 0x80 != 0 {
                        s.fields("w")?;
                    }
                    s.fields("e")?;
                }
                2 => s.fields("e")?,
                _ => {}
            }
            return Ok(true);
        }
        0x0a => {
            let m = s.byte()?;
            if m != 4 && m != 5 && m & 1 == 0 {
                s.fields("e")?;
            }
            return Ok(true);
        }
        0x0c => {
            let f = s.byte()?;
            if f & 1 != 0 {
                s.fields("e")?;
            }
            s.fields("e")?;
            if f & 2 != 0 {
                s.fields("e")?;
            }
            s.fields(if f & 0x80 != 0 { "m" } else { "t" })?;
            return Ok(true);
        }
        0x11 => {
            let m = s.byte()?;
            if matches!(m, 5..=7) || (m == 11 && s.layout.glyph_width == 4) {
                s.fields("e")?;
            }
            return Ok(true);
        }
        0x12 => {
            let m = s.byte()?;
            if m == 0 {
                s.fields("we")?;
            } else {
                s.fields(if m & 0x80 != 0 { "m" } else { "t" })?;
                if m & 0x7f == 2 {
                    s.fields("e")?;
                }
            }
            return Ok(true);
        }
        0x13 => {
            // Mode 0 conditionally skips the following 12 bytes of code;
            // they are not an opaque operand (sub_140089D90).
            if s.byte()? == 2 {
                s.fields("e")?;
            }
            return Ok(true);
        }
        0x14 => {
            let m = s.byte()?;
            if m > 1 {
                s.fields(if m & 0x80 != 0 { "m" } else { "t" })?;
            }
            return Ok(true);
        }
        0x15 => {
            let m = s.byte()?;
            s.fields(match m & 0xf {
                0 => "ee",
                2 | 3 => "e",
                _ => "",
            })?;
            return Ok(true);
        }
        0x16 => {
            if s.byte()? != 0 {
                s.fields("e")?;
            }
            return Ok(true);
        }
        0x1e => {
            let m = s.byte()?;
            s.fields(match m {
                0 | 4 | 5 => "e",
                1 | 9 | 0x14 | 0x15 => "eeeeb",
                6 => "eeeee",
                _ => "",
            })?;
            return Ok(true);
        }
        0x22 => {
            let m = s.byte()?;
            s.fields(if m == 0x63 { "eeee" } else { "bee" })?;
            return Ok(true);
        }
        0x25 => {
            let m = s.byte()?;
            if m & 0xf > (if s.layout.extended_context { 5 } else { 3 }) {
                return Ok(true);
            }
            if matches!(m & 0xf, 1 | 5) {
                s.fields("ee")?;
            }
            s.fields(if m & 0x80 != 0 { "m" } else { "t" })?;
            if m & 0xf == 3 {
                s.fields("eee")?;
            }
            return Ok(true);
        }
        0x28 => {
            let m = s.byte()?;
            s.fields(match m {
                2 | 3 => "d",
                4..=6 => "e",
                _ => "",
            })?;
            return Ok(true);
        }
        0x2c => {
            let m = s.byte()?;
            s.fields(match m & 3 {
                0 => "tb",
                2 => "e",
                3 => "ee",
                _ => "",
            })?;
            return Ok(true);
        }
        0x2d => {
            if s.byte()? == 2 {
                s.fields("e")?;
            }
            return Ok(true);
        }
        0x30 => {
            let m = s.byte()?;
            s.fields(if m == 0 { "eee" } else { "eeeeeeeee" })?;
            return Ok(true);
        }
        0x31 => {
            let m = s.byte()?;
            s.fields(match m {
                0 | 2 => "b",
                1 => "beee",
                3 => "bee",
                _ => "",
            })?;
            return Ok(true);
        }
        _ => return Ok(false),
    };
    s.fields(layout)?;
    Ok(true)
}

fn table10(code: u8, s: &mut Operands<'_>) -> Result<bool> {
    if s.layout.extended_context && code == 0x3f {
        s.fields("e")?;
        return Ok(true);
    }
    if s.layout.extended_context && code == 0x3a {
        return Ok(true);
    }
    if s.layout.glyph_width == 2 {
        match code {
            0x0f | 0x2c | 0x3a | 0x41 => return Ok(true),
            0x0d => {
                let mode = s.byte()?;
                s.fields(match mode {
                    1 => "ed",
                    2 => "e",
                    4 => "ee",
                    5 => "eeeeeee",
                    _ => "",
                })?;
                return Ok(true);
            }
            0x36 => {
                let mode = s.byte()?;
                s.fields(match s.layout.layer_operands {
                    Some(1) => "e",
                    Some(6) => match mode {
                        0 | 2 => "ee",
                        1 | 3 => "e",
                        _ => "",
                    },
                    _ => {
                        return Err(Error::Unsupported(
                            "Unresolved SCX layer opcode layout".into(),
                        ));
                    }
                })?;
                return Ok(true);
            }
            1 | 8 => {
                s.fields("ee")?;
                return Ok(true);
            }
            5 => {
                s.fields("bee")?;
                return Ok(true);
            }
            0x11 => {
                s.fields("e")?;
                return Ok(true);
            }
            0x30 => {
                let m = s.byte()?;
                s.fields(match m {
                    1 | 3 | 11 => "eeeee",
                    4 | 5 | 12 => "eeeeee",
                    13 => "eeeeeee",
                    14 | 21 => "eeeeeeee",
                    22 => "ee",
                    23 => "e",
                    _ => "",
                })?;
                return Ok(true);
            }
            _ => {}
        }
    }
    let layout = match code {
        0x00 | 0x05 | 0x10 | 0x17 | 0x28 | 0x2e | 0x3d => "e",
        0x02 | 0x03 | 0x06 | 0x07 | 0x09 | 0x0e | 0x16 => "ee",
        0x08
        | 0x0a
        | 0x0b
        | 0x0d
        | 0x11
        | 0x12
        | 0x18
        | 0x19
        | 0x1e
        | 0x25
        | 0x26
        | 0x2b
        | 0x2d
        | 0x2f
        | 0x31
        | 0x32
        | 0x35
        | 0x38
        | 0x39
        | 0x3b
        | 0x3e..=0x40 => "",
        0x0c | 0x14 | 0x15 | 0x1a..=0x1d | 0x1f..=0x21 | 0x34 | 0x36 | 0x41 => "b",
        0x0f | 0x3c => "bee",
        0x29 => "be",
        0x2a => "beee",
        0x01 => {
            let m = s.byte()?;
            s.fields(if m & 0x7f == 0x10 { "eee" } else { "ee" })?;
            if m & 0x80 != 0 {
                s.string()?;
            }
            return Ok(true);
        }
        0x04 => {
            let m = s.byte()?;
            s.fields(if m >= 4 { "eeee" } else { "eee" })?;
            return Ok(true);
        }
        0x13 => {
            if s.byte()? == 5 {
                s.fields("ee")?;
            }
            return Ok(true);
        }
        0x22 => {
            if s.byte()? == 10 {
                s.fields("w")?;
            }
            return Ok(true);
        }
        0x23 => {
            if s.byte()? == 0 {
                s.fields("b")?;
            }
            return Ok(true);
        }
        0x24 => {
            if s.byte()? == 0 {
                s.fields("ee")?;
            }
            return Ok(true);
        }
        0x27 => {
            let m = s.byte()?;
            s.fields(if m == 1 { "ee" } else { "e" })?;
            return Ok(true);
        }
        0x2c => {
            match s.byte()? {
                0 => s.fields("eee")?,
                1 => s.fields("eeeee")?,
                2 => s.fields("e")?,
                3 => s.fields("eb")?,
                4 => {
                    if s.byte()? == 0 {
                        s.fields("e")?;
                    }
                }
                10 => {}
                _ => return Ok(false),
            }
            return Ok(true);
        }
        0x30 => {
            let m = s.byte()?;
            s.fields(match m {
                1 | 3 | 11 => "eeeee",
                4 | 5 | 12 => "eeeeee",
                _ => "",
            })?;
            return Ok(true);
        }
        0x33 => {
            if s.byte()? == 0 {
                // sub_14009DB50 consumes exactly two data-label indices.
                s.fields("dd")?;
            }
            return Ok(true);
        }
        0x37 => {
            if matches!(s.byte()?, 0 | 2 | 3) {
                s.fields("e")?;
            }
            return Ok(true);
        }
        0x3a => {
            if matches!(s.byte()?, 0 | 2) {
                s.fields("ee")?;
            }
            return Ok(true);
        }
        _ => return Ok(false),
    };
    s.fields(layout)?;
    Ok(true)
}
fn table20(code: u8, s: &mut Operands<'_>) -> Result<bool> {
    if s.layout.glyph_width == 4 && !s.layout.extended_context && code <= 4 {
        return Ok(true);
    }
    if s.layout.dialogue_extension && code == 4 {
        return Ok(true);
    }
    if s.layout.glyph_width == 2 && code != 0 && s.layout.layer_operands == Some(6) {
        // Ever17/Never7 dispatch all remaining slots to the empty handler.
        return Ok(code <= 0x40);
    }
    if s.layout.extended_context && code >= 5 {
        return Ok(code <= 0x40);
    }
    if s.layout.glyph_width == 2 && matches!(code, 3 | 4 | 0x11 | 0x12 | 0x13) {
        return Ok(true);
    }
    if s.layout.surface_operands == Some(0) && code == 0x13 {
        return Ok(true);
    }
    match code {
        0 => {
            let m = s.byte()?;
            if s.layout.dialogue_extension {
                s.fields(match m {
                    0 => "w",
                    1 => "me",
                    2 => "mee",
                    4 => "e",
                    _ => "",
                })?;
            } else if m == 0 && s.layout.glyph_width == 2 {
                s.fields("e")?;
            }
        }
        1 => {
            let m = s.byte()?;
            if s.layout.glyph_width == 2 && matches!(m, 0 | 0x10 | 0x20 | 0x30 | 0x40) {
                s.fields("e")?;
            }
        }
        2 => {
            let m = s.byte()?;
            if s.layout.glyph_width == 2 && matches!(m, 0 | 0x20 | 0x30) {
                s.fields("e")?;
            }
        }
        3 | 4 | 0x13 => s.fields("b")?,
        5..=0x0f | 0x14..=0x40 => {}
        0x10 => {
            if matches!(s.byte()?, 0 | 0x20) {
                s.fields("e")?;
            }
        }
        0x11 | 0x12 => s.fields("b")?,
        _ => return Ok(false),
    }
    Ok(true)
}
