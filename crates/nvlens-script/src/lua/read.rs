//! Read-only Lua 5.0-5.5 layouts adapted from unluac_rs's classic/modern
//! codecs. Version-specific ordering is preserved. Function traversal uses
//! an explicit stack; byte ranges and counts are bounded by the input.
mod header;
use super::{
    chunk::{Chunk, Constant, Function, Header},
    corrupt,
};
use nvlens_core::Result;
use nvlens_io::{BinaryIo, BinaryReader};

pub(super) fn read(data: &[u8]) -> Result<Chunk<'_>> {
    let mut r = BinaryReader::new(data);
    let h = header::read(&mut r)?;
    let mut parser = Parser {
        r,
        h,
        strings: Vec::new(),
    };
    let mut functions = Vec::<Function<'_>>::new();
    enum Step {
        Start(Option<(usize, usize)>),
        Children(usize, usize, usize),
        Finish(usize),
    }
    let mut pending = vec![Step::Start(None)];
    while let Some(step) = pending.pop() {
        match step {
            Step::Start(parent) => {
                let index = functions.len();
                let (mut f, count) = parser.start()?;
                f.parent = parent;
                functions.push(f);
                if let Some((parent, _)) = parent {
                    functions[parent].children.push(index);
                }
                pending.push(Step::Finish(index));
                pending.push(Step::Children(index, 0, count));
            }
            Step::Children(parent, ordinal, count) if ordinal < count => {
                pending.push(Step::Children(parent, ordinal + 1, count));
                pending.push(Step::Start(Some((parent, ordinal))));
            }
            Step::Children(..) => {}
            Step::Finish(index) => parser.finish(&mut functions[index])?,
        }
    }
    if parser.r.remaining() != 0 {
        return Err(corrupt(
            parser.r.position(),
            "Trailing bytes after Lua main function",
        ));
    }
    if parser.h.version >= 0x53 && functions[0].num_upvalues != parser.h.main_upvalues {
        return Err(corrupt(0, "Lua main upvalue count mismatch"));
    }
    Ok(Chunk {
        header: parser.h,
        functions,
    })
}

struct Parser<'a> {
    r: BinaryReader<'a>,
    h: Header,
    strings: Vec<&'a [u8]>,
}
impl<'a> Parser<'a> {
    fn integer(&mut self) -> Result<u32> {
        let at = self.r.position();
        let n = if self.h.version >= 0x54 {
            self.r.read_msb_base128_u64(self.h.version == 0x54)?
        } else if self.h.version == 0x53 {
            self.r
                .read_compact_u64(self.h.integer_size, self.h.endian)?
        } else {
            u64::try_from(
                self.r
                    .read_compact_i64(self.h.integer_size, self.h.endian)?,
            )
            .map_err(|_| corrupt(at, "Negative Lua count or location"))?
        };
        u32::try_from(n).map_err(|_| corrupt(at, "Lua integer exceeds u32"))
    }
    fn count(&mut self, minimum: usize) -> Result<usize> {
        let count = usize::try_from(self.integer()?)
            .map_err(|_| corrupt(self.r.position(), "Lua count exceeds address space"))?;
        if count > self.r.remaining() / minimum {
            return Err(BinaryIo::unexpected_eof(format!(
                "Lua list exceeds input at {:#x}",
                self.r.position()
            ))
            .into());
        }
        Ok(count)
    }
    fn align(&mut self, width: u8) -> Result<()> {
        let width = usize::from(width);
        let n = (width - self.r.position() % width) % width;
        if self.r.read_bytes(n)?.iter().any(|&b| b != 0) {
            return Err(corrupt(
                self.r.position() - n,
                "Nonzero Lua alignment bytes",
            ));
        }
        Ok(())
    }
    fn string(&mut self) -> Result<Option<&'a [u8]>> {
        let v = self.h.version;
        let n = if v < 0x53 {
            self.r.read_compact_u64(self.h.size_t_size, self.h.endian)?
        } else if v == 0x53 {
            let n = self.r.read_u8()?;
            if n == 255 {
                self.r.read_compact_u64(self.h.size_t_size, self.h.endian)?
            } else {
                u64::from(n)
            }
        } else {
            self.r.read_msb_base128_u64(v == 0x54)?
        };
        if n == 0 {
            if v != 0x55 {
                return Ok(None);
            }
            let index = self.integer()?;
            if index == 0 {
                return Ok(None);
            }
            return self
                .strings
                .get(index as usize - 1)
                .copied()
                .map(Some)
                .ok_or_else(|| {
                    corrupt(self.r.position(), "Lua saved string index is out of range")
                });
        }
        let n = usize::try_from(n)
            .map_err(|_| corrupt(self.r.position(), "Lua string size exceeds address space"))?;
        let stored = if matches!(v, 0x53 | 0x54) { n - 1 } else { n };
        let bytes = self.r.read_bytes(stored)?;
        let value = &bytes[..n - 1];
        if v == 0x55 {
            self.strings.push(value);
        }
        Ok(Some(value))
    }
    fn constant(&mut self) -> Result<Constant<'a>> {
        let at = self.r.position();
        let tag = self.r.read_u8()?;
        let v = self.h.version;
        match tag {
            0 => Ok(Constant::Nil),
            1 if v < 0x54 => match self.r.read_u8()? {
                0 => Ok(Constant::Boolean(false)),
                1 => Ok(Constant::Boolean(true)),
                _ => Err(corrupt(at, "Invalid Lua boolean")),
            },
            1 => Ok(Constant::Boolean(false)),
            17 if v >= 0x54 => Ok(Constant::Boolean(true)),
            3 if v < 0x53 && self.h.number_integral => Ok(Constant::Integer(
                self.r.read_compact_i64(self.h.number_size, self.h.endian)?,
            )),
            3 if v < 0x54 => self.float(),
            19 if v >= 0x54 => self.float(),
            19 if v == 0x53 => self.number(),
            3 if v >= 0x54 => self.number(),
            4 => self.string().map(Constant::String),
            20 if v >= 0x53 => self.string().map(Constant::String),
            _ => Err(corrupt(at, format!("Unknown Lua constant tag {tag}"))),
        }
    }
    fn float(&mut self) -> Result<Constant<'a>> {
        let bits = self.r.read_compact_u64(self.h.number_size, self.h.endian)?;
        Ok(if self.h.number_size == 4 {
            Constant::Float32(bits as u32)
        } else {
            Constant::Float64(bits)
        })
    }
    fn number(&mut self) -> Result<Constant<'a>> {
        let width = self.h.lua_integer_size;
        let n = if self.h.version == 0x55 {
            let n = self.r.read_msb_base128_u64(false)?;
            ((n >> 1) as i64) ^ -((n & 1) as i64)
        } else {
            self.r.read_compact_i64(width, self.h.endian)?
        };
        if width < 8 && (n < -(1i64 << (width * 8 - 1)) || n >= (1i64 << (width * 8 - 1))) {
            return Err(corrupt(
                self.r.position(),
                "Lua integer exceeds its header width",
            ));
        }
        Ok(Constant::Integer(n))
    }
    fn code(&mut self, f: &mut Function<'a>) -> Result<()> {
        let count = self.count(usize::from(self.h.instruction_size))?;
        if self.h.version == 0x55 {
            self.align(4)?;
        }
        let start = self.r.position();
        for _ in 0..count {
            let word = self
                .r
                .read_compact_u64(self.h.instruction_size, self.h.endian)?;
            f.code.push(u32::try_from(word).map_err(|_| {
                corrupt(
                    self.r.position(),
                    "Nonzero padding above Lua instruction word",
                )
            })?);
        }
        f.code_range = start..self.r.position();
        Ok(())
    }
    fn upvalues(&mut self, f: &mut Function<'a>) -> Result<()> {
        let count = self.count(if self.h.version >= 0x54 { 3 } else { 2 })?;
        for _ in 0..count {
            if self.r.read_u8()? > 1 {
                return Err(corrupt(
                    self.r.position() - 1,
                    "Invalid Lua upvalue stack flag",
                ));
            }
            self.r.read_u8()?;
            if self.h.version >= 0x54 {
                self.r.read_u8()?;
            }
        }
        f.num_upvalues = u8::try_from(count)
            .map_err(|_| corrupt(self.r.position(), "Lua upvalue count exceeds byte field"))?;
        Ok(())
    }
    fn debug(&mut self, f: &mut Function<'a>) -> Result<()> {
        let v = self.h.version;
        let count = self.count(if v >= 0x54 {
            1
        } else {
            usize::from(self.h.integer_size)
        })?;
        for _ in 0..count {
            f.line_info.push(if v >= 0x54 {
                u32::from(self.r.read_u8()?)
            } else {
                self.integer()?
            });
        }
        if v >= 0x54 {
            let count = self.count(2)?;
            if v == 0x55 && count != 0 {
                self.align(self.h.integer_size)?;
            }
            for _ in 0..count {
                let (pc, line) = if v == 0x55 {
                    let pc = self
                        .r
                        .read_compact_u64(self.h.integer_size, self.h.endian)?;
                    let line = self
                        .r
                        .read_compact_u64(self.h.integer_size, self.h.endian)?;
                    (
                        u32::try_from(pc).map_err(|_| {
                            corrupt(self.r.position(), "Lua absolute PC exceeds u32")
                        })?,
                        u32::try_from(line).map_err(|_| {
                            corrupt(self.r.position(), "Lua absolute line exceeds u32")
                        })?,
                    )
                } else {
                    (self.integer()?, self.integer()?)
                };
                f.absolute_lines.push((pc, line));
            }
        }
        let count = self.count(3)?;
        for _ in 0..count {
            self.string()?;
            self.integer()?;
            self.integer()?;
        }
        let count = self.count(1)?;
        if v >= 0x53 && count > usize::from(f.num_upvalues) {
            return Err(corrupt(self.r.position(), "Too many Lua upvalue names"));
        }
        for _ in 0..count {
            self.string()?;
        }
        Ok(())
    }
    fn start(&mut self) -> Result<(Function<'a>, usize)> {
        let mut f = Function::default();
        let v = self.h.version;
        if !matches!(v, 0x52 | 0x55) {
            f.source = self.string()?;
        }
        f.line_defined = self.integer()?;
        if v != 0x50 {
            self.integer()?;
        }
        if v < 0x52 {
            f.num_upvalues = self.r.read_u8()?;
        }
        f.num_params = self.r.read_u8()?;
        f.vararg_flags = self.r.read_u8()?;
        f.max_stack_size = self.r.read_u8()?;
        if v == 0x50 {
            self.debug(&mut f)?;
        } else {
            self.code(&mut f)?;
        }
        let count = self.count(1)?;
        for _ in 0..count {
            f.constants.push(self.constant()?);
        }
        if v >= 0x53 {
            self.upvalues(&mut f)?;
        }
        let children = self.count(1)?;
        Ok((f, children))
    }
    fn finish(&mut self, f: &mut Function<'a>) -> Result<()> {
        let v = self.h.version;
        if v == 0x50 {
            return self.code(f);
        }
        if v == 0x52 {
            self.upvalues(f)?;
        }
        if matches!(v, 0x52 | 0x55) {
            f.source = self.string()?;
        }
        self.debug(f)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::{BinaryWriter, Endian};

    fn word(bytes: &mut Vec<u8>, n: u32, endian: Endian) {
        let mut out = [0; 4];
        match endian {
            Endian::Little => BinaryWriter::u32_le(n, &mut out),
            Endian::Big => BinaryWriter::u32_be(n, &mut out),
        }
        bytes.extend(out);
    }
    fn wide(bytes: &mut Vec<u8>, n: u64, endian: Endian) {
        let mut out = [0; 8];
        match endian {
            Endian::Little => BinaryWriter::u64_le(n, &mut out),
            Endian::Big => BinaryWriter::u64_be(n, &mut out),
        }
        bytes.extend(out);
    }
    fn header(endian: Endian) -> Vec<u8> {
        let mut bytes = b"\x1bLua\x53\0\x19\x93\r\n\x1a\n\x04\x08\x04\x08\x08".to_vec();
        wide(&mut bytes, 0x5678, endian);
        wide(&mut bytes, 370.5f64.to_bits(), endian);
        bytes.push(0);
        bytes
    }
    fn prefix(bytes: &mut Vec<u8>, endian: Endian) {
        bytes.push(0); // Inherited source string.
        word(bytes, 0, endian);
        word(bytes, 0, endian);
        bytes.extend([0, 0, 2]);
    }
    fn debug(bytes: &mut Vec<u8>, endian: Endian) {
        for _ in 0..3 {
            word(bytes, 0, endian);
        }
    }

    #[test]
    fn endian_constants_and_original_instruction_ranges() {
        for endian in [Endian::Little, Endian::Big] {
            let mut bytes = header(endian);
            prefix(&mut bytes, endian);
            word(&mut bytes, 1, endian);
            let at = bytes.len();
            word(&mut bytes, 0x0080_0026, endian); // RETURN A=0 B=1.
            word(&mut bytes, 4, endian);
            bytes.extend([0, 1, 1, 19]);
            wide(&mut bytes, (-123i64) as u64, endian);
            bytes.push(3);
            wide(&mut bytes, 0x7ff8_0000_0000_1234, endian);
            word(&mut bytes, 0, endian); // Upvalues.
            word(&mut bytes, 0, endian); // Children.
            debug(&mut bytes, endian);
            let chunk = read(&bytes).unwrap();
            let f = &chunk.functions[0];
            assert_eq!(f.code_range, at..at + 4);
            assert_eq!(f.code, [0x0080_0026]);
            assert!(matches!(
                f.constants.as_slice(),
                [
                    Constant::Nil,
                    Constant::Boolean(true),
                    Constant::Integer(-123),
                    Constant::Float64(0x7ff8_0000_0000_1234)
                ]
            ));
            let ir = super::super::disasm::parse(&bytes).unwrap();
            assert_eq!(ir.instructions[1].span.offset, at as u64);
            assert_eq!(
                ir.instructions[1].opcode.operation,
                crate::ir::Operation::Native
            );
            assert_eq!(ir.sections[0].raw, bytes);
            assert!(
                matches!(read(&bytes[..bytes.len()-1]), Err(nvlens_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
            );
        }
    }

    #[test]
    fn deeply_nested_functions_parse_and_drop_without_recursion() {
        let endian = Endian::Little;
        let mut bytes = header(endian);
        let depth = 4096;
        for index in 0..depth {
            prefix(&mut bytes, endian);
            for _ in 0..3 {
                word(&mut bytes, 0, endian);
            } // Code, constants, upvalues.
            word(&mut bytes, u32::from(index + 1 < depth), endian);
        }
        for _ in 0..depth {
            debug(&mut bytes, endian);
        }
        let chunk = read(&bytes).unwrap();
        assert_eq!(chunk.functions.len(), depth);
        assert_eq!(chunk.functions[depth - 1].parent, Some((depth - 2, 0)));
        drop(chunk);
        bytes.pop();
        assert!(read(&bytes).is_err());
    }

    fn lua54(code: &[u32]) -> Vec<u8> {
        let mut bytes = b"\x1bLua\x54\0\x19\x93\r\n\x1a\n\x04\x08\x08".to_vec();
        wide(&mut bytes, 0x5678, Endian::Little);
        wide(&mut bytes, 370.5f64.to_bits(), Endian::Little);
        bytes.extend([0, 0x80, 0x80, 0x80, 0, 0, 2, 0x80 | code.len() as u8]);
        for &n in code {
            word(&mut bytes, n, Endian::Little);
        }
        bytes.extend([0x80; 7]);
        bytes
    }

    fn lua55(code: &[u32]) -> Vec<u8> {
        let mut bytes = b"\x1bLua\x55\0\x19\x93\r\n\x1a\n\x04".to_vec();
        word(&mut bytes, (-0x5678i32) as u32, Endian::Little);
        bytes.push(4);
        word(&mut bytes, 0x1234_5678, Endian::Little);
        bytes.push(8);
        wide(&mut bytes, (-0x5678i64) as u64, Endian::Little);
        bytes.push(8);
        wide(&mut bytes, (-370.5f64).to_bits(), Endian::Little);
        bytes.extend([0, 0, 0, 0, 0, 2, code.len() as u8]);
        let pad = (4 - bytes.len() % 4) % 4;
        bytes.resize(bytes.len() + pad, 0);
        for &n in code {
            word(&mut bytes, n, Endian::Little);
        }
        bytes.extend([0; 9]);
        bytes
    }

    #[test]
    fn lua54_and_lua55_forprep_and_variable_width_fields() -> Result<()> {
        use crate::ir::{ArgName, Operation, Value};
        // FORPREP A=0 Bx=1: fetched PC + Bx + 1, hence original PC + 3.
        let forprep = 74 | (1 << 15);
        for bytes in [
            lua54(&[forprep, 0, 0, 71 | (1 << 16)]),
            lua55(&[forprep, 0, 0, 71 | (1 << 16)]),
        ] {
            let parsed = super::super::disasm::parse(&bytes)?;
            let offset = parsed.instructions[1].span.offset;
            assert_eq!(parsed.instructions[1].opcode.operation, Operation::Native);
            assert!(
                parsed.instructions[1]
                    .args
                    .iter()
                    .any(|o| o.name == ArgName::Target
                        && matches!(o.value, Value::CodeAddress(a) if a == offset + 12))
            );
        }
        // NEWTABLE A=0 vB=2 vC=513 k=0, followed by its required EXTRAARG.
        let parsed = super::super::disasm::parse(&lua55(&[
            19 | (2 << 16) | (513 << 22),
            84,
            71 | (1 << 16),
        ]))?;
        let args = &parsed.instructions[1].args;
        assert_eq!(args[1].native_name.as_deref(), Some("vB"));
        assert!(matches!(args[1].value, Value::Integer(2)));
        assert_eq!(args[2].native_name.as_deref(), Some("vC"));
        assert!(matches!(args[2].value, Value::Integer(513)));
        // ERRNNIL Bx=0 is an unavailable diagnostic name, not constant 0.
        let parsed = super::super::disasm::parse(&lua55(&[82, 71 | (1 << 16)]))?;
        assert!(matches!(
            parsed.instructions[1].args[1].value,
            Value::Integer(0)
        ));
        Ok(())
    }
}
