//! Directed Cotopha operand decoding. Storage classes, type IDs and operation
//! subcodes remain numeric; strings can be inline or refer to conststr.
//! Layouts follow classic sub_41B3A0..sub_41DC50 and ECS sub_49B1B0..sub_49ECB0.
use super::*;

struct Reader<'a> {
    bytes: &'a [u8],
    r: BinaryReader<'a>,
    base: u64,
    pool: &'a [Value],
    args: Vec<Arg>,
}
impl Reader<'_> {
    fn value(&mut self, name: &'static str, size: usize, signed: bool) -> Result<u64> {
        let at = self.r.position();
        let bytes = self.r.read_bytes(size)?;
        let value = BinaryReader::compact_u64_le(bytes)?;
        let value_ir = if signed {
            Value::Integer(BinaryReader::compact_i64_le(bytes)?)
        } else {
            Value::Unsigned(value)
        };
        self.args.push(Arg {
            name: ArgName::Native(NativeArg::Named(name)),
            native_name: None,
            span: Span {
                offset: self.base + at as u64,
                size: size as u64,
            },
            value: value_ir,
            attributes: Vec::new(),
        });
        Ok(value)
    }
    fn string(&mut self, name: &'static str) -> Result<()> {
        let start = self.r.position();
        let length = self.r.read_u32_le()?;
        let (value, attributes) = if length == 0x8000_0000 {
            let index = self.r.read_u32_le()?;
            let value = self
                .pool
                .get(index as usize)
                .ok_or_else(|| {
                    bad(
                        self.base + start as u64,
                        "Cotopha string reference exceeds constant pool",
                    )
                })?
                .clone();
            (
                value,
                vec![Attribute {
                    name: "constant_index".into(),
                    value: u64::from(index),
                }],
            )
        } else {
            let size = usize::try_from(u64::from(length) * 2).map_err(std::io::Error::other)?;
            let bytes = self.r.read_bytes(size).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "Cotopha {name} at 0x{:X}, length {length}: {e}",
                        self.base + start as u64
                    ),
                )
            })?;
            (utf16_bytes(bytes)?, Vec::new())
        };
        self.args.push(Arg {
            name: ArgName::Native(NativeArg::Named(name)),
            native_name: None,
            span: Span {
                offset: self.base + start as u64,
                size: (self.r.position() - start) as u64,
            },
            value,
            attributes,
        });
        Ok(())
    }
    fn typed(&mut self, newer: bool) -> Result<u64> {
        let kind = self.value("type", 1, false)?;
        if kind == 0 {
            self.string("class")?;
        }
        if newer && kind == 9 {
            self.value("class_index", 4, false)?;
        }
        self.string("name")?;
        Ok(kind)
    }
    fn literal(&mut self, storage: u64, kind: u64, newer: bool) -> Result<()> {
        match kind {
            0 if storage == 0 => self.string("class"),
            1..=3 | 8 => Ok(()),
            4 | 15 | 16 => {
                self.value("value", 4, kind != 16)?;
                Ok(())
            }
            5 if storage == 0 => {
                let at = self.r.position();
                let bits = self.r.read_u64_le()?;
                self.args.push(Arg {
                    name: ArgName::Native(NativeArg::Named("value")),
                    native_name: None,
                    span: Span {
                        offset: self.base + at as u64,
                        size: 8,
                    },
                    value: Value::Float64Bits(bits),
                    attributes: Vec::new(),
                });
                Ok(())
            }
            6 => self.string("value"),
            7 if newer && storage == 0 => {
                self.value("value", 8, true)?;
                Ok(())
            }
            9 if newer && storage == 0 => {
                self.value("class_index", 4, false)?;
                Ok(())
            }
            10..=12 if newer && storage == 0 => {
                self.value("value", 1, kind != 12)?;
                Ok(())
            }
            13..=14 if newer && storage == 0 => {
                self.value("value", 2, kind == 13)?;
                Ok(())
            }
            _ => Err(Error::Unsupported(format!(
                "Cotopha storage {storage} type {kind}"
            ))),
        }
    }
    fn relative(&mut self) -> Result<()> {
        let at = self.r.position();
        let relative = self.r.read_u32_le()? as i32;
        let target = (self.r.position() as i128)
            .checked_add(i128::from(relative))
            .and_then(|v| usize::try_from(v).ok())
            .filter(|&v| v <= self.bytes.len())
            .ok_or_else(|| bad(self.base + at as u64, "Cotopha branch exceeds code image"))?;
        self.args.push(Arg {
            name: ArgName::Native(NativeArg::Named("target")),
            native_name: None,
            span: Span {
                offset: self.base + at as u64,
                size: 4,
            },
            value: Value::CodeAddress(self.base + target as u64),
            attributes: vec![Attribute {
                name: "relative_bits".into(),
                value: relative as u32 as u64,
            }],
        });
        Ok(())
    }
}

pub(super) fn disassemble(
    bytes: &[u8],
    base: u64,
    pool: &[Value],
    newer: bool,
    seeds: &[usize],
    cancel: &AtomicBool,
) -> Result<Vec<Instruction>> {
    let mut r = Reader {
        bytes,
        r: BinaryReader::new(bytes),
        base,
        pool,
        args: Vec::new(),
    };
    let mut instructions = std::collections::BTreeMap::new();
    let mut pending: Vec<_> = seeds.iter().map(|&s| (s, usize::MAX)).collect();
    pending.push((0, usize::MAX));
    while let Some((start, origin)) = pending.pop() {
        r.r.set_position(start)?;
        while r.r.remaining() != 0 {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let at = r.r.position();
            if instructions.contains_key(&at) {
                break;
            }
            let code = r.r.read_u8()?;
            r.args.clear();
            let parsed = (|| -> Result<()> {
                match code {
                    0 => {
                        r.value("storage", 1, false)?;
                        r.typed(newer)?;
                    }
                    1 | 5 | 11 => {}
                    2 => {
                        let storage = r.value("storage", 1, false)?;
                        let kind = r.value("type", 1, false)?;
                        r.literal(storage, kind, newer)?;
                    }
                    3 | 9 | 12..=14 => {
                        r.value("operation", 1, false)?;
                    }
                    4 => {
                        r.string("function")?;
                        let count = r.value("parameter_count", 4, false)?;
                        if count == u64::from(u32::MAX) {
                            r.value("namespace", 1, false)?;
                            r.relative()?;
                        } else {
                            for _ in 0..count {
                                r.typed(newer)?;
                            }
                        }
                    }
                    6 => r.relative()?,
                    7 => {
                        r.value("condition", 1, false)?;
                        r.relative()?;
                    }
                    8 => {
                        r.value("storage", 1, false)?;
                        r.value("argument_count", 4, false)?;
                        r.string("function")?;
                    }
                    10 => {
                        let kind = r.value("type", 1, false)?;
                        r.literal(1, kind, newer)?;
                    }
                    15 if newer => {
                        let operation = r.value("operation", 1, false)?;
                        if operation == 0 {
                            let count = r.value("dimension_count", 4, false)?;
                            for _ in 0..count {
                                r.value("dimension", 4, false)?;
                            }
                        }
                    }
                    16 if newer => {
                        let operation = r.value("operation", 1, false)?;
                        match operation {
                            4 => {
                                for _ in 0..3 {
                                    r.value("reference_field", 4, false)?;
                                }
                            }
                            5 => r.string("class")?,
                            _ => {}
                        }
                    }
                    17 if newer => {
                        r.value("argument_count", 4, false)?;
                        let storage = r.value("storage", 1, false)?;
                        let kind = r.value("type", 1, false)?;
                        r.literal(storage, kind, newer)?;
                    }
                    18 if newer => {
                        r.value("return_value", 1, false)?;
                    }
                    26 if newer => {
                        r.value("type", 1, false)?;
                    }
                    19 | 20 if newer => {
                        for _ in 0..3 {
                            r.value("call_field", 4, false)?;
                        }
                    }
                    21 if newer => {
                        r.value("flags", 1, false)?;
                        r.value("first", 4, false)?;
                        r.value("second", 4, false)?;
                    }
                    22 | 24 | 28 if newer => {
                        r.value("value", 4, false)?;
                    }
                    23 | 25 | 27 if newer => {}
                    29 if newer => {
                        r.value("argument_count", 4, false)?;
                        r.value("native_index", 4, false)?;
                    }
                    0x80..=0xff if newer => match code {
                        0x80
                        | 0x84
                        | 0x90
                        | 0x92
                        | 0x93
                        | 0xa0..=0xad
                        | 0xb0..=0xb3
                        | 0xb8..=0xbd
                        | 0xc0..=0xcd
                        | 0xde
                        | 0xdf => {
                            r.value("destination", 1, false)?;
                            r.value("source", 1, false)?;
                        }
                        0x81 | 0x85 | 0x88 | 0x8a | 0x98 | 0x99 => {
                            r.value("control", 1, false)?;
                            r.value("register", 1, false)?;
                            r.value("offset", 4, true)?;
                        }
                        0x82 | 0x86 | 0x94..=0x97 | 0xe1 | 0xe2 | 0xe4 => {
                            r.value("control", 1, false)?;
                            r.value("source", 1, false)?;
                            r.value("destination", 1, false)?;
                        }
                        0x83 | 0x87 | 0x89 | 0x8b => {
                            r.value("control", 1, false)?;
                            r.value("index", 1, false)?;
                            r.value("register", 1, false)?;
                            r.value("offset", 4, true)?;
                        }
                        0x9a => {
                            r.value("stack_adjustment", 4, true)?;
                        }
                        0x9b => {
                            r.value("destination", 1, false)?;
                            r.value("bits", 8, false)?;
                        }
                        0x9c..=0x9e | 0xd1 | 0xd5 | 0xd7 | 0xdc | 0xdd => {
                            r.value("register", 1, false)?;
                        }
                        0xd0 => r.relative()?,
                        0xd2 | 0xd3 => {
                            r.value("condition_register", 1, false)?;
                            r.relative()?;
                        }
                        0xd4 => {
                            r.value("function_address", 4, false)?;
                        }
                        0xd6 => {
                            r.value("native_index", 4, false)?;
                        }
                        0xd8 | 0xfd | 0xfe => {}
                        0xe0 => {
                            r.value("control", 1, false)?;
                            r.value("reserved", 1, false)?;
                        }
                        0xe3 | 0xe5 => {
                            for _ in 0..4 {
                                r.value("simd_operand", 1, false)?;
                            }
                        }
                        _ => {
                            return Err(Error::Unsupported(format!("Sakura2 opcode 0x{code:02X}")));
                        }
                    },
                    _ => {
                        return Err(bad(
                            base + at as u64,
                            &format!(
                                "Unknown Cotopha opcode 0x{code:02X} in function at 0x{:X}, referenced from 0x{origin:X}",
                                base + start as u64
                            ),
                        ));
                    }
                }
                Ok(())
            })();
            parsed.map_err(|error| match error {
            Error::Io(cause) => Error::Io(std::io::Error::new(cause.kind(), format!("Cotopha opcode {code} at 0x{:X} from 0x{origin:X}, root 0x{start:X}: {cause}", base + at as u64))),
            cause => cause,
        })?;
            let targets: Vec<_> = r
                .args
                .iter()
                .filter_map(|a| match a.value {
                    Value::CodeAddress(address) => usize::try_from(address - base).ok(),
                    Value::Integer(address)
                        if code == 17 && address >= 0 && address < bytes.len() as i64 =>
                    {
                        Some(address as usize)
                    }
                    _ => None,
                })
                .collect();
            if newer {
                pending.extend(targets.into_iter().map(|s| (s, at)));
            }
            for arg in &r.args {
                if newer
                    && let Value::Integer(address) = arg.value
                    && (address as u64 >> 32) == 0x0100_0000
                {
                    pending.push((address as u32 as usize, at));
                }
            }
            instructions.insert(
                at,
                Instruction {
                    id: 0,
                    span: Span {
                        offset: base + at as u64,
                        size: (r.r.position() - at) as u64,
                    },
                    source_line: None,
                    opcode: Opcode {
                        operation: if code >= 128 {
                            Operation::Native
                        } else {
                            operation(code)
                        },
                        variant: None,
                        namespace: if code >= 128 {
                            "sakura2"
                        } else if newer {
                            "cotopha/ecs"
                        } else {
                            "cotopha/classic"
                        }
                        .into(),
                        code: u32::from(code),
                        native_mnemonic: mnemonic(code).map(str::to_owned),
                    },
                    args: std::mem::take(&mut r.args),
                    attributes: Vec::new(),
                },
            );
            if newer && matches!(code, 6 | 9 | 18 | 0xd0 | 0xd1 | 0xd8 | 0xfd) {
                break;
            }
        }
    }
    let mut instructions: Vec<_> = instructions.into_values().collect();
    for (id, instruction) in instructions.iter_mut().enumerate() {
        instruction.id = id as u64;
    }
    Ok(instructions)
}

fn operation(code: u8) -> Operation {
    use ControlFlowOperation as C;
    use StorageOperation as S;
    match code {
        0 => Operation::Storage(S::Declare),
        1 => Operation::Storage(S::Pop),
        2 => Operation::Storage(S::Load),
        3 => Operation::Storage(S::Store),
        4 => Operation::Storage(S::EnterFrame),
        5 => Operation::Storage(S::LeaveFrame),
        6 => Operation::ControlFlow(C::Jump),
        7 => Operation::ControlFlow(C::Branch),
        8 | 17 | 19 | 20 | 28 | 29 => Operation::ControlFlow(C::Call),
        9 | 18 => Operation::ControlFlow(C::Return),
        10 | 11 => Operation::Storage(S::Reference),
        _ => Operation::Unknown,
    }
}
fn mnemonic(code: u8) -> Option<&'static str> {
    Some(match code {
        0x80..=0x83 | 0x88 | 0x89 => "load",
        0x84..=0x87 | 0x8a | 0x8b => "store",
        0x90 | 0x9b => "move",
        0x92 => "cvt.f2i",
        0x93 => "cvt.i2f",
        0x94 | 0xa8 => "srl",
        0x95 | 0xa9 => "sra",
        0x96 | 0xaa => "sll",
        0x97 => "maskmove",
        0x98 | 0xa0 => "add",
        0x99 | 0xa2 => "mul",
        0x9a => "add.sp",
        0x9c => "neg",
        0x9d => "not",
        0x9e => "fneg",
        0xa1 => "sub",
        0xa3 => "div",
        0xa4 => "mod",
        0xa5 => "and",
        0xa6 => "or",
        0xa7 => "xor",
        0xab => "mov.sx.dq",
        0xac => "mov.sx.wq",
        0xad => "mov.sx.bq",
        0xb0 => "fadd",
        0xb1 => "fsub",
        0xb2 => "fmul",
        0xb3 => "fdiv",
        0xb8 => "mul.dq",
        0xb9 => "imul.dq",
        0xba => "div.qd",
        0xbb => "idiv.qd",
        0xbc => "mod.qd",
        0xbd => "imod.qd",
        0xc0 => "cmp.ne",
        0xc1 => "cmp.eq",
        0xc2 => "cmp.lt",
        0xc3 => "cmp.le",
        0xc4 => "cmp.gt",
        0xc5 => "cmp.ge",
        0xc6 => "cmp.c",
        0xc7 => "cmp.cz",
        0xc8 => "fcmp.ne",
        0xc9 => "fcmp.eq",
        0xca => "fcmp.lt",
        0xcb => "fcmp.le",
        0xcc => "fcmp.gt",
        0xcd => "fcmp.ge",
        0xd0 | 0xd1 => "jump",
        0xd2 => "cnjump",
        0xd3 => "cjump",
        0xd4 | 0xd5 => "call",
        0xd6 | 0xd7 => "syscall",
        0xd8 => "ret",
        0xdc | 0xde => "push",
        0xdd | 0xdf => "pop",
        _ => return None,
    })
}
