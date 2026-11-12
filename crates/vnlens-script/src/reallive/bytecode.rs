//! Native SEEN stream framing: comma/padding, line and kidoku markers,
//! '$' memory expressions, '#' command tuples, branch addresses and CP932 text.
//! Commands retain type/module/number/argc/overload without guessing semantics.
//! Expression groups are traversed iteratively and retain every original token.
use super::*;
use crate::ir::*;

fn span(start: usize, end: usize) -> Span {
    Span {
        offset: start as u64,
        size: (end - start) as u64,
    }
}
fn arg(name: ArgName, start: usize, end: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: span(start, end),
        value,
        attributes: Vec::new(),
    }
}
fn native(name: &'static str, start: usize, end: usize, value: Value) -> Arg {
    arg(ArgName::Native(NativeArg::Named(name)), start, end, value)
}
fn opcode(code: u32, name: &str) -> Opcode {
    Opcode {
        operation: Operation::Native,
        variant: None,
        namespace: "reallive".into(),
        code,
        native_mnemonic: Some(name.into()),
    }
}
fn peek(r: &BinaryReader<'_>, data: &[u8]) -> Option<u8> {
    data.get(r.position()).copied()
}
fn lead(b: u8) -> bool {
    (0x81..=0x9f).contains(&b) || (0xe0..=0xfc).contains(&b)
}

// TextoutElement::GetText removes compilation quotes and unescapes quoted
// quotation marks. Multibyte trail bytes never act as quote or escape tokens.
fn textout(raw: &[u8]) -> Result<Value> {
    let mut r = BinaryReader::new(raw);
    let mut bytes = Vec::new();
    let mut quoted = false;
    while r.remaining() != 0 {
        let b = r.read_u8()?;
        if lead(b) {
            bytes.extend([b, r.read_u8()?]);
        } else if b == b'"' {
            quoted = !quoted;
        } else if quoted && b == b'\\' && peek(&r, raw) == Some(b'"') {
            bytes.push(r.read_u8()?);
        } else {
            bytes.push(b);
        }
    }
    if quoted {
        return Err(vnlens_io::BinaryIo::unexpected_eof("Unterminated RealLive text quote").into());
    }
    let (text, _, invalid) = encoding_rs::SHIFT_JIS.decode(&bytes);
    Ok(if invalid {
        Value::Bytes(bytes)
    } else {
        Value::Text(text.into_owned())
    })
}

fn atom(r: &mut BinaryReader<'_>, data: &[u8]) -> Result<Token> {
    let start = r.position();
    let first = r.read_u8()?;
    let mut args = Vec::new();
    let name = match first {
        b'$' => {
            let bank = r.read_u8()?;
            args.push(native(
                "bank",
                start + 1,
                start + 2,
                Value::Unsigned(u64::from(bank)),
            ));
            if bank == 0xff {
                let value = r.read_u32_le()? as i32;
                args.push(native(
                    "integer",
                    start + 2,
                    r.position(),
                    Value::Integer(i64::from(value)),
                ));
            } else if peek(r, data) == Some(b'[') {
                let token = group(r, data)?;
                args.push(native(
                    "index",
                    token.span.offset as usize,
                    r.position(),
                    Value::Expression(vec![token]),
                ));
            }
            "memory"
        }
        b'\\' => {
            let operator = r.read_u8()?;
            args.push(native(
                "operator",
                start + 1,
                r.position(),
                Value::Unsigned(u64::from(operator)),
            ));
            "operator"
        }
        b'\n' | b'@' | b'!' => {
            let value = r.read_u16_le()?;
            args.push(native(
                "marker",
                start + 1,
                r.position(),
                Value::Unsigned(u64::from(value)),
            ));
            "metadata"
        }
        b'"' => {
            while r.remaining() != 0 {
                let b = r.read_u8()?;
                if b == b'\\' && matches!(peek(r, data), Some(b'"' | b'\\')) {
                    r.read_u8()?;
                } else if b == b'"' {
                    break;
                } else if lead(b) {
                    r.read_u8()?;
                }
            }
            "string"
        }
        b if lead(b) => {
            r.read_u8()?;
            "text"
        }
        _ => "byte",
    };
    Ok(Token {
        opcode: opcode(u32::from(first), name),
        span: span(start, r.position()),
        args,
        raw: data[start..r.position()].to_vec(),
    })
}

fn group(r: &mut BinaryReader<'_>, data: &[u8]) -> Result<Token> {
    let start = r.position();
    let opening = r.read_u8()?;
    let close = match opening {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        _ => return Err(corrupt(start, "Invalid RealLive group opening")),
    };
    let mut pending = vec![close];
    let mut tokens = Vec::new();
    while let Some(&close) = pending.last() {
        let at = r.position();
        let b = peek(r, data)
            .ok_or_else(|| vnlens_io::BinaryIo::unexpected_eof("Truncated RealLive group"))?;
        if b == close {
            r.read_u8()?;
            pending.pop();
            tokens.push(Token {
                opcode: opcode(u32::from(b), "close"),
                span: span(at, r.position()),
                args: Vec::new(),
                raw: vec![b],
            });
        } else if matches!(b, b'(' | b'[' | b'{') {
            r.read_u8()?;
            pending.push(match b {
                b'(' => b')',
                b'[' => b']',
                _ => b'}',
            });
            tokens.push(Token {
                opcode: opcode(u32::from(b), "open"),
                span: span(at, r.position()),
                args: Vec::new(),
                raw: vec![b],
            });
        } else {
            // Memory indices nested in an outer group are part of the same
            // iterative traversal, rather than a recursive atom call.
            if b == b'a' {
                r.read_u8()?;
                let tag = r.read_u8()?;
                tokens.push(Token {
                    opcode: opcode(u32::from(b), "special_parameter"),
                    span: span(at, r.position()),
                    args: vec![native(
                        "tag",
                        at + 1,
                        r.position(),
                        Value::Unsigned(u64::from(tag)),
                    )],
                    raw: data[at..r.position()].to_vec(),
                });
            } else if b == b'$' && data.get(at + 1) != Some(&0xff) {
                r.read_u8()?;
                let bank = r.read_u8()?;
                tokens.push(Token {
                    opcode: opcode(u32::from(b), "memory"),
                    span: span(at, r.position()),
                    args: vec![native(
                        "bank",
                        at + 1,
                        r.position(),
                        Value::Unsigned(u64::from(bank)),
                    )],
                    raw: data[at..r.position()].to_vec(),
                });
            } else {
                tokens.push(atom(r, data)?);
            }
        }
    }
    Ok(Token {
        opcode: opcode(u32::from(opening), "group"),
        span: span(start, r.position()),
        args: vec![native(
            "tokens",
            start,
            r.position(),
            Value::Expression(tokens),
        )],
        raw: data[start..r.position()].to_vec(),
    })
}

fn expression(r: &mut BinaryReader<'_>, data: &[u8]) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    loop {
        while peek(r, data) == Some(b'\\') {
            tokens.push(atom(r, data)?);
        }
        tokens.push(if peek(r, data) == Some(b'(') {
            group(r, data)?
        } else {
            atom(r, data)?
        });
        if peek(r, data) != Some(b'\\') {
            break;
        }
        tokens.push(atom(r, data)?);
    }
    Ok(tokens)
}

fn address(r: &mut BinaryReader<'_>, base: usize, args: &mut Vec<Arg>) -> Result<()> {
    let at = r.position();
    let target = r.read_u32_le()?;
    args.push(arg(
        ArgName::Target,
        at,
        r.position(),
        Value::CodeAddress(base as u64 + u64::from(target)),
    ));
    Ok(())
}

pub(super) fn parse(data: &[u8], h: &Header) -> Result<Script> {
    let base = h.code as usize;
    let end = base
        .checked_add(h.size as usize)
        .ok_or_else(|| corrupt(base, "RealLive code extent overflow"))?;
    let mut r = BinaryReader::new_at(&data[..end], base)?;
    let mut instructions = Vec::new();
    let mut line = None;
    while r.remaining() != 0 {
        let start = r.position();
        let b = r.read_u8()?;
        let mut args = Vec::new();
        let mut attributes = Vec::new();
        let op;
        match b {
            0 | b',' => op = opcode(u32::from(b), "separator"),
            b'\n' => {
                let value = r.read_u16_le()?;
                line = Some(u32::from(value));
                op = opcode(u32::from(b), "line");
                args.push(native(
                    "line",
                    start + 1,
                    r.position(),
                    Value::Unsigned(u64::from(value)),
                ));
            }
            b'@' | b'!' => {
                let index = r.read_u16_le()?;
                if u32::from(index) >= h.kidoku_count {
                    return Err(corrupt(start, "RealLive kidoku index is out of range"));
                }
                let mut table =
                    BinaryReader::new_at(data, h.kidoku as usize + usize::from(index) * 4)?;
                let value = table.read_u32_le()?;
                op = opcode(
                    u32::from(b),
                    if value >= 1000000 {
                        "entrypoint"
                    } else {
                        "kidoku"
                    },
                );
                args.push(native(
                    "table_index",
                    start + 1,
                    r.position(),
                    Value::Unsigned(u64::from(index)),
                ));
                attributes.push(Attribute {
                    name: "kidoku_value".into(),
                    value: u64::from(value),
                });
            }
            b'$' => {
                r.set_position(start)?;
                let tokens = expression(&mut r, &data[..end])?;
                op = opcode(u32::from(b), "expression");
                args.push(arg(
                    ArgName::Value,
                    start,
                    r.position(),
                    Value::Expression(tokens),
                ));
            }
            b'#' => {
                let kind = r.read_u8()?;
                let (module, number, argc, overload) = if h.version / 10000 % 10 == 2 {
                    let unknown = r.read_u8()?;
                    args.push(native(
                        "command_variant",
                        start + 2,
                        start + 3,
                        Value::Unsigned(u64::from(unknown)),
                    ));
                    let module = r.read_u8()?;
                    let dispatch = r.read_u8()?;
                    args.push(native(
                        "dispatch",
                        start + 4,
                        start + 5,
                        Value::Unsigned(u64::from(dispatch)),
                    ));
                    (module, r.read_u16_le()?, r.read_u16_le()?, r.read_u8()?)
                } else {
                    (
                        r.read_u8()?,
                        r.read_u16_le()?,
                        r.read_u16_le()?,
                        r.read_u8()?,
                    )
                };
                let code = (u32::from(kind) << 24) | (u32::from(module) << 16) | u32::from(number);
                op = opcode(code, "command");
                for (name, value) in [
                    ("type", u64::from(kind)),
                    ("module", u64::from(module)),
                    ("number", u64::from(number)),
                    ("argc", u64::from(argc)),
                    ("overload", u64::from(overload)),
                ] {
                    args.push(native(
                        name,
                        start + 1,
                        r.position(),
                        Value::Unsigned(value),
                    ));
                }
                let branch = if kind == 0 {
                    match (module, number) {
                        (1, 0 | 5) | (5, 1 | 5) | (6, 1 | 5) => 1,
                        (1, 1 | 2 | 6 | 7) | (5, 2 | 6 | 7) | (6, 0 | 2 | 6 | 7) => 2,
                        (1 | 5 | 6, 3 | 8) => 3,
                        (1 | 5 | 6, 4 | 9) => 4,
                        (1 | 6, 16) => 5,
                        _ => 0,
                    }
                } else {
                    0
                };
                if matches!(branch, 2..=4)
                    || (matches!(branch, 0 | 5) && peek(&r, data) == Some(b'('))
                {
                    let at = r.position();
                    let tokens = if peek(&r, data) == Some(b'(') {
                        vec![group(&mut r, &data[..end])?]
                    } else {
                        expression(&mut r, &data[..end])?
                    };
                    args.push(arg(
                        ArgName::Value,
                        at,
                        r.position(),
                        Value::Expression(tokens),
                    ));
                }
                if matches!(branch, 1 | 2 | 5) {
                    address(&mut r, base, &mut args)?;
                } else if matches!(branch, 3 | 4) {
                    if r.read_u8()? != b'{' {
                        return Err(corrupt(
                            r.position() - 1,
                            "RealLive branch table lacks opening brace",
                        ));
                    }
                    for _ in 0..argc {
                        if branch == 4 {
                            let token = group(&mut r, &data[..end])?;
                            args.push(native(
                                "case",
                                token.span.offset as usize,
                                r.position(),
                                Value::Expression(vec![token]),
                            ));
                        }
                        address(&mut r, base, &mut args)?;
                    }
                    if r.read_u8()? != b'}' {
                        return Err(corrupt(
                            r.position() - 1,
                            "RealLive branch table lacks closing brace",
                        ));
                    }
                } else if peek(&r, data) == Some(b'{') {
                    let token = group(&mut r, &data[..end])?;
                    args.push(native(
                        "choices",
                        token.span.offset as usize,
                        r.position(),
                        Value::Expression(vec![token]),
                    ));
                }
            }
            _ => {
                let mut quoted = b == b'"';
                if lead(b) {
                    r.read_u8()?;
                }
                while let Some(next) = peek(&r, &data[..end]) {
                    if !quoted && matches!(next, 0 | b',' | b'\n' | b'@' | b'!' | b'#' | b'$') {
                        break;
                    }
                    r.read_u8()?;
                    if next == b'\\' && quoted && peek(&r, data) == Some(b'"') {
                        r.read_u8()?;
                    } else if next == b'"' {
                        quoted = !quoted;
                    } else if lead(next) {
                        r.read_u8()?;
                    }
                }
                let raw = &data[start..r.position()];
                op = Opcode {
                    operation: Operation::Text(TextOperation::Show),
                    variant: None,
                    namespace: "reallive".into(),
                    code: 0,
                    native_mnemonic: Some("textout".into()),
                };
                args.push(arg(ArgName::Text, start, r.position(), textout(raw)?));
            }
        }
        instructions.push(Instruction {
            id: instructions.len() as u64,
            span: span(start, r.position()),
            source_line: line,
            opcode: op,
            args,
            attributes,
        });
    }
    for instruction in &instructions {
        for arg in &instruction.args {
            if let Value::CodeAddress(target) = arg.value
                && !(base as u64..=end as u64).contains(&target)
            {
                return Err(corrupt(
                    instruction.span.offset as usize,
                    "RealLive branch target is outside the bytecode",
                ));
            }
        }
    }
    Ok(Script {
        ir_version: VERSION,
        format: "RealLive SEEN".into(),
        format_version: h.version,
        sections: vec![
            Section {
                name: "compiler_tables".into(),
                span: span(0, base),
                raw: data[..base].to_vec(),
            },
            Section {
                name: "bytecode".into(),
                span: span(base, end),
                raw: data[base..end].to_vec(),
            },
            Section {
                name: "trailing_data".into(),
                span: span(end, data.len()),
                raw: data[end..].to_vec(),
            },
        ],
        instructions,
    })
}
