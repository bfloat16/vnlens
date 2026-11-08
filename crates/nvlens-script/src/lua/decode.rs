//! Lua bytecode decoder adapted from unluac_rs; no encoding or source lifting.
use super::corrupt;
use super::{
    chunk::{Chunk, Function, Header},
    instruction::{Fields, Instruction, Role},
    opcode::Op,
};
use nvlens_core::Result;

fn standard(version: u8) -> &'static [Op] {
    match version {
        0x50 => &Op::STANDARD50,
        0x52 => &Op::STANDARD52,
        0x53 => &Op::STANDARD53,
        0x54 => &Op::STANDARD54,
        0x55 => &Op::STANDARD55,
        _ => &Op::STANDARD,
    }
}
fn extract(word: u32, h: &Header) -> Fields {
    if h.version >= 0x54 {
        return Fields {
            a: (word >> 7) & 255,
            b: (word >> 16) & 255,
            c: word >> 24,
            bx: word >> 15,
            sbx: (word >> 15) as i32 - 65535,
        };
    }
    let l = layout(h);
    let old = h.lua50_layout.is_some();
    let bxshift = if old { l.opcode } else { l.opcode + l.a };
    let bx = (word >> bxshift) & mask(l.b + l.c);
    Fields {
        a: (word >> if old { l.opcode + l.b + l.c } else { l.opcode }) & mask(l.a),
        b: (word
            >> if old {
                l.opcode + l.c
            } else {
                l.opcode + l.a + l.c
            })
            & mask(l.b),
        c: (word >> if old { l.opcode } else { l.opcode + l.a }) & mask(l.c),
        bx,
        sbx: bx as i32 - (mask(l.b + l.c) / 2) as i32,
    }
}

pub(super) fn layout(header: &Header) -> super::chunk::Layout {
    if header.version >= 0x54 {
        return super::chunk::Layout {
            opcode: 7,
            a: 8,
            b: 8,
            c: 8,
        };
    }
    header.lua50_layout.unwrap_or(super::chunk::Layout {
        opcode: 6,
        a: 8,
        b: 9,
        c: 9,
    })
}
pub(super) fn mask(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX
            .checked_shr(u32::from(32u8.saturating_sub(bits)))
            .unwrap_or(0)
    }
}

pub(super) fn instructions(chunk: &Chunk<'_>, f: &Function<'_>) -> Result<Vec<Instruction>> {
    let header = &chunk.header;
    let mut map = [None; 256];
    for (i, &op) in standard(header.version).iter().enumerate() {
        map[i] = Some(op);
    }
    let mut instructions: Vec<_> = f
        .code
        .iter()
        .enumerate()
        .map(|(pc, code)| {
            let word = *code;
            Instruction {
                pc: pc as u32,
                raw: word,
                opcode: map[(word & mask(layout(header).opcode)) as usize],
                fields: extract(word, header),
                role: Role::Code,
            }
        })
        .collect();
    let mut pc = 0;
    while pc < instructions.len() {
        let count = match instructions[pc].opcode {
            Some(Op::SetList) if instructions[pc].fields.c == 0 => 1,
            Some(Op::SetList52) if instructions[pc].fields.c == 0 => 1,
            Some(Op::LoadKX) => 1,
            Some(Op::Newtable54 | Op::Newtable55) => 1,
            Some(Op::Setlist54 | Op::Setlist55) if instructions[pc].raw & (1 << 15) != 0 => 1,
            Some(Op::Closure) if header.version < 0x52 => {
                let child = *f
                    .children
                    .get(instructions[pc].fields.bx as usize)
                    .ok_or_else(|| {
                        corrupt(
                            f.code_range.start + pc * usize::from(header.instruction_size),
                            "Lua closure child index out of range",
                        )
                    })?;
                usize::from(chunk.functions[child].num_upvalues)
            }
            _ => 0,
        };
        if count > instructions.len() - pc - 1 {
            return Err(corrupt(
                f.code_range.start + pc * usize::from(header.instruction_size),
                "Truncated Lua auxiliary instruction group",
            ));
        }
        let extra = matches!(
            instructions[pc].opcode,
            Some(
                Op::SetList
                    | Op::SetList52
                    | Op::LoadKX
                    | Op::Newtable54
                    | Op::Newtable55
                    | Op::Setlist54
                    | Op::Setlist55
            )
        );
        for index in 1..=count {
            instructions[pc + index].role = if extra {
                Role::ExtraWord
            } else {
                Role::Upvalue
            };
            if extra && header.version < 0x52 {
                instructions[pc + index].opcode = None;
            }
        }
        pc += count + 1;
    }
    Ok(instructions)
}
