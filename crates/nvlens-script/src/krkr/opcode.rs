//! TJS2 instruction widths, shared operation selection and native names.
//! tTJSInterCodeContext uses signed 16-bit VM words and expanded call args.
use super::bad;
use crate::ir::*;
use nvlens_core::Result;

pub(super) fn width(code: &[i16], pc: usize) -> Result<usize> {
    Ok(match code[pc] {
        0 | 14 | 119 | 121 | 126 | 127 => 1,
        3 | 5 | 6 | 11..=13 | 15..=18 | 22 | 82 | 83 | 86 | 87 | 89..=98 | 118 | 122 | 124 => 2,
        1 | 2 | 4 | 7..=10 | 21 | 25 | 88 | 114 | 115 | 120 | 123 | 125 => 3,
        19 | 20 | 23 | 24 | 84 | 85 | 103..=113 | 116 | 117 => 4,
        26..=81 => match (code[pc] - 26) % 4 {
            0 => 3,
            1 | 2 => 5,
            _ => 4,
        },
        99..=102 => {
            let base = if matches!(code[pc], 99 | 102) { 4 } else { 5 };
            let count = *code
                .get(pc + base - 1)
                .ok_or_else(|| bad(pc, "Truncated TJS call"))?;
            match count {
                -1 => base,
                -2 => {
                    let count = *code
                        .get(pc + base)
                        .ok_or_else(|| bad(pc, "Truncated TJS expanded call"))?;
                    base + 1
                        + usize::try_from(count)
                            .map_err(|_| bad(pc, "Negative TJS argument count"))?
                            * 2
                }
                n if n >= 0 => base + n as usize,
                _ => return Err(bad(pc, "Invalid TJS call count")),
            }
        }
        _ => code.len() - pc,
    })
}
pub(super) fn operation(code: i16) -> (Operation, Option<Qualifier>) {
    if (26..=81).contains(&code) {
        return (
            [
                Operation::ControlFlow(ControlFlowOperation::LogicalOr),
                Operation::ControlFlow(ControlFlowOperation::LogicalAnd),
                Operation::Basic(BasicOperation::BitOr),
                Operation::Basic(BasicOperation::BitXor),
                Operation::Basic(BasicOperation::BitAnd),
                Operation::Basic(BasicOperation::ShiftRight),
                Operation::Basic(BasicOperation::ShiftLeft),
                Operation::Basic(BasicOperation::ShiftRight),
                Operation::Basic(BasicOperation::Add),
                Operation::Basic(BasicOperation::Subtract),
                Operation::Basic(BasicOperation::Remainder),
                Operation::Basic(BasicOperation::Divide),
                Operation::Basic(BasicOperation::Divide),
                Operation::Basic(BasicOperation::Multiply),
            ][((code - 26) / 4) as usize],
            match (code - 26) / 4 {
                5 => Some(Qualifier::Arithmetic),
                7 => Some(Qualifier::Logical),
                12 => Some(Qualifier::Integer),
                _ => None,
            },
        );
    }
    match code {
        1 => (
            Operation::Storage(StorageOperation::Load),
            Some(Qualifier::Constant),
        ),
        2 => (
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::Register),
        ),
        3 | 4 => (
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::Clear),
        ),
        7 => (Operation::ControlFlow(ControlFlowOperation::Equal), None),
        8 => (
            Operation::ControlFlow(ControlFlowOperation::Equal),
            Some(Qualifier::Strict),
        ),
        9 => (Operation::ControlFlow(ControlFlowOperation::Less), None),
        10 => (Operation::ControlFlow(ControlFlowOperation::Greater), None),
        13 => (
            Operation::ControlFlow(ControlFlowOperation::LogicalNot),
            None,
        ),
        15 | 16 => (Operation::ControlFlow(ControlFlowOperation::Branch), None),
        17 => (Operation::ControlFlow(ControlFlowOperation::Jump), None),
        18..=21 => (
            Operation::Basic(BasicOperation::Add),
            Some(Qualifier::Increment),
        ),
        22..=25 => (
            Operation::Basic(BasicOperation::Subtract),
            Some(Qualifier::Decrement),
        ),
        82 => (Operation::Basic(BasicOperation::BitNot), None),
        89..=91 | 95..=98 => (Operation::Basic(BasicOperation::Convert), None),
        92 => (Operation::Basic(BasicOperation::Negate), None),
        99..=101 => (Operation::ControlFlow(ControlFlowOperation::Call), None),
        102 => (
            Operation::ControlFlow(ControlFlowOperation::Call),
            Some(Qualifier::Constructor),
        ),
        103 | 107 | 110 | 112 | 115 | 124 => (Operation::Storage(StorageOperation::Load), None),
        104..=106 | 108 | 109 | 111 | 113 | 114 => {
            (Operation::Storage(StorageOperation::Store), None)
        }
        116 | 117 => (
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::Delete),
        ),
        119 => (Operation::ControlFlow(ControlFlowOperation::Return), None),
        120 => (
            Operation::ControlFlow(ControlFlowOperation::RegisterException),
            None,
        ),
        121 => (
            Operation::ControlFlow(ControlFlowOperation::UnregisterException),
            None,
        ),
        122 => (
            Operation::ControlFlow(ControlFlowOperation::Halt),
            Some(Qualifier::Throw),
        ),
        _ => (Operation::Unknown, None),
    }
}

pub(super) fn mnemonic(code: i16) -> Option<String> {
    const NAMES: [&str; 128] = [
        "nop",
        "const",
        "cp",
        "cl",
        "ccl",
        "tt",
        "tf",
        "ceq",
        "cdeq",
        "clt",
        "cgt",
        "setf",
        "setnf",
        "lnot",
        "nf",
        "jf",
        "jnf",
        "jmp",
        "inc",
        "incpd",
        "incpi",
        "incp",
        "dec",
        "decpd",
        "decpi",
        "decp",
        "lor",
        "lorpd",
        "lorpi",
        "lorp",
        "land",
        "landpd",
        "landpi",
        "landp",
        "bor",
        "borpd",
        "borpi",
        "borp",
        "bxor",
        "bxorpd",
        "bxorpi",
        "bxorp",
        "band",
        "bandpd",
        "bandpi",
        "bandp",
        "sar",
        "sarpd",
        "sarpi",
        "sarp",
        "sal",
        "salpd",
        "salpi",
        "salp",
        "sr",
        "srpd",
        "srpi",
        "srp",
        "add",
        "addpd",
        "addpi",
        "addp",
        "sub",
        "subpd",
        "subpi",
        "subp",
        "mod",
        "modpd",
        "modpi",
        "modp",
        "div",
        "divpd",
        "divpi",
        "divp",
        "idiv",
        "idivpd",
        "idivpi",
        "idivp",
        "mul",
        "mulpd",
        "mulpi",
        "mulp",
        "bnot",
        "typeof",
        "typeofd",
        "typeofi",
        "eval",
        "eexp",
        "chkins",
        "asc",
        "chr",
        "num",
        "chs",
        "inv",
        "chkinv",
        "int",
        "real",
        "str",
        "octet",
        "call",
        "calld",
        "calli",
        "new",
        "gpd",
        "spd",
        "spde",
        "spdeh",
        "gpi",
        "spi",
        "spie",
        "gpds",
        "spds",
        "gpis",
        "spis",
        "setp",
        "getp",
        "deld",
        "deli",
        "srv",
        "ret",
        "entry",
        "extry",
        "throw",
        "chgthis",
        "global",
        "addci",
        "regmember",
        "debugger",
    ];
    usize::try_from(code)
        .ok()
        .and_then(|n| NAMES.get(n))
        .map(|s| (*s).into())
}
