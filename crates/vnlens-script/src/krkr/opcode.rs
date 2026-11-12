//! TJS2100 VM widths and semantic mapping, checked against
//! tTJSByteCodeLoader::TranslateCodeAddress and tTJSInterCodeContext::ExecuteCode.
use super::bad;
use crate::ir::*;
use vnlens_core::Result;
use vnlens_io::BinaryIo;

pub(super) fn width(code: &[i16], pc: usize, base: usize) -> Result<usize> {
    let at = base + pc * 2;
    let word = |index| {
        code.get(pc + index).copied().ok_or_else(|| {
            vnlens_core::Error::Io(BinaryIo::unexpected_eof(format!(
                "Truncated TJS instruction at 0x{at:X}"
            )))
        })
    };
    let width = match word(0)? {
        0 | 14 | 119 | 121 | 126 | 127 => 1,
        3 | 5 | 6 | 11..=13 | 15..=18 | 22 | 82 | 83 | 86 | 87 | 89..=98 | 118 | 122 | 124 => 2,
        1 | 2 | 4 | 7..=10 | 21 | 25 | 88 | 114 | 115 | 120 | 123 | 125 => 3,
        19 | 20 | 23 | 24 | 84 | 85 | 103..=113 | 116 | 117 => 4,
        op @ 26..=81 => match (op - 26) % 4 {
            0 => 3,
            1 | 2 => 5,
            _ => 4,
        },
        op @ 99..=102 => {
            let start = if matches!(op, 99 | 102) { 4 } else { 5 };
            match word(start - 1)? {
                -1 => start,
                -2 => {
                    let count = usize::try_from(word(start)?)
                        .map_err(|_| bad(at, "Negative TJS expanded argument count"))?;
                    count
                        .checked_mul(2)
                        .and_then(|n| n.checked_add(start + 1))
                        .ok_or_else(|| bad(at, "TJS call width overflow"))?
                }
                count if count >= 0 => start + count as usize,
                _ => return Err(bad(at, "Invalid TJS call argument count")),
            }
        }
        op => {
            return Err(bad(
                at,
                &format!("Unknown TJS opcode {op}; instruction width is undefined"),
            ));
        }
    };
    word(width - 1)?;
    Ok(width)
}

pub(super) fn operation(code: i16) -> (Operation, Option<Qualifier>) {
    use BasicOperation as B;
    use ControlFlowOperation as C;
    use Operation::{Basic, ControlFlow, Runtime, Storage};
    use Qualifier as Q;
    use StorageOperation as S;
    if (26..=81).contains(&code) {
        return (
            [
                ControlFlow(C::LogicalOr),
                ControlFlow(C::LogicalAnd),
                Basic(B::BitOr),
                Basic(B::BitXor),
                Basic(B::BitAnd),
                Basic(B::ShiftRight),
                Basic(B::ShiftLeft),
                Basic(B::ShiftRight),
                Basic(B::Add),
                Basic(B::Subtract),
                Basic(B::Remainder),
                Basic(B::Divide),
                Basic(B::Divide),
                Basic(B::Multiply),
            ][((code - 26) / 4) as usize],
            match (code - 26) / 4 {
                5 => Some(Q::Arithmetic),
                7 => Some(Q::Logical),
                12 => Some(Q::Integer),
                _ => None,
            },
        );
    }
    match code {
        0 => (Runtime(RuntimeOperation::NoOp), None),
        1 => (Storage(S::Load), Some(Q::Constant)),
        2 => (Storage(S::Store), Some(Q::Register)),
        3 | 4 => (Storage(S::Store), Some(Q::Clear)),
        5 | 11 => (Storage(S::Store), Some(Q::Flag)),
        6 | 12 | 14 => (ControlFlow(C::LogicalNot), Some(Q::Flag)),
        7 => (ControlFlow(C::Equal), None),
        8 => (ControlFlow(C::Equal), Some(Q::Strict)),
        9 => (ControlFlow(C::Less), None),
        10 => (ControlFlow(C::Greater), None),
        13 => (ControlFlow(C::LogicalNot), None),
        15 => (ControlFlow(C::Branch), Some(Q::Nonzero)),
        16 => (ControlFlow(C::Branch), Some(Q::Zero)),
        17 => (ControlFlow(C::Jump), None),
        18..=21 => (Basic(B::Add), Some(Q::Increment)),
        22..=25 => (Basic(B::Subtract), Some(Q::Decrement)),
        82 => (Basic(B::BitNot), None),
        83..=85 => (Basic(B::TypeOf), None),
        86 | 87 => (Basic(B::Evaluate), Some(Q::Text)),
        88 => (ControlFlow(C::InstanceOf), None),
        89 => (Basic(B::CharacterCode), None),
        90 => (Basic(B::CharacterFromCode), None),
        91 => (Basic(B::Convert), Some(Q::Number)),
        92 => (Basic(B::Negate), None),
        93 => (Storage(S::Invalidate), None),
        94 => (Basic(B::IsValid), None),
        95 => (Basic(B::Convert), Some(Q::Integer)),
        96 => (Basic(B::Convert), Some(Q::Float64)),
        97 => (Basic(B::Convert), Some(Q::Text)),
        98 => (Basic(B::Convert), Some(Q::Bytes)),
        99..=101 => (ControlFlow(C::Call), None),
        102 => (ControlFlow(C::Call), Some(Q::Constructor)),
        103 | 107 | 115 => (Storage(S::Load), Some(Q::Property)),
        110 | 112 => (Storage(S::Load), Some(Q::Reference)),
        104..=106 | 108 | 109 | 114 => (Storage(S::Store), Some(Q::Property)),
        111 | 113 => (Storage(S::Store), Some(Q::Reference)),
        116 | 117 => (Storage(S::Store), Some(Q::Delete)),
        118 => (Storage(S::Store), Some(Q::ReturnValue)),
        119 => (ControlFlow(C::Return), None),
        120 => (ControlFlow(C::RegisterException), None),
        121 => (ControlFlow(C::UnregisterException), None),
        122 => (ControlFlow(C::Halt), Some(Q::Throw)),
        123 => (Storage(S::BindContext), None),
        124 => (Storage(S::Load), Some(Q::Global)),
        125..=127 => (Runtime(RuntimeOperation::EngineCall), None),
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
