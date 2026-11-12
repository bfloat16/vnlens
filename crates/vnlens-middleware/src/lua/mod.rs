//! Lua middleware, adapted from unluac_rs 0.2.0 for read-only disassembly.
//! Binary parsing and instruction decoding stay private; native disassembly
//! is exposed independently of game routing.

use vnlens_core::Error;
mod chunk;
mod decode;
mod disasm;
mod instruction;
mod opcode;
mod read;

fn corrupt(offset: usize, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}

/// Disassembles a standard Lua chunk with its native opcodes and operands.
/// Returns owned output; malformed or unsupported chunks return an error.
pub use disasm::parse as disassemble;
