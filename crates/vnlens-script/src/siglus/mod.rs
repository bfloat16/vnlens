//! SiglusEngine scene bytecode. sub_6984D0 maps the 0x84-byte LE scene header;
//! sub_674B40 dispatches byte opcodes with unaligned LE args. Strings use
//! UTF-16LE XOR (string_index * 0x7087), verified by sub_699530. No decompilation.
mod bytecode;
mod gan;
mod opcode;
mod scene;
use crate::{ScriptFormat, ScriptRegistration, ir::*};
use vnlens_core::{Error, Format, ResourceResolver, Result};
use vnlens_io::BinaryReader;

#[derive(Debug, Default)]
struct Siglus;
impl Format for Siglus {
    fn tag(&self) -> &'static str {
        "script/siglus"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x84, 0x2710]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ss", "gan"]
    }
    fn description(&self) -> &'static str {
        "SiglusEngine scene bytecode and GAN animation records"
    }
}
impl ScriptFormat for Siglus {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        if data.len() >= 8
            && BinaryReader::u32_le(data) == 10000
            && BinaryReader::u32_le(&data[4..]) == 10000
        {
            return gan::parse(data).map(Some);
        }
        if data.len() < 4 || BinaryReader::u32_le(data) != 0x84 {
            return Ok(None);
        }
        bytecode::parse(data).map(Some)
    }
}
vnlens_core::inventory::submit! {ScriptRegistration(||Box::new(Siglus))}

fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
fn operand(name: ArgName, start: usize, end: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: Span {
            offset: start as u64,
            size: (end - start) as u64,
        },
        value,
        attributes: Vec::new(),
    }
}
