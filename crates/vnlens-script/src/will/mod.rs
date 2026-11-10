//! AdvHD WS2: byte opcodes and PE-defined typed args. Strings are CP932 or
//! UTF-16LE; type 8 stores their separate terminator. Type 7 repeats the next
//! type using a byte count. Opcode 15 embeds choice records and a command.
//! The final two u32 values belong to the plaintext footer, not the code.
//! Verified against the WS2 constructor and parameter/choice readers.

mod opcode;
mod text;
mod ws2;
use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use vnlens_core::{ArchiveOptions, Error, Format, ResourceResolver, Result};

#[derive(Debug, Default)]
struct Ws2;
impl Format for Ws2 {
    fn tag(&self) -> &'static str {
        "ws2/will"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ws2"]
    }
    fn description(&self) -> &'static str {
        "AdvHD WS2 bytecode"
    }
}
impl ScriptFormat for Ws2 {
    fn disassemble(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Option<Script>> {
        self.disassemble_with_options(data, resources, &ArchiveOptions::default())
    }
    fn disassemble_with_options(
        &self,
        data: &[u8],
        _: Option<&dyn ResourceResolver>,
        options: &ArchiveOptions,
    ) -> Result<Option<Script>> {
        let bytes = options.keys.get("will_ws2").ok_or_else(|| {
            Error::UnknownScheme(Some("AdvHD WS2 parameter table is unavailable".into()))
        })?;
        let encoding = match options.numbers.get("will_ws2_codepage").copied() {
            Some(932) => ws2::TextEncoding::Cp932,
            None | Some(1200) => ws2::TextEncoding::Utf16,
            Some(codepage) => {
                return Err(Error::Unsupported(format!(
                    "Unsupported AdvHD WS2 code page {codepage}"
                )));
            }
        };
        ws2::parse(data, bytes.bytes(), encoding).map(Some)
    }
}
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Ws2)) }

#[derive(Debug, Default)]
struct Json;
impl Format for Json {
    fn tag(&self) -> &'static str {
        "json/will"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["json"]
    }
    fn description(&self) -> &'static str {
        "AdvHD JSON resource"
    }
}
impl ScriptFormat for Json {
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        text::decode(data)
    }
    fn disassemble(&self, _: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        Ok(None)
    }
}
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Json)) }
