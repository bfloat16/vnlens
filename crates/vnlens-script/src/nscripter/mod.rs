//! NScripter 2.82 sub_40D780 loads CP932 source: nscript.dat XOR 0x84,
//! nscript.zat XOR 0x6f, or unencrypted numbered .txt files. These are source
//! text, not bytecode; retain the complete source without synthesizing IR.
use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use std::borrow::Cow;
use vnlens_core::{ArchiveOptions, Error, Format, ResourceResolver, Result};

#[derive(Debug)]
struct Text {
    tag: &'static str,
    extensions: &'static [&'static str],
    xor: Option<u8>,
}
impl Format for Text {
    fn tag(&self) -> &'static str {
        self.tag
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        self.extensions
    }
    fn description(&self) -> &'static str {
        "NScripter CP932 source text"
    }
}
impl ScriptFormat for Text {
    fn decode<'a>(&self, data: &'a [u8], _: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
        if let Some(xor) = self.xor {
            let mut out = data.to_vec();
            vnlens_crypto::cipher::xor::apply(&mut out, &[xor])
                .map_err(|e| Error::Unsupported(e.to_string()))?;
            Ok(Cow::Owned(out))
        } else {
            Ok(Cow::Borrowed(data))
        }
    }
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        let (text, _, invalid) = encoding_rs::SHIFT_JIS.decode(data);
        if invalid {
            return Err(Error::Corrupt {
                offset: 0,
                reason: "Invalid NScripter CP932 source text".into(),
            });
        }
        Ok(Some(text.into_owned()))
    }
    fn disassemble(&self, _: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        Ok(None)
    }
}
vnlens_core::inventory::submit! {ScriptRegistration(|| Box::new(Text { tag: "nscript/nscripter", extensions: &["dat"], xor: Some(0x84) }))}
vnlens_core::inventory::submit! {ScriptRegistration(|| Box::new(Text { tag: "zat/nscripter", extensions: &["zat"], xor: Some(0x6f) }))}
vnlens_core::inventory::submit! {ScriptRegistration(|| Box::new(Text { tag: "text/nscripter", extensions: &["txt"], xor: None }))}

#[cfg(test)]
#[path = "../../tests/nscripter/mod.rs"]
mod tests;
