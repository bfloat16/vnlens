//! KiriKiri TJS2 bytecode, FE FE text wrappers and PSB/MDF scenario trees.
//! Bytecode uses the common IR; structured scenarios retain their PSB trees.
mod bytecode;
mod names;
mod opcode;
mod text;
use crate::{ScriptContent, ScriptFormat, ScriptRegistration, ir::Script};
pub use names::name_candidates;
use nvlens_core::{Format, ResourceResolver, Result};
#[derive(Debug, Default)]
struct Tjs;
impl Format for Tjs {
    fn tag(&self) -> &'static str {
        "script/krkr"
    }
    fn signatures(&self) -> &'static [u32] {
        &[
            0x32534a54, 0xff00fefe, 0xff01fefe, 0xff02fefe, 0x00425350, 0x0066646d,
        ]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["tjs", "ks", "scn"]
    }
    fn description(&self) -> &'static str {
        "KiriKiri TJS2 bytecode, encoded text and PSB scenarios"
    }
}
impl ScriptFormat for Tjs {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        if !data.starts_with(b"TJS2") {
            return Ok(None);
        }
        bytecode::parse(data).map(Some)
    }
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        self.decode_content(data)?
            .map(|content| match content {
                ScriptContent::Text(text) => Ok(text),
                ScriptContent::Psb(psb) => psb.to_json(),
            })
            .transpose()
    }
    fn decode_content(&self, data: &[u8]) -> Result<Option<ScriptContent>> {
        let decoded = crate::mdf::is_mdf(data)
            .then(|| crate::mdf::decode(data, None))
            .transpose()?;
        let data = decoded.as_deref().unwrap_or(data);
        if data.starts_with(b"PSB\0") {
            return crate::psb::parse_source(&data, None).map(|psb| Some(ScriptContent::Psb(psb)));
        }
        text::decode(data).map(|text| text.map(ScriptContent::Text))
    }
}
nvlens_core::inventory::submit! {ScriptRegistration(||Box::new(Tjs))}

fn bad(offset: usize, reason: &str) -> nvlens_core::Error {
    nvlens_core::Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
