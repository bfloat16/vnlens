//! Escu:de's host scripts are pseudo-C source (CP932 or UTF-8), kept as text.
//! The host's misc/script.c and misc/script.inc additionally define @code:__
//! scenario programs and @mess:__ message tables. MDB/LSF/MOT are structured
//! resources read by misc/game.c and misc/anime.c, not pseudo-C programs.
mod database;
mod graphics;
mod motion;
mod procedure;
mod scenario;
mod sound;
mod source;
use crate::{ScriptFormat, ScriptRegistration, ir::*};
use nvlens_core::{ArchiveOptions, Error, Format, ResourceResolver, Result};
use nvlens_io::BinaryReader;
use std::borrow::Cow;

const SIGNATURES: &[u32] = &[
    0x646f_6340,
    0x7365_6d40,
    0x0062_646d,
    0x0046_534c,
    0x0054_4f4d,
    0x0074_6f6d,
];

#[derive(Debug, Default)]
struct Escude;
impl Format for Escude {
    fn tag(&self) -> &'static str {
        "script/escude"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bin", "001", "lsf", "mot"]
    }
    fn description(&self) -> &'static str {
        "Escu:de scenario and structured resources"
    }
}
impl ScriptFormat for Escude {
    fn decode<'a>(&self, data: &'a [u8], _: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
        envelope(data)
    }
    fn disassemble(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Option<Script>> {
        let data = envelope(data)?;
        let data = data.as_ref();
        if data.starts_with(b"@code:__") {
            let mut script = scenario::code(data)?;
            scenario::resolve(&mut script, resources)?;
            Ok(Some(script))
        } else if data.starts_with(b"@mess:__") {
            scenario::messages(data).map(Some)
        } else if data.starts_with(b"mdb\0") {
            database::parse(data).map(Some)
        } else if data.starts_with(b"LSF\0") {
            graphics::lsf(data).map(Some)
        } else if data.starts_with(b"MOT\0") || data.starts_with(b"mot\0") {
            graphics::mot(data).map(Some)
        } else {
            Ok(None)
        }
    }
}
nvlens_core::inventory::submit! { ScriptRegistration(||Box::new(Escude)) }

#[derive(Debug, Default)]
struct Text;
impl Format for Text {
    fn tag(&self) -> &'static str {
        "text/escude"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["c", "h", "inc", "txt", "cfg", "001"]
    }
    fn description(&self) -> &'static str {
        "Escu:de pseudo-C source and text"
    }
}
impl ScriptFormat for Text {
    fn decode<'a>(&self, data: &'a [u8], _: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
        envelope(data)
    }
    fn disassemble(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Option<Script>> {
        Escude.disassemble(data, resources)
    }
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        let data = envelope(data)?;
        if data.starts_with(b"@mess:__") {
            return Ok(None);
        }
        if let Ok(text) = std::str::from_utf8(&data) {
            return Ok(Some(text.into()));
        }
        let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(&data);
        if errors {
            return Err(bad(0, "Invalid Escu:de CP932 source text"));
        }
        Ok(Some(text.into_owned()))
    }
}
nvlens_core::inventory::submit! { ScriptRegistration(||Box::new(Text)) }

fn envelope(data: &[u8]) -> Result<Cow<'_, [u8]>> {
    if data.starts_with(b"acp\0") {
        let decoded = nvlens_crypto::compress::acp::unpack(data).map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidInput {
                bad(0, &error.to_string())
            } else {
                error.into()
            }
        })?;
        Ok(Cow::Owned(decoded))
    } else {
        Ok(Cow::Borrowed(data))
    }
}
fn bad(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
fn span(offset: usize, size: usize) -> Span {
    Span {
        offset: offset as u64,
        size: size as u64,
    }
}
fn arg(name: ArgName, offset: usize, size: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: span(offset, size),
        value,
        attributes: Vec::new(),
    }
}
fn number(name: ArgName, offset: usize, value: u32) -> Arg {
    arg(name, offset, 4, Value::Unsigned(u64::from(value)))
}
fn text(bytes: &[u8]) -> Value {
    let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
    if errors {
        Value::Bytes(bytes.to_vec())
    } else {
        Value::Text(text.into_owned())
    }
}
fn cstring(data: &[u8], offset: usize) -> Result<&[u8]> {
    let mut r = BinaryReader::new_at(data, offset)?;
    while r.read_u8()? != 0 {}
    Ok(&data[offset..r.position() - 1])
}
fn script(data: &[u8], format: &str, version: u32) -> Script {
    Script {
        ir_version: VERSION,
        format: format.into(),
        format_version: version,
        sections: vec![Section {
            name: "resource".into(),
            span: span(0, data.len()),
            raw: data.to_vec(),
        }],
        instructions: Vec::new(),
    }
}
fn record(script: &mut Script, offset: usize, size: usize, variant: Qualifier, args: Vec<Arg>) {
    script.instructions.push(Instruction {
        id: script.instructions.len() as u64,
        span: span(offset, size),
        source_line: None,
        opcode: Opcode {
            operation: Operation::Data(DataOperation::Record),
            variant: Some(variant),
            namespace: script.format.clone(),
            code: 0,
            native_mnemonic: None,
        },
        args,
        attributes: Vec::new(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

    fn word(out: &mut Vec<u8>, value: u32) {
        let at = out.len();
        out.resize(at + 4, 0);
        BinaryWriter::u32_le(value, &mut out[at..]);
    }
    fn scene(code: &[u8]) -> Vec<u8> {
        let mut b = b"@code:__".to_vec();
        for v in [code.len() as u32, 1, 3, 1] {
            word(&mut b, v);
        }
        b.extend(code);
        word(&mut b, 0);
        b.extend(b"ok\0");
        b
    }

    #[test]
    fn pseudo_c_is_text_and_never_pretends_to_be_bytecode() -> Result<()> {
        crate::init();
        let source = "#include \"acpx.h\"\r\n// 日本語\r\nvoid main(){ exit(); }\r\n";
        let (bytes, _, errors) = encoding_rs::SHIFT_JIS.encode(source);
        assert!(!errors);
        assert!(crate::disassemble_as("text/escude", &bytes, None)?.is_none());
        assert_eq!(
            crate::decode_text_as("text/escude", &bytes)?,
            Some(source.into())
        );
        assert_eq!(
            crate::decode_text_as("text/escude", source.as_bytes())?,
            Some(source.into())
        );
        Ok(())
    }

    #[test]
    fn scenario_keeps_stack_operations_float_bits_and_relative_targets() -> Result<()> {
        let mut code = vec![5];
        word(&mut code, 0x8000_0000);
        code.push(7);
        word(&mut code, 0);
        code.push(15);
        word(&mut code, 15);
        code.push(18);
        let data = scene(&code);
        let parsed = scenario::code(&data)?;
        assert_eq!(parsed.sections[0].raw, data);
        assert!(matches!(
            parsed.instructions[1].args[0].value,
            Value::Float32Bits(0x8000_0000)
        ));
        assert!(
            parsed.instructions[2]
                .args
                .iter()
                .any(|a| matches!(&a.value,Value::Text(s) if s=="ok"))
        );
        let jump = &parsed.instructions[3];
        assert!(matches!(jump.args[0].value, Value::Unsigned(15)));
        assert!(matches!(jump.args[1].value, Value::CodeAddress(39)));
        assert_eq!(jump.args[1].span.size, 0);
        let mut invalid = code.clone();
        BinaryWriter::u32_le(11, &mut invalid[11..]);
        assert!(scenario::code(&scene(&invalid)).is_err());
        for end in 8..data.len() {
            assert!(scenario::code(&data[..end]).is_err());
        }
        assert!(scenario::code(&scene(&[255])).is_err());
        Ok(())
    }

    #[test]
    fn message_pool_keeps_duplicate_offsets_empty_and_multibyte_values() -> Result<()> {
        let mut data = b"@mess:__".to_vec();
        word(&mut data, 3);
        word(&mut data, 4);
        for v in [0, 0, 3] {
            word(&mut data, v);
        }
        data.extend([0x82 ^ 0x55, 0xa0 ^ 0x55, 0x55, 0x55]);
        let out = scenario::messages(&data)?;
        let json = out.instructions[0].to_json()?;
        assert!(json.contains('あ'));
        assert!(json.contains("\"index\": 2"));
        assert_eq!(out.sections[0].raw, data);
        for end in 8..data.len() {
            assert!(scenario::messages(&data[..end]).is_err());
        }
        BinaryWriter::u32_le(4, &mut data[16..]);
        assert!(scenario::messages(&data).is_err());
        Ok(())
    }

    fn db() -> Vec<u8> {
        let mut b = b"mdb\0".to_vec();
        word(&mut b, 16);
        word(&mut b, 4);
        word(&mut b, 1);
        b.extend([4, 0, 4, 0]);
        word(&mut b, 10);
        word(&mut b, 8);
        word(&mut b, 0);
        word(&mut b, 3);
        word(&mut b, 14);
        b.extend(b"ok\0\0sheet\0col\0");
        word(&mut b, 0);
        b
    }
    #[test]
    fn database_rows_names_and_string_references_keep_source_spans() -> Result<()> {
        let b = db();
        let out = database::parse(&b)?;
        assert_eq!(out.sections[0].raw, b);
        let json = out.instructions[1].to_json()?;
        for s in ["sheet", "col", "ok", "rows", "column"] {
            assert!(json.contains(s));
        }
        for end in 4..b.len() {
            assert!(database::parse(&b[..end]).is_err());
        }
        let mut bad = b;
        BinaryWriter::u32_le(1000, &mut bad[28..]);
        assert!(database::parse(&bad).is_err());
        Ok(())
    }

    #[test]
    fn motion_shared_keyframe_suffixes_and_one_byte_terminator() -> Result<()> {
        let mut code = Vec::new();
        for offset in [19, 28] {
            code.push(7);
            word(&mut code, 0x8000_0000);
            word(&mut code, offset);
        }
        code.push(0);
        for t in [0, 100] {
            code.push(1);
            word(&mut code, t);
            word(&mut code, 42);
        }
        code.push(255);
        let mut out = script(&code, "mot/escude", 2);
        motion::parse(&mut out, &code, 100)?;
        let frames: Vec<_> = out
            .instructions
            .iter()
            .filter(|i| i.opcode.variant == Some(Qualifier::Frame))
            .collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[2].span.size, 1);
        assert_eq!(frames[2].span.offset, 137);
        let mut bad = code;
        BinaryWriter::u32_le(20, &mut bad[5..]);
        let mut out = script(&bad, "mot/escude", 2);
        assert!(motion::parse(&mut out, &bad, 0).is_err());
        Ok(())
    }

    #[test]
    fn layer_rows_preserve_coordinates_and_reject_truncation() -> Result<()> {
        let mut b = b"LSF\0".to_vec();
        b.extend([2, 0, 0, 0, 0, 0, 1, 0]);
        for v in [320, 240, 160, 120] {
            word(&mut b, v);
        }
        b.extend([0; 128]);
        for v in [u32::MAX, 2, 319, 242, 160, 120] {
            word(&mut b, v);
        }
        b.extend([0, 0, 3, 255]);
        word(&mut b, 0xff000000);
        word(&mut b, 0);
        let out = graphics::lsf(&b)?;
        assert_eq!(out.sections[0].raw, b);
        assert!(out.instructions[0].to_json()?.contains("rect_left"));
        for end in 4..b.len() {
            assert!(graphics::lsf(&b[..end]).is_err());
        }
        Ok(())
    }
}
