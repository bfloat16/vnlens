//! C,system Arc record tables, all little endian. Native readers: f0 41C900,
//! l0 41D3F0, m0 4974C0, e0 4AEEE0, r0 41C130, s0 41D920, B0 419C30,
//! C0 41FCF0, x0 419370, q0 41E700, t0 41D530, c0 4AE6A0.
//! Counts frame arrays; strings are counted UTF-16 code units. Unknown numeric
//! fields retain their bits and source spans rather than invented VM semantics.
//! v0 is retained as raw integer fields; its nonempty record schema is unknown.
use super::*;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Composition,
    Words,
    Timeline,
    Buttons,
    Curves,
    Source,
    Properties,
    References,
    Gallery,
    Groups,
    Mapping,
    Animation,
    LegacyAnimation,
    MoviePath,
}

#[derive(Debug)]
struct Resource {
    tag: &'static str,
    extensions: &'static [&'static str],
    kind: Kind,
}
impl Format for Resource {
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
        "C,system structured resource"
    }
}
impl ScriptFormat for Resource {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        self.disassemble_with_options(data, None, &nvlens_core::ArchiveOptions::default())
    }
    fn disassemble_with_options(
        &self,
        data: &[u8],
        _: Option<&dyn ResourceResolver>,
        options: &nvlens_core::ArchiveOptions,
    ) -> Result<Option<Script>> {
        let legacy = options.numbers.get("csystem_legacy") == Some(&1);
        let mut d = Decoder {
            r: BinaryReader::new(data),
            instructions: Vec::new(),
            tag: self.tag,
        };
        let mut args = Vec::new();
        match self.kind {
            Kind::Composition => {
                for (name, width) in [
                    (ArgName::Resources, 1),
                    (ArgName::Values, 1),
                    (ArgName::SourceField(0), 2),
                    (ArgName::SourceField(1), 2),
                    (ArgName::Arguments, 4),
                ] {
                    args.push(d.array(name, width, false)?);
                }
                args.push(d.words(ArgName::Metadata, 4)?);
                // sub_41C900 stops after four settings. Preserve the unused
                // trailing fields present in newer records without assigning
                // semantics or requiring a version-specific fixed tail.
                if d.r.remaining() != 0 {
                    let at = d.r.position();
                    let bytes = d.r.read_bytes(d.r.remaining())?;
                    args.push(named(
                        ArgName::Reserved,
                        at,
                        bytes.len(),
                        Value::Bytes(bytes.to_vec()),
                    ));
                }
            }
            Kind::Words => args.push(d.words(ArgName::Values, d.r.remaining() / 4)?),
            Kind::Timeline => {
                args.push(d.word(ArgName::Duration)?);
                let (count, field) = d.count(ArgName::FrameCount, 8)?;
                args.push(field);
                d.emit(0, "timeline", std::mem::take(&mut args));
                for _ in 0..count {
                    let at = d.r.position();
                    let args = vec![
                        d.word(ArgName::StartTime)?,
                        d.array(ArgName::Rows, 8, false)?,
                    ];
                    d.emit(at, "frame", args);
                }
                let at = d.r.position();
                let fields = vec![d.array(ArgName::Arguments, 5, false)?];
                d.emit(at, "parameters", fields);
            }
            Kind::Buttons => {
                args.push(d.word(ArgName::Id)?);
                for name in [
                    ArgName::ValueAt(0),
                    ArgName::ValueAt(1),
                    ArgName::ValueAt(2),
                ] {
                    args.push(d.array(name, 1, false)?);
                }
                let (count, field) = d.count(ArgName::Count, if legacy { 68 } else { 72 })?;
                args.push(field);
                d.emit(0, "button_set", std::mem::take(&mut args));
                for _ in 0..count {
                    let at = d.r.position();
                    let mut fields = vec![d.words(ArgName::SourceField(0), 5)?];
                    for name in [
                        ArgName::SourceField(0),
                        ArgName::SourceField(1),
                        ArgName::SourceField(2),
                        ArgName::SourceField(3),
                    ] {
                        fields.push(d.array(name, 2, false)?);
                    }
                    fields.push(d.words(ArgName::Metadata, 8)?);
                    // CPicture button reader sub_485BA0 predates the optional
                    // extension and the final tenth setting in sub_4AEEE0.
                    if !legacy {
                        let flag = d.r.read_u32_le()?;
                        fields.push(named(
                            ArgName::Flags,
                            d.r.position() - 4,
                            4,
                            Value::Unsigned(flag.into()),
                        ));
                        if flag != u32::MAX {
                            fields.push(d.words(ArgName::Reserved, 3)?);
                        }
                    }
                    d.emit(at, "button", fields);
                }
                let at = d.r.position();
                let fields = vec![
                    d.array(ArgName::ValueAt(3), 1, false)?,
                    d.array(ArgName::ValueAt(4), 1, false)?,
                    d.words(ArgName::Metadata, if legacy { 9 } else { 10 })?,
                ];
                d.emit(at, "button_settings", fields);
            }
            Kind::Curves => {
                args.push(d.word(ArgName::Id)?);
                for name in [
                    ArgName::SourceField(0),
                    ArgName::SourceField(1),
                    ArgName::SourceField(2),
                ] {
                    args.push(d.array(name, 5, true)?);
                }
                args.push(d.floats(ArgName::Arguments, 5)?);
            }
            Kind::Source => {
                args.push(d.word(ArgName::Id)?);
                args.push(d.string(ArgName::Name)?);
                args.push(d.string(ArgName::Source)?);
                args.push(d.array(ArgName::Resources, 1, false)?);
            }
            Kind::Properties => {
                args.push(d.string(ArgName::Name)?);
                let (count, field) = d.count(ArgName::Count, 8)?;
                args.push(field);
                d.emit(0, "properties", std::mem::take(&mut args));
                for _ in 0..count {
                    let at = d.r.position();
                    let mut fields = vec![d.string(ArgName::Name)?];
                    let (values, field) = d.count(ArgName::Count, 4)?;
                    fields.push(field);
                    for _ in 0..values {
                        let at = d.r.position();
                        let ty = d.r.read_u32_le()?;
                        let mut value = match ty {
                            0 => named(ArgName::Value, at, 4, Value::Nil),
                            1 => d.string(ArgName::Value)?,
                            2 => d.floats(ArgName::Value, 1)?,
                            3 => d.word(ArgName::Value)?,
                            _ => return Err(bad(at, "Unknown C,system property value type")),
                        };
                        value.attributes.push(Attribute {
                            name: "type".into(),
                            value: u64::from(ty),
                        });
                        value.span = Span {
                            offset: at as u64,
                            size: (d.r.position() - at) as u64,
                        };
                        fields.push(value);
                    }
                    d.emit(at, "property", fields);
                }
            }
            Kind::References => {
                args.push(d.string(ArgName::Name)?);
                args.push(d.array(ArgName::Resources, 1, false)?);
            }
            Kind::Gallery => {
                for name in [
                    ArgName::Resources,
                    ArgName::Resources,
                    ArgName::ValueAt(0),
                    ArgName::ValueAt(1),
                ] {
                    args.push(d.array(name, 1, false)?);
                }
            }
            Kind::Groups | Kind::Mapping => {
                let (count, field) = d.count(
                    ArgName::Count,
                    if matches!(self.kind, Kind::Mapping) {
                        8
                    } else {
                        4
                    },
                )?;
                args.push(field);
                d.emit(0, "groups", std::mem::take(&mut args));
                for _ in 0..count {
                    let at = d.r.position();
                    let (count, field) = d.count(ArgName::Count, 4)?;
                    let mut fields = vec![field];
                    if matches!(self.kind, Kind::Mapping) {
                        fields.push(d.word(ArgName::Id)?);
                    }
                    fields.push(d.words(ArgName::Values, count as usize)?);
                    d.emit(at, "group", fields);
                }
            }
            Kind::Animation => args.push(d.array(ArgName::Frames, 2, false)?),
            Kind::LegacyAnimation => {
                // sub_4851D0 reads six UTF-16-sized values per frame. Numeric
                // pairs use radix 254 with FF as the zero high digit; separator
                // words and the repeated header count remain visible in the IR.
                let count = d.r.read_u16_le()?;
                args.push(named(ArgName::Count, 0, 2, Value::Unsigned(count.into())));
                args.push(d.units(ArgName::Metadata, 2)?);
                d.emit(0, "animation", std::mem::take(&mut args));
                for _ in 0..count {
                    let at = d.r.position();
                    let mut fields = Vec::new();
                    for name in [ArgName::Id, ArgName::Duration] {
                        fields.push(d.units(ArgName::Reserved, 1)?);
                        let at = d.r.position();
                        let high = d.r.read_u16_le()?;
                        let low = d.r.read_u16_le()?;
                        let value =
                            u64::from(if high == 255 { 0 } else { high }) * 254 + u64::from(low);
                        fields.push(named(name, at, 4, Value::Unsigned(value)));
                    }
                    d.emit(at, "frame", fields);
                }
                if d.r.remaining() != 0 {
                    args.push(d.units(ArgName::Reserved, d.r.remaining() / 2)?);
                }
            }
            Kind::MoviePath => {
                let text = utf16(d.r.read_bytes(d.r.remaining())?, 0)?;
                args.push(named(ArgName::Path, 0, data.len(), Value::Text(text)));
            }
        }
        if d.r.remaining() != 0 {
            return Err(bad(d.r.position(), "Trailing C,system resource fields"));
        }
        if !args.is_empty() {
            d.emit(0, "resource", args);
        }
        Ok(Some(Script {
            ir_version: VERSION,
            format: self.tag.into(),
            format_version: 1,
            sections: vec![Section {
                name: "source".into(),
                span: Span {
                    offset: 0,
                    size: data.len() as u64,
                },
                raw: data.to_vec(),
            }],
            instructions: d.instructions,
        }))
    }
}

struct Decoder<'a> {
    r: BinaryReader<'a>,
    instructions: Vec<Instruction>,
    tag: &'static str,
}
impl Decoder<'_> {
    fn units(&mut self, name: ArgName, count: usize) -> Result<Arg> {
        let at = self.r.position();
        let mut fields = Vec::new();
        for _ in 0..count {
            let at = self.r.position();
            fields.push(named(
                ArgName::Value,
                at,
                2,
                Value::Unsigned(self.r.read_u16_le()?.into()),
            ));
        }
        Ok(named(
            name,
            at,
            self.r.position() - at,
            Value::Group(fields),
        ))
    }
    fn word(&mut self, name: ArgName) -> Result<Arg> {
        let at = self.r.position();
        Ok(named(
            name,
            at,
            4,
            Value::Integer(i64::from(self.r.read_u32_le()? as i32)),
        ))
    }
    fn count(&mut self, name: ArgName, minimum: u64) -> Result<(u32, Arg)> {
        let at = self.r.position();
        let count = self.r.read_u32_le()?;
        if u64::from(count) * minimum > self.r.remaining() as u64 {
            return Err(
                nvlens_io::BinaryIo::unexpected_eof("C,system table exceeds resource").into(),
            );
        }
        Ok((count, named(name, at, 4, Value::Unsigned(count.into()))))
    }
    fn words(&mut self, name: ArgName, count: usize) -> Result<Arg> {
        let at = self.r.position();
        let mut fields = Vec::new();
        for _ in 0..count {
            fields.push(self.word(ArgName::Value)?);
        }
        Ok(named(
            name,
            at,
            self.r.position() - at,
            Value::Group(fields),
        ))
    }
    fn floats(&mut self, name: ArgName, count: usize) -> Result<Arg> {
        let at = self.r.position();
        let mut fields = Vec::new();
        for _ in 0..count {
            let at = self.r.position();
            let bits = self.r.read_u64_le()?;
            fields.push(named(ArgName::Value, at, 8, Value::Float64Bits(bits)));
        }
        Ok(named(
            name,
            at,
            self.r.position() - at,
            Value::Group(fields),
        ))
    }
    fn array(&mut self, name: ArgName, width: usize, floats: bool) -> Result<Arg> {
        let at = self.r.position();
        let (count, field) =
            self.count(ArgName::Count, width as u64 * if floats { 8 } else { 4 })?;
        let mut fields = vec![field];
        for _ in 0..count {
            fields.push(if floats {
                self.floats(ArgName::Rows, width)?
            } else {
                self.words(ArgName::Rows, width)?
            });
        }
        Ok(named(
            name,
            at,
            self.r.position() - at,
            Value::Group(fields),
        ))
    }
    fn string(&mut self, name: ArgName) -> Result<Arg> {
        let at = self.r.position();
        let count = self.r.read_u32_le()?;
        let size = usize::try_from(u64::from(count) * 2)
            .map_err(|_| bad(at, "C,system string exceeds address space"))?;
        let text = utf16(self.r.read_bytes(size)?, at)?;
        Ok(named(name, at, self.r.position() - at, Value::Text(text)))
    }
    fn emit(&mut self, at: usize, name: &str, args: Vec<Arg>) {
        self.instructions.push(Instruction {
            id: self.instructions.len() as u64,
            span: Span {
                offset: at as u64,
                size: (self.r.position() - at) as u64,
            },
            source_line: None,
            opcode: Opcode {
                operation: Operation::Data(DataOperation::Record),
                variant: None,
                namespace: format!("{}.{}", self.tag, name),
                code: 0,
                native_mnemonic: None,
            },
            args,
            attributes: Vec::new(),
        });
    }
}
fn utf16(bytes: &[u8], at: usize) -> Result<String> {
    let mut r = BinaryReader::new(bytes);
    let mut units = Vec::new();
    while r.remaining() != 0 {
        units.push(r.read_u16_le()?);
    }
    String::from_utf16(&units).map_err(|_| bad(at, "Invalid C,system resource UTF-16"))
}
fn named(name: ArgName, at: usize, size: usize, value: Value) -> Arg {
    let mut arg = argument(at, size, value, Vec::new());
    arg.name = name;
    arg
}
macro_rules! register {
    ($tag:literal, $ext:literal, $kind:ident) => {
        nvlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Resource { tag: $tag, extensions: &[$ext], kind: Kind::$kind })) }
    };
}
register!("f0/csystem", "f0", Composition);
register!("l0/csystem", "l0", Words);
register!("m0/csystem", "m0", Timeline);
register!("e0/csystem", "e0", Buttons);
register!("r0/csystem", "r0", Curves);
register!("s0/csystem", "s0", Source);
register!("properties/csystem", "b0", Properties);
register!("references/csystem", "c0", References);
register!("x0/csystem", "x0", Gallery);
register!("q0/csystem", "q0", Groups);
register!("t0/csystem", "t0", Mapping);
register!("v0/csystem", "v0", Words);
register!("animation/csystem", "c0", Animation);
register!("animation-legacy/csystem", "c0", LegacyAnimation);
register!("movie-path/csystem", "i0", MoviePath);

#[cfg(test)]
#[path = "../../tests/csystem/resource.rs"]
mod tests;
