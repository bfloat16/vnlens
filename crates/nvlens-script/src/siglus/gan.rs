//! GAN tagged animation records. sub_6881B0 reads the CP932 image name and
//! groups; sub_688310/sub_6883A0 read counted frame lists terminated by 999999.
//! Values are declarative animation fields, represented as records, not opcodes.
use super::*;
use crate::ir::ArgName;
use crate::ir::DataOperation;
pub(super) fn parse(data: &[u8]) -> Result<Script> {
    let mut r = BinaryReader::new_at(data, 8)?;
    let mut records = Vec::new();
    let mut tag = r.read_u32_le()?;
    while tag == 10100 {
        let start = r.position() - 4;
        let length = r.read_u32_le()? as usize;
        let raw = r.read_bytes(length)?;
        let raw = raw.strip_suffix(&[0]).unwrap_or(raw);
        let (text, _, invalid) = encoding_rs::SHIFT_JIS.decode(raw);
        let value = if invalid {
            Value::Bytes(raw.to_vec())
        } else {
            Value::Text(text.into_owned())
        };
        records.push(record(
            records.len(),
            tag,
            Qualifier::Image,
            start,
            r.position(),
            vec![operand(ArgName::Resource, start + 8, r.position(), value)],
        ));
        tag = r.read_u32_le()?;
    }
    if tag != 20000 {
        return Err(corrupt(r.position() - 4, "Invalid GAN group marker"));
    }
    let groups = r.read_u32_le()?;
    for group in 0..groups {
        let start = r.position();
        if r.read_u32_le()? != 30000 {
            return Err(corrupt(start, "Invalid GAN frame-list marker"));
        }
        let count = r.read_u32_le()?;
        records.push(record(
            records.len(),
            30000,
            Qualifier::Animation,
            start,
            r.position(),
            vec![operand(
                ArgName::FrameCount,
                start + 4,
                start + 8,
                Value::Unsigned(u64::from(count)),
            )],
        ));
        for _ in 0..count {
            let start = r.position();
            let mut fields = Vec::new();
            loop {
                let at = r.position();
                let tag = r.read_u32_le()?;
                if tag == 999999 {
                    break;
                }
                let name = match tag {
                    30100 => ArgName::ImageFrame,
                    30101 => ArgName::OffsetX,
                    30102 => ArgName::OffsetY,
                    30103 => ArgName::Duration,
                    30104 => ArgName::Opacity,
                    30105 => ArgName::Mode,
                    _ => return Err(Error::Unsupported(format!("GAN field {tag} at {at:#x}"))),
                };
                let value = r.read_u32_le()?;
                let mut field = operand(name, at, at + 8, Value::Integer(i64::from(value as i32)));
                field.attributes.push(Attribute {
                    name: "field_id".into(),
                    value: u64::from(tag),
                });
                fields.push(field);
            }
            let mut frame = record(
                records.len(),
                999999,
                Qualifier::Frame,
                start,
                r.position(),
                fields,
            );
            frame.attributes.push(Attribute {
                name: "animation_index".into(),
                value: u64::from(group),
            });
            records.push(frame);
        }
    }
    Ok(Script {
        ir_version: VERSION,
        format: "SiglusEngine GAN".into(),
        format_version: 10000,
        sections: vec![Section {
            name: "animation".into(),
            span: Span {
                offset: 0,
                size: data.len() as u64,
            },
            raw: data.to_vec(),
        }],
        instructions: records,
    })
}
fn record(
    id: usize,
    code: u32,
    variant: Qualifier,
    start: usize,
    end: usize,
    args: Vec<Arg>,
) -> Instruction {
    Instruction {
        id: id as u64,
        span: Span {
            offset: start as u64,
            size: (end - start) as u64,
        },
        source_line: None,
        opcode: Opcode {
            operation: Operation::Data(DataOperation::Record),
            variant: Some(variant),
            namespace: "siglus.gan".into(),
            code,
            native_mnemonic: None,
        },
        args,
        attributes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    #[test]
    fn animation_records_preserve_signed_offsets_and_reject_unknown_layout() -> Result<()> {
        let words = [
            10000,
            10000,
            20000,
            1,
            30000,
            1,
            30100,
            2,
            30101,
            u32::MAX,
            30103,
            60,
            30104,
            128,
            999999,
        ];
        let mut bytes = vec![0; words.len() * 4];
        for (i, word) in words.into_iter().enumerate() {
            BinaryWriter::u32_le(word, &mut bytes[i * 4..]);
        }
        let script = parse(&bytes)?;
        assert_eq!(script.instructions.len(), 2);
        assert!(
            script.instructions[1]
                .args
                .iter()
                .any(|o| o.name == ArgName::OffsetX && matches!(o.value, Value::Integer(-1)))
        );
        assert_eq!(script.sections[0].raw, bytes);
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
        BinaryWriter::u32_le(30199, &mut bytes[24..]);
        assert!(parse(&bytes).is_err());
        Ok(())
    }
}
