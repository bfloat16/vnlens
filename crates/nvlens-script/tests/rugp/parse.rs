use super::*;
use nvlens_io::BinaryWriter;
#[test]
fn image_extensions_keep_names_values_without_creating_a_child_copy() -> Result<()> {
    let mut body = vec![
        1, 2, 0, 1, b'A', 0x34, 0x12, 0, 0, 1, b'B', 0x78, 0x56, 0, 0,
    ];
    let start = body.len();
    body.resize(start + 46, 0);
    BinaryWriter::u32_le(1, &mut body[start + 30..]);
    let data = wire::envelope(
        &body,
        &Class {
            name: "Cr6Tix".into(),
            schema: 3,
            encoded: None,
        },
        3,
        20,
        1,
    )?;
    let parsed = parse(&data, &ArchiveOptions::default())?;
    assert!(parsed.objects.is_empty() && parsed.embedded.is_empty());
    let fields = &parsed
        .script
        .instructions
        .last()
        .ok_or(Error::InvalidFormat)?
        .args;
    assert!(
        fields
            .iter()
            .any(|a| a.name == A::StringAt(1) && matches!(&a.value,Value::Text(s) if s=="B"))
    );
    assert!(
        fields
            .iter()
            .any(|a| a.name == A::ValueAt(1) && matches!(a.value, Value::Unsigned(0x5678)))
    );
    assert!(parse(&data[..data.len() - 2], &ArchiveOptions::default()).is_err());
    Ok(())
}
#[test]
fn object_records_decode_fields_and_reject_truncated_values() -> Result<()> {
    let mut body = vec![4, b'v', b'o', b'i', b'c'];
    dword(&mut body, 7);
    let class = Class {
        name: "CCharVoiceRegistOb".into(),
        schema: 1,
        encoded: None,
    };
    let data = wire::envelope(&body, &class, 1, 20, 1)?;
    let parsed = parse(&data, &ArchiveOptions::default())?;
    let record = parsed
        .script
        .instructions
        .last()
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(record.opcode.operation, O::Data(DataOperation::Record));
    assert!(matches!(&record.args[0].value, Value::Text(value) if value == "voic"));
    assert!(matches!(record.args[1].value, Value::Unsigned(7)));
    assert_eq!(record.span.size, 9);
    assert!(parse(&data[..data.len() - 1], &ArchiveOptions::default()).is_err());
    Ok(())
}
fn word(out: &mut Vec<u8>, value: u16) {
    let at = out.len();
    out.resize(at + 2, 0);
    BinaryWriter::u16_le(value, &mut out[at..]);
}
fn dword(out: &mut Vec<u8>, value: u32) {
    let at = out.len();
    out.resize(at + 4, 0);
    BinaryWriter::u32_le(value, &mut out[at..]);
}
fn class(out: &mut Vec<u8>, name: &str) -> Result<()> {
    word(out, 0xffff);
    word(out, 17);
    let name = nvlens_crypto::compress::rugp::encode_class_name(name.as_bytes())?;
    out.push(name.len() as u8);
    out.extend(name);
    Ok(())
}
fn rsa(code: &[u8], count: u32) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    word(&mut body, 0);
    word(&mut body, 1);
    body.push(0);
    dword(&mut body, 0);
    let mut stream = Vec::new();
    word(&mut stream, 20);
    word(&mut stream, 1);
    for value in [0xffff0000, 17, 0, count, 0] {
        dword(&mut stream, value);
    }
    stream.extend(code);
    dword(&mut body, stream.len() as u32);
    body.extend(stream);
    wire::envelope(
        &body,
        &Class {
            name: "CRsa".into(),
            schema: 5,
            encoded: None,
        },
        5,
        20,
        1,
    )
}
#[test]
fn messages_preserve_text_native_tags_and_truncation_errors() -> Result<()> {
    let mut code = Vec::new();
    class(&mut code, "CVmMsg")?;
    dword(&mut code, u32::MAX);
    dword(&mut code, 0);
    code.push(0);
    word(&mut code, 0);
    code.extend([2, 0x82, 0xa0]);
    word(&mut code, 0);
    let data = rsa(&code, 1)?;
    let parsed = parse(&data, &ArchiveOptions::default())?;
    let message = parsed
        .script
        .instructions
        .last()
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(message.opcode.operation, O::Text(TextOperation::Show));
    assert_eq!(message.opcode.code, 0x80007fff);
    assert!(
        message
            .args
            .iter()
            .any(|a| a.name == A::Text && matches!(&a.value,Value::Text(t) if t=="あ"))
    );
    assert_eq!(message.span.size as usize, code.len());
    assert!(
        matches!(parse(&data[..data.len()-1],&ArchiveOptions::default()),Err(Error::Io(e)) if e.kind()==std::io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}
#[test]
fn generic_messages_require_current_host_definitions() -> Result<()> {
    let mut code = Vec::new();
    class(&mut code, "CVmGenericMsg")?;
    dword(&mut code, u32::MAX);
    dword(&mut code, 0);
    dword(&mut code, 2);
    word(&mut code, 0xffff);
    code.extend([0, 9]);
    code.extend(b"&-OM_Test");
    dword(&mut code, 42);
    word(&mut code, 0);
    word(&mut code, 0);
    let data = rsa(&code, 1)?;
    assert!(matches!(
        parse(&data, &ArchiveOptions::default()),
        Err(Error::UnknownScheme(_))
    ));
    let mut options = ArchiveOptions::default();
    options.keys.insert("rugp_messages",nvlens_core::Secret::new(br#"{"&-OM_Test":{"schema":0,"fields":[{"name":"counter","type":2516582400,"size":4,"native_type":"int"}]}}"#.to_vec()));
    let script = parse(&data, &options)?.script;
    let instruction = script.instructions.last().ok_or(Error::InvalidFormat)?;
    assert_eq!(
        instruction.opcode.native_mnemonic.as_deref(),
        Some("&-OM_Test")
    );
    let command = instruction
        .args
        .iter()
        .find(|a| a.name == A::Command)
        .ok_or(Error::InvalidFormat)?;
    let Value::Group(fields) = &command.value else {
        return Err(Error::InvalidFormat);
    };
    assert!(
        fields
            .iter()
            .any(|f| f.native_name.as_deref() == Some("counter")
                && matches!(f.value, Value::Integer(42)))
    );
    Ok(())
}

#[test]
fn zero_and_nonzero_branches_keep_native_operands_and_derived_spans() -> Result<()> {
    for (operator, comparison) in [
        (0x40, ControlFlowOperation::NotEqual),
        (0x41, ControlFlowOperation::Equal),
    ] {
        let mut code = Vec::new();
        class(&mut code, "CVmFlagOp")?;
        for value in [u32::MAX, 0, 6, 2] {
            dword(&mut code, value);
        }
        code.push(0);
        word(&mut code, 0);
        word(&mut code, operator);
        code.push(1);
        dword(&mut code, 4);
        let script = parse(&rsa(&code, 1)?, &ArchiveOptions::default())?.script;
        let instruction = script.instructions.last().ok_or(Error::InvalidFormat)?;
        assert_eq!(
            instruction.opcode.operation,
            O::ControlFlow(ControlFlowOperation::Branch)
        );
        let condition = instruction
            .args
            .iter()
            .find(|a| a.name == A::Condition)
            .ok_or(Error::InvalidFormat)?;
        let Value::Expression(tokens) = &condition.value else {
            return Err(Error::InvalidFormat);
        };
        assert_eq!(tokens[0].opcode.operation, O::ControlFlow(comparison));
        assert_eq!(tokens[0].span.size, 0);
        assert!(tokens[0].args.iter().all(|a| a.span.size == 0));
        assert!(
            instruction
                .args
                .iter()
                .any(|a| a.name == A::Operator && a.span.size == 2)
        );
    }
    Ok(())
}
