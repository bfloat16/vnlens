use super::*;
use vnlens_script::ir::{Arg, ArgName, Instruction, Opcode, Operation, Span};

fn instruction(name: &str, args: &[(&str, Value)]) -> Instruction {
    let span = Span { offset: 0, size: 0 };
    Instruction {
        id: 0,
        span,
        source_line: None,
        opcode: Opcode {
            namespace: "yuris.command".into(),
            code: 0,
            operation: Operation::Unknown,
            variant: None,
            native_mnemonic: Some(name.into()),
        },
        args: args
            .iter()
            .map(|(name, value)| Arg {
                name: ArgName::Value,
                native_name: Some((*name).into()),
                span,
                value: value.clone(),
                attributes: vec![],
            })
            .collect(),
        attributes: vec![],
    }
}

fn voice(channel: i64, name: &str) -> Instruction {
    instruction(
        "GOSUB",
        &[
            ("#", Value::Text("es.SND".into())),
            ("PINT", Value::Integer(channel)),
            ("PSTR2", Value::Text(name.into())),
        ],
    )
}

fn script(mut instructions: Vec<Instruction>) -> Script {
    for (id, instruction) in instructions.iter_mut().enumerate() {
        instruction.id = id as u64;
    }
    Script {
        ir_version: vnlens_script::ir::VERSION,
        format: "ybn/yuris".into(),
        format_version: 0x1e1,
        sections: vec![],
        instructions,
    }
}

#[test]
fn collects_complete_fragments_and_replaces_the_same_voice_channel() -> Result<()> {
    let script = script(vec![
        voice(21, "old"),
        voice(21, "new"),
        instruction("WORD", &[("#", Value::Text("【Alice】「Hello".into()))]),
        instruction("_", &[("#", Value::Text("!」".into()))]),
        instruction("RETURNCODE", &[]),
    ]);
    let mut output = vec![];
    let mut skipped = 0;
    collect(
        &script,
        "ysbin/yst00001.ybn",
        &Config::default(),
        &AtomicBool::new(false),
        &mut output,
        &mut skipped,
    )?;
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].voice, "new");
    assert_eq!(output[0].text, "「Hello!」");
    assert_eq!(skipped, 0);
    Ok(())
}

#[test]
fn earlier_voice_slots_replace_modern_channels_and_unknown_font_text_is_skipped() -> Result<()> {
    for (text, expected) in [
        (Value::Text("【Alice】Hello".into()), 1),
        (Value::Bytes(vec![0xef, 0xf0]), 0),
    ] {
        let mut old = voice(1, "old-style");
        old.args[0].value = Value::Text("es.VoiceSet".into());
        let mut output = Vec::new();
        collect(
            &script(vec![
                voice(21, "modern"),
                old,
                instruction("WORD", &[("#", text)]),
                instruction("RETURNCODE", &[]),
            ]),
            "ysbin/yst00001.ybn",
            &Config::default(),
            &AtomicBool::new(false),
            &mut output,
            &mut 0,
        )?;
        assert_eq!(output.len(), expected);
        if let Some(dialogue) = output.first() {
            assert_eq!(dialogue.voice, "old-style");
        }
    }
    Ok(())
}

#[test]
fn rejects_chorus_dynamic_fragments_and_interrupted_messages() -> Result<()> {
    for instructions in [
        vec![
            voice(21, "one"),
            voice(22, "two"),
            instruction("WORD", &[("#", Value::Text("【Alice】Hello".into()))]),
            instruction("RETURNCODE", &[]),
        ],
        vec![
            voice(21, "one"),
            instruction("WORD", &[("#", Value::Text("【Alice】Hello".into()))]),
            instruction("_", &[("#", Value::Nil)]),
            instruction("RETURNCODE", &[]),
        ],
        vec![
            voice(21, "one"),
            instruction("GO", &[]),
            instruction("WORD", &[("#", Value::Text("【Alice】Hello".into()))]),
            instruction("RETURNCODE", &[]),
        ],
        vec![
            voice(21, "one"),
            instruction("WORD", &[("#", Value::Text("【Alice】Hello".into()))]),
        ],
    ] {
        let mut output = vec![];
        let mut skipped = 0;
        collect(
            &script(instructions),
            "ysbin/yst00001.ybn",
            &Config::default(),
            &AtomicBool::new(false),
            &mut output,
            &mut skipped,
        )?;
        assert!(output.is_empty());
        assert!(skipped > 0);
    }
    Ok(())
}

#[test]
fn rejects_entry_points_that_bypass_sound_or_enter_a_message_fragment() -> Result<()> {
    let script = script(vec![
        voice(21, "one"),
        instruction("WORD", &[("#", Value::Text("【Alice】Hello".into()))]),
        instruction("_", &[("#", Value::Text("!".into()))]),
        instruction("RETURNCODE", &[]),
    ]);
    for target in [1, 2, 3] {
        let mut config = Config::default();
        config
            .entry_points
            .insert("ysbin/yst00001.ybn".into(), BTreeSet::from([target]));
        let mut output = vec![];
        collect(
            &script,
            "ysbin/yst00001.ybn",
            &config,
            &AtomicBool::new(false),
            &mut output,
            &mut 0,
        )?;
        assert!(output.is_empty());
    }
    let mut local = script.clone();
    local.instructions.push(instruction(
        "IF",
        &[(
            "END",
            Value::Group(vec![Arg {
                name: ArgName::Target,
                native_name: None,
                span: Span { offset: 0, size: 0 },
                value: Value::InstructionTarget(0),
                attributes: vec![],
            }]),
        )],
    ));
    let mut output = vec![];
    collect(
        &local,
        "ysbin/yst00001.ybn",
        &Config::default(),
        &AtomicBool::new(false),
        &mut output,
        &mut 0,
    )?;
    assert!(output.is_empty());
    assert!(matches!(
        collect(
            &script,
            "ysbin/yst00001.ybn",
            &Config::default(),
            &AtomicBool::new(true),
            &mut output,
            &mut 0
        ),
        Err(vnlens_core::Error::Cancelled)
    ));
    Ok(())
}
