use super::*;
use vnlens_io::BinaryWriter;

struct Companion {
    commands: Vec<u8>,
    code: Vec<u8>,
}
impl ResourceResolver for Companion {
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(match name {
            "ysbin/ysc.ybn" => Some(self.commands.clone()),
            "ysbin/yst00007.ybn" => Some(self.code.clone()),
            _ => None,
        })
    }
}

fn companion(opcodes: &[u8]) -> Companion {
    let mut commands = vec![0; 16];
    commands[..4].copy_from_slice(b"YSCM");
    BinaryWriter::u32_le(0x1e1, &mut commands[4..]);
    let names = [
        "LET", "RETURN", "IF", "IFEND", "LOOP", "LOOPEND", "GO", "END",
    ];
    BinaryWriter::u32_le(names.len() as u32, &mut commands[8..]);
    for name in names {
        commands.extend_from_slice(name.as_bytes());
        commands.extend_from_slice(&[0, 0]);
    }
    let mut code = vec![0; 32];
    code[..4].copy_from_slice(b"YSTB");
    BinaryWriter::u32_le(0x1e1, &mut code[4..]);
    BinaryWriter::u32_le(opcodes.len() as u32, &mut code[8..]);
    BinaryWriter::u32_le(opcodes.len() as u32 * 4, &mut code[12..]);
    BinaryWriter::u32_le(opcodes.len() as u32 * 4, &mut code[24..]);
    for &opcode in opcodes {
        code.extend_from_slice(&[opcode, 0, 0, 0]);
    }
    code.resize(code.len() + opcodes.len() * 4, 0);
    Companion { commands, code }
}

fn labels() -> Result<Script> {
    let mut data = vec![0; 12 + 1024];
    data[..4].copy_from_slice(b"YSLB");
    BinaryWriter::u32_le(0x1e1, &mut data[4..]);
    BinaryWriter::u32_le(1, &mut data[8..]);
    data.extend_from_slice(b"\x03abc");
    let offset = data.len();
    data.resize(offset + 12, 0);
    BinaryWriter::u32_le(0x3524_41c2, &mut data[offset..]);
    BinaryWriter::u32_le(1, &mut data[offset + 4..]);
    BinaryWriter::u16_le(7, &mut data[offset + 8..]);
    vnlens_script::disassemble_as("ybn/yuris", &data, None)?.ok_or(Error::InvalidFormat)
}

#[test]
fn definitions_follow_typed_label_targets_and_stop_at_return() -> Result<()> {
    let cancel = AtomicBool::new(false);
    let labels = labels()?;
    let code = definition(&companion(&[7, 0, 1, 6]), &labels, "abc", &cancel)?;
    assert_eq!(code.len(), 1);
    assert_eq!(code[0].id, 1);
    assert_eq!(code[0].opcode.native_mnemonic.as_deref(), Some("LET"));
    assert!(definition(&companion(&[7]), &labels, "abc", &cancel).is_err());
    assert!(definition(&companion(&[7, 0]), &labels, "abc", &cancel).is_err());
    assert!(definition(&companion(&[7, 6, 1]), &labels, "abc", &cancel).is_err());
    assert!(matches!(
        definition(
            &companion(&[7, 0, 1]),
            &labels,
            "abc",
            &AtomicBool::new(true)
        ),
        Err(Error::Cancelled)
    ));
    Ok(())
}

#[test]
fn voice_paths_preserve_first_prefix_priority_and_default_folder() {
    let config = Config {
        voice_root: "voice/".into(),
        other_folder: "other/".into(),
        voice_rules: vec![
            VoiceRule {
                prefix: "a".into(),
                folder: "first/".into(),
            },
            VoiceRule {
                prefix: "ab".into(),
                folder: "second/".into(),
            },
        ],
        ..Config::default()
    };
    assert_eq!(
        config.voice_path("ABC_001"),
        Some("voice/first/abc_001".into())
    );
    assert_eq!(
        config.voice_path("c001.ogg"),
        Some("voice/other/c001.ogg".into())
    );
    assert!(config.voice_path("../../../missing").is_none());
}

#[test]
fn legacy_voice_references_are_scoped_to_the_declared_voice_root() {
    let mut config = Config {
        voice_root: "voice/".into(),
        legacy_voice_lookup: true,
        ..Config::default()
    };
    assert_eq!(
        config.voice_resource_alias("voice/chapter/explicit.ogg"),
        Some("voice/explicit.ogg".into())
    );
    assert_eq!(config.voice_resource_alias("se/chapter/explicit.ogg"), None);
    assert_eq!(
        config.voice_resource_alias("voice/../se/chapter/explicit.ogg"),
        None
    );
    config.legacy_voice_lookup = false;
    assert_eq!(
        config.voice_resource_alias("voice/chapter/explicit.ogg"),
        None
    );
}

#[test]
fn composite_speakers_need_an_unambiguous_declared_identity() {
    let config = Config {
        names: BTreeSet::from(["【Alice】".into(), "【Bob】".into()]),
        identities: [
            ("Alice＠???", Some("???")),
            ("???／Alice", Some("???")),
            ("Alice／Bob", None),
        ]
        .into_iter()
        .map(|(key, display)| (key.into(), character_identity(key, display)))
        .collect(),
        ..Config::default()
    };
    let speakers: Vec<_> = [
        "Alice",
        "Alice＠???",
        "???／Alice",
        "Alice／Bob",
        "Alice＆Bob",
        "Unknown＠???",
        "???",
    ]
    .into_iter()
    .map(|speaker| config.speaker(speaker))
    .collect();
    assert_eq!(
        speakers,
        vec![
            Some("Alice".into()),
            Some("Alice".into()),
            Some("Alice".into()),
            None,
            None,
            None,
            None
        ]
    );
}

#[test]
fn character_keys_and_display_aliases_do_not_exchange_character_identities() {
    assert_eq!(character_identity("＠x＠", Some("Alice")), None);
    assert_eq!(character_identity("x＠", Some("Alice")), None);
    assert_eq!(
        character_identity("【Student D＠Student A】", Some("Student A")),
        Some("Student D".into())
    );
    assert_eq!(
        character_identity("nickname／Alice", Some("nickname")),
        Some("Alice".into())
    );
    assert_eq!(
        character_identity("Alice／Alice aged 10", Some("Alice")),
        Some("Alice aged 10".into())
    );
    assert_eq!(character_identity("Alice＠Bob", Some("???")), None);
    assert_eq!(character_identity("Alice＠Bob", None), None);
    assert_eq!(character_identity("Alice＆Bob", Some("Bob")), None);
    assert_eq!(
        character_identity("【Alice】", Some("different display")),
        Some("Alice".into())
    );
}
