#![allow(clippy::unwrap_used)]

use super::*;
use crate::ScriptFormat;
use crate::exhibit::Rld;
use crate::ir::{Operation, TextOperation};
use vnlens_core::Secret;

fn fixture() -> Vec<u8> {
    let mut data = vec![0; 276];
    for (i, word) in [0x524c_4400, 3, 272, 1].into_iter().enumerate() {
        BinaryWriter::u32_le(word, &mut data[i * 4..]);
    }
    let mut word = [0; 4];
    BinaryWriter::u32_le(0x1101_001c, &mut word);
    data.extend(word);
    BinaryWriter::u32_le(u32::MAX, &mut word);
    data.extend(word);
    data.extend([0x82, 0xa0, 0]);
    data
}

#[test]
fn system_and_game_parameters_decode_to_reopenable_lossless_ir() {
    let mut options = ArchiveOptions::default();
    for (name, seed) in [("exhibit_rld", 1), ("exhibit_rld_system", 7)] {
        let mut bytes = vec![0; 4];
        BinaryWriter::u32_le(seed, &mut bytes);
        options.keys.insert(name, Secret::new(bytes));
    }
    for seed in [1, 7] {
        let mut encrypted = fixture();
        vnlens_crypto::cipher::exhibit::apply_rld(&mut encrypted[16..], seed);
        let decoded = Rld.decode(&encrypted, &options).unwrap();
        assert_eq!(Rld.decode(&decoded, &options).unwrap(), decoded);
        let script = Rld.disassemble(&decoded, None).unwrap().unwrap();
        assert_eq!(
            script.instructions[0].opcode.operation,
            Operation::Text(TextOperation::Show)
        );
        assert!(matches!(&script.instructions[0].args[1].value, Value::Text(s) if s == "あ"));
        assert_eq!(
            script
                .sections
                .iter()
                .flat_map(|s| s.raw.iter().copied())
                .collect::<Vec<_>>(),
            &*decoded
        );
        assert!(
            Rld.decode(&encrypted[..encrypted.len() - 1], &options)
                .is_err()
        );
        assert!(Rld.decode(&encrypted, &ArchiveOptions::default()).is_err());
        let mut empty = fixture();
        empty.truncate(276);
        BinaryWriter::u32_le(0, &mut empty[12..16]);
        let mut expected = empty.clone();
        BinaryWriter::u32_le(2, &mut expected[4..8]);
        vnlens_crypto::cipher::exhibit::apply_rld(&mut empty[16..], seed);
        assert_eq!(&*Rld.decode(&empty, &options).unwrap(), expected);
    }
    assert!(Rld.disassemble(b"unrelated", None).unwrap().is_none());
}

#[test]
fn unknown_commands_and_invalid_text_preserve_source_values() {
    let mut data = fixture();
    BinaryWriter::u32_le(0x0100_ffff, &mut data[276..]);
    data.truncate(280);
    data.extend([0x81, 0]);
    let script = parse(&data).unwrap();
    assert_eq!(script.instructions[0].opcode.operation, Operation::Unknown);
    assert!(matches!(&script.instructions[0].args[0].value, Value::Bytes(b) if b == &[0x81]));
}
