#![allow(clippy::unwrap_used)]

use super::*;
use crate::ir::{
    AudioOperation, ControlFlowOperation, ImageOperation, Operation, StorageOperation,
    TextOperation,
};
use std::cell::Cell;
use vnlens_io::BinaryWriter;
fn sample() -> Vec<u8> {
    let mut words = vec![0; 32];
    words[..10].copy_from_slice(&[32, 0x66660001, 0x55550001, 0, 1, 76, 2, 77, 1, 79]);
    words.extend([
        8, 0x66660005, 0, 0xa0000000, 3, 0x80000007, 0x9000ffff, 0xa000003d,
    ]);
    words.extend([6, 0x66660006, 0x22220001, 0, 1, 7]);
    words.extend([5, 0x66660007, 0x33330015, 2, 0]);
    words.extend([6, 0x66660007, 0x33330008, 2, 1, 0]);
    words.extend([5, 0x66660002, 0x55560009, 0, 0]);
    words.extend([5, 0x6666fffe, 0xabcdef, 123, 456]);
    words.extend([5, 0x66660004, 0, 1, 0x90000005]);
    words.extend([14, 0x66660001, 0x55550002, 0x44440001, 80, 81, 83, 32]);
    words.resize(86, 0);
    let mut data = vec![0; words.len() * 4];
    for (word, bytes) in words.into_iter().zip(data.as_chunks_mut::<4>().0) {
        BinaryWriter::u32_le(word, bytes);
    }
    data[48..58].copy_from_slice(b"SPTHEADER0");
    data[320..323].copy_from_slice(b"\x82\xa0\0");
    data[324..329].copy_from_slice(b"bg01\0");
    data[332..341].copy_from_slice(b"aa000001\0");
    data
}
struct Names(Cell<usize>);
impl ResourceResolver for Names {
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        assert_eq!(name, "function.xtx");
        self.0.set(self.0.get() + 1);
        Ok(Some(b"stopf5,stop F5\r\n".to_vec()))
    }
}
#[test]
fn bytecode_maps_semantics_strings_targets_and_keeps_unknowns_losslessly() -> Result<()> {
    let plain = sample();
    let mut encrypted = plain.clone();
    vnlens_crypto::cipher::xor::apply_u32_key(&mut encrypted, &[255; 4]);
    let resolver = Names(Cell::new(0));
    let script = parse(&encrypted, Some(&resolver)).unwrap();
    assert_eq!(resolver.0.get(), 1);
    assert_eq!(script.sections[0].raw, plain);
    assert_eq!(script.instructions.len(), 9);
    let ins = &script.instructions;
    assert_eq!(
        ins[1].opcode.operation,
        Operation::Storage(StorageOperation::Store)
    );
    let Value::Expression(tokens) = &ins[1].args[0].value else {
        return Err(Error::InvalidFormat);
    };
    assert!(matches!(tokens[1].args[0].value, Value::Integer(-1)));
    assert_eq!(
        ins[2].opcode.operation,
        Operation::Text(TextOperation::Show)
    );
    assert!(matches!(&ins[2].args[0].value,Value::Text(s) if s=="あ"));
    assert_eq!(
        ins[3].opcode.operation,
        Operation::Image(ImageOperation::Load)
    );
    assert!(matches!(&ins[3].args[1].value,Value::Text(s) if s=="bg01"));
    assert_eq!(
        ins[4].opcode.operation,
        Operation::Audio(AudioOperation::Play)
    );
    assert!(matches!(&ins[4].args[1].value,Value::Text(s) if s=="aa000001"));
    assert_eq!(
        ins[5].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Call)
    );
    assert_eq!(ins[5].args[0].name, A::LabelId);
    assert!(matches!(ins[5].args[0].value, Value::Unsigned(0)));
    assert_eq!(ins[5].args[1].name, A::ResolvedTarget);
    assert_eq!(ins[5].args[1].span.size, 0);
    assert!(matches!(ins[5].args[1].value, Value::CodeAddress(128)));
    assert_eq!(ins[6].opcode.operation, Operation::Unknown);
    assert_eq!(ins[6].args.len(), 2);
    assert_eq!(ins[6].args[1].name, A::Unknown(1));
    assert_eq!(ins[7].opcode.native_mnemonic.as_deref(), Some("stopf5"));
    assert!(script.to_json().is_ok());
    Ok(())
}
#[test]
fn truncation_invalid_record_lengths_pointer_tables_and_targets_fail() {
    let bytes = sample();
    for end in 0..bytes.len() {
        assert!(parse(&bytes[..end], None).is_err(), "{end}");
    }
    for (at, value) in [
        (128, 0),
        (128, 2),
        (128, u32::MAX),
        (20, u32::MAX),
        (304, u32::MAX),
        (316, 33),
    ] {
        let mut bad = bytes.clone();
        BinaryWriter::u32_le(value, &mut bad[at..]);
        assert!(parse(&bad, None).is_err(), "{at}");
    }
}
#[test]
fn unknown_expression_tokens_survive_with_native_word_and_span() -> Result<()> {
    let mut bytes = sample();
    BinaryWriter::u32_le(0xdeadbeef, &mut bytes[39 * 4..]);
    let parsed = parse(&bytes, None).unwrap();
    assert_eq!(parsed.instructions[1].opcode.operation, Operation::Unknown);
    let Value::Expression(tokens) = &parsed.instructions[1].args[0].value else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(tokens[2].opcode.code, 0xdeadbeef);
    assert_eq!(tokens[2].span.offset, 39 * 4);
    assert_eq!(tokens[2].args[0].name, A::Unknown(0));
    Ok(())
}

fn records(records: &[(u32, u32, &[u32])]) -> Vec<u8> {
    let mut words = vec![0; 19];
    words[..3].copy_from_slice(&[19, 0x66660001, 0x55550001]);
    for &(family, code, body) in records {
        words.extend([body.len() as u32 + 3, family, code]);
        words.extend_from_slice(body);
    }
    let mut bytes = vec![0; words.len() * 4];
    for (&value, target) in words.iter().zip(bytes.as_chunks_mut::<4>().0) {
        BinaryWriter::u32_le(value, target);
    }
    bytes[48..58].copy_from_slice(b"SPTHEADER0");
    bytes
}
#[test]
fn conditional_and_skip_targets_follow_record_and_block_boundaries() -> Result<()> {
    let bytes = records(&[
        (0x66660002, 0x55560002, &[0x90000001]),
        (0x66660002, 0xa000007b, &[10]),
        (0x66660002, 0x55560001, &[]),
        (0x66660002, 0xa000007d, &[]),
        (0x66660002, 0x55560004, &[]),
        (0x66660002, 0x55560001, &[]),
        (0x66660002, 0x55560006, &[]),
    ]);
    let script = parse(&bytes, None)?;
    let branch = &script.instructions[1];
    assert_eq!(branch.args[1].name, A::NextBranchTarget);
    assert_eq!(branch.args[1].span.size, 0);
    assert!(
        matches!(branch.args[1].value, Value::CodeAddress(value) if value == script.instructions[5].span.offset)
    );
    assert!(
        matches!(script.instructions[5].args[0].value, Value::CodeAddress(value) if value == script.instructions[7].span.offset)
    );
    assert_eq!(
        script.instructions[7].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Halt)
    );
    let mut bad = bytes.clone();
    BinaryWriter::u32_le(9, &mut bad[104..]);
    assert!(parse(&bad, None).is_err());
    Ok(())
}
#[test]
fn command_returns_unknown_ordinals_and_companion_names_stay_distinct() -> Result<()> {
    struct Names;
    impl ResourceResolver for Names {
        fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
            Ok(Some(if name == "function.xtx" {
                b"custom,description\n,empty name\nlayer,layer state\n".to_vec()
            } else {
                b"custom,description\n".to_vec()
            }))
        }
    }
    let bytes = records(&[
        (0x66660003, 0, &[1, 0xa0000000, 1, 0x90000002, 77, 88]),
        (0x66660004, 1, &[0]),
        (0x66660004, 2, &[2, 0x90000003, 0x80000004, 99]),
    ]);
    let script = parse(&bytes, Some(&Names))?;
    let command = &script.instructions[1];
    assert_eq!(command.opcode.operation, Operation::Unknown);
    assert_eq!(command.args[1].name, A::Unknown(0));
    assert_eq!(command.args[2].name, A::Unknown(4));
    assert_eq!(command.args[3].name, A::ReturnCode);
    assert!(matches!(command.args[3].value, Value::Unsigned(88)));
    assert_eq!(
        script.instructions[2].opcode.native_mnemonic.as_deref(),
        Some("")
    );
    let layer = &script.instructions[3];
    assert_eq!(
        layer.opcode.operation,
        Operation::Image(ImageOperation::SetVisibility)
    );
    assert_eq!(layer.args[1].name, A::Index);
    assert_eq!(layer.args[2].name, A::Flags);
    assert_eq!(layer.args[3].name, A::Unknown(3));
    assert!(parse(&records(&[(0x66660003, 0, &[0])]), None).is_err());
    Ok(())
}
#[test]
fn choice_groups_keep_every_pointer_once_and_unknown_tail_slots() -> Result<()> {
    for body in [&[2, 0, 1, 55][..], &[1, 0, 1, 55, 1][..]] {
        let mut bytes = sample();
        let extra = records(&[(0x66660006, 0x22220006, body)]);
        bytes.extend_from_slice(&extra[76..]);
        let script = parse(&bytes, None)?;
        let choices = &script.instructions[9];
        assert_eq!(
            choices.args.iter().map(|arg| arg.span.size).sum::<u64>(),
            body.len() as u64 * 4
        );
        for (index, expected) in [(0, "bg01"), (1, "aa000001")] {
            let item = &choices.args[index + 1];
            let heading = body.len() == 5;
            assert_eq!(
                item.name,
                if heading && index == 0 {
                    A::Title
                } else {
                    A::Choice((index - usize::from(heading)) as u64)
                }
            );
            let Value::Group(fields) = &item.value else {
                return Err(Error::InvalidFormat);
            };
            assert!(matches!(&fields[0].value, Value::Text(value) if value == expected));
        }
    }
    let mut bytes = sample();
    let extra = records(&[(0x66660006, 0x22220006, &[u32::MAX, 0])]);
    bytes.extend_from_slice(&extra[76..]);
    assert!(parse(&bytes, None).is_err());
    Ok(())
}
#[test]
fn companion_tables_are_requested_only_by_their_native_call_family() -> Result<()> {
    struct Unexpected;
    impl ResourceResolver for Unexpected {
        fn read_resource(&self, _: &str) -> Result<Option<Vec<u8>>> {
            Err(Error::Unsupported("Unexpected companion access".into()))
        }
    }
    let bytes = records(&[(0x66660007, 0x33330012, &[])]);
    assert!(parse(&bytes, Some(&Unexpected)).is_ok());
    let mut body = vec![257];
    body.extend(std::iter::repeat_n(0x90000000, 257));
    let bytes = records(&[(0x66660004, 99, &body)]);
    let script = parse(&bytes, None)?;
    assert_eq!(script.instructions[1].args.len(), 258);
    assert_eq!(script.instructions[1].args[257].name, A::Unknown(256));
    Ok(())
}
