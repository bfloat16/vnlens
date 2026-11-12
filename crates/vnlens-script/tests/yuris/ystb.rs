#![allow(clippy::unwrap_used)]
use super::*;
use vnlens_core::ir::Span;
use vnlens_io::BinaryWriter;

fn commands() -> Vec<Command> {
    ["WORD", "IF", "RETURNCODE", "_"]
        .into_iter()
        .map(|name| Command {
            name: name.into(),
            arguments: Vec::new(),
            span: Span { offset: 0, size: 0 },
        })
        .collect()
}
fn fixture(first_offset: u32) -> Vec<u8> {
    let mut data = vec![0; 32];
    data[..4].copy_from_slice(b"YSTB");
    for (at, value) in [(4, 0x227), (8, 2), (12, 8), (16, 24), (20, 12), (24, 8)] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    data.extend_from_slice(&[0, 1, 0, 0, 0, 1, 0, 0]);
    for offset in [first_offset, 0] {
        let mut arg = [0; 12];
        BinaryWriter::u32_le(4, &mut arg[4..]);
        BinaryWriter::u32_le(offset, &mut arg[8..]);
        data.extend_from_slice(&arg);
    }
    data.extend_from_slice(b"abcdefghijkl");
    data.extend_from_slice(&[0; 8]);
    data
}

#[test]
fn recovers_section_keys_including_zero_without_assuming_first_argument_offset() {
    let cancel = AtomicBool::new(false);
    for key in [[0; 4], [0x91, 0x82, 0x73, 0x64], [0xff; 4], [0, 1, 0, 0]] {
        let mut bytes = fixture(4);
        decrypt(&mut bytes, &key).unwrap();
        assert_eq!(
            recover_key(&bytes, &commands(), &cancel)
                .unwrap()
                .unwrap()
                .bytes(),
            key
        );
        assert!(matches!(
            recover_key(&bytes, &commands(), &AtomicBool::new(true)),
            Err(Error::Cancelled)
        ));
    }
}

#[test]
fn candidates_require_native_command_and_argument_consistency() {
    let mut bytes = fixture(4);
    // A zero-offset ciphertext hint alone is insufficient: argc no longer
    // accounts for the argument table, despite otherwise valid framing.
    bytes[33] = 0;
    let key = [0x12, 0x34, 0x56, 0x78];
    decrypt(&mut bytes, &key).unwrap();
    assert!(
        recover_key(&bytes, &commands(), &AtomicBool::new(false))
            .unwrap()
            .is_none()
    );
    let plain = fixture(4);
    for end in 0..plain.len() {
        assert!(sections(&plain[..end]).is_err());
    }
}

#[test]
fn control_descriptors_are_validated_as_targets_instead_of_data_ranges() {
    let mut bytes = fixture(0);
    bytes[32] = 1;
    bytes[33] = 2;
    bytes[37] = 0;
    BinaryWriter::u32_le(2, &mut bytes[56..]);
    BinaryWriter::u32_le(u32::MAX, &mut bytes[60..]);
    let key = [0x12, 0x34, 0x56, 0x78];
    decrypt(&mut bytes, &key).unwrap();
    assert_eq!(
        recover_key(&bytes, &commands(), &AtomicBool::new(false))
            .unwrap()
            .unwrap()
            .bytes(),
        key
    );
}
