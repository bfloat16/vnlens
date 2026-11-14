#![allow(clippy::unwrap_used)]
use super::*;
use crate::criware::tests::{Cell, Watched, source, table};
use vnlens_io::{BinaryReader, BinaryWriter};

#[test]
fn sdk_acb_appended_fields_preserve_the_declared_row_stride() -> Result<()> {
    let mut bytes = table(
        "Header",
        &[
            ("original", 4, 0x50, vec![Cell::Number(7)]),
            ("appended", 6, 0x50, vec![Cell::Number(0x1122334455667788)]),
        ],
        1,
    );
    BinaryWriter::u16_be(4, &mut bytes[26..28]);
    let parsed = Table::open(source(bytes))?;
    assert_eq!(parsed.row_width, 4);
    assert_eq!(parsed.number(0, "appended")?, Some(0x1122334455667788));
    let empty = table("Empty", &[("unused", 4, 0x50, vec![])], 0);
    let parsed = Table::open(source(empty))?;
    assert_eq!(parsed.row_count, 0);
    Ok(())
}

#[test]
fn typed_defaults_rows_binary_ranges_and_encrypted_tables_are_preserved() -> Result<()> {
    let bytes = table(
        "Test",
        &[
            ("zero", 4, 0x10, vec![]),
            ("legacy", 4, 0x70, vec![Cell::Number(7)]),
            (
                "name",
                10,
                0x50,
                vec![Cell::Text("台詞"), Cell::Text("two")],
            ),
            ("data", 11, 0x30, vec![Cell::Data(b"BODY".to_vec())]),
        ],
        2,
    );
    let end = 8 + u64::from(BinaryReader::u32_be(&bytes[16..20]));
    let watched = Arc::new(Watched {
        bytes: bytes.clone(),
        end,
        reads: Default::default(),
    });
    let parsed = Table::open(watched)?;
    assert_eq!(parsed.number(1, "zero")?, Some(0));
    assert_eq!(parsed.number(1, "legacy")?, Some(7));
    assert_eq!(parsed.value(0, "name")?.unwrap().text(), Some("台詞"));
    assert!(parsed.binary(0, "data")?.is_some());
    let mut encrypted = bytes.clone();
    apply_utf(0, &mut encrypted);
    let parsed = Table::open(source(encrypted))?;
    assert_eq!(
        parsed.binary(0, "data")?.unwrap().read_at(0, 4)?.as_ref(),
        b"BODY"
    );
    for end in [0, 4, 7, 31] {
        assert!(Table::open(source(bytes[..end].to_vec())).is_err());
    }
    let mut invalid = bytes;
    BinaryWriter::u32_be(u32::MAX, &mut invalid[28..]);
    assert!(Table::open(source(invalid)).is_err());
    Ok(())
}
