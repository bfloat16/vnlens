#![allow(clippy::unwrap_used)]
use super::*;
use crate::criware::tests::{Cell, Watched, awb, source, table};
use vnlens_io::BinaryReader;

#[test]
fn acb_retains_native_tables_and_defers_wave_bank_reads() -> Result<()> {
    let cues = table(
        "CueTable",
        &[("ReferenceType", 1, 0x30, vec![Cell::Number(1)])],
        3,
    );
    let bytes = table(
        "Header",
        &[
            ("AwbFile", 11, 0x30, vec![Cell::Data(awb())]),
            ("CueTable", 11, 0x30, vec![Cell::Data(cues)]),
        ],
        1,
    );
    let end = 8 + u64::from(BinaryReader::u32_be(&bytes[16..20]));
    let watched = Arc::new(Watched {
        bytes: bytes.clone(),
        end,
        reads: Default::default(),
    });
    let bank = Bank::open(watched, TableKind::Acb)?;
    assert_eq!(bank.entries.len(), 2);
    let bank = Bank::open(source(bytes), TableKind::Acb)?;
    assert_eq!(bank.cue_count()?, 3);
    let awb = bank
        .entries
        .iter()
        .find(|e| e.name == "AwbFile.awb")
        .unwrap();
    assert_eq!(bank.source(awb)?.read_at(0, 4)?.as_ref(), b"AFS2");
    Ok(())
}
