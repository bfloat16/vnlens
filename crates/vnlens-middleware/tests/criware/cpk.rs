#![allow(clippy::unwrap_used)]
use super::*;
use crate::criware::tests::{Cell, Watched, cpk, packet, source, table};

#[test]
fn toc_offsets_use_the_earlier_base_and_mount_does_not_read_payload() -> Result<()> {
    let bytes = cpk();
    let watched = Arc::new(Watched {
        bytes: bytes.clone(),
        end: 0x800,
        reads: Default::default(),
    });
    let archive = Cpk::open(watched)?;
    assert_eq!(archive.entries.len(), 2);
    assert_eq!(archive.entries[0].offset, 0x800);
    assert_eq!(archive.entries[1].name, "dir/../two.bin");
    let archive = Cpk::open(source(bytes.clone()))?;
    assert!(matches!(
        archive.read(&archive.entries[0])?,
        Cow::Borrowed(b"GOOD")
    ));
    assert_eq!(
        archive.source(&archive.entries[1])?.read_at(0, 4)?.as_ref(),
        b"FAIL"
    );
    assert!(Cpk::open(source(bytes[..0x807].to_vec())).is_err());
    Ok(())
}
#[test]
fn itoc_uses_ids_and_declared_alignment() -> Result<()> {
    let ids = table(
        "CpkItocL",
        &[
            ("ID", 2, 0x50, vec![Cell::Number(23), Cell::Number(7)]),
            ("FileSize", 2, 0x30, vec![Cell::Number(4)]),
        ],
        2,
    );
    let itoc = packet(
        b"ITOC",
        table(
            "CpkItocInfo",
            &[("DataL", 11, 0x30, vec![Cell::Data(ids)])],
            1,
        ),
    );
    let header = packet(
        b"CPK ",
        table(
            "CpkHeader",
            &[
                ("ContentOffset", 6, 0x30, vec![Cell::Number(0x800)]),
                ("ItocOffset", 6, 0x30, vec![Cell::Number(0x400)]),
                ("Align", 2, 0x30, vec![Cell::Number(16)]),
                ("Files", 4, 0x30, vec![Cell::Number(2)]),
            ],
            1,
        ),
    );
    let mut bytes = vec![0; 0x814];
    bytes[..header.len()].copy_from_slice(&header);
    bytes[0x400..0x400 + itoc.len()].copy_from_slice(&itoc);
    bytes[0x800..0x804].copy_from_slice(b"SEVN");
    bytes[0x810..].copy_from_slice(b"TTRE");
    let archive = Cpk::open(source(bytes))?;
    assert_eq!(
        archive
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        ["7", "23"]
    );
    assert_eq!(archive.entries[1].offset, 0x810);
    Ok(())
}
