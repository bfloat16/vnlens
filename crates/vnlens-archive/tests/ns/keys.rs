use super::*;
use crate::ns::fixtures;
use vnlens_io::BinaryWriter;

#[test]
fn common_tickets_follow_signature_layout_and_keys_remain_redacted() -> Result<()> {
    for (signature, offset) in [
        (0x10000, 0x240),
        (0x10001, 0x140),
        (0x10002, 0x80),
        (0x10003, 0x240),
        (0x10004, 0x140),
        (0x10005, 0x80),
    ] {
        let mut bytes = vec![0; offset + 0x170];
        BinaryWriter::u32_le(signature, &mut bytes);
        bytes[offset + 0x40..offset + 0x50].fill(0x7b);
        bytes[offset + 0x160..offset + 0x170].fill(0x12);
        let mut keys = Keys::default();
        keys.ticket(fixtures::source(bytes.clone()).as_ref())?;
        assert_eq!(keys.get::<16>(&"12".repeat(16))?, [0x7b; 16]);
        assert!(!format!("{keys:?}").contains("7b"));
        keys.ticket(fixtures::source(bytes.clone()).as_ref())?;
        bytes[offset + 0x40] ^= 1;
        assert!(matches!(
            keys.ticket(fixtures::source(bytes.clone()).as_ref()),
            Err(Error::Corrupt { .. })
        ));
        bytes[offset + 0x141] = 1;
        let mut personal = Keys::default();
        personal.ticket(fixtures::source(bytes.clone()).as_ref())?;
        assert!(personal.values.is_empty());
        bytes.truncate(offset + 0x16f);
        assert!(
            matches!(keys.ticket(fixtures::source(bytes).as_ref()), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }
    assert!(matches!(
        Keys::default().ticket(fixtures::source(vec![0; 4]).as_ref()),
        Err(Error::Corrupt { .. })
    ));
    Ok(())
}
