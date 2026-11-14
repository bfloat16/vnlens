#![allow(clippy::unwrap_used)]
use super::*;
use crate::criware::tests::{Watched, awb, source};
use vnlens_io::BinaryWriter;

#[test]
fn alignment_ids_subkey_and_lazy_reads_follow_the_index() -> Result<()> {
    let bytes = awb();
    let watched = Arc::new(Watched {
        bytes: bytes.clone(),
        end: 32,
        reads: Default::default(),
    });
    let archive = Awb::open(watched)?;
    assert_eq!(archive.ids, [7, 23]);
    assert_eq!(archive.subkey, 123);
    assert_eq!(archive.entries[0].size, 4);
    assert_eq!(archive.entries[1].offset, 48);
    let archive = Awb::open(source(bytes.clone()))?;
    assert!(matches!(
        archive.read(&archive.entries[0])?,
        Cow::Borrowed(b"GOOD")
    ));
    let mut invalid = bytes;
    BinaryWriter::u32_le(u32::MAX, &mut invalid[8..]);
    assert!(Awb::open(source(invalid)).is_err());
    Ok(())
}
