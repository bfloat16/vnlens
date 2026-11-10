use super::*;
#[test]
fn identification_and_truncated_pages_use_format_bounds() -> Result<()> {
    let parsed = info(&mut BitReader::new(&[0x08, 0x0d, 0x17], BitOrder::Msb))?;
    assert_eq!(
        (parsed.channels, parsed.rate, parsed.small, parsed.large),
        (1, 44100, 8, 11)
    );
    assert!(to_ogg(&[0x08, 0x0d, 0x17]).is_err());
    assert!(to_ogg(&[0x08, 0x0d]).is_err());
    assert!(Oor.metadata(b"unrelated").map(|v| v.is_none())?);
    Ok(())
}
