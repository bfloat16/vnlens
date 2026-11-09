use super::*;
#[test]
fn audio_mode_validation_rejects_unassigned_values() -> Result<()> {
    assert_eq!(block_size(&[0], &[false, true, false], 8, 11)?, 256);
    assert_eq!(block_size(&[2], &[false, true, false], 8, 11)?, 2048);
    assert!(block_size(&[6], &[false, true, false], 8, 11).is_err());
    assert!(block_size(&[], &[false], 8, 11).is_err());
    Ok(())
}
