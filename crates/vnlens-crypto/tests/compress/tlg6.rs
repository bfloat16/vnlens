use super::*;
#[test]
fn signed_values_zero_runs_escape_and_declared_bounds() -> io::Result<()> {
    assert_eq!(decode(&[0x07], 3, 1)?, [255]);
    assert_eq!(decode(&[0x0b], 4, 1)?, [1]);
    assert_eq!(decode(&[0x0c], 4, 3)?, [0, 0, 0]);
    let escape = [3, 0, 0, 0, 254];
    assert_eq!(decode(&escape, 40, 1)?, [128]);
    for size in 0..escape.len() {
        assert!(decode(&escape[..size], 40, 1).is_err());
    }
    assert!(decode(&[3, 0, 0, 0, 255], 40, 1).is_err());
    assert!(decode(&[0x0c], 4, 2).is_err());
    assert!(decode(&[0x0c], 3, 3).is_err());
    Ok(())
}
