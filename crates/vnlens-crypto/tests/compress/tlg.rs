use super::*;
#[test]
fn overlap_extended_lengths_and_dictionary_persistence() -> io::Result<()> {
    let mut slide = Slide::default();
    assert_eq!(slide.decode(&[8, b'A', b'B', b'C', 0, 0], 6)?, b"ABCABC");
    assert_eq!(slide.decode(&[1, 3, 0], 3)?, b"ABC");
    assert_eq!(Slide::default().decode(&[1, 0, 0xf0, 0], 18)?, [0; 18]);
    assert!(Slide::default().decode(&[1, 0, 0xf0], 18).is_err());
    assert!(Slide::default().decode(&[1, 0, 0xf0, 0], 17).is_err());
    Ok(())
}
