use super::*;
#[test]
fn movie_windows_match_native_sequence() {
    let mut expected = vec![0; 32_000];
    let mut at = 0x800;
    let mut key = 1;
    while at < expected.len() {
        expected[at] ^= key;
        key = if key == 127 { 1 } else { key + 1 };
        at += usize::from(key);
    }
    let mut actual = vec![0; expected.len()];
    movie(&mut actual, 0);
    assert_eq!(actual, expected);
    for start in [0, 2047, 2048, 2049, 10_175, 10_176, 16_383, 31_900] {
        let size = expected.len() - start;
        let mut window = vec![0; size];
        movie(&mut window, start as u64);
        assert_eq!(window, expected[start..]);
    }
    movie(&mut actual, 0);
    assert!(actual.iter().all(|b| *b == 0));
    let start = 5_000_000_000;
    let mut large = vec![0; 9000];
    movie(&mut large, start);
    let mut split = vec![0; 9000];
    movie(&mut split[..4001], start);
    movie(&mut split[4001..], start + 4001);
    assert_eq!(large, split);
}
