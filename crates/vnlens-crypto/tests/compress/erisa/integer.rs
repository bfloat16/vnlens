use super::*;
#[test]
fn integer_idct_dc_vector() {
    let mut block = [0; 64];
    block[0] = 1024;
    idct(&mut block);
    assert_eq!(block, [256; 64]);
    let mut block = [0; 64];
    ilot(&mut block, &mut [0; 64], &mut [0; 64]);
    assert_eq!(block, [0; 64]);
}
