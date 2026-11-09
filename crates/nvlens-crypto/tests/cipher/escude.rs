use super::*;
#[test]
fn native_header_vector_and_continuous_state() {
    let mut cipher = IndexCipher::new(0x3526_4916);
    assert_eq!(cipher.decode_word(0xd368_592b), 281);
    assert_eq!(cipher.decode_word(0x711a_e1d4), 4244);
    assert_eq!(cipher.decode_word(0xf9be_fb3b), 0);
    assert_eq!(cipher.decode_word(0xa7e4_d914), 7636);
}
