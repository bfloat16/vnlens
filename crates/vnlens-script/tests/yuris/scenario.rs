#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn decodes_cp932_scenario_text_and_rejects_invalid_bytes() {
    let text = "\\VO(0001)【アリス】「こんにちは」\r\n";
    let (encoded, _, _) = encoding_rs::SHIFT_JIS.encode(text);
    assert_eq!(Scenario.tag(), "scenario/yuris");
    assert_eq!(
        crate::decode_text_as("scenario/yuris", &encoded).unwrap(),
        Some(text.into())
    );
    assert!(
        crate::disassemble_as("scenario/yuris", &encoded, None)
            .unwrap()
            .is_none()
    );
    assert!(crate::decode_text_as("scenario/yuris", &[0xff]).is_err());
}
