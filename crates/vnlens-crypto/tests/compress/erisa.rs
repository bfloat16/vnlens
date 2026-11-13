#![allow(clippy::unwrap_used)]
use super::*;

#[test]
fn empty_stream_and_truncated_initial_register() {
    // Root escape followed by phrase-index escape and arithmetic termination.
    let mut decoder = NemesisDecoder::new([0, 0, 0xff, 0xfe, 0xff].as_slice()).unwrap();
    let mut output = Vec::new();
    decoder.read_to_end(&mut output).unwrap();
    assert!(output.is_empty());
    assert!(NemesisDecoder::new([0, 0, 0xff].as_slice()).is_err());
}
