#![allow(clippy::unwrap_used)]
use super::*;
use vnlens_io::{BitOrder, BitWriter};

#[test]
fn gamma_runs_and_huffman_escape_order() {
    let mut bits = BitReader::new(&[0x50, 0], BitOrder::Msb);
    let mut gamma = GammaDecoder::default();
    gamma.reset(&mut bits).unwrap();
    let mut bytes = [255; 5];
    gamma.decode(&mut bits, &mut bytes, None).unwrap();
    assert_eq!(bytes, [0, 0, 0, 0, 1]);
    let mut bits = BitReader::new(&[0x41, 0x10, 0x80], BitOrder::Msb);
    let mut tree = HuffmanTree::default();
    assert_eq!(tree.decode(&mut bits, false, false).unwrap(), 65);
    assert_eq!(tree.decode(&mut bits, false, false).unwrap(), 65);
    assert_eq!(tree.decode(&mut bits, false, false).unwrap(), 66);
}

#[test]
fn huffman_rebuild_preserves_code_order() {
    let mut encoded = BitWriter::new(BitOrder::Msb);
    for bit in [0, 1, 0, 0, 0, 0, 0, 1, 0] {
        encoded.write_bits_le(bit, 1).unwrap();
    }
    for _ in 2..20_000 {
        encoded.write_bits_le(1, 1).unwrap();
    }
    let bytes = encoded.into_bytes();
    let mut bits = BitReader::new(&bytes, BitOrder::Msb);
    let mut tree = HuffmanTree::default();
    for _ in 0..20_000 {
        assert_eq!(tree.decode(&mut bits, false, false).unwrap(), 65);
    }
}
