use super::*;
use nvlens_io::BinaryWriter;

fn literal_dsc(data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 544];
    bytes[..16].copy_from_slice(b"DSC FORMAT 1.00\0");
    BinaryWriter::u32_le(data.len() as u32, &mut bytes[20..]);
    BinaryWriter::u32_le(data.len() as u32, &mut bytes[24..]);
    let mut generator = Generator::new(0);
    for (index, byte) in bytes[32..].iter_mut().enumerate() {
        *byte = generator
            .next_byte()
            .wrapping_add(if index < 256 { 8 } else { 0 });
    }
    bytes.extend_from_slice(data);
    bytes
}
#[test]
fn dsc_canonical_literals_and_truncated_payloads() -> Result<()> {
    let data: Vec<_> = (0..=255).collect();
    let bytes = literal_dsc(&data);
    assert_eq!(dsc(&bytes)?, data);
    for end in [0, 15, 31, 543, 544, bytes.len() - 1] {
        assert!(dsc(&bytes[..end]).is_err());
    }
    let mut bad = bytes.clone();
    BinaryWriter::u32_le(1, &mut bad[20..]);
    assert!(dsc(&bad).is_err());
    assert!(dsc(&literal_dsc(&[]))?.is_empty());
    Ok(())
}
#[test]
fn dsc_sparse_deep_codes_and_overlapping_back_references() -> Result<()> {
    for (depth, tokens, size, stream) in [(255, 1, 1, vec![0; 32]), (1, 3, 4, vec![0x20, 0])] {
        let mut bytes = literal_dsc(&[]);
        BinaryWriter::u32_le(size, &mut bytes[20..]);
        BinaryWriter::u32_le(tokens, &mut bytes[24..]);
        let mut generator = Generator::new(0);
        for (symbol, byte) in bytes[32..].iter_mut().enumerate() {
            let length = if symbol == 65 || (depth == 1 && symbol == 256) {
                depth
            } else {
                0
            };
            *byte = generator.next_byte().wrapping_add(length);
        }
        bytes.extend(stream);
        assert_eq!(dsc(&bytes)?, vec![b'A'; size as usize]);
    }
    Ok(())
}
#[test]
fn lookup_matches_bitwise_tree_for_both_weight_orders() -> Result<()> {
    for order in [WeightOrder::V1, WeightOrder::V2] {
        let weights: Vec<_> = (0..256).map(|i| 1 + (i * 37) % 101).collect();
        let tree = Huffman::new(&weights, order)?;
        let bytes: Vec<_> = (0..4096).map(|i| ((i * 19 + 23) % 256) as u8).collect();
        let mut fast = BitReader::new(&bytes, BitOrder::Msb);
        let mut slow = BitReader::new(&bytes, BitOrder::Msb);
        for _ in 0..1000 {
            let mut node = tree.root;
            while let Some(children) = tree.nodes[node].children {
                node = children[usize::from(slow.read_bit()?)]
                    .ok_or_else(|| invalid("Missing test branch"))?;
            }
            assert_eq!(tree.decode(&mut fast)?, node);
        }
    }
    Ok(())
}
