//! BGI DSC FORMAT 1.00: sub_1400B7DD0 builds canonical Huffman codes from
//! encrypted depths; sub_1400B7C60 reads MSB bits and 12-bit LZ distances.
//! The PRNG follows sub_1400F5750, with explicitly wrapping 32-bit state.

use nvlens_io::{BinaryReader, BitOrder, BitReader};
use std::io::{Error, ErrorKind, Result};

pub struct Generator(u32);
impl std::fmt::Debug for Generator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generator").finish_non_exhaustive()
    }
}
impl Generator {
    #[must_use]
    pub fn new(seed: u32) -> Self {
        Self(seed)
    }
    pub fn next_byte(&mut self) -> u8 {
        let low = 20021 * (self.0 & 0xffff);
        let high = (low >> 16)
            .wrapping_add(346u32.wrapping_mul(self.0))
            .wrapping_add(20021 * (self.0 >> 16));
        self.0 = (low & 0xffff)
            .wrapping_add(1)
            .wrapping_add(high.wrapping_shl(16));
        high as u8
    }
}

#[derive(Debug)]
enum Node {
    Leaf(u16),
    Branch([usize; 2]),
    Vacant,
}

/// Decompresses one complete DSC payload. The declared output and token counts
/// must agree with the stream; malformed trees and backward references fail.
pub fn dsc(data: &[u8]) -> Result<Vec<u8>> {
    let mut r = BinaryReader::new(data);
    if r.read_bytes(16)? != b"DSC FORMAT 1.00\0" {
        return Err(invalid("Invalid DSC signature"));
    }
    let mut generator = Generator::new(r.read_u32_le()?);
    let output_size = r.read_u32_le()? as usize;
    let tokens = r.read_u32_le()?;
    r.read_bytes(4)?;
    let mut lengths = Vec::new();
    for (symbol, &byte) in r.read_bytes(512)?.iter().enumerate() {
        let depth = byte.wrapping_sub(generator.next_byte());
        if depth != 0 {
            lengths.push((depth, symbol as u16));
        }
    }
    lengths.sort_unstable();
    if tokens == 0 && output_size == 0 {
        return Ok(Vec::new());
    }
    if lengths.is_empty() {
        return Err(invalid("Empty DSC Huffman alphabet"));
    }
    let mut nodes = vec![Node::Vacant];
    let mut code = Vec::<u8>::new();
    for (number, &(depth, symbol)) in lengths.iter().enumerate() {
        if number != 0 {
            let Some(zero) = code.iter().rposition(|&bit| bit == 0) else {
                return Err(invalid("Oversubscribed DSC Huffman tree"));
            };
            code[zero] = 1;
            code[zero + 1..].fill(0);
        }
        code.resize(usize::from(depth), 0);
        let mut index = 0;
        for &bit in &code {
            if matches!(nodes[index], Node::Vacant) {
                let child = nodes.len();
                nodes[index] = Node::Branch([child, child + 1]);
                nodes.extend([Node::Vacant, Node::Vacant]);
            }
            let Node::Branch(children) = nodes[index] else {
                return Err(invalid("Overlapping DSC Huffman codes"));
            };
            index = children[usize::from(bit)];
        }
        if !matches!(nodes[index], Node::Vacant) {
            return Err(invalid("Overlapping DSC Huffman codes"));
        }
        nodes[index] = Node::Leaf(symbol);
    }
    let mut bits = BitReader::new(&data[r.position()..], BitOrder::Msb);
    let mut out = Vec::new();
    for _ in 0..tokens {
        let mut index = 0;
        let symbol = loop {
            match nodes[index] {
                Node::Leaf(symbol) => break symbol,
                Node::Branch(children) => index = children[usize::from(bits.read_bit()?)],
                Node::Vacant => return Err(invalid("Missing DSC Huffman node")),
            }
        };
        if symbol < 256 {
            if out.len() == output_size {
                return Err(invalid("DSC output exceeds declared size"));
            }
            out.push(symbol as u8);
        } else {
            let distance = bits.read_bits(12)? as usize + 2;
            let count = usize::from(symbol & 255) + 2;
            if distance > out.len() || count > output_size - out.len() {
                return Err(invalid("Invalid DSC back reference"));
            }
            super::copy::append(&mut out, distance, count);
        }
    }
    if out.len() != output_size {
        return Err(invalid("DSC output size mismatch"));
    }
    Ok(out)
}

fn invalid(reason: &str) -> Error {
    Error::new(ErrorKind::InvalidData, reason)
}

/// Weight-tree variants used by CompressedBG. The v2 selector starts the
/// second candidate scan at index 2 (sub_140104AF0); v1 scans from zero.
#[derive(Clone, Copy, Debug)]
pub enum WeightOrder {
    V1,
    V2,
}

#[derive(Debug)]
pub struct Huffman {
    nodes: Vec<WeightNode>,
    root: usize,
    lookup: [(usize, u8); 256],
}
#[derive(Debug)]
struct WeightNode {
    weight: u64,
    active: bool,
    children: Option<[Option<usize>; 2]>,
}

impl Huffman {
    pub fn new(weights: &[u32], order: WeightOrder) -> Result<Self> {
        let mut nodes: Vec<_> = weights
            .iter()
            .map(|&weight| WeightNode {
                weight: u64::from(weight),
                active: weight != 0,
                children: None,
            })
            .collect();
        let total: u64 = weights.iter().map(|&v| u64::from(v)).sum();
        if total == 0 {
            return Err(invalid("Empty BGI Huffman weights"));
        }
        loop {
            let mut children = [None; 2];
            let mut weight = 0;
            for (which, child) in children.iter_mut().enumerate() {
                let Some(first) = nodes.iter().position(|node| node.active) else {
                    break;
                };
                let start = match order {
                    WeightOrder::V1 => 0,
                    WeightOrder::V2 => which + 1,
                };
                let mut best = first;
                for index in start..nodes.len() {
                    if nodes[index].active && nodes[index].weight < nodes[best].weight {
                        best = index;
                    }
                }
                nodes[best].active = false;
                weight += nodes[best].weight;
                *child = Some(best);
            }
            let root = nodes.len();
            nodes.push(WeightNode {
                weight,
                active: true,
                children: Some(children),
            });
            if weight == total {
                let lookup = std::array::from_fn(|prefix| {
                    let mut index = root;
                    let mut consumed = 0;
                    while let Some(children) = nodes[index].children {
                        if consumed == 8 {
                            break;
                        }
                        let Some(child) = children[(prefix >> (7 - consumed)) & 1] else {
                            return (usize::MAX, 0);
                        };
                        index = child;
                        consumed += 1;
                    }
                    (index, consumed)
                });
                return Ok(Self {
                    nodes,
                    root,
                    lookup,
                });
            }
        }
    }
    pub fn decode(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        let mut node = self.root;
        if let Some(prefix) = bits.peek_byte() {
            let (index, count) = self.lookup[usize::from(prefix)];
            if index == usize::MAX {
                return Err(invalid("Invalid Huffman branch"));
            }
            bits.read_bits(count)?;
            node = index;
        }
        while let Some(children) = self.nodes[node].children {
            node = children[usize::from(bits.read_bit()?)]
                .ok_or_else(|| invalid("Invalid Huffman branch"))?;
        }
        Ok(node)
    }
}

#[cfg(test)]
#[path = "../../tests/compress/bgi.rs"]
mod tests;
