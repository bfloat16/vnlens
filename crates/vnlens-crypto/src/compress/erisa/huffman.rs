//! ERINA adaptive Huffman and interleaved Gamma run-length coding, adapted
//! from GARbro EriReader.cs (MIT, morkt). Huffman weights and rebuild order
//! match HuffmanTree::Normalize / HalfAndRebuild, including the order-0 freeze.
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_io::{BinaryIo, BitReader};

const ROOT: usize = 0x200;
const LEAF: i32 = i32::MIN;
const EMPTY: i32 = 0x8000;

#[derive(Clone, Copy, Debug, Default)]
struct Node {
    weight: u16,
    parent: usize,
    child: i32,
}

#[derive(Debug)]
pub struct HuffmanTree {
    nodes: Vec<Node>,
    start: usize,
}
impl Default for HuffmanTree {
    fn default() -> Self {
        let mut nodes = vec![Node::default(); ROOT + 1];
        nodes[ROOT].child = EMPTY;
        nodes[ROOT].parent = EMPTY as usize;
        Self { nodes, start: ROOT }
    }
}
impl HuffmanTree {
    fn recount(&mut self, parent: usize) {
        let child = self.nodes[parent].child as usize;
        self.nodes[parent].weight = self.nodes[child].weight + self.nodes[child + 1].weight;
    }
    fn move_children(&mut self, from: usize, to: usize) {
        let child = self.nodes[from].child;
        if child >= 0 {
            self.nodes[child as usize].parent = to;
            self.nodes[child as usize + 1].parent = to;
        }
    }
    fn normalize(&mut self, mut entry: usize) {
        while entry < ROOT {
            let weight = self.nodes[entry].weight;
            let mut swap = entry + 1;
            while swap < ROOT && self.nodes[swap].weight < weight {
                swap += 1;
            }
            swap -= 1;
            if swap == entry {
                entry = self.nodes[entry].parent;
                self.recount(entry);
                continue;
            }
            self.move_children(entry, swap);
            self.move_children(swap, entry);
            let entry_parent = self.nodes[entry].parent;
            let swap_parent = self.nodes[swap].parent;
            self.nodes.swap(entry, swap);
            self.nodes[entry].parent = entry_parent;
            self.nodes[swap].parent = swap_parent;
            self.recount(swap_parent);
            entry = swap_parent;
        }
    }
    fn rebuild(&mut self) {
        let mut next = ROOT;
        for i in (self.start..ROOT).rev() {
            if self.nodes[i].child < 0 {
                let mut node = self.nodes[i];
                node.weight = node.weight.div_ceil(2);
                self.nodes[next] = node;
                next -= 1;
            }
        }
        next += 1;
        let mut i = self.start;
        loop {
            self.nodes[i] = self.nodes[next];
            self.nodes[i + 1] = self.nodes[next + 1];
            next += 2;
            self.move_children(i, i);
            self.move_children(i + 1, i + 1);
            let weight = self.nodes[i].weight + self.nodes[i + 1].weight;
            if next <= ROOT {
                let mut j = next;
                while j <= ROOT && weight > self.nodes[j].weight {
                    self.nodes[j - 1] = self.nodes[j];
                    j += 1;
                }
                self.nodes[j - 1].weight = weight;
                self.nodes[j - 1].child = i as i32;
                next -= 1;
            } else {
                self.nodes[ROOT] = Node {
                    weight,
                    parent: EMPTY as usize,
                    child: i as i32,
                };
                self.nodes[i].parent = ROOT;
                self.nodes[i + 1].parent = ROOT;
                break;
            }
            i += 2;
        }
    }
    fn add(&mut self, code: i32) {
        if self.start == 0 {
            let index = usize::from(self.nodes[0].child == -1);
            self.nodes[index].child = LEAF | code;
            return;
        }
        self.start -= 2;
        let i = self.start;
        self.nodes[i].weight = 1;
        self.nodes[i].child = LEAF | code;
        if self.nodes[ROOT].child != EMPTY {
            self.nodes[i + 1] = self.nodes[i + 2];
            self.nodes[i + 2].weight = 1 + self.nodes[i + 1].weight;
            self.nodes[i + 2].parent = self.nodes[i + 1].parent;
            self.nodes[i + 2].child = i as i32;
            self.nodes[i].parent = i + 2;
            self.nodes[i + 1].parent = i + 2;
            self.normalize(i + 2);
        } else {
            self.nodes[i].parent = ROOT;
            self.nodes[i + 1] = Node {
                weight: 1,
                parent: ROOT,
                child: -1,
            };
            self.nodes[ROOT].weight = 2;
            self.nodes[ROOT].child = i as i32;
        }
    }
    pub fn decode(
        &mut self,
        bits: &mut BitReader<'_>,
        length: bool,
        order_zero: bool,
    ) -> io::Result<u32> {
        if self.nodes[ROOT].child != EMPTY {
            let mut child = self.nodes[ROOT].child;
            let mut entry = ROOT;
            while child >= 0 {
                entry = child as usize + usize::from(bits.read_bit()?);
                child = self.nodes[entry].child;
            }
            if !order_zero || self.nodes[ROOT].weight < 0x3fff {
                self.nodes[entry].weight += 1;
                self.normalize(entry);
                if self.nodes[ROOT].weight >= 0x4000 {
                    self.rebuild();
                }
            }
            if child != -1 {
                return Ok((child & i32::MAX) as u32);
            }
        }
        let value = if length {
            gamma(bits)?
        } else {
            bits.read_bits(8)?
        };
        if value > i32::MAX as u32 {
            return Err(BinaryIo::invalid_input("ERINA code exceeds signed field"));
        }
        self.add(value as i32);
        Ok(value)
    }
}

/// ERISA's Gamma code: zero encodes one; otherwise data and continuation bits
/// alternate. Range derives from the native signed 32-bit code representation.
fn gamma(bits: &mut BitReader<'_>) -> io::Result<u32> {
    if bits.read_bit()? == 0 {
        return Ok(1);
    }
    let mut base = 2u32;
    let mut code = 0u32;
    loop {
        let bit = u32::from(bits.read_bit()?);
        code = code
            .checked_mul(2)
            .and_then(|v| v.checked_add(bit))
            .ok_or_else(|| BinaryIo::invalid_input("ERISA Gamma code overflow"))?;
        if bits.read_bit()? == 0 {
            return base
                .checked_add(code)
                .ok_or_else(|| BinaryIo::invalid_input("ERISA Gamma code overflow"));
        }
        base = base
            .checked_mul(2)
            .ok_or_else(|| BinaryIo::invalid_input("ERISA Gamma code overflow"))?;
    }
}

#[derive(Debug, Default)]
pub struct GammaDecoder {
    nonzero: bool,
    pending: u32,
}
impl GammaDecoder {
    pub fn reset(&mut self, bits: &mut BitReader<'_>) -> io::Result<()> {
        self.nonzero = bits.read_bit()? != 0;
        self.pending = 0;
        Ok(())
    }
    pub fn decode(
        &mut self,
        bits: &mut BitReader<'_>,
        out: &mut [u8],
        cancel: Option<&AtomicBool>,
    ) -> io::Result<()> {
        for (i, byte) in out.iter_mut().enumerate() {
            if i.is_multiple_of(4096) && cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "ERISA decoding cancelled",
                ));
            }
            if self.pending == 0 {
                self.pending = gamma(bits)?;
            }
            *byte = if self.nonzero {
                let negative = bits.read_bit()? != 0;
                let code = gamma(bits)? as u8;
                if code == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid ERISA nonzero Gamma byte",
                    ));
                }
                if negative { code.wrapping_neg() } else { code }
            } else {
                0
            };
            self.pending -= 1;
            if self.pending == 0 {
                self.nonzero = !self.nonzero;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ErinaDecoder {
    trees: Vec<Option<HuffmanTree>>,
    last: usize,
    pending: u32,
    order_zero: bool,
}
impl ErinaDecoder {
    #[must_use]
    pub fn new(order_zero: bool) -> Self {
        Self {
            trees: (0..257).map(|_| None).collect(),
            last: 0,
            pending: 0,
            order_zero,
        }
    }
    pub fn decode(
        &mut self,
        bits: &mut BitReader<'_>,
        out: &mut [u8],
        cancel: Option<&AtomicBool>,
    ) -> io::Result<()> {
        for (i, byte) in out.iter_mut().enumerate() {
            if i.is_multiple_of(4096) && cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "ERISA decoding cancelled",
                ));
            }
            if self.pending != 0 {
                self.pending -= 1;
                *byte = 0;
                continue;
            }
            let tree = self.trees[self.last].get_or_insert_with(HuffmanTree::default);
            let symbol = tree.decode(bits, false, self.order_zero)? as u8;
            *byte = symbol;
            if symbol == 0 {
                let tree = self.trees[256].get_or_insert_with(HuffmanTree::default);
                self.pending = tree.decode(bits, true, self.order_zero)? - 1;
            }
            self.last = if self.order_zero {
                0
            } else {
                usize::from(symbol)
            };
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../../tests/compress/erisa/huffman.rs"]
mod tests;
