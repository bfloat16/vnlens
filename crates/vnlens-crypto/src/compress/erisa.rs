//! ERISA Nemesis adaptive arithmetic coding and phrase dictionary. Adapted
//! from GARbro's NemesisDecodeContext / ErisaProbModel (MIT, morkt 2015-2018),
//! verified against ERISADecodeContext sub_42B610, sub_42B990 and sub_50F030.
//! The 0x800 model slots, 64 KiB history, 256 phrase indices and arithmetic
//! postbits are codec constants, independent of input or output length.

use std::io::{self, Read};
use vnlens_io::{BinaryIo, BitOrder, BitReader, StreamBitReader};

mod huffman;
pub mod integer;
pub mod transform;
pub use huffman::{ErinaDecoder, GammaDecoder, HuffmanTree};

#[derive(Clone, Debug)]
struct Model {
    total: u32,
    symbols: Vec<(u16, i16)>,
    children: [(u16, Option<usize>); 128],
}

impl Model {
    fn full() -> Self {
        Self {
            total: 257,
            symbols: (0..256).map(|s| (1, s)).chain([(1, -1)]).collect(),
            children: [(0, None); 128],
        }
    }

    fn child(parent: &Self) -> Self {
        let mut symbols: Vec<_> = parent
            .symbols
            .iter()
            .filter_map(|&(count, symbol)| {
                (count >= 16 && symbol != -1).then_some((count >> 4, symbol))
            })
            .collect();
        symbols.push((1, -1));
        Self {
            total: symbols.iter().map(|&(count, _)| u32::from(count)).sum(),
            symbols,
            children: [(0, None); 128],
        }
    }

    fn increase(&mut self, mut index: usize) {
        self.symbols[index].0 += 1;
        while index > 0 && self.symbols[index - 1].0 < self.symbols[index].0 {
            self.symbols.swap(index - 1, index);
            index -= 1;
        }
        self.total += 1;
        if self.total >= 0x2000 {
            self.total = 0;
            for (count, _) in &mut self.symbols {
                *count = count.div_ceil(2);
                self.total += u32::from(*count);
            }
            for (count, _) in &mut self.children {
                *count >>= 1;
            }
        }
    }

    fn add(&mut self, symbol: i16) -> io::Result<()> {
        if self.symbols.len() >= 257 || self.symbols.iter().any(|&(_, s)| s == symbol) {
            return Err(invalid("Invalid ERISA escaped symbol"));
        }
        self.symbols.push((1, symbol));
        self.total += 1;
        Ok(())
    }
}

#[derive(Debug)]
struct Arithmetic<B> {
    bits: B,
    code: u32,
    augend: u32,
    postbits: u16,
}

trait CodeBits {
    fn bit(&mut self) -> io::Result<u8>;
    fn bits(&mut self, count: u8) -> io::Result<u32>;
}
impl<R: Read> CodeBits for StreamBitReader<R> {
    fn bit(&mut self) -> io::Result<u8> {
        self.read_bit()
    }
    fn bits(&mut self, count: u8) -> io::Result<u32> {
        self.read_bits(count)
    }
}
impl CodeBits for &mut BitReader<'_> {
    fn bit(&mut self) -> io::Result<u8> {
        self.read_bit()
    }
    fn bits(&mut self, count: u8) -> io::Result<u32> {
        self.read_bits(count)
    }
}
impl<B: CodeBits> Arithmetic<B> {
    fn new(mut bits: B) -> io::Result<Self> {
        let code = bits.bits(32)?;
        Ok(Self {
            bits,
            code,
            augend: 0xffff,
            postbits: 0,
        })
    }

    fn symbol(&mut self, model: &mut Model) -> io::Result<i16> {
        let mut acc = self.code.wrapping_mul(model.total) / self.augend;
        let mut cumulative = 0;
        let index = model
            .symbols
            .iter()
            .position(|&(count, _)| {
                if acc < u32::from(count) {
                    true
                } else {
                    acc -= u32::from(count);
                    cumulative += u32::from(count);
                    false
                }
            })
            .ok_or_else(|| invalid("Invalid ERISA arithmetic symbol"))?;
        let (count, symbol) = model.symbols[index];
        self.code = self
            .code
            .wrapping_sub((self.augend * cumulative).div_ceil(model.total));
        self.augend = self.augend * u32::from(count) / model.total;
        if self.augend == 0 {
            return Err(invalid("Empty ERISA arithmetic interval"));
        }
        while self.augend & 0x8000 == 0 {
            let bit = match self.bits.bit() {
                Ok(bit) => bit,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    self.postbits += 1;
                    if self.postbits >= 256 {
                        return Err(BinaryIo::unexpected_eof(
                            "ERISA arithmetic postbits exhausted",
                        ));
                    }
                    0
                }
                Err(error) => return Err(error),
            };
            self.code = (self.code << 1) | u32::from(bit);
            self.augend <<= 1;
        }
        self.code &= 0xffff;
        model.increase(index);
        Ok(symbol)
    }
}

/// Stateful streaming decoder. Each instance owns its arithmetic models and
/// dictionary. The stream's escape marker ends output; expected logical size
/// and any enclosing checksum are verified by the caller.
#[derive(Debug)]
pub struct NemesisDecoder<R> {
    arithmetic: Arithmetic<StreamBitReader<R>>,
    models: Vec<Model>,
    phrase_length: Model,
    phrase_index: Model,
    run_length: Model,
    history: Vec<u8>,
    lookup: Vec<[u16; 256]>,
    first: [u8; 256],
    position: u16,
    recent: [u8; 4],
    recent_index: usize,
    pending: usize,
    copy: Option<u16>,
    eof: bool,
}

impl<R: Read> NemesisDecoder<R> {
    pub fn new(reader: R) -> io::Result<Self> {
        Ok(Self {
            arithmetic: Arithmetic::new(StreamBitReader::new(reader, BitOrder::Msb))?,
            models: vec![Model::full()],
            phrase_length: Model::full(),
            phrase_index: Model::full(),
            run_length: Model::full(),
            history: vec![0; 0x10000],
            lookup: vec![[0; 256]; 256],
            first: [0; 256],
            position: 0,
            recent: [0; 4],
            recent_index: 0,
            pending: 0,
            copy: None,
            eof: false,
        })
    }

    fn append(&mut self, byte: u8) {
        self.recent[self.recent_index] = byte;
        self.recent_index = (self.recent_index + 1) & 3;
        let symbol = usize::from(byte);
        self.lookup[symbol][usize::from(self.first[symbol])] = self.position;
        self.first[symbol] = self.first[symbol].wrapping_add(1);
        self.history[usize::from(self.position)] = byte;
        self.position = self.position.wrapping_add(1);
    }

    fn next(&mut self) -> io::Result<Option<u8>> {
        const SHIFT: [u8; 4] = [1, 3, 4, 5];
        const LIMIT: [u16; 4] = [1, 8, 16, 32];
        loop {
            if self.eof {
                return Ok(None);
            }
            if self.pending != 0 {
                let byte = if let Some(position) = &mut self.copy {
                    let byte = self.history[usize::from(*position)];
                    *position = position.wrapping_add(1);
                    byte
                } else {
                    self.history[usize::from(self.position.wrapping_sub(1))]
                };
                self.pending -= 1;
                self.append(byte);
                return Ok(Some(byte));
            }
            let mut model = 0;
            let mut degree = 0;
            while degree < 4 {
                let recent = self.recent[(self.recent_index + 3 - degree) & 3];
                let slot = usize::from(recent >> SHIFT[degree]);
                let Some(child) = self.models[model].children[slot].1 else {
                    break;
                };
                model = child;
                degree += 1;
            }
            let mut symbol = self.arithmetic.symbol(&mut self.models[model])?;
            if symbol == -1 && model != 0 {
                symbol = self.arithmetic.symbol(&mut self.models[0])?;
                if symbol != -1 {
                    self.models[model].add(symbol)?;
                }
            }
            if symbol == -1 {
                let index = self.arithmetic.symbol(&mut self.phrase_index)?;
                if index == -1 {
                    self.eof = true;
                    return Ok(None);
                }
                let length = self.arithmetic.symbol(if index == 0 {
                    &mut self.run_length
                } else {
                    &mut self.phrase_length
                })?;
                if length <= 0 {
                    return Err(invalid("Invalid ERISA phrase length"));
                }
                self.pending = usize::try_from(length).map_err(io::Error::other)?;
                let last = self.history[usize::from(self.position.wrapping_sub(1))];
                self.copy = if index == 0 {
                    None
                } else {
                    let slot = self.first[usize::from(last)].wrapping_sub(index as u8);
                    let position = self.lookup[usize::from(last)][usize::from(slot)];
                    if self.history[usize::from(position)] != last {
                        return Err(invalid("Invalid ERISA phrase reference"));
                    }
                    Some(position.wrapping_add(1))
                };
                continue;
            }
            let byte = u8::try_from(symbol).map_err(|_| invalid("Invalid ERISA literal"))?;
            self.append(byte);
            // Root plus 0x800 subordinate slots are defined by the native codec.
            if self.models.len() <= 0x800 && degree < 4 {
                let slot = usize::from(byte >> SHIFT[degree]);
                self.models[model].children[slot].0 += 1;
                if self.models[model].children[slot].0 >= LIMIT[degree] {
                    let mut target = 0;
                    for (i, shift) in SHIFT.iter().enumerate().take(degree + 1) {
                        let recent = self.recent[(self.recent_index + 3 - i) & 3];
                        let slot = usize::from(recent >> shift);
                        if let Some(child) = self.models[target].children[slot].1 {
                            target = child;
                        } else {
                            let child = Model::child(&self.models[model]);
                            self.models[target].children[slot].1 = Some(self.models.len());
                            self.models.push(child);
                            break;
                        }
                    }
                }
            }
            return Ok(Some(byte));
        }
    }
}

impl<R: Read> Read for NemesisDecoder<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        for (i, byte) in buffer.iter_mut().enumerate() {
            match self.next()? {
                Some(value) => *byte = value,
                None => return Ok(i),
            }
        }
        Ok(buffer.len())
    }
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// Adaptive ERISA byte/run coding used by Nemesis-architecture ERI images.
/// Operation symbols and byte contexts share the same arithmetic interval.
#[derive(Debug)]
pub struct ProbabilityDecoder<'a, 'b> {
    arithmetic: Arithmetic<&'a mut BitReader<'b>>,
    models: Vec<Model>,
    operation: Model,
    run: Model,
    last: usize,
    pending: u32,
}
impl<'a, 'b> ProbabilityDecoder<'a, 'b> {
    pub fn new(bits: &'a mut BitReader<'b>) -> io::Result<Self> {
        Ok(Self {
            arithmetic: Arithmetic::new(bits)?,
            models: (0..256).map(|_| Model::full()).collect(),
            operation: Model::full(),
            run: Model::full(),
            last: 0,
            pending: 0,
        })
    }
    pub fn operation(&mut self) -> io::Result<u32> {
        Ok(u32::from(self.arithmetic.symbol(&mut self.operation)? as u8))
    }
    pub fn decode(
        &mut self,
        out: &mut [u8],
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> io::Result<()> {
        for (i, byte) in out.iter_mut().enumerate() {
            if i.is_multiple_of(4096)
                && cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
            {
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
            *byte = self.arithmetic.symbol(&mut self.models[self.last])? as u8;
            if *byte == 0 {
                self.pending = self.arithmetic.symbol(&mut self.run)? as u32;
            }
            self.last = usize::from(*byte);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/compress/erisa.rs"]
mod tests;
