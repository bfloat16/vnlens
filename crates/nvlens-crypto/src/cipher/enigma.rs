// Adapted from bfloat16/enigma_rs (Apache-2.0), commit 18fae558.
//! RC4 shared by configuration decoding (16 bytes) and sections (16/32 bytes).

#[cfg(feature = "wgpu")]
#[allow(unsafe_code)]
pub mod gpu;

pub struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl std::fmt::Debug for Rc4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Rc4([redacted])")
    }
}
impl Rc4 {
    /// Starts PRGA from a stored EVB table; arbitrary byte tables are legal.
    #[must_use]
    pub fn from_state(state: [u8; 256]) -> Self {
        Self { state, i: 0, j: 0 }
    }
    pub fn new<const N: usize>(key: &[u8; N]) -> std::io::Result<Self> {
        if N == 0 {
            return Err(nvlens_io::BinaryIo::invalid_input("RC4 key is empty"));
        }

        let mut state = std::array::from_fn(|i| i as u8);
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }
        Ok(Self { state, i: 0, j: 0 })
    }

    #[inline(always)]
    pub fn byte(&mut self, byte: u8) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);
        let at = self.state[self.i as usize].wrapping_add(self.state[self.j as usize]);
        byte ^ self.state[at as usize]
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            *byte = self.byte(*byte);
        }
    }
}

pub fn decipher<const N: usize>(data: &[u8], key: &[u8; N]) -> std::io::Result<Vec<u8>> {
    let mut result = data.to_vec();
    Rc4::new(key)?.apply(&mut result);
    Ok(result)
}

pub fn section_key(seed: &[u8; 16], salt: u32) -> [u8; 32] {
    let mut key = [0; 32];
    key[..16].copy_from_slice(seed);
    let mut bytes = [0; 4];
    nvlens_io::BinaryWriter::u32_le(salt, &mut bytes);
    key[16..].copy_from_slice(&crate::hash::md5::digest(&bytes));
    key
}

/// The first 16 KSA rounds depend only on the seed. Reuse them for every salt.
pub struct SectionProbe {
    initial: [u8; 256],
    initial_j: u8,
    seed: [u8; 16],
}

impl std::fmt::Debug for SectionProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SectionProbe([redacted])")
    }
}
impl SectionProbe {
    pub fn new(seed: [u8; 16]) -> Self {
        let mut state = std::array::from_fn(|i| i as u8);
        let mut j = 0u8;
        for i in 0..16 {
            j = j.wrapping_add(state[i]).wrapping_add(seed[i]);
            state.swap(i, j as usize);
        }
        Self {
            initial: state,
            initial_j: j,
            seed,
        }
    }

    #[inline]
    pub fn cipher(&self, salt: u32) -> Rc4 {
        let key = section_key(&self.seed, salt);
        let mut state = self.initial;
        let mut j = self.initial_j;
        for i in 16..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i & 31]);
            state.swap(i, j as usize);
        }
        Rc4 { state, i: 0, j: 0 }
    }

    /// Interleave independent KSA chains so the CPU can overlap indexed loads.
    pub fn ciphers(&self, start: u32) -> [Rc4; 4] {
        let salts = std::array::from_fn(|n| {
            let mut bytes = [0; 4];
            nvlens_io::BinaryWriter::u32_le(start.wrapping_add(n as u32), &mut bytes);
            bytes
        });
        let digests = crate::hash::md5::digest_four_suffix(&[], &salts);
        let keys: [_; 4] = std::array::from_fn(|n| {
            let mut key = [0; 32];
            key[..16].copy_from_slice(&self.seed);
            key[16..].copy_from_slice(&digests[n]);
            key
        });
        let mut states = [self.initial; 4];
        let mut js = [self.initial_j; 4];
        for i in 16..256 {
            for lane in 0..4 {
                let state = &mut states[lane];
                js[lane] = js[lane]
                    .wrapping_add(state[i])
                    .wrapping_add(keys[lane][i & 31]);
                state.swap(i, js[lane] as usize);
            }
        }
        states.map(|state| Rc4 { state, i: 0, j: 0 })
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/enigma.rs"]
mod tests;
