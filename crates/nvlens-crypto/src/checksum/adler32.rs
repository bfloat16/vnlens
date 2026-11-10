//! Adler-32 checksum (RFC 1950).

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd;

const MOD_ADLER: u32 = 65_521;

/// Computes Adler-32 with the standard initial value.
#[must_use]
pub fn checksum(data: &[u8]) -> u32 {
    let mut state = Adler32::default();
    state.update(data);
    state.checksum()
}

/// Incremental Adler-32 for independently sized streaming buffers.
#[derive(Clone, Copy, Debug)]
pub struct Adler32 {
    a: u32,
    b: u32,
}
impl Default for Adler32 {
    fn default() -> Self {
        Self { a: 1, b: 0 }
    }
}
impl Adler32 {
    pub fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(5_552) {
            #[cfg(target_arch = "x86_64")]
            let processed = simd::update(&mut self.a, &mut self.b, chunk);
            #[cfg(not(target_arch = "x86_64"))]
            let processed = 0;
            for &byte in &chunk[processed..] {
                self.a += u32::from(byte);
                self.b += self.a;
            }
            self.a %= MOD_ADLER;
            self.b %= MOD_ADLER;
        }
    }
    #[must_use]
    pub fn checksum(self) -> u32 {
        (self.b << 16) | self.a
    }
}

#[cfg(test)]
#[path = "../../tests/checksum/adler32.rs"]
mod tests;
