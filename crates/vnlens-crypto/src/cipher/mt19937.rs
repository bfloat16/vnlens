//! Shared MT19937 state with standard and legacy initialization.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd;

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908_B0DF;
const UPPER_MASK: u32 = 0x8000_0000;
const LOWER_MASK: u32 = 0x7FFF_FFFF;

#[derive(Clone)]
pub(super) struct Mt19937 {
    mt: [u32; N],
    index: usize,
}

impl Mt19937 {
    /// Original MT initialization used by ExHIBIT's UxRandomMT.
    pub(super) fn legacy(mut seed: u32) -> Self {
        let mut mt = [0; N];
        for word in &mut mt {
            let upper = seed & 0xffff_0000;
            seed = seed.wrapping_mul(69069).wrapping_add(1);
            *word = upper | (seed >> 16);
            seed = seed.wrapping_mul(69069).wrapping_add(1);
        }
        Self { mt, index: N }
    }

    pub(super) fn from_slice(keys: &[u32]) -> Self {
        let mut this = Self::seed_from_u32(19_650_218);
        let mut i = 1usize;
        let mut j = 0usize;
        let mut k = N.max(keys.len());
        while k > 0 {
            let x = this.mt[i - 1] ^ (this.mt[i - 1] >> 30);
            this.mt[i] = (this.mt[i] ^ x.wrapping_mul(1_664_525))
                .wrapping_add(keys[j])
                .wrapping_add(u32::try_from(j).unwrap_or(u32::MAX));
            i += 1;
            j += 1;
            if i >= N {
                this.mt[0] = this.mt[N - 1];
                i = 1;
            }
            if j >= keys.len() {
                j = 0;
            }
            k -= 1;
        }

        k = N - 1;
        while k > 0 {
            let x = this.mt[i - 1] ^ (this.mt[i - 1] >> 30);
            this.mt[i] = (this.mt[i] ^ x.wrapping_mul(1_566_083_941))
                .wrapping_sub(u32::try_from(i).unwrap_or(u32::MAX));
            i += 1;
            if i >= N {
                this.mt[0] = this.mt[N - 1];
                i = 1;
            }
            k -= 1;
        }

        this.mt[0] = UPPER_MASK;
        this
    }

    pub(super) fn seed_from_u32(seed: u32) -> Self {
        let mut mt = [0u32; N];
        mt[0] = seed;
        for i in 1..N {
            let prev = mt[i - 1] ^ (mt[i - 1] >> 30);
            mt[i] = 1_812_433_253u32
                .wrapping_mul(prev)
                .wrapping_add(u32::try_from(i).unwrap_or(u32::MAX));
        }
        Self { mt, index: N }
    }

    pub(super) fn next_u32(&mut self) -> u32 {
        if self.index >= N {
            self.twist();
        }

        let mut y = self.mt[self.index];
        self.index += 1;

        y ^= y >> 11;
        y ^= (y << 7) & 0x9D2C_5680;
        y ^= (y << 15) & 0xEFC6_0000;
        y ^ (y >> 18)
    }

    fn twist(&mut self) {
        #[cfg(target_arch = "x86_64")]
        simd::twist(&mut self.mt);
        #[cfg(not(target_arch = "x86_64"))]
        twist_scalar(&mut self.mt);
        self.index = 0;
    }
}

#[cfg(any(test, not(target_arch = "x86_64")))]
fn twist_scalar(mt: &mut [u32; N]) {
    for i in 0..N {
        let y = (mt[i] & UPPER_MASK) | (mt[(i + 1) % N] & LOWER_MASK);
        let mut next = mt[(i + M) % N] ^ (y >> 1);
        if y & 1 != 0 {
            next ^= MATRIX_A;
        }
        mt[i] = next;
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/mt19937.rs"]
mod tests;
