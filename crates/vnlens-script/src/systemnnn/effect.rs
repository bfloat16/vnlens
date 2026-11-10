//! CEffect registrations at 0x47bc30, initializers at the registered
//! vtable +4, and interpolation at 0x4f1360. Offsets below are original
//! callback parameter indexes (after layer and effect IDs).
//! RGB ordering is verified by CEffectCharaFlash -> CPicture::0x46f5a0
//! -> 0x474e60 packing R:G:B into bits 16:8:0, not inferred from names.
use crate::ir::ArgName as A;

pub(super) fn argument(effect: u32, index: usize) -> A {
    // Initializers store this parameter in the effect's frame duration
    // (layer +0x70). Fill instead hard-codes that field to 9999.
    if index == 0
        && matches!(effect, 9..=11 | 20 | 31 | 33 | 50 | 52 | 61 | 64..=66 | 74 | 80 | 90 | 99 | 100 | 125)
    {
        return A::Duration;
    }
    match (effect, index) {
        // Fill 0x4981a0; fade 0x498260/0x498970; light 0x49c270;
        // character flash 0x48b1c0; color addition 0x487dc0.
        (10 | 11 | 20 | 54 | 90 | 99, 1) => A::Red,
        (10 | 11 | 20 | 54 | 90 | 99, 2) => A::Green,
        (10 | 11 | 20 | 54 | 90 | 99, 3) => A::Blue,
        (10 | 11 | 20, 4) => A::Easing,
        (10 | 11 | 20, 5) => A::EasingParameter,
        (99, 8) => A::Easing,
        (99, 9) => A::EasingParameter,
        _ => A::Unknown((index + 3) as u64),
    }
}
