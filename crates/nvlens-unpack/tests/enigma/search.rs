use super::*;
use crate::enigma::config::Descriptor;
use nvlens_crypto::cipher::enigma::{decipher, section_key};

#[test]
fn cpu_search_boundaries_and_cancellation() -> Result<()> {
    let cancel = AtomicBool::new(false);
    let seed = [0x31; 16];
    let packed = [0x00, 0xa4, 0x01, 0x70, 0x80, 0x8f, 0xf7, 0xec, 0];
    for (salt, range) in [(0, 0..7), (5, 0..7), (u32::MAX, (END - 7)..END)] {
        let section = StoredSection {
            descriptor: Descriptor {
                index: 0,
                enabled: true,
                flags: 9,
                packed_size: packed.len(),
                expanded_size: 512,
                rva: 0x1000,
                characteristics: 0x40000040,
                seed,
                crc32: crc32::ieee(0, &packed),
            },
            ciphertext: decipher(&packed, &section_key(&seed, salt))?.into(),
        };
        assert_eq!(
            find(
                std::slice::from_ref(&section),
                &section,
                range,
                &cancel,
                &|_, _| {}
            )?,
            Some(salt)
        );
    }
    cancel.store(true, Ordering::Relaxed);
    let error = search(&[], Mode::Cpu, &cancel, &|_, _| {})
        .err()
        .context("Expected cancellation")?;
    assert!(matches!(
        error.downcast_ref::<nvlens_core::Error>(),
        Some(nvlens_core::Error::Cancelled)
    ));
    Ok(())
}
