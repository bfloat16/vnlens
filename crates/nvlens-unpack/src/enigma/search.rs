//! Full u32 salt search with independent CPU workers and section verification.
use super::extract::{StoredSection, verify_all};
use anyhow::{Context, Result};
use nvlens_crypto::{
    checksum::crc32,
    cipher::enigma::{Rc4, SectionProbe},
    compress::enigma as codec,
};
use std::{
    ops::Range,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    thread,
};

const END: u64 = 1u64 << 32;
const CHUNK: u64 = 4096;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Auto,
    Cpu,
    Wgpu,
}

fn screen_matches(section: &StoredSection, mut cipher: Rc4) -> bool {
    let data = section.ciphertext.as_ref();
    let mut prefix = [0; 64];
    let length = data.len().min(prefix.len());
    let first = length.min(8);
    for (out, &byte) in prefix[..first].iter_mut().zip(data) {
        *out = cipher.byte(byte);
    }
    if section.descriptor.flags & 1 != 0
        && !codec::plausible_prefix(
            &prefix[..first],
            data.len(),
            section.descriptor.expanded_size,
        )
    {
        return false;
    }
    for (out, &byte) in prefix[first..length].iter_mut().zip(&data[first..]) {
        *out = cipher.byte(byte);
    }
    if section.descriptor.flags & 1 != 0
        && !codec::plausible_prefix(
            &prefix[..length],
            data.len(),
            section.descriptor.expanded_size,
        )
    {
        return false;
    }
    let mut crc = crc32::ieee(0, &prefix[..length]);
    let mut block = [0; 256];
    for chunk in data[length..].chunks(block.len()) {
        for (out, &byte) in block.iter_mut().zip(chunk) {
            *out = cipher.byte(byte);
        }
        crc = crc32::ieee(crc, &block[..chunk.len()]);
    }
    crc == section.descriptor.crc32
}

pub(super) fn search(
    sections: &[StoredSection],
    mode: Mode,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Result<Option<u32>> {
    super::check(cancel)?;
    if verify_all(sections, None).is_ok() {
        return Ok(None);
    }
    let screen = sections
        .iter()
        .filter(|s| s.descriptor.flags & 8 != 0 && !s.ciphertext.is_empty())
        .min_by_key(|s| s.ciphertext.len())
        .context("No encrypted Enigma section to search")?;
    if mode != Mode::Cpu {
        #[cfg(feature = "wgpu")]
        {
            // Driver initialization and shader compilation can unwind inside
            // CubeCL. Automatic mode may use the CPU after a backend failure.
            let gpu = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || -> Result<Option<u32>> {
                    use nvlens_crypto::cipher::enigma::gpu::{BATCH, GpuProbe};
                    let mut probe = GpuProbe::new(
                        &screen.ciphertext,
                        &screen.descriptor.seed,
                        u32::try_from(screen.descriptor.expanded_size)?,
                        screen.descriptor.crc32,
                        screen.descriptor.flags & 1 != 0,
                    )?;
                    tracing::info!("Searching Enigma section salt on WGPU");
                    for start in (0..END).step_by(BATCH as usize) {
                        super::check(cancel)?;
                        let end = (start + BATCH).min(END);
                        for salt in probe.scan(start, end)? {
                            super::check(cancel)?;
                            if verify_all(sections, Some(salt)).is_ok() {
                                progress(end, END);
                                return Ok(Some(salt));
                            }
                        }
                        progress(end, END);
                    }
                    Ok(None)
                },
            ));
            super::check(cancel)?;
            match gpu {
                Ok(Ok(found)) => {
                    return found
                        .map(Some)
                        .context("No salt passed section verification");
                }
                Ok(Err(error)) if mode == Mode::Wgpu => return Err(error),
                Err(_) if mode == Mode::Wgpu => {
                    anyhow::bail!("WGPU driver failed during salt search")
                }
                _ => tracing::warn!("WGPU salt search unavailable; selecting CPU"),
            }
        }
        #[cfg(not(feature = "wgpu"))]
        if mode == Mode::Wgpu {
            anyhow::bail!("WGPU salt search is not enabled");
        }
    }
    find(sections, screen, 0..END, cancel, progress)?
        .map(Some)
        .context("No salt passed section verification")
}

fn find(
    sections: &[StoredSection],
    screen: &StoredSection,
    range: Range<u64>,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Result<Option<u32>> {
    let threads = thread::available_parallelism()?.get();
    let probe = SectionProbe::new(screen.descriptor.seed);
    let next = AtomicU64::new(range.start);
    let found = AtomicU64::new(END);
    let completed = std::sync::Mutex::new(0u64);
    tracing::info!(threads, "Searching Enigma section salt on CPU");
    thread::scope(|scope| {
        for _ in 0..threads {
            let (probe, next, found) = (&probe, &next, &found);
            let completed = &completed;
            scope.spawn(move || {
                while !cancel.load(Ordering::Relaxed) && found.load(Ordering::Relaxed) == END {
                    let start = next.fetch_add(CHUNK, Ordering::Relaxed);
                    if start >= range.end {
                        break;
                    }
                    let stop = (start + CHUNK).min(range.end);
                    let mut value = start;
                    while value + 4 <= stop {
                        if cancel.load(Ordering::Relaxed) || found.load(Ordering::Relaxed) != END {
                            return;
                        }
                        for (lane, cipher) in probe.ciphers(value as u32).into_iter().enumerate() {
                            let salt = (value + lane as u64) as u32;
                            if screen_matches(screen, cipher)
                                && verify_all(sections, Some(salt)).is_ok()
                            {
                                found.store(u64::from(salt), Ordering::Relaxed);
                                return;
                            }
                        }
                        value += 4;
                    }
                    for value in value..stop {
                        if cancel.load(Ordering::Relaxed) || found.load(Ordering::Relaxed) != END {
                            return;
                        }
                        if screen_matches(screen, probe.cipher(value as u32))
                            && verify_all(sections, Some(value as u32)).is_ok()
                        {
                            found.store(value, Ordering::Relaxed);
                            return;
                        }
                    }
                    if let Ok(mut count) = completed.lock() {
                        *count += stop - start;
                        progress(*count, range.end - range.start);
                    }
                }
            });
        }
    });
    super::check(cancel)?;
    let salt = found.load(Ordering::Relaxed);
    Ok((salt != END).then_some(salt as u32))
}

#[cfg(test)]
#[path = "../../tests/enigma/search.rs"]
mod tests;
