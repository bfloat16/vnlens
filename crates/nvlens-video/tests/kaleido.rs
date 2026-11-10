use super::*;
use nvlens_core::Secret;
use std::{
    io::{Read, Seek, SeekFrom},
    sync::{Mutex, atomic::Ordering},
};
fn options() -> ArchiveOptions {
    let mut options = ArchiveOptions::default();
    options
        .keys
        .insert("kaleido_movie", Secret::new(b"fixture-base".to_vec()));
    options
}
fn encrypt(data: &mut [u8]) {
    MdfStream::new("fixture-basemovie.webm", Some(PERIOD)).apply(data);
}
#[test]
fn offset_cipher_crosses_mt_and_key_boundaries_and_preserves_independent_cursors() -> Result<()> {
    let mut plain: Vec<_> = (0..13001).map(|i| (i * 37 + 11) as u8).collect();
    plain[..4].copy_from_slice(&[0x1a, 0x45, 0xdf, 0xa3]);
    let mut bytes = plain.clone();
    encrypt(&mut bytes);
    let source = Kaleido.decode_source(
        Arc::new(Arc::<[u8]>::from(bytes)),
        "folder/MOVIE.WEBM",
        &options(),
    )?;
    for (at, size) in [
        (0, 32),
        (127, 19),
        (2495, 17),
        (4095, 19),
        (4096, 4097),
        (8190, 111),
        (13001, 0),
    ] {
        assert_eq!(
            &*source.read_at(at, size)?,
            &plain[at as usize..at as usize + size]
        );
    }
    assert!(source.read_at(13000, 2).is_err());
    assert!(source.read_at(u64::MAX, 1).is_err());
    let token = Arc::new(AtomicBool::new(false));
    let mut first = source.clone().reader(token.clone())?;
    let mut second = source.reader(token.clone())?;
    for at in [8192, 3, 4090] {
        first.seek(SeekFrom::Start(at))?;
        let mut block = [0; 23];
        first.read_exact(&mut block)?;
        assert_eq!(&block, &plain[at as usize..at as usize + 23]);
    }
    let mut block = [0; 31];
    second.read_exact(&mut block)?;
    assert_eq!(&block, &plain[..31]);
    token.store(true, Ordering::Relaxed);
    assert!(second.read(&mut block).is_err());
    Ok(())
}
struct Sparse {
    reads: Mutex<Vec<(u64, usize)>>,
    key: [u8; PERIOD],
}
impl ReadAt for Sparse {
    fn len(&self) -> u64 {
        (1u64 << 33) + 111
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        self.reads
            .lock()
            .map_err(|_| io::Error::other("test lock poisoned"))?
            .push((offset, size));
        let mut bytes: Vec<_> = (0..size).map(|i| (offset + i as u64) as u8).collect();
        if offset == 0 && size >= 4 {
            bytes[..4].copy_from_slice(&[0x1a, 0x45, 0xdf, 0xa3]);
        }
        for (i, b) in bytes.iter_mut().enumerate() {
            *b ^= self.key[((offset + i as u64) % PERIOD as u64) as usize];
        }
        Ok(Cow::Owned(bytes))
    }
}
#[test]
fn large_sources_read_only_requested_ranges() -> Result<()> {
    let mut key = [0; PERIOD];
    encrypt(&mut key);
    let backing = Arc::new(Sparse {
        reads: Mutex::new(Vec::new()),
        key,
    });
    let source = Kaleido.decode_source(backing.clone(), "movie.webm", &options())?;
    let offset = (1u64 << 32) + 4090;
    let bytes = source.read_at(offset, 23)?;
    assert_eq!(
        &*bytes,
        &(0..23).map(|i| (offset + i) as u8).collect::<Vec<_>>()
    );
    assert_eq!(
        *backing
            .reads
            .lock()
            .map_err(|_| io::Error::other("test lock poisoned"))?,
        [(0, 4), (0, 4), (offset, 23)]
    );
    Ok(())
}
#[test]
fn plaintext_and_missing_or_wrong_parameters() -> Result<()> {
    let plain: Arc<dyn ReadAt> = Arc::new(Arc::<[u8]>::from([0x1a, 0x45, 0xdf, 0xa3]));
    assert!(Arc::ptr_eq(
        &plain,
        &Kaleido.decode_source(plain.clone(), "movie.webm", &ArchiveOptions::default())?
    ));
    let mut bytes = vec![0x1a, 0x45, 0xdf, 0xa3];
    encrypt(&mut bytes);
    let encrypted: Arc<dyn ReadAt> = Arc::new(Arc::<[u8]>::from(bytes));
    assert!(matches!(
        Kaleido.decode_source(encrypted.clone(), "movie.webm", &ArchiveOptions::default()),
        Err(Error::UnknownScheme(_))
    ));
    assert!(
        Kaleido
            .decode_source(encrypted, "wrong.webm", &options())
            .is_err()
    );
    Ok(())
}
