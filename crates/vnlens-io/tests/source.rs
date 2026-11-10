use super::*;

#[test]
fn range_source_and_cursor_bound_reads_and_seeks() -> io::Result<()> {
    let backing: Arc<dyn ReadAt> = Arc::new(Arc::<[u8]>::from(&b"0123456789abcdef"[..]));
    assert!(RangeSource::new(backing.clone(), 10, 8).is_err());
    let range = Arc::new(RangeSource::new(backing, 4, 8)?);
    assert_eq!(range.len(), 8);
    assert_eq!(&*range.read_at(2, 4)?, b"6789");
    assert!(range.read_at(6, 3).is_err());

    let cancel = Arc::new(AtomicBool::new(false));
    let mut cursor = range.reader(cancel.clone())?;
    let mut buf = [0u8; 3];
    cursor.read_exact(&mut buf)?;
    assert_eq!(&buf, b"456");
    assert_eq!(cursor.seek(SeekFrom::End(-2))?, 6);
    let mut tail = Vec::new();
    cursor.read_to_end(&mut tail)?;
    assert_eq!(&tail, b"ab");
    assert!(cursor.seek(SeekFrom::Current(-20)).is_err());

    cancel.store(true, Ordering::Relaxed);
    assert!(cursor.seek(SeekFrom::Start(0)).is_err());
    Ok(())
}

#[test]
fn replay_reader_supports_forward_skip_backward_replay_and_size_checks() -> io::Result<()> {
    let data = b"abcdefghij";
    let factory: ReadFactory = Arc::new(|_| Ok(Box::new(io::Cursor::new(*data))));
    let cancel = Arc::new(AtomicBool::new(false));
    let mut reader = ReplayReader::new(factory, data.len() as u64, cancel.clone())?;

    assert_eq!(reader.seek(SeekFrom::Start(4))?, 4);
    let mut slice = [0u8; 3];
    reader.read_exact(&mut slice)?;
    assert_eq!(&slice, b"efg");

    assert_eq!(reader.seek(SeekFrom::Start(1))?, 1);
    reader.read_exact(&mut slice)?;
    assert_eq!(&slice, b"bcd");

    let mut rest = Vec::new();
    reader.read_to_end(&mut rest)?;
    assert_eq!(&rest, b"efghij");

    let short: ReadFactory = Arc::new(|_| Ok(Box::new(io::Cursor::new(&b"abc"[..]))));
    let mut truncated = ReplayReader::new(short, 5, cancel.clone())?;
    let mut out = Vec::new();
    assert_eq!(
        truncated.read_to_end(&mut out).err().map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );

    let long: ReadFactory = Arc::new(|_| Ok(Box::new(io::Cursor::new(&b"abcdef"[..]))));
    let mut overflow = ReplayReader::new(long, 3, cancel)?;
    out.clear();
    assert_eq!(
        overflow.read_to_end(&mut out).err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}
