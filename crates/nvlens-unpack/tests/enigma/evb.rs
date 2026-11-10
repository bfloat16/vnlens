use super::*;
use nvlens_io::BinaryWriter;

#[test]
fn plain_and_compressed_random_reads_restart_cipher_per_block() -> Result<()> {
    let state = std::array::from_fn(|i| (i * 31 + 9) as u8);
    let plain: Vec<_> = (0..20000).map(|i| (i * 73 + 5) as u8).collect();
    let bytes = plain
        .chunks(8192)
        .flat_map(|b| decipher(b, &state))
        .collect::<Vec<_>>();
    let mode = Arc::new(std::sync::OnceLock::new());
    let _ = mode.set(false);
    let file = File {
        view: Arc::new(ArcView::from_bytes(
            PathBuf::from("fixture.exe"),
            bytes.into(),
        )),
        offset: 0,
        size: plain.len() as u64,
        stored: plain.len() as u64,
        state,
        mode,
    };
    assert_eq!(&*file.read_at(8190, 23)?, &plain[8190..8213]);
    assert_eq!(&*file.read_at(0, plain.len())?, &plain);
    assert!(file.read_at(plain.len() as u64, 1).is_err());

    let packed = [0x00, 0xa4, 0x01, 0x70, 0x80, 0x8f, 0xf7, 0xec, 0];
    let expected = codec::decompress(&packed, 512, true)?;
    let mut index = [0; 12];
    BinaryWriter::u64_le(12, &mut index);
    BinaryWriter::u32_le(packed.len() as u32, &mut index[8..]);
    let mut bytes = decipher(&index, &state);
    bytes.extend(decipher(&packed, &state));
    let mode = Arc::new(std::sync::OnceLock::new());
    let _ = mode.set(true);
    let file = File {
        view: Arc::new(ArcView::from_bytes(
            PathBuf::from("fixture.exe"),
            bytes.into(),
        )),
        offset: 0,
        size: 512,
        stored: 21,
        state,
        mode,
    };
    assert_eq!(&*file.read_at(15, 400)?, &expected[15..415]);
    assert_eq!(&*file.read_at(0, 512)?, &expected);
    Ok(())
}

#[test]
fn directory_preserves_names_and_checks_declared_structure() -> Result<()> {
    let mut tree = vec![0; 12];
    for unit in "CON.foo".encode_utf16().chain([0]) {
        let mut bytes = [0; 2];
        BinaryWriter::u16_le(unit, &mut bytes);
        tree.extend(bytes);
    }
    tree.push(2);
    tree.extend([0; 2]);
    let at = tree.len();
    tree.resize(at + 8, 0);
    BinaryWriter::u64_le(7, &mut tree[at..]);
    tree.extend([0; 29]);
    tree.extend([0; 2]);
    tree.push(0);
    let at = tree.len();
    tree.resize(at + 16, 0);
    BinaryWriter::u64_le(8, &mut tree[at..]);
    BinaryWriter::u64_le(7, &mut tree[at + 8..]);
    let nodes = directory(&tree)?;
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].path, PathBuf::from("CON.foo"));
    assert_eq!((nodes[0].size, nodes[0].offset, nodes[0].stored), (7, 8, 7));
    for cut in 0..tree.len() {
        assert!(directory(&tree[..cut]).is_err());
    }
    BinaryWriter::u32_le(1, &mut tree[8..]);
    assert!(directory(&tree).is_err());
    assert!(path(std::path::Path::new(""), "../escape").is_err());
    Ok(())
}
