use super::*;
use std::io::Write;
use vnlens_io::BinaryWriter;
#[test]
fn all_text_modes_preserve_unicode_and_check_lengths() -> Result<()> {
    let text = "hello 日本語😀\r\n";
    let mut plain = vec![0; text.encode_utf16().count() * 2];
    for (w, b) in text.encode_utf16().zip(plain.as_chunks_mut::<2>().0) {
        BinaryWriter::u16_le(w, b);
    }
    for mode in [0, 1] {
        let mut data = vec![0xfe, 0xfe, mode, 0xff, 0xfe];
        for w in text.encode_utf16() {
            let value = if mode == 0 && w >= 32 {
                w ^ (((w ^ 1) & 0xfe) << 8) ^ 1
            } else if mode == 1 {
                ((w & 0xaaaa) >> 1) | ((w & 0x5555) << 1)
            } else {
                w
            };
            let mut bytes = [0; 2];
            BinaryWriter::u16_le(value, &mut bytes);
            data.extend(bytes);
        }
        assert_eq!(decode(&data)?.as_deref(), Some(text));
        data.pop();
        assert!(matches!(decode(&data), Err(Error::Io(_))));
    }
    let mut zip = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    zip.write_all(&plain)?;
    let zip = zip.finish()?;
    let mut data = vec![0xfe, 0xfe, 2, 0xff, 0xfe];
    data.resize(21, 0);
    BinaryWriter::u64_le(zip.len() as u64, &mut data[5..]);
    BinaryWriter::u64_le(plain.len() as u64, &mut data[13..]);
    data.extend(zip);
    assert_eq!(decode(&data)?.as_deref(), Some(text));
    BinaryWriter::u64_le(1, &mut data[13..]);
    assert!(decode(&data).is_err());
    Ok(())
}
