#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn utf8_and_cesu8_preserve_supplementary_characters() -> std::io::Result<()> {
    use std::borrow::Cow;
    for text in ["", "日本語", "a😅𐀀\u{10ffff}\0z"] {
        assert!(
            matches!(BinaryReader::utf8_cesu8(text.as_bytes())?, Cow::Borrowed(value) if value == text)
        );
    }
    for (encoded, expected) in [
        (b"\xed\xa0\xbd\xed\xb8\x85".as_slice(), "😅"),
        (b"\xed\xa0\x80\xed\xb0\x80".as_slice(), "𐀀"),
        (b"\xed\xaf\xbf\xed\xbf\xbf".as_slice(), "\u{10ffff}"),
    ] {
        assert_eq!(BinaryReader::utf8_cesu8(encoded)?, expected);
        for length in 1..encoded.len() {
            assert_eq!(
                BinaryReader::utf8_cesu8(&encoded[..length])
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
        }
    }
    let mut mixed = "日本語😅".as_bytes().to_vec();
    mixed.extend(b"\xed\xa0\xbd\xed\xb8\x85\xed\xa0\x80\xed\xb0\x80!");
    assert_eq!(BinaryReader::utf8_cesu8(&mixed)?, "日本語😅😅𐀀!");
    for invalid in [
        b"\xed\xb8\x85\xed\xa0\xbd".as_slice(),
        b"\xed\xa0\xbdx\xed\xb8\x85".as_slice(),
        b"\xed\xa0\xbd\xed\xa0\xbd".as_slice(),
        b"\xed\xa0\xbd\xed\xb8\x85\xff".as_slice(),
        b"\xc0\x80".as_slice(),
        b"\xc1\xbf".as_slice(),
        b"\xf4\x90\x80\x80".as_slice(),
        b"\xe3\x81x".as_slice(),
    ] {
        assert!(BinaryReader::utf8_cesu8(invalid).is_err());
    }
    Ok(())
}

#[test]
fn msb_fields_and_variable_prefix_lookahead_keep_the_bit_cursor() -> std::io::Result<()> {
    let mut writer = BitWriter::new(BitOrder::Msb);
    writer.write_bits(0b101, 3)?;
    writer.write_bits(0x12345678, 32)?;
    let bytes = writer.into_bytes();
    let mut reader = BitReader::new(&bytes, BitOrder::Msb);
    assert_eq!(reader.peek_bits(3)?, 0b101);
    assert_eq!(reader.peek_bits(2)?, 0b10);
    assert_eq!(reader.read_bits(3)?, 0b101);
    assert_eq!(reader.peek_bits(32)?, 0x12345678);
    assert_eq!(reader.read_bits(32)?, 0x12345678);
    assert_eq!(reader.peek_bits(0)?, 0);
    assert!(reader.peek_bits(33).is_err());
    assert!(reader.read_bits(6).is_err());
    Ok(())
}

#[test]
fn mfc_strings_and_bit_writes_keep_extended_widths() -> std::io::Result<()> {
    let mut bytes = vec![255, 255, 255, 0, 0, 0, 0];
    BinaryWriter::u32_le(3, &mut bytes[3..]);
    bytes.extend(b"a\0b");
    assert_eq!(
        BinaryReader::new(&bytes).read_mfc_string()?,
        (false, b"a\0b".as_slice())
    );
    assert_eq!(
        BinaryReader::new(&[255, 254, 255, 1, 0x42, 0x30]).read_mfc_string()?,
        (true, [0x42, 0x30].as_slice())
    );
    assert_eq!(
        BinaryReader::new(&bytes[..8])
            .read_mfc_string()
            .err()
            .map(|e| e.kind()),
        Some(std::io::ErrorKind::UnexpectedEof)
    );
    let mut writer = BitWriter::new(BitOrder::Lsb);
    writer.write_bits_le(0x13, 5)?;
    writer.write_bits_le(6, 3)?;
    assert_eq!(writer.into_bytes(), [0xd3]);
    let mut bits = BitReader::new(&[1, 2, 3, 4, 5, 6, 7, 8], BitOrder::Msb);
    assert_eq!(bits.read_bits_u64(64)?, 0x0102030405060708);
    assert!(bits.read_bits_u64(65).is_err());
    Ok(())
}

#[test]
fn bit_cache_orders_alignment_and_truncation() -> std::io::Result<()> {
    let mut bits = BitReader::new(&[0xab, 0xcd, 0xef], BitOrder::Msb);
    assert_eq!(bits.read_bits(3)?, 5);
    assert_eq!(bits.peek_byte(), Some(0x5e));
    bits.align_byte();
    assert_eq!(bits.read_bits(8)?, 0xcd);
    assert_eq!(bits.read_bits(4)?, 0xe);
    assert_eq!(bits.peek_byte(), None);
    assert_eq!(bits.read_bits(4)?, 0xf);
    assert_eq!(
        bits.read_bit().err().map(|e| e.kind()),
        Some(std::io::ErrorKind::UnexpectedEof)
    );
    let mut bits = BitReader::new(&[0x81, 0x02], BitOrder::Lsb);
    assert_eq!(bits.read_bits(8)?, 0x81);
    assert_eq!(bits.read_bits(8)?, 0x40);
    assert_eq!(
        BinaryReader::new(&[0xe5, 0x8e, 0x26]).read_uleb32()?,
        624485
    );
    assert_eq!(
        BinaryReader::new(&[0x9b, 0xf1, 0x59]).read_tagged_sleb64(0)?,
        (0, -624485)
    );
    assert_eq!(BinaryReader::new(&[0x7e]).read_tagged_sleb64(2)?, (2, -1));
    assert_eq!(
        BinaryReader::new(&[0x82, 0x02]).read_tagged_sleb64(2)?,
        (2, 64)
    );
    Ok(())
}

#[test]
fn bit_positions_exclude_lookahead_and_wide_fields_preserve_order() -> std::io::Result<()> {
    let mut bytes = [0; 9];
    BinaryWriter::u64_le(0xfedc_ba98_7654_3210, &mut bytes);
    bytes[8] = 0xab;
    let mut bits = BitReader::new(&bytes, BitOrder::Lsb);
    assert_eq!(bits.position(), (0, 0));
    assert_eq!(bits.read_bits_le(4)?, 0);
    assert!(bits.peek_byte().is_some());
    assert_eq!(bits.position(), (0, 4));
    assert_eq!(bits.read_bits_le_u64(64)?, 0xbfed_cba9_8765_4321);
    assert_eq!(bits.position(), (8, 4));
    assert_eq!(bits.read_bits_le(4)?, 0xa);
    assert_eq!(bits.position(), (9, 0));
    assert!(bits.read_bit().is_err());
    Ok(())
}

#[test]
fn compact_signed_values_extend_the_highest_byte() {
    for width in 1..=8 {
        assert_eq!(
            BinaryReader::compact_i64_le(&[0xff; 8][..width]).unwrap(),
            -1
        );
    }
    assert_eq!(BinaryReader::compact_i64_le(&[0x80]).unwrap(), -128);
    assert_eq!(BinaryReader::compact_i64_le(&[0, 0x80]).unwrap(), -32768);
    assert_eq!(BinaryReader::compact_i64_le(&[0xff, 0]).unwrap(), 255);
}

#[test]
fn compact_integer_reads_keep_byte_order_sign_and_bounds() {
    for (bytes, endian) in [
        ([0x80, 0x01, 0x23], Endian::Big),
        ([0x23, 0x01, 0x80], Endian::Little),
    ] {
        assert_eq!(
            BinaryReader::new(&bytes)
                .read_compact_u64(3, endian)
                .unwrap(),
            0x800123
        );
        assert_eq!(
            BinaryReader::new(&bytes)
                .read_compact_i64(3, endian)
                .unwrap(),
            -8388317
        );
        assert!(
            BinaryReader::new(&bytes)
                .read_compact_u64(0, endian)
                .is_err()
        );
        assert!(
            BinaryReader::new(&bytes)
                .read_compact_u64(9, endian)
                .is_err()
        );
        assert_eq!(
            BinaryReader::new(&bytes)
                .read_compact_u64(4, endian)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
    assert_eq!(
        BinaryReader::new(&[255; 8])
            .read_compact_i64(8, Endian::Big)
            .unwrap(),
        -1
    );
}

#[test]
fn msb_base128_handles_both_terminators_and_integer_overflow() {
    assert_eq!(
        BinaryReader::new(&[1, 0x82])
            .read_msb_base128_u64(true)
            .unwrap(),
        130
    );
    assert_eq!(
        BinaryReader::new(&[0x81, 2])
            .read_msb_base128_u64(false)
            .unwrap(),
        130
    );
    let mut maximum = [0x7f; 10];
    maximum[0] = 1;
    maximum[9] = 255;
    assert_eq!(
        BinaryReader::new(&maximum)
            .read_msb_base128_u64(true)
            .unwrap(),
        u64::MAX
    );
    maximum[0] = 2;
    assert_eq!(
        BinaryReader::new(&maximum)
            .read_msb_base128_u64(true)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(
        BinaryReader::new(&[0])
            .read_msb_base128_u64(true)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    let mut zeros = [0; 20];
    zeros[19] = 0x80;
    assert_eq!(
        BinaryReader::new(&zeros)
            .read_msb_base128_u64(true)
            .unwrap(),
        0
    );
}
