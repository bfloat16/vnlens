use super::*;
use vnlens_io::BitWriter;

fn framed(transform: u8, coder: u8, payload: &[u8], size: u32) -> Vec<u8> {
    let mut bytes = vec![transform, coder, 0, 0, 0, 0, 0, 0];
    BinaryWriter::u32_le(size, &mut bytes[2..]);
    bytes.extend_from_slice(payload);
    bytes
}
#[test]
fn rle_all_run_classes_and_delta_vectors() -> io::Result<()> {
    let data = framed(
        b'N',
        b'R',
        b"\x02\x43abc\x82x\xc0\x02\xd0\x02YZ\xe0\x03q\xf0",
        14,
    );
    assert_eq!(
        decompress(&data, 14, &AtomicBool::new(false))?,
        b"\0\0abcxx\0\0YZqqq"
    );
    assert_eq!(
        decompress(
            &framed(b'B', b'R', b"\x43\x01\x03\x06\xf0", 3),
            3,
            &AtomicBool::new(false)
        )?,
        [255, 254, 253]
    );
    for transform in *b"WS" {
        let words = if transform == b'W' {
            &b"\x01\x00\x03\x00"[..]
        } else {
            &b"\x00\x01\x00\x03"[..]
        };
        let mut payload = vec![0x44];
        payload.extend_from_slice(words);
        payload.push(0xf0);
        let out = decompress(
            &framed(transform, b'R', &payload, 4),
            4,
            &AtomicBool::new(false),
        )?;
        assert_eq!(
            if transform == b'W' {
                BinaryReader::u16_le(&out[2..])
            } else {
                BinaryReader::u16_be(&out[2..])
            },
            65534
        );
    }
    assert!(decompress(&data[..data.len() - 1], 14, &AtomicBool::new(false)).is_err());
    assert!(decompress(&data, 13, &AtomicBool::new(false)).is_err());
    assert_eq!(
        decompress(&data, 14, &AtomicBool::new(true))
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::Interrupted)
    );
    Ok(())
}
#[test]
fn explicit_huffman_codes_cross_byte_boundaries_and_reject_conflicts() -> io::Result<()> {
    let mut payload = vec![1, 0];
    for symbol in 0..=255u8 {
        match symbol {
            b'A' => payload.extend([1, 0]),
            b'B' => payload.extend([1, 1]),
            _ => payload.push(0),
        }
    }
    let mut writer = BitWriter::new(BitOrder::Lsb);
    for bit in [0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0] {
        writer.write_bits_le(bit, 1)?;
    }
    payload.extend(writer.into_bytes());
    let bytes = framed(b'N', b'H', &payload, 11);
    assert_eq!(
        decompress(&bytes, 11, &AtomicBool::new(false))?,
        b"ABBABAAABBA"
    );
    assert!(decompress(&bytes[..bytes.len() - 1], 11, &AtomicBool::new(false)).is_err());
    payload[2 + usize::from(b'B') + 2] = 0;
    assert!(
        decompress(
            &framed(b'N', b'H', &payload, 11),
            11,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    Ok(())
}
