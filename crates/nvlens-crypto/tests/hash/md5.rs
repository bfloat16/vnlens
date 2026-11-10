use super::*;

#[test]
fn known_vectors() {
    assert_eq!(hex(&digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hex(&digest(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
}

#[test]
fn block_boundaries_and_fragmented_input() {
    for (len, expected) in [
        (55, "ef1772b6dff9a122358552954ad0df65"),
        (56, "3b0c8ac703f828b04c6c197006d17218"),
        (63, "b06521f39153d618550606be297466d5"),
        (64, "014842d480b571495a4a0363793f7367"),
        (65, "c743a45e0d2e6a95cb859adae0248435"),
        (128, "e510683b3f5ffe4093d021808bc6ff70"),
    ] {
        let data = vec![b'a'; len];
        for split in 0..=len {
            assert_eq!(
                hex(&digest_parts(&[&data[..split], &[], &data[split..]])),
                expected
            );
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn four_lanes_match_serial_digest_across_padding_and_prefix_blocks() {
    for length in 0..260 {
        let prefix: Vec<_> = (0..length).map(|i| (i * 37 + 9) as u8).collect();
        let suffixes = [[0; 4], [255; 4], [1, 127, 128, 254], [89, 21, 3, 44]];
        let actual = digest_four_suffix(&prefix, &suffixes);
        for (digest, suffix) in actual.into_iter().zip(suffixes) {
            assert_eq!(digest, digest_parts(&[&prefix, &suffix]));
        }
    }
}
