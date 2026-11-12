use super::*;
use vnlens_io::BinaryReader;
#[test]
fn stitches_rows_and_crops_padded_width_without_decoding() -> Result<()> {
    let bytes: Vec<_> = (0..64).collect();
    let mut canvas = Canvas {
        width: 4,
        height: 8,
        tiles: vec![
            Tile {
                resource: PsbResource {
                    index: 0,
                    is_extra: false,
                    offset: 0,
                    size: 32,
                },
                width: 8,
                height: 4,
                x: 0,
                y: 0,
            },
            Tile {
                resource: PsbResource {
                    index: 1,
                    is_extra: false,
                    offset: 32,
                    size: 32,
                },
                width: 8,
                height: 4,
                x: 0,
                y: 4,
            },
        ],
    };
    let dds = canvas.wrap(&bytes.as_slice())?;
    assert_eq!(BinaryReader::u32_le(&dds[12..]), 8);
    assert_eq!(BinaryReader::u32_le(&dds[16..]), 4);
    assert_eq!(&dds[148..164], &bytes[..16]);
    assert_eq!(&dds[164..], &bytes[32..48]);
    canvas.tiles[0].resource.size = 31;
    assert!(canvas.wrap(&bytes.as_slice()).is_err());
    assert!(
        Encoding::Bc7 {
            width: u32::MAX,
            height: u32::MAX
        }
        .wrap(&bytes.as_slice(), &[])
        .is_err()
    );
    Ok(())
}
