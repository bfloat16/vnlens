use super::*;

#[test]
fn straight_alpha_preserves_transparency_and_composes_known_colors() -> Result<()> {
    let mode = Mode::new(13)?;
    let mut transparent = [0; 4];
    mode.apply(&mut transparent, [255, 0, 0, 128], 255);
    assert_eq!(transparent, [255, 0, 0, 128]);
    let mut opaque = [0, 0, 255, 255];
    mode.apply(&mut opaque, [255, 0, 0, 255], 128);
    assert_eq!(opaque, [128, 0, 127, 255]);
    mode.apply(&mut opaque, [0, 255, 0, 255], 0);
    assert_eq!(opaque, [128, 0, 127, 255]);
    Ok(())
}

#[test]
fn opaque_layers_ignore_pixel_alpha_but_keep_layer_opacity() -> Result<()> {
    let mode = Mode::new(1)?;
    let mut dest = [0; 4];
    mode.apply(&mut dest, [32, 64, 128, 0], 255);
    assert_eq!(dest, [32, 64, 128, 255]);
    Ok(())
}
