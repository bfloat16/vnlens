//! Field programs for CFadeData subclasses, verified from rvmm's virtual
//! Serialize methods (1001E5A0 through 10022570). Zero denotes the base
//! serializer, 8 an object reference, and 1/2/4 the native scalar byte width.
//! These are metadata parameters of a VM blit, not additional VM opcodes.
pub(super) fn fields(name: &str, schema: u16) -> Option<Vec<u8>> {
    let mut xs = vec![0];
    if schema >= 7 {
        xs.extend([1, 1, 2]);
        if schema >= 9 {
            xs.push(2);
        }
    }
    let mut raster = xs.clone();
    raster.extend([2, 2, 2, 2, 1, 1, 1]);
    if matches!(schema, 4 | 5) {
        raster.extend([1, 2]);
    }
    let mut stretch = vec![0, 2, 2, 2, 2];
    if schema >= 2 {
        stretch.extend([2, 2, 2, 2]);
        if schema >= 11 {
            stretch.push(1);
        }
    }
    Some(match name {
        "CFadeData" | "CFadeShock" | "CFadeRSideCarten" | "CFadeHorzLine" | "CFadeSdtMulQube"
        | "CFadeSdtRatio" | "CFadeInvert" | "CFadeMozaik" | "CFadeMulHorz" | "CFadeMergeBlack"
        | "CFadeStepRatio" | "CFadeRatio" | "CFadeNormal" => vec![0],
        "CFadeXsTile" | "CFadeXsMergeBlack" | "CFadeXsRatio" | "CFadeXsData" => xs,
        "CFadeXsSqrRaster_HRasterV_VRasterH"
        | "CFadeXsSqrRaster_HRasterH_VRasterV"
        | "CFadeXsHRasterVOffset"
        | "CFadeXsHRasterHOffset"
        | "CFadeXsRaster" => raster,
        "CFadeXsCircleRaster" => {
            raster.push(4);
            raster
        }
        "CFadeXsRasterNoize" => {
            raster.extend([4, 2]);
            raster
        }
        "CFadeXsSrcRotate" => {
            xs.extend([4, 4, 2, 2, 2, 2, 1, 1]);
            xs
        }
        "CFadeXsOverStretchAnti" => {
            xs.extend([2; 12]);
            xs
        }
        "CFadeStretchAnti" | "CFadeSdtSpriteStretch" | "CFadeStretch" => stretch,
        "CFadeOverStretchAnti" => {
            stretch.extend(if schema < 5 { vec![2; 5] } else { vec![2; 4] });
            stretch
        }
        "CFadeQubeStretchAnti" => {
            stretch.extend([2; 13]);
            stretch.push(1);
            stretch
        }
        "CFadeMergeWhite" | "CFadeMergeColor" => {
            if schema >= 12 {
                vec![0, 4]
            } else {
                vec![0]
            }
        }
        "CFadeHSV" => {
            let mut p = vec![0];
            p.extend([2; 13]);
            p
        }
        "CFadeOrsdtRatio" => vec![0, 1, 1, 2],
        "CFadeFreeStretch" => vec![0, 4, 4, 4, 4],
        "CFadeCarten" => vec![2, 2, 1, 1, 0],
        "CFadeSdtPattern" => vec![8, 2, 2, 1, 1, 0],
        "CFadeOverride" => vec![0, 2, 2],
        "CFadeMulRotate" => vec![0, 2, 2, 4, 2, 1, 1],
        "CFadeVertScrollStretch" => vec![2, 2, 2, 2, 2, 2, 0],
        "CFadeSdtCircleRaster" => vec![2, 2, 2, 2, 1, 1, 1, 4, 0],
        _ => return None,
    })
}
