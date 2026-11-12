#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_core::Error;

#[test]
fn collects_single_voice_lines_and_clears_on_chorus_or_unknown_macros() -> Result<()> {
    let config = Config::default();
    let source = "\
// comment
\\VO(v001)(ID:12)【アリス】「こんにちは」
\\VO1(v002)\\VO2(v003)【アリス】「合唱」
\\VO(v004)\\UNKNOWN【アリス】「未知マクロ」
\\VO(v005)
【ボブ】「次の行」
";
    let mut output = Vec::new();
    let mut skipped = 0;
    collect(
        source,
        &config,
        &AtomicBool::new(false),
        &mut output,
        &mut skipped,
    )?;
    assert_eq!(output.len(), 2);
    assert_eq!(output[0].speaker, "アリス");
    assert_eq!(output[0].voice, "v001");
    assert_eq!(output[0].text, "「こんにちは」");
    assert_eq!(output[1].speaker, "ボブ");
    assert_eq!(output[1].voice, "v005");
    assert_eq!(output[1].text, "「次の行」");
    assert_eq!(skipped, 2);
    assert!(matches!(
        collect(
            source,
            &config,
            &AtomicBool::new(true),
            &mut output,
            &mut skipped
        ),
        Err(Error::Cancelled)
    ));
    Ok(())
}
