use super::*;
#[test]
fn registry_preserves_order_and_ignores_comments_and_quoted_calls() -> Result<()> {
    let src=br#"void f(){ adv_proc_count=0; /* set_proc(fake); */ set_proc(proc_wait); set_proc(proc_bgm_play); } "set_proc(fake);" "#;
    assert_eq!(
        registry(&tokens(src)?),
        Some(vec!["proc_wait".into(), "proc_bgm_play".into()])
    );
    assert_eq!(
        fingerprint(&tokens(b"a/*ignored*/ + b")?),
        fingerprint(&tokens(b"a+b")?)
    );
    assert_ne!(
        fingerprint(&tokens(br#""a b""#)?),
        fingerprint(&tokens(br#""ab""#)?)
    );
    assert!(tokens(b"/* missing end").is_err());
    assert!(tokens(b"\"missing end").is_err());
    assert!(
        registry(&tokens(
            b"adv_proc_count=0; set_proc(foo); adv_proc_count=0; set_proc(bar);"
        )?)
        .is_none()
    );
    Ok(())
}
