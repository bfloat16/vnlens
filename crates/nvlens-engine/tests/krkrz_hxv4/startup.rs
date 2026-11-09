use super::*;
fn script(tail: &[i16]) -> Startup {
    let mut code = vec![1, 1, 0, 123, 1, -1, 111, -1, 1, 1];
    code.extend_from_slice(tail);
    Startup {
        strings: vec![
            "_bootStrap".into(),
            "actual argument".into(),
            "decoy".into(),
        ],
        values: vec![(2, 1), (3, 0), (3, 1), (3, 2)],
        code,
    }
}
#[test]
fn uses_call_dataflow_and_rejects_ambiguous_branches() -> Result<()> {
    let startup = script(&[1, 4, 2, 2, 5, 4, 100, 6, -2, 1, 2, 5, 4, 119]);
    assert_eq!(startup.bootstrap_argument()?, "actual argument");
    let mut no_registration = script(&[1, 4, 2, 100, 6, -2, 1, 2, 4, 4, 119]);
    no_registration.values[0] = (3, 2);
    assert!(no_registration.bootstrap_argument().is_err());
    // Two branches meet at the same call with different first arguments.
    let ambiguous = script(&[15, 7, 1, 4, 2, 17, 5, 1, 4, 3, 100, 6, -2, 1, 2, 4, 4, 119]);
    assert!(ambiguous.bootstrap_argument().is_err());
    let looped = script(&[1, 4, 2, 58, 4, 4, 15, -3, 100, 6, -2, 1, 2, 4, 4, 119]);
    assert!(looped.bootstrap_argument().is_err());
    assert!(decode(&[100, 0, -2, 1, 2, 4]).is_err());
    Ok(())
}
