use super::*;

const HEADER: &str = "#layer_type\tname\tleft\ttop\twidth\theight\ttype\topacity\tvisible\tlayer_id\tgroup_layer_id\tbase\timages\n";

#[test]
fn layer_ids_use_actual_normal_layers_and_the_resolved_definition_name() -> Result<()> {
    let table = format!(
        "{HEADER}\t\t\t\t1024\t2500\n0\tface\t0\t0\t1\t1\t13\t255\t1\t44\t45\n2\tgroup\t0\t0\t0\t0\t13\t255\t1\t45\n0\tmarker\t0\t0\t0\t0\t13\t255\t1\t-1\n0\tzero\t0\t0\t1\t1\t13\t255\t1\t0\n"
    );
    let mut out = BTreeSet::new();
    candidates(&table, "fg/actor1.txt", &AtomicBool::new(false), &mut out)?;
    assert_eq!(
        out,
        BTreeSet::from(["fg/actor1_44.tlg".into(), "0.tlg".into()])
    );
    let mut unknown = BTreeSet::new();
    candidates(
        &table,
        "UNRESOLVED_HASH",
        &AtomicBool::new(false),
        &mut unknown,
    )?;
    candidates(
        "0\tface\t0\t0\t1\t1\t13\t255\t1\t44",
        "unrelated.txt",
        &AtomicBool::new(false),
        &mut unknown,
    )?;
    assert!(unknown.is_empty());
    assert!(matches!(
        candidates(&table, "actor1.txt", &AtomicBool::new(true), &mut out),
        Err(vnlens_core::Error::Cancelled)
    ));
    Ok(())
}
