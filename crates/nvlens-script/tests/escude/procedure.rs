use super::*;
use nvlens_io::BinaryWriter;
use std::cell::RefCell;
fn sample(ops: &[(u8, u32)]) -> Result<Script> {
    let mut data = b"@code:__".to_vec();
    data.resize(24, 0);
    for &(op, value) in ops {
        data.push(op);
        let at = data.len();
        data.resize(at + 4, 0);
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    data.push(18);
    let size = data.len() - 24;
    BinaryWriter::u32_le(size as u32, &mut data[8..]);
    scenario::code(&data)
}
#[test]
fn unreviewed_abi_never_enables_semantic_mapping() -> Result<()> {
    struct Changed(RefCell<Vec<String>>);
    impl ResourceResolver for Changed {
        fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
            self.0.borrow_mut().push(name.into());
            Ok(match name {
                "adv/adv.c" => Some(b"adv_proc_count=0;set_proc(proc_bgm_play);".to_vec()),
                "misc/script.inc" => Some(b"different interpreter".to_vec()),
                _ => None,
            })
        }
    }
    let resolver = Changed(RefCell::new(Vec::new()));
    let mut ir = sample(&[(4, 4), (44, 0)])?;
    let before = ir.to_json()?;
    resolve(&mut ir, &resolver)?;
    assert_eq!(ir.to_json()?, before);
    assert_eq!(*resolver.0.borrow(), ["adv/adv.c", "misc/script.inc"]);
    Ok(())
}
#[test]
fn argument_producers_keep_stack_order_and_stop_at_control_flow_entries() -> Result<()> {
    let ir = sample(&[(4, 100), (4, 7), (4, 2), (44, 0)])?;
    let calls = ir
        .instructions
        .iter()
        .position(|i| i.opcode.code == 44)
        .ok_or_else(|| bad(0, "No call"))?;
    let known = stack_literals(&ir.instructions, calls, &Default::default());
    assert!(matches!(
        known.as_slice(),
        [Some(Value::Integer(7)), Some(Value::Integer(100))]
    ));
    let target = ir.instructions[calls - 1].span.offset;
    assert!(stack_literals(&ir.instructions, calls, &[target].into()).is_empty());
    Ok(())
}
