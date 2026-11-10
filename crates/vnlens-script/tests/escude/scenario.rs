use super::*;
use std::cell::RefCell;
use vnlens_io::BinaryWriter;
struct Companion {
    requests: RefCell<Vec<String>>,
    bytes: Vec<u8>,
}
impl ResourceResolver for Companion {
    fn resource_name(&self) -> Option<&str> {
        Some("chapter.bin")
    }
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.requests.borrow_mut().push(name.into());
        Ok((name == "chapter.001").then(|| self.bytes.clone()))
    }
}
fn program(index: u32) -> Vec<u8> {
    let mut b = b"@code:__".to_vec();
    b.resize(30, 0);
    for (at, n) in [(8, 6), (20, 3), (25, index)] {
        BinaryWriter::u32_le(n, &mut b[at..]);
    }
    b[24] = 41;
    b[29] = 18;
    b
}
#[test]
fn companion_messages_keep_empty_lines_and_request_only_the_named_file() -> Result<()> {
    let source = Companion {
        requests: RefCell::new(Vec::new()),
        bytes: b"first\r\n\r\nthird\r\n".to_vec(),
    };
    let mut ir = code(&program(1))?;
    let raw = ir.sections[0].raw.clone();
    resolve(&mut ir, Some(&source))?;
    assert_eq!(*source.requests.borrow(), ["chapter.001"]);
    let message = ir.instructions[1]
        .args
        .iter()
        .find(|a| a.name == A::Message)
        .ok_or_else(|| bad(0, "Missing message"))?;
    let Value::Group(fields) = &message.value else {
        return Err(bad(0, "Missing fields"));
    };
    assert!(
        fields
            .iter()
            .any(|a| matches!(&a.value,Value::Text(v) if v.is_empty()))
    );
    assert_eq!(message.span.size, 0);
    assert_eq!(ir.sections[0].raw, raw);
    assert!(resolve(&mut code(&program(3))?, Some(&source)).is_err());
    Ok(())
}
