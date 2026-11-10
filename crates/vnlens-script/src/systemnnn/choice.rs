//! CScript::Execute 0x45bd70 and CCommonGame choice callback 0x412f70.
//! Short records have count resource pointers and a terminal word. Extended
//! records carry an additional pointer count in the last word; optional tail
//! controls are addressed relative to the record end, not after count alone.
use super::spt::{Tables, arg, unsigned, word};
use crate::ir::{Arg, ArgName as A, Attribute, Value};
use vnlens_core::{Error, Result};
use vnlens_io::BinaryReader;

pub(super) fn parse(body: &[u8], at: usize, tables: &Tables<'_>) -> Result<Vec<Arg>> {
    let count = word(body, 0)? as usize;
    let words = body.len() / 4;
    let short = count.checked_add(2) == Some(words);
    let extra = if short {
        0
    } else {
        word(body, words.checked_sub(1).ok_or(Error::InvalidFormat)?)? as usize
    };
    let total = count.checked_add(extra).ok_or(Error::Corrupt {
        offset: at as u64,
        reason: "SPT choice count overflow".into(),
    })?;
    // Count + pointers + the terminal control word must fit this record.
    let pointer_bytes = total.checked_mul(4).ok_or(Error::Corrupt {
        offset: at as u64,
        reason: "SPT choice table overflow".into(),
    })?;
    let mut pointers = BinaryReader::new_at(body, 4)?;
    pointers.read_bytes(pointer_bytes)?;
    pointers.read_u32_le()?;
    let mut args = vec![unsigned(A::Count, at, count as u32)];
    for index in 0..total {
        let position = at + 4 + index * 4;
        let text = tables.string(tables.resources, word(body, index + 1)?, A::Text, position)?;
        let mut item = arg(
            if index < extra {
                A::Title
            } else {
                A::Choice((index - extra) as u64)
            },
            position,
            4,
            Value::Group(vec![text]),
        );
        item.attributes.push(Attribute {
            name: "prefix_skipped_by_host".into(),
            value: u64::from(index < extra),
        });
        args.push(item);
    }
    // Execute's end-relative controls can alias other fields in short
    // extended records. Preserve each stored word once and expose aliased
    // roles as zero-length derived annotations rather than rejecting them.
    let mut roles = vec![(total + 1, A::ChoiceId)];
    if !short {
        roles.push((words - 1, A::HeadingCount));
    }
    if words > total + 2 {
        roles.extend([(words - 2, A::Duration), (words - 3, A::DefaultChoice)]);
    }
    if words > total + 3 {
        roles.push((words - 4, A::Mode));
    }
    for index in total + 1..words {
        let name = roles
            .iter()
            .find(|(slot, _)| *slot == index)
            .map_or(A::Unknown(index as u64), |(_, name)| *name);
        args.push(control(name, at + index * 4, 4, word(body, index)?));
    }
    for (position, &(index, name)) in roles.iter().enumerate() {
        if index <= total || roles[..position].iter().any(|(slot, _)| *slot == index) {
            args.push(control(name, at + index * 4, 0, word(body, index)?));
        }
    }
    Ok(args)
}
fn control(name: A, at: usize, size: usize, value: u32) -> Arg {
    arg(
        name,
        at,
        size,
        if name == A::Duration {
            Value::Integer(i64::from(value as i32))
        } else {
            Value::Unsigned(u64::from(value))
        },
    )
}
