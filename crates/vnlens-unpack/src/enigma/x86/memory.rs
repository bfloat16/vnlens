// Adapted from bfloat16/enigma_rs (Apache-2.0), commit 18fae558.
//! Copy-on-write pages for the interpreter's sparse numeric memory.
use super::cpu::Value;
use std::sync::Arc;

const BITS: u32 = 5;
const CELLS: usize = 1 << BITS;
#[derive(Clone, Debug, PartialEq, Eq)]
struct Page {
    present: u32,
    values: [Value; CELLS],
}
impl Default for Page {
    fn default() -> Self {
        Self {
            present: 0,
            values: [Value::UNKNOWN; CELLS],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Memory {
    pages: Vec<(u32, Arc<Page>)>,
    shift: u32,
}
impl Memory {
    pub fn new(shift: u32) -> Self {
        Self {
            pages: Vec::new(),
            shift,
        }
    }
    fn location(&self, address: u32) -> (u32, usize) {
        debug_assert_eq!(address & ((1 << self.shift) - 1), 0);
        let cell = address >> self.shift;
        (cell >> BITS, (cell & (CELLS as u32 - 1)) as usize)
    }
    pub fn get(&self, address: u32) -> Option<Value> {
        let (base, index) = self.location(address);
        let page = &self
            .pages
            .get(self.pages.binary_search_by_key(&base, |p| p.0).ok()?)?
            .1;
        (page.present & (1 << index) != 0).then_some(page.values[index])
    }
    pub fn contains_key(&self, address: u32) -> bool {
        self.get(address).is_some()
    }
    pub fn insert(&mut self, address: u32, value: Value) {
        let (base, index) = self.location(address);
        let page = match self.pages.binary_search_by_key(&base, |p| p.0) {
            Ok(i) => i,
            Err(i) => {
                self.pages.insert(i, (base, Arc::new(Page::default())));
                i
            }
        };
        let flag = 1 << index;
        let old = &self.pages[page].1;
        if old.present & flag != 0 && old.values[index] == value {
            return;
        }
        let page = Arc::make_mut(&mut self.pages[page].1);
        page.present |= flag;
        page.values[index] = value;
    }
    pub fn insert_span(&mut self, mut address: u32, mut values: &[Value]) {
        while !values.is_empty() {
            let (base, offset) = self.location(address);
            let count = values.len().min(CELLS - offset);
            let index = match self.pages.binary_search_by_key(&base, |p| p.0) {
                Ok(i) => i,
                Err(i) => {
                    self.pages.insert(i, (base, Arc::new(Page::default())));
                    i
                }
            };
            let mask = (u32::MAX >> (CELLS - count)) << offset;
            let old = &self.pages[index].1;
            if old.present & mask != mask || old.values[offset..offset + count] != values[..count] {
                let page = Arc::make_mut(&mut self.pages[index].1);
                page.values[offset..offset + count].copy_from_slice(&values[..count]);
                page.present |= mask;
            }
            address = address.wrapping_add((count as u32) << self.shift);
            values = &values[count..];
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, Value)> + '_ {
        self.pages.iter().flat_map(move |(base, page)| {
            let mut mask = page.present;
            std::iter::from_fn(move || {
                if mask == 0 {
                    return None;
                }
                let index = mask.trailing_zeros();
                mask &= mask - 1;
                Some((
                    ((base << BITS) + index) << self.shift,
                    page.values[index as usize],
                ))
            })
        })
    }
    /// Shared immutable pages are already equal on both predecessors.
    pub fn changed<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = (u32, Value)> + 'a {
        debug_assert_eq!(self.shift, other.shift);
        self.pages
            .iter()
            .filter(move |(base, page)| {
                other
                    .pages
                    .binary_search_by_key(base, |p| p.0)
                    .map_or(true, |i| !Arc::ptr_eq(page, &other.pages[i].1))
            })
            .flat_map(move |(base, page)| {
                let mut mask = page.present;
                std::iter::from_fn(move || {
                    if mask == 0 {
                        return None;
                    }
                    let index = mask.trailing_zeros();
                    mask &= mask - 1;
                    Some((
                        ((base << BITS) + index) << self.shift,
                        page.values[index as usize],
                    ))
                })
            })
    }
    pub fn extend(&mut self, values: impl IntoIterator<Item = (u32, Value)>) {
        for (at, value) in values {
            self.insert(at, value);
        }
    }
}
