use super::*;
use vnlens_crypto::hash::sha256::Sha256;
use vnlens_io::{BinaryReader, BinaryWriter};

pub(super) fn source(bytes: Vec<u8>) -> Arc<dyn ReadAt> {
    Arc::new(Arc::<[u8]>::from(bytes))
}
pub(super) fn pfs(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut names = Vec::new();
    let mut records = Vec::new();
    let mut body = Vec::new();
    for (name, bytes) in entries {
        let mut record = [0; 24];
        BinaryWriter::u64_le(body.len() as u64, &mut record);
        BinaryWriter::u64_le(bytes.len(), &mut record[8..]);
        BinaryWriter::u32_le(names.len() as u32, &mut record[16..]);
        records.extend_from_slice(&record);
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        body.extend_from_slice(bytes);
    }
    let mut bytes = vec![0; 16];
    bytes[..4].copy_from_slice(b"PFS0");
    BinaryWriter::u32_le(entries.len() as u32, &mut bytes[4..]);
    BinaryWriter::u32_le(names.len() as u32, &mut bytes[8..]);
    bytes.extend(records);
    bytes.extend(names);
    bytes.extend(body);
    bytes
}
pub(super) fn nca(data: &[u8], fs: &[u8; 512], kind: u8) -> Vec<u8> {
    let size = (0xc00 + data.len()).div_ceil(512) * 512;
    let mut bytes = vec![0; size];
    bytes[0x200..0x204].copy_from_slice(b"NCA3");
    bytes[0x205] = kind;
    BinaryWriter::u64_le(size as u64, &mut bytes[0x208..]);
    BinaryWriter::u32_le(6, &mut bytes[0x240..]);
    BinaryWriter::u32_le((size / 512) as u32, &mut bytes[0x244..]);
    bytes[0x400..0x600].copy_from_slice(fs);
    bytes[0x280..0x2a0].copy_from_slice(&Sha256::digest(fs));
    bytes[0xc00..0xc00 + data.len()].copy_from_slice(data);
    bytes
}
pub(super) fn fs_header() -> [u8; 512] {
    let mut fs = [0; 512];
    fs[2] = 1;
    fs[3] = 1;
    fs[4] = 1;
    fs
}
pub(super) fn table(rows: &[Vec<u8>], end: u64) -> ([u8; 16], Vec<u8>) {
    let stride = rows.first().map_or(20, Vec::len);
    let capacity = (0x4000 - 16) / stride;
    let sets = rows.len().div_ceil(capacity);
    // These fixtures use one root; production also handles the format's L2
    // node region when the entry-set count exceeds the root offset capacity.
    let mut bytes = vec![0; (sets + 1) * 0x4000];
    BinaryWriter::u32_le(sets as u32, &mut bytes[4..]);
    BinaryWriter::u64_le(end, &mut bytes[8..]);
    for (index, chunk) in rows.chunks(capacity).enumerate() {
        BinaryWriter::u64_le(
            BinaryReader::u64_le(&chunk[0]),
            &mut bytes[16 + index * 8..],
        );
        let at = (index + 1) * 0x4000;
        BinaryWriter::u32_le(index as u32, &mut bytes[at..]);
        BinaryWriter::u32_le(chunk.len() as u32, &mut bytes[at + 4..]);
        let stop = rows
            .get((index + 1) * capacity)
            .map_or(end, |row| BinaryReader::u64_le(row));
        BinaryWriter::u64_le(stop, &mut bytes[at + 8..]);
        for (i, row) in chunk.iter().enumerate() {
            bytes[at + 16 + i * stride..at + 16 + (i + 1) * stride].copy_from_slice(row);
        }
    }
    let mut header = [0; 16];
    header[..4].copy_from_slice(b"BKTR");
    BinaryWriter::u32_le(1, &mut header[4..]);
    BinaryWriter::u32_le(rows.len() as u32, &mut header[8..]);
    (header, bytes)
}
