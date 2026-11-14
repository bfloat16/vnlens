use super::*;
use crate::criware::tests::{Cell, Watched, source, table};
use std::sync::Mutex;
use vnlens_io::BinaryWriter;
#[test]
fn chunk_lengths_and_initial_metadata_are_directed_and_bounded() -> Result<()> {
    let table = table("CRIUSF_DIR_STREAM", &[], 0);
    let mut bytes = vec![0; 32 + table.len() + 36];
    bytes[..4].copy_from_slice(b"CRID");
    BinaryWriter::u32_be((24 + table.len()) as u32, &mut bytes[4..]);
    bytes[9] = 24;
    bytes[15] = 1;
    bytes[32..32 + table.len()].copy_from_slice(&table);
    let at = 32 + table.len();
    bytes[at..at + 4].copy_from_slice(b"@SFV");
    BinaryWriter::u32_be(28, &mut bytes[at + 4..]);
    bytes[at + 9] = 24;
    bytes[at + 32..].copy_from_slice(b"DATA");
    let movie = Usm::open(source(bytes.clone()))?;
    assert_eq!(movie.headers.len(), 1);
    assert_eq!(movie.first_data, at as u64);
    let chunk = movie.chunk(at as u64)?;
    assert_eq!(movie.payload(&chunk)?.read_at(0, 4)?.as_ref(), b"DATA");
    BinaryWriter::u32_be(u32::MAX, &mut bytes[4..]);
    assert!(Usm::open(source(bytes)).is_err());
    Ok(())
}

fn stream_chunk(id: &[u8; 4], kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes[..4].copy_from_slice(id);
    BinaryWriter::u32_be((24 + payload.len()) as u32, &mut bytes[4..]);
    bytes[9] = 24;
    bytes[15] = kind;
    bytes.extend_from_slice(payload);
    bytes
}

fn seek_movie(frames: &[u64], offsets: Option<&[u64]>) -> (Vec<u8>, u64, u64) {
    let mut bytes = stream_chunk(b"CRID", 1, &table("CRIUSF_DIR_STREAM", &[], 0));
    bytes.extend(stream_chunk(b"@SFV", 1, &table("VIDEO_HDRINFO", &[], 0)));
    bytes.extend(stream_chunk(b"@SFA", 1, &table("AUDIO_HDRINFO", &[], 0)));
    let index = |offsets: &[u64]| {
        stream_chunk(
            b"@SFV",
            3,
            &table(
                "VIDEO_SEEKINFO",
                &[
                    (
                        "ofs_byte",
                        6,
                        0x40,
                        offsets.iter().copied().map(Cell::Number).collect(),
                    ),
                    (
                        "ofs_frmid",
                        5,
                        0x40,
                        frames.iter().copied().map(Cell::Number).collect(),
                    ),
                    ("num_skip", 2, 0x10, Vec::new()),
                ],
                frames.len() as u32,
            ),
        )
    };
    let first = bytes.len() as u64 + index(&vec![0; frames.len()]).len() as u64;
    let late = first + 36;
    bytes.extend(index(offsets.unwrap_or(&[first, late])));
    bytes.extend(stream_chunk(b"@SFV", 0, b"GOP0"));
    bytes.extend(stream_chunk(b"@SFV", 0, b"GOP1"));
    (bytes, first, late)
}

#[test]
fn native_seek_index_is_lazy_and_seek_view_skips_prior_payload_and_audio_headers() -> Result<()> {
    let (bytes, first, late) = seek_movie(&[0, 13], None);
    let watched = Arc::new(Watched {
        bytes: bytes.clone(),
        end: first + 32,
        reads: Mutex::new(Vec::new()),
    });
    let movie = Usm::open(watched.clone())?;
    let points = movie.video_seek_points(0)?;
    assert_eq!(
        points,
        [
            SeekPoint {
                offset: first,
                frame: 0,
                skip: 0
            },
            SeekPoint {
                offset: late,
                frame: 13,
                skip: 0
            }
        ]
    );
    assert!(
        watched
            .reads
            .lock()
            .map_err(|_| io::Error::other("read log poisoned"))?
            .iter()
            .all(|&(offset, size)| offset + size as u64 <= first + 32)
    );

    let reads = Arc::new(Watched {
        bytes: bytes.clone(),
        end: bytes.len() as u64,
        reads: Mutex::new(Vec::new()),
    });
    let movie = Usm::open(reads.clone())?;
    reads
        .reads
        .lock()
        .map_err(|_| io::Error::other("read log poisoned"))?
        .clear();
    let view = movie.video_seek_source(0, late)?;
    let mut expected = Vec::new();
    let mut offset = 0;
    while offset < first {
        let chunk = movie.chunk(offset)?;
        if chunk.id != *b"@SFA" {
            expected.extend_from_slice(&bytes[offset as usize..(offset + chunk.size) as usize]);
        }
        offset += chunk.size;
    }
    expected.extend_from_slice(&bytes[late as usize..]);
    assert_eq!(view.len(), expected.len() as u64);
    assert_eq!(view.read_at(0, expected.len())?.as_ref(), expected);
    // Cross-range reads and direct, borrowed reads must have identical bytes.
    for start in 0..expected.len() {
        let size = 33.min(expected.len() - start);
        assert_eq!(
            view.read_at(start as u64, size)?.as_ref(),
            &expected[start..start + size]
        );
    }
    assert!(view.read_at(view.len(), 1).is_err());
    assert!(view.read_at(view.len(), 0)?.is_empty());
    assert!(movie.video_seek_source(0, 0).is_err());
    assert!(
        reads
            .reads
            .lock()
            .map_err(|_| io::Error::other("read log poisoned"))?
            .iter()
            .all(|&(offset, size)| offset >= late || offset + size as u64 <= first)
    );
    Ok(())
}

#[test]
fn native_seek_index_checks_source_bounds_and_order() -> Result<()> {
    for (frames, offsets) in [
        ([13, 0], None),
        ([0, 13], Some([0, 32])),
        ([0, 13], Some([u64::MAX - 1, u64::MAX])),
    ] {
        let (bytes, _, _) = seek_movie(&frames, offsets.as_ref().map(|v| v.as_slice()));
        let movie = Usm::open(source(bytes))?;
        assert!(movie.video_seek_points(0).is_err());
    }
    Ok(())
}
