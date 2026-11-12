//! Dataset records and background progress, independent of desktop widgets.

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Record {
    pub speaker: String,
    /// Relative path to the successfully written, original-format voice file.
    pub voice: String,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Stage {
    #[default]
    Indexing,
    ReadingScripts,
    Writing,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Progress {
    pub stage: Stage,
    pub completed: usize,
    pub total: usize,
    pub records: usize,
    pub voices: usize,
    pub skipped: usize,
    pub failed: usize,
}
