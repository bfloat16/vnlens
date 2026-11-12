//! Typed operation families. Category is derived from the enum variant,
//! so consumers cannot construct contradictory category/operation pairs.
use serde::{Serialize, Serializer, ser::SerializeStruct};

macro_rules! define_operations {
    (pub enum $ty:ident { $($variant:ident => $name:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum $ty { $($variant),+ }
        impl $ty {
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }
        }
    };
}

mod basic;
pub use basic::BasicOperation;
mod storage;
pub use storage::StorageOperation;
mod control_flow;
pub use control_flow::ControlFlowOperation;
mod text;
pub use text::TextOperation;
mod audio;
pub use audio::AudioOperation;
mod video;
pub use video::VideoOperation;
mod image;
pub use image::ImageOperation;
mod effect;
pub use effect::EffectOperation;
mod runtime;
pub use runtime::RuntimeOperation;
mod data;
pub use data::DataOperation;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Basic,
    Storage,
    ControlFlow,
    Text,
    Audio,
    Video,
    Image,
    Effect,
    Runtime,
    Data,
    /// A documented VM kept in its native instruction set and vocabulary.
    Native,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    Basic(BasicOperation),
    Storage(StorageOperation),
    ControlFlow(ControlFlowOperation),
    Text(TextOperation),
    Audio(AudioOperation),
    Video(VideoOperation),
    Image(ImageOperation),
    Effect(EffectOperation),
    Runtime(RuntimeOperation),
    Data(DataOperation),
    /// A documented VM kept in its native instruction set and vocabulary.
    Native,
    Unknown,
}

impl Operation {
    #[must_use]
    pub const fn category(self) -> Category {
        match self {
            Self::Basic(_) => Category::Basic,
            Self::Storage(_) => Category::Storage,
            Self::ControlFlow(_) => Category::ControlFlow,
            Self::Text(_) => Category::Text,
            Self::Audio(_) => Category::Audio,
            Self::Video(_) => Category::Video,
            Self::Image(_) => Category::Image,
            Self::Effect(_) => Category::Effect,
            Self::Runtime(_) => Category::Runtime,
            Self::Data(_) => Category::Data,
            Self::Native => Category::Native,
            Self::Unknown => Category::Unknown,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Basic(op) => op.name(),
            Self::Storage(op) => op.name(),
            Self::ControlFlow(op) => op.name(),
            Self::Text(op) => op.name(),
            Self::Audio(op) => op.name(),
            Self::Video(op) => op.name(),
            Self::Image(op) => op.name(),
            Self::Effect(op) => op.name(),
            Self::Runtime(op) => op.name(),
            Self::Data(op) => op.name(),
            Self::Native => "native",
            Self::Unknown => "unknown",
        }
    }
}

impl Serialize for Operation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("Operation", 2)?;
        value.serialize_field("category", &self.category())?;
        value.serialize_field("operation", self.name())?;
        value.end()
    }
}
