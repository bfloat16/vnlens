//! Closed argument vocabulary shared by every engine. Indexed arguments keep
//! their ordinal separately; engine names belong only to native_name.
use super::Category;
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeArg {
    A,
    B,
    C,
    K,
    VB,
    VC,
    SJ,
    Ax,
    Bx,
    SBx,
    SB,
    SC,
}
impl NativeArg {
    pub const fn name(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::K => "k",
            Self::VB => "vB",
            Self::VC => "vC",
            Self::SJ => "sJ",
            Self::Ax => "Ax",
            Self::Bx => "Bx",
            Self::SBx => "sBx",
            Self::SB => "sB",
            Self::SC => "sC",
        }
    }
}

macro_rules! arguments {
    ($($category:ident { $($plain:ident => $plain_name:literal),* $(,)? }
        indexed { $($indexed:ident => $indexed_name:literal),* $(,)? })*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ArgName {
            $($($plain,)* $($indexed(u64),)*)*
            Native(NativeArg),
        }
        impl ArgName {
            #[must_use]
            pub const fn category(self) -> Category {
                match self {
                    $($(Self::$plain => Category::$category,)*
                      $(Self::$indexed(_) => Category::$category,)*)*
                    Self::Native(_) => Category::Native,
                }
            }
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $($(Self::$plain => $plain_name,)*
                      $(Self::$indexed(_) => $indexed_name,)*)*
                    Self::Native(field) => field.name(),
                }
            }
            #[must_use]
            pub const fn index(self) -> Option<u64> {
                match self {
                    $($(Self::$plain => None,)*
                      $(Self::$indexed(index) => Some(index),)*)*
                    Self::Native(_) => None,
                }
            }
        }
    };
}

arguments! {
    Basic {
        Value => "value",
        Left => "left",
        Right => "right",
        ValueType => "value_type",
        LeftType => "left_type",
        RightType => "right_type",
        Operator => "operator",
        Count => "count",
        ByteCount => "byte_count",
        Mode => "mode",
        Flags => "flags",
        Duration => "duration",
    } indexed {
        ValueAt => "value",
    }
    Storage {
        Destination => "destination",
        Source => "source",
        Variable => "variable",
        VariableId => "variable_id",
        InitialValue => "initial_value",
        Sigil => "sigil",
        LocalOffset => "local_offset",
        LocalDescriptor => "local_descriptor",
        DataOffset => "data_offset",
        WidthTag => "width_tag",
        Delta => "delta",
        DestinationType => "destination_type",
        Register => "register",
        Upvalue => "upvalue",
        FunctionIndex => "function_index",
        ConstantIndex => "constant_index",
        Scope => "scope",
        Storage => "storage",
        Dimensions => "dimensions",
        InitialLength => "initial_length",
    } indexed {
        Dimension => "dimension",
    }
    ControlFlow {
        Target => "target",
        ResolvedTarget => "resolved_target",
        Condition => "condition",
        NextBranchTarget => "next_branch_target",
        EndTarget => "end_target",
        LabelId => "label_id",
        Label => "label",
        Callee => "callee",
        ArgumentCount => "argument_count",
        NamedArgumentCount => "named_argument_count",
        ReturnType => "return_type",
        ReturnCode => "return_code",
        Overload => "overload",
        Descriptor => "descriptor",
        Instruction => "instruction",
        ConditionalDepth => "conditional_depth",
        LoopDepth => "loop_depth",
    } indexed {
        ArgumentType => "argument_type",
        TupleCount => "tuple_count",
        NamedArgument => "named_argument",
        Component => "component",
        Choice => "choice",
    }
    Text {
        Text => "text",
        TextId => "text_id",
        Message => "message",
        Title => "title",
        TitleLength => "title_length",
    } indexed {
    }
    Audio {
        Channel => "channel",
        Volume => "volume",
    } indexed {
    }
    Image {
        Resource => "resource",
        ImageFrame => "image_frame",
        FrameCount => "frame_count",
        OffsetX => "offset_x",
        OffsetY => "offset_y",
        Width => "width",
        Height => "height",
        Opacity => "opacity",
    } indexed {
    }
    Data {
        SourceFile => "source_file",
        SourceLine => "source_line",
        SourcePath => "source_path",
        Path => "path",
        Constants => "constants",
        Data => "data",
        Id => "id",
        Index => "index",
        Name => "name",
        Type => "type",
        Metadata => "metadata",
        Code => "code",
        Command => "command",
        CommandCount => "command_count",
        ErrorCount => "error_count",
        MaximumVariableId => "maximum_variable_id",
        ReturnCodeCount => "return_code_count",
        ScriptCount => "script_count",
        ScriptId => "script_id",
        PathLength => "path_length",
        RuntimeFlags => "runtime_flags",
        LabelCount => "label_count",
        FirstLabel => "first_label",
        NameLength => "name_length",
        NameHash => "name_hash",
        VariableCount => "variable_count",
        VirtualKey => "virtual_key",
        WindowOption => "window_option",
        Word => "word",
        Reserved => "reserved",
    } indexed {
        Constant => "constant",
        ReservedAt => "reserved",
        SourceStamp => "source_stamp",
        SourceField => "source_field",
        ResourcePriority => "resource_priority",
        Option => "option",
        Terminator => "terminator",
    }
    Unknown {
    } indexed {
        Unknown => "unknown",
    }
}

impl fmt::Display for ArgName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        if let Some(index) = self.index() {
            write!(f, "[{index}]")?;
        }
        Ok(())
    }
}
impl Serialize for ArgName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value =
            serializer.serialize_struct("ArgName", if self.index().is_some() { 3 } else { 2 })?;
        value.serialize_field("category", &self.category())?;
        value.serialize_field("name", self.name())?;
        if let Some(index) = self.index() {
            value.serialize_field("index", &index)?;
        }
        value.end()
    }
}
