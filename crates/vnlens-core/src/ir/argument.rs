//! Shared semantic vocabulary with an open native-VM field namespace.
//! Indexed arguments keep their ordinal separately; companion names retain
//! their original spelling in native_name.
use super::Category;
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeArg {
    /// A field from a documented native VM, outside the shared vocabulary.
    Named(&'static str),
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
            Self::Named(name) => name,
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
        Values => "values",
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
        Mask => "mask",
        Precedence => "precedence",
        Duration => "duration",
        StartTime => "start_time",
        Enabled => "enabled",
        Minimum => "minimum",
        Maximum => "maximum",
    } indexed {
        ValueAt => "value",
    }
    Storage {
        Destination => "destination",
        Source => "source",
        Variable => "variable",
        VariableId => "variable_id",
        FlagId => "flag_id",
        ContextId => "context_id",
        ParentIndex => "parent_index",
        ReserveCount => "reserve_count",
        MaximumRegisterIndex => "maximum_register_index",
        ArgumentBase => "argument_base",
        CollapseBase => "collapse_base",
        SetterIndex => "setter_index",
        GetterIndex => "getter_index",
        SuperClassGetterIndex => "super_class_getter_index",
        InitialValue => "initial_value",
        Sigil => "sigil",
        LocalOffset => "local_offset",
        LocalIndex => "local_index",
        LocalDescriptor => "local_descriptor",
        DataOffset => "data_offset",
        WidthTag => "width_tag",
        Delta => "delta",
        DestinationType => "destination_type",
        Register => "register",
        Upvalue => "upvalue",
        FunctionIndex => "function_index",
        ConstantIndex => "constant_index",
        StringIndex => "string_index",
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
        LabelBase => "label_base",
        ChoiceId => "choice_id",
        DefaultChoice => "default_choice",
        HeadingCount => "heading_count",
        Label => "label",
        Callee => "callee",
        ArgumentCount => "argument_count",
        Arguments => "arguments",
        StackIndex => "stack_index",
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
        Case => "case",
    }
    Text {
        Text => "text",
        TextId => "text_id",
        MessageIndex => "message_index",
        SpeakerId => "speaker_id",
        VoiceId => "voice_id",
        VoiceSpeakerId => "voice_speaker_id",
        GlyphId => "glyph_id",
        CharacterSet => "character_set",
        Alignment => "alignment",
        StyleId => "style_id",
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
        ResourceId => "resource_id",
        ImageFrame => "image_frame",
        FrameCount => "frame_count",
        OffsetX => "offset_x",
        OffsetY => "offset_y",
        OriginX => "origin_x",
        OriginY => "origin_y",
        RectLeft => "rect_left",
        RectTop => "rect_top",
        RectRight => "rect_right",
        RectBottom => "rect_bottom",
        Color => "color",
        Layer => "layer",
        ScaleX => "scale_x",
        ScaleY => "scale_y",
        Rotation => "rotation",
        Priority => "priority",
        Width => "width",
        Height => "height",
        Opacity => "opacity",
        Red => "red",
        Green => "green",
        Blue => "blue",
    } indexed {
    }
    Effect {
        Easing => "easing",
        EasingParameter => "easing_parameter",
        EffectId => "effect_id",
    } indexed {
    }
    Data {
        SourceFile => "source_file",
        SourceLine => "source_line",
        SourcePath => "source_path",
        SourceMap => "source_map",
        SourceOffset => "source_offset",
        Properties => "properties",
        Path => "path",
        Constants => "constants",
        Messages => "messages",
        Resources => "resources",
        Labels => "labels",
        Targets => "targets",
        ReturnTargets => "return_targets",
        ChoiceTargets => "choice_targets",
        CommandTargets => "command_targets",
        ScriptCallTargets => "script_call_targets",
        Signature => "signature",
        StringPool => "string_pool",
        Padding => "padding",
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
        Version => "version",
        State => "state",
        Rows => "rows",
        Frames => "frames",
        ProcedureId => "procedure_id",
    } indexed {
        Constant => "constant",
        Row => "row",
        Column => "column",
        StringAt => "string",
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
