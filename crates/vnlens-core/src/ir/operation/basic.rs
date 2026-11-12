//! Basic operations in the shared script IR.

define_operations! {
    pub enum BasicOperation {
        Evaluate => "evaluate",
        Add => "add",
        Subtract => "subtract",
        Multiply => "multiply",
        Divide => "divide",
        Power => "power",
        Remainder => "remainder",
        Negate => "negate",
        BitAnd => "bit_and",
        BitOr => "bit_or",
        BitXor => "bit_xor",
        BitNot => "bit_not",
        ShiftLeft => "shift_left",
        ShiftRight => "shift_right",
        Convert => "convert",
        Concatenate => "concatenate",
        Length => "length",
        TypeOf => "type_of",
        CharacterCode => "character_code",
        CharacterFromCode => "character_from_code",
        IsValid => "is_valid",
        Absolute => "absolute",
        Minimum => "minimum",
        Maximum => "maximum",
        Random => "random",
        PackColor => "pack_color",
    }
}
