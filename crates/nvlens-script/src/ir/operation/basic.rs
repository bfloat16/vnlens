//! Basic operations in the shared script IR.

define_operations! {
    pub enum BasicOperation {
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
    }
}
