//! ControlFlow operations in the shared script IR.

define_operations! {
    pub enum ControlFlowOperation {
        Equal => "equal",
        NotEqual => "not_equal",
        Less => "less",
        Greater => "greater",
        LessEqual => "less_equal",
        GreaterEqual => "greater_equal",
        LogicalAnd => "logical_and",
        LogicalOr => "logical_or",
        LogicalNot => "logical_not",
        Jump => "jump",
        Branch => "branch",
        Call => "call",
        Return => "return",
        Halt => "halt",
        RegisterException => "register_exception",
        UnregisterException => "unregister_exception",
    }
}
