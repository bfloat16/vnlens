//! Storage operations in the shared script IR.

define_operations! {
    pub enum StorageOperation {
        Push => "push",
        Pop => "pop",
        Duplicate => "duplicate",
        Declare => "declare",
        Load => "load",
        Store => "store",
        Reference => "reference",
        Invalidate => "invalidate",
        BindContext => "bind_context",
        GetStackPointer => "get_stack_pointer",
        SetStackPointer => "set_stack_pointer",
        AdjustStackPointer => "adjust_stack_pointer",
        EnterFrame => "enter_frame",
        LeaveFrame => "leave_frame",
        GetArguments => "get_arguments",
        GetArgument => "get_argument",
        GetArgumentCount => "get_argument_count",
        IndexBegin => "index_begin",
        IndexEnd => "index_end",
        IndexSeparator => "index_separator",
    }
}
