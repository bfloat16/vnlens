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
        GetStackPointer => "get_stack_pointer",
        SetStackPointer => "set_stack_pointer",
        AdjustStackPointer => "adjust_stack_pointer",
        GetArguments => "get_arguments",
        IndexBegin => "index_begin",
        IndexEnd => "index_end",
        IndexSeparator => "index_separator",
    }
}
