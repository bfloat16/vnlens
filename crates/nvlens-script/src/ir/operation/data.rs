//! Data operations in the shared script IR.

define_operations! {
    pub enum DataOperation {
        SourceLocation => "source_location",
        Record => "record",
    }
}
