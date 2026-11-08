//! Runtime operations in the shared script IR.

define_operations! {
    pub enum RuntimeOperation {
        EngineCall => "engine_call",
    }
}
