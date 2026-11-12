//! Runtime operations in the shared script IR.

define_operations! {
    pub enum RuntimeOperation {
        NoOp => "no_op",
        SetFrameDuration => "set_frame_duration",
        MarkSeen => "mark_seen",
        StopSkip => "stop_skip",
        Wait => "wait",
        Yield => "yield",
        EngineCall => "engine_call",
        Save => "save_game",
    }
}
