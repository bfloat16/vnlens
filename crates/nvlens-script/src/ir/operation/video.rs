//! Video operations in the shared script IR.

define_operations! {
    pub enum VideoOperation {
        Play => "play_video",
        Stop => "stop_video",
    }
}
