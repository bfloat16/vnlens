//! Audio operations in the shared script IR.

define_operations! {
    pub enum AudioOperation {
        Play => "play_audio",
        Stop => "stop_audio",
        SetVolume => "set_audio_volume",
        Wait => "wait_audio",
        Control => "control_audio",
    }
}
