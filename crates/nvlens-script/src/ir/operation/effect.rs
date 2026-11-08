//! Visual effect operations in the shared script IR.
define_operations! {
    pub enum EffectOperation {
        Fade => "fade",
        StopFade => "stop_fade",
        Blur => "blur",
        StopBlur => "stop_blur",
        Shake => "shake",
    }
}
