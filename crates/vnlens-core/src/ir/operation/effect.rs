//! Visual effect operations in the shared script IR.
define_operations! {
    pub enum EffectOperation {
        Configure => "configure_effect",
        Transition => "transition",
        Fade => "fade",
        StopFade => "stop_fade",
        Blur => "blur",
        StopBlur => "stop_blur",
        Shake => "shake",
        Flash => "flash",
    }
}
