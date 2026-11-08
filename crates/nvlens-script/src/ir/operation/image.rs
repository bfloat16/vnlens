//! Image operations in the shared script IR.

define_operations! {
    pub enum ImageOperation {
        Load => "load_image",
        Clear => "clear_image",
        SetRegion => "set_image_region",
        SetVisibility => "set_image_visibility",
        Capture => "capture_image",
        Draw => "draw_image",
        Configure => "configure_image",
    }
}
