//! Text operations in the shared script IR.

define_operations! {
    pub enum TextOperation {
        Show => "show_text",
        Clear => "clear_text",
        Configure => "configure_text",
        Wait => "wait_text",
    }
}
