//! Text operations in the shared script IR.

define_operations! {
    pub enum TextOperation {
        Show => "show_text",
        Clear => "clear_text",
        Configure => "configure_text",
        Wait => "wait_text",
        LineBreak => "text_line_break",
        BeginSpan => "begin_text_span",
        EndSpan => "end_text_span",
        End => "end_text",
        AppendHistory => "append_text_history",
    }
}
