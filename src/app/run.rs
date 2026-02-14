use crate::app::LogAtlasApp;
use eframe::egui;

pub fn run() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Log Atlas")
            .with_inner_size([1100.0, 720.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Log Atlas",
        native_options,
        Box::new(|_cc| Box::<LogAtlasApp>::default()),
    )
}
