mod details;
mod timeline;
mod timeline_bar;

use crate::app::LogAtlasApp;
use crate::model::Severity;
use eframe::egui;

pub fn render_app(ctx: &egui::Context, frame: &mut eframe::Frame, app: &mut LogAtlasApp) {
    apply_visuals(ctx);
    top_bar(ctx, frame, app);

    egui::SidePanel::left("timeline_panel")
        .resizable(true)
        .default_width(400.0)
        .min_width(300.0)
        .show(ctx, |ui| timeline::timeline_panel(ui, app));

    egui::CentralPanel::default().show(ctx, |ui| details::details_panel(ui, app));

    about_window(ctx, app);
    status_bar(ctx, app);
}

fn apply_visuals(ctx: &egui::Context) {
    let visuals_applied_id = egui::Id::new("log_atlas_visuals_applied");
    let already_applied =
        ctx.data_mut(|d| d.get_persisted::<bool>(visuals_applied_id).unwrap_or(false));
    if already_applied {
        return;
    }
    ctx.data_mut(|d| d.insert_persisted(visuals_applied_id, true));

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 4.0);
    style.spacing.window_margin = egui::Margin::symmetric(10.0, 8.0);
    ctx.set_style(style);

    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(egui::Color32::from_rgb(222, 226, 232));
    visuals.panel_fill = egui::Color32::from_rgb(21, 24, 29);
    visuals.window_fill = egui::Color32::from_rgb(21, 24, 29);
    visuals.extreme_bg_color = egui::Color32::from_rgb(12, 14, 18);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(28, 32, 38);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(36, 42, 50);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(44, 55, 68);
    visuals.selection.bg_fill = egui::Color32::from_rgb(34, 114, 166);
    visuals.selection.stroke.color = egui::Color32::from_rgb(140, 200, 245);
    ctx.set_visuals(visuals);
}

fn top_bar(ctx: &egui::Context, frame: &mut eframe::Frame, app: &mut LogAtlasApp) {
    egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open minidump...").clicked() {
                    ui.close_menu();
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Minidump", &["dmp", "mdmp"])
                        .pick_file()
                    {
                        if let Err(e) = app.load_minidump(path) {
                            app.ui.last_error = Some(e.to_string());
                        }
                    }
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    let _ = frame; // keep signature stable if we later use frame APIs
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });

            ui.menu_button("View", |ui| {
                if ui.button("Reset zoom").clicked() {
                    ctx.set_zoom_factor(1.0);
                    ui.close_menu();
                }
            });

            ui.menu_button("Help", |ui| {
                if ui.button("About").clicked() {
                    app.ui.show_about = true;
                    ui.close_menu();
                }
            });
        });
    });
}

fn about_window(ctx: &egui::Context, app: &mut LogAtlasApp) {
    if !app.ui.show_about {
        return;
    }

    egui::Window::new("About Log Atlas")
        .open(&mut app.ui.show_about)
        .resizable(false)
        .show(ctx, |ui| {
            ui.label("Phase 1: GUI scaffold + event timeline placeholder.");
            ui.label("Next: minidump ingestion -> normalized events -> detectors.");
        });
}

fn status_bar(ctx: &egui::Context, app: &mut LogAtlasApp) {
    egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.label(format!("Events: {}", app.events.len()));
            ui.separator();
            if let Some(p) = &app.dump_path {
                let name = p
                    .file_name()
                    .map(|s| s.to_string_lossy())
                    .unwrap_or_else(|| p.to_string_lossy());
                ui.label(format!("Dump: {name}"));
                ui.separator();
            }
            if let Some(id) = app.selected {
                if let Some(ev) = app.events.get(id) {
                    ui.label(format!("Selected: {} (+{}ms)", ev.title, ev.t_ms));
                } else {
                    ui.label("Selected: (missing)");
                }
            } else {
                ui.label("Selected: (none)");
            }
            if let Some(err) = &app.ui.last_error {
                ui.separator();
                ui.colored_label(
                    egui::Color32::from_rgb(255, 70, 70),
                    format!("Error: {err}"),
                );
            }
        });
    });
}

pub fn severity_color(sev: Severity) -> egui::Color32 {
    match sev {
        Severity::Info => egui::Color32::from_rgb(90, 160, 255),
        Severity::Warning => egui::Color32::from_rgb(255, 170, 0),
        Severity::High => egui::Color32::from_rgb(255, 70, 70),
    }
}

pub use timeline_bar::timeline_bar;
