use crate::app::LogAtlasApp;
use eframe::egui;

pub fn timeline_panel(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    ui.heading("Timeline");
    ui.add_space(6.0);

    crate::ui::timeline_bar(ui, app);
    ui.add_space(8.0);

    let mut info = 0usize;
    let mut warning = 0usize;
    let mut high = 0usize;
    for ev in app.events.iter() {
        match ev.severity {
            crate::model::Severity::Info => info += 1,
            crate::model::Severity::Warning => warning += 1,
            crate::model::Severity::High => high += 1,
        }
    }
    ui.horizontal_wrapped(|ui| {
        ui.label(format!("Total {}", app.events.len()));
        ui.colored_label(
            crate::ui::severity_color(crate::model::Severity::Info),
            format!("Info {info}"),
        );
        ui.colored_label(
            crate::ui::severity_color(crate::model::Severity::Warning),
            format!("Warn {warning}"),
        );
        ui.colored_label(
            crate::ui::severity_color(crate::model::Severity::High),
            format!("High {high}"),
        );
    });
    ui.add_space(6.0);

    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.text_edit_singleline(&mut app.ui.filter);
        if ui.button("Clear").clicked() {
            app.ui.filter.clear();
        }
    });

    ui.add_space(6.0);

    egui::ScrollArea::vertical()
        .id_source("timeline_events_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for ev in app.events.iter() {
                if !passes_filter(ev, &app.ui.filter) {
                    continue;
                }

                let selected = app.selected == Some(ev.id);
                let label = format!(
                    "+{:>4}ms  {:<4}  {}",
                    ev.t_ms,
                    ev.severity.label(),
                    ev.title
                );
                let label = egui::RichText::new(label)
                    .monospace()
                    .color(crate::ui::severity_color(ev.severity));

                let response = ui
                    .add_sized(
                        [ui.available_width(), 0.0],
                        egui::SelectableLabel::new(selected, label),
                    )
                    .on_hover_text(format!("{}\nsource={}", ev.details, ev.source));

                if response.clicked() {
                    app.selected = Some(ev.id);
                }

                ui.add_space(2.0);
            }
        });
}

fn passes_filter(ev: &crate::model::Event, filter: &str) -> bool {
    let f = filter.trim();
    if f.is_empty() {
        return true;
    }

    let f = f.to_ascii_lowercase();
    ev.title.to_ascii_lowercase().contains(&f)
        || ev.details.to_ascii_lowercase().contains(&f)
        || ev.source.to_ascii_lowercase().contains(&f)
}
