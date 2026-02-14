use crate::app::LogAtlasApp;
use eframe::egui;

pub fn timeline_bar(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    if app.events.len() == 0 {
        return;
    }

    let w = ui.available_width().max(120.0);
    let h = 34.0;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(w, h), egui::Sense::click());

    let painter = ui.painter_at(rect);
    let stroke = egui::Stroke::new(1.0, ui.visuals().widgets.inactive.fg_stroke.color);

    let mid_y = rect.center().y;
    painter.line_segment(
        [
            egui::pos2(rect.left() + 6.0, mid_y),
            egui::pos2(rect.right() - 6.0, mid_y),
        ],
        stroke,
    );

    let max_t = app.events.iter().map(|e| e.t_ms).max().unwrap_or(0).max(1);

    let mut points: Vec<(egui::Pos2, crate::model::EventId)> = Vec::new();
    for ev in app.events.iter() {
        let x = rect.left() + 6.0 + (rect.width() - 12.0) * (ev.t_ms as f32 / max_t as f32);
        let p = egui::pos2(x, mid_y);
        let r = if app.selected == Some(ev.id) {
            5.5
        } else {
            4.0
        };
        let fill = crate::ui::severity_color(ev.severity);
        painter.circle_filled(p, r, fill);
        points.push((p, ev.id));
    }

    if response.clicked() {
        if let Some(pos) = response.interact_pointer_pos() {
            if let Some((_, id)) = nearest_point(&points, pos, 10.0) {
                app.selected = Some(*id);
            }
        }
    }

    if response.hovered() {
        if let Some(pos) = response.hover_pos() {
            if let Some((d, id)) = nearest_point(&points, pos, 10.0) {
                if let Some(ev) = app.events.get(*id) {
                    egui::show_tooltip_at_pointer(
                        ui.ctx(),
                        egui::Id::new("timeline_hover"),
                        |ui| {
                            ui.label(egui::RichText::new("Timeline").strong());
                            ui.monospace(format!("+{}ms", ev.t_ms));
                            ui.label(format!("{}  {}", ev.severity.label(), ev.title));
                            let _ = d;
                        },
                    );
                }
            }
        }
    }
}

fn nearest_point<'a>(
    points: &'a [(egui::Pos2, crate::model::EventId)],
    pos: egui::Pos2,
    max_dist: f32,
) -> Option<(f32, &'a crate::model::EventId)> {
    points
        .iter()
        .map(|(p, id)| (p.distance(pos), id))
        .filter(|(d, _)| *d <= max_dist)
        .min_by(|(a, _), (b, _)| a.total_cmp(b))
}
