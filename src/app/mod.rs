mod run;
mod ui_state;

use crate::model::{EventId, EventStore};
use eframe::egui;
use std::path::PathBuf;

pub use run::run;
pub use ui_state::DetailsTab;

pub struct LogAtlasApp {
    pub events: EventStore,
    pub selected: Option<EventId>,
    pub ui: ui_state::UiState,
    pub dump_path: Option<PathBuf>,
    pub dump_summary: Option<crate::model::MinidumpSummary>,
    pub dump_report: Option<crate::model::MinidumpReport>,
}

impl Default for LogAtlasApp {
    fn default() -> Self {
        let events = EventStore::demo();
        let selected = events.first_id();
        Self {
            events,
            selected,
            ui: ui_state::UiState::default(),
            dump_path: None,
            dump_summary: None,
            dump_report: None,
        }
    }
}

impl eframe::App for LogAtlasApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        crate::ui::render_app(ctx, frame, self);
    }
}

impl LogAtlasApp {
    pub fn load_minidump(&mut self, path: PathBuf) -> anyhow::Result<()> {
        self.ui.last_error = None;
        let ingested = crate::ingest::minidump::ingest(&path)?;
        self.dump_path = Some(path);
        self.dump_summary = Some(ingested.summary);
        self.dump_report = Some(ingested.report);
        self.events = ingested.events;
        self.selected = self.events.first_id();
        self.ui.details_tab = DetailsTab::Overview;
        self.ui.selected_exec_artifact = None;
        self.ui.selected_injected_region = None;
        self.ui.selected_module = None;
        self.ui.selected_thread = None;
        self.ui.selected_stack_thread = None;
        self.ui.stack_filter.clear();
        Ok(())
    }
}
