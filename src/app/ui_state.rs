#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetailsTab {
    Event,
    Overview,
    Processes,
    Memory,
    Modules,
    Threads,
    Exception,
    Detections,
}

impl Default for DetailsTab {
    fn default() -> Self {
        Self::Event
    }
}

#[derive(Default)]
pub struct UiState {
    pub filter: String,
    pub show_about: bool,
    pub last_error: Option<String>,

    pub details_tab: DetailsTab,
    pub process_filter: String,
    pub selected_exec_artifact: Option<usize>,
    pub selected_injected_region: Option<usize>,
    pub module_filter: String,
    pub thread_filter: String,
    pub selected_module: Option<usize>,
    pub selected_thread: Option<u32>,
}
