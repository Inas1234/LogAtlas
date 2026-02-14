#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::High => "HIGH",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub id: EventId,
    /// Milliseconds from capture start (placeholder until we parse real timestamps).
    pub t_ms: u64,
    pub severity: Severity,
    pub title: String,
    pub details: String,
    pub source: String,
}
