#[derive(Clone, Debug, Default)]
pub struct MinidumpSummary {
    pub file_size: Option<u64>,
    pub time_date_stamp: Option<u32>,
    pub os: Option<String>,
    pub cpu: Option<String>,
    pub module_count: Option<usize>,
    pub thread_count: Option<usize>,
    pub exception: Option<String>,
}

impl MinidumpSummary {
    pub fn pretty(&self) -> String {
        let mut lines = Vec::new();

        if let Some(sz) = self.file_size {
            lines.push(format!("File size: {sz} bytes"));
        }
        if let Some(ts) = self.time_date_stamp {
            lines.push(format!("TimeDateStamp (unix): {ts}"));
            if let Some(utc) = crate::util::time::unix_seconds_to_utc_string(ts as u64) {
                lines.push(format!("TimeDateStamp (utc): {utc}"));
            }
        }
        if let Some(os) = &self.os {
            lines.push(format!("OS: {os}"));
        }
        if let Some(cpu) = &self.cpu {
            lines.push(format!("CPU: {cpu}"));
        }
        if let Some(n) = self.thread_count {
            lines.push(format!("Threads: {n}"));
        }
        if let Some(n) = self.module_count {
            lines.push(format!("Modules: {n}"));
        }
        if let Some(e) = &self.exception {
            lines.push(format!("Exception: {e}"));
        }

        if lines.is_empty() {
            "<no summary>".into()
        } else {
            lines.join("\n")
        }
    }
}
