use crate::model::Severity;

#[derive(Clone, Debug, Default)]
pub struct MinidumpReport {
    pub os: Option<String>,
    pub cpu: Option<String>,
    /// Details about the process that produced this minidump.
    pub process: Option<ProcessInfo>,
    /// Best-effort execution artifacts (heuristics over dump memory).
    pub exec_artifacts: Vec<ProcessExecArtifact>,
    /// Best-effort detection of executable memory regions that look like injection/shellcode.
    ///
    /// Requires `MemoryInfoListStream` to be present in the dump.
    pub injected_regions: Vec<InjectedRegion>,
    pub memory_region_count: Option<usize>,
    pub memory_region_64_count: Option<usize>,
    pub memory_info_region_count: Option<usize>,
    pub modules: Vec<ModuleInfo>,
    pub threads: Vec<ThreadInfo>,
    pub exception: Option<ExceptionInfo>,
}

impl MinidumpReport {
    pub fn last_thread_create_time_unix(&self) -> Option<u64> {
        self.threads
            .iter()
            .filter_map(|t| t.create_time_unix)
            .max()
    }

    pub fn detections(&self) -> Vec<Detection> {
        let mut out = Vec::new();

        if let Some(exc) = &self.exception {
            if exc.code == 0xC000_0005 {
                out.push(Detection {
                    severity: Severity::High,
                    title: "Access violation".into(),
                    details: format!(
                        "Exception code 0xC0000005 at address 0x{:016X} (thread_id={}).",
                        exc.address, exc.thread_id
                    ),
                });
            }
        }

        for m in &self.modules {
            let name_lc = m.name.to_ascii_lowercase();
            if name_lc.contains("\\appdata\\local\\temp\\")
                || name_lc.contains("/tmp/")
                || name_lc.contains("\\temp\\")
            {
                out.push(Detection {
                    severity: Severity::Warning,
                    title: "Module loaded from temp path".into(),
                    details: format!("Module: {}", m.name),
                });
            }
        }

        for a in &self.exec_artifacts {
            if let Some(det) = detect_exec_artifact(a) {
                out.push(det);
            }
        }

        for r in &self.injected_regions {
            out.push(Detection {
                severity: r.risk,
                title: "Suspicious executable memory allocation".into(),
                details: format!(
                    "base=0x{base:016X} size=0x{size:X}\nprotection={prot}\ntype={ty}\nstate={state}\n\nReasons:\n{reasons}",
                    base = r.base,
                    size = r.size,
                    prot = r.protection,
                    ty = r.ty,
                    state = r.state,
                    reasons = if r.reasons.is_empty() {
                        "- (none)".into()
                    } else {
                        r.reasons
                            .iter()
                            .map(|s| format!("- {s}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    }
                ),
            });
        }

        out
    }
}

fn detect_exec_artifact(a: &ProcessExecArtifact) -> Option<Detection> {
    let cl = a.command_line.to_ascii_lowercase();
    let img = a.image.to_ascii_lowercase();

    let is_lolbin = [
        "powershell",
        "pwsh",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "schtasks",
        "wmic",
        "certutil",
        "bitsadmin",
        "msbuild",
        "installutil",
    ]
    .iter()
    .any(|k| img.contains(k) || cl.contains(k));

    if !is_lolbin {
        return None;
    }

    let mut reasons: Vec<&str> = Vec::new();
    if cl.contains(" -enc") || cl.contains(" -encodedcommand") {
        reasons.push("encoded command");
    }
    if cl.contains("frombase64string") || cl.contains("iex") || cl.contains("invoke-expression") {
        reasons.push("in-memory execution pattern");
    }
    if cl.contains("\\appdata\\local\\temp\\") || cl.contains("\\temp\\") || cl.contains("/tmp/") {
        reasons.push("temp path");
    }
    if cl.contains("http://") || cl.contains("https://") {
        reasons.push("network indicator");
    }

    let severity = if reasons.is_empty() {
        Severity::Warning
    } else {
        Severity::High
    };

    Some(Detection {
        severity,
        title: "Suspicious execution artifact".into(),
        details: if reasons.is_empty() {
            format!("Image: {}\nCommand line: {}", a.image, a.command_line)
        } else {
            format!(
                "Reasons: {}\nImage: {}\nCommand line: {}",
                reasons.join(", "),
                a.image,
                a.command_line
            )
        },
    })
}

#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: Option<u32>,
    /// Unix epoch seconds (time_t in the stream), if present.
    pub create_time_unix: Option<u64>,
    pub integrity_level: Option<u32>,
    pub execute_flags: Option<u32>,
    pub protected_process: Option<u32>,
    pub main_image: Option<String>,
    pub main_image_version: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecArtifactEncoding {
    Ascii,
    Utf16Le,
}

#[derive(Clone, Debug)]
pub struct ProcessExecArtifact {
    /// Extracted executable/script "image" (best-effort).
    pub image: String,
    /// Full command line or invocation string.
    pub command_line: String,
    /// Source encoding of the recovered string.
    pub encoding: ExecArtifactEncoding,
    /// Virtual memory address of the string if known (base+offset).
    pub address: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct InjectedRegion {
    /// Allocation base (useful "base address" to pivot on).
    pub base: u64,
    /// Total size in bytes aggregated for this allocation.
    pub size: u64,
    /// Memory protection flags (stringified).
    pub protection: String,
    /// Memory type flags (stringified).
    pub ty: String,
    /// Memory state flags (stringified).
    pub state: String,
    /// Why we think this is interesting.
    pub reasons: Vec<String>,
    /// Simple risk hint for UI.
    pub risk: Severity,
}

#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub file_version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ThreadInfo {
    pub thread_id: u32,
    pub name: Option<String>,
    /// Windows FILETIME (100ns ticks since 1601-01-01 UTC), if present.
    pub create_time_filetime: Option<u64>,
    /// Derived unix seconds (UTC) from `create_time_filetime`, if conversion succeeds.
    pub create_time_unix: Option<u64>,
    /// Thread entrypoint (instruction pointer at thread start), if available.
    pub start_address: Option<u64>,
    pub suspend_count: u32,
    pub priority_class: u32,
    pub priority: u32,
    pub teb: u64,
    pub stack_start: u64,
    pub stack_size: u64,
}

#[derive(Clone, Debug)]
pub struct ExceptionInfo {
    pub thread_id: u32,
    pub code: u32,
    pub flags: u32,
    pub address: u64,
    pub number_parameters: u32,
}

#[derive(Clone, Debug)]
pub struct Detection {
    pub severity: Severity,
    pub title: String,
    pub details: String,
}
