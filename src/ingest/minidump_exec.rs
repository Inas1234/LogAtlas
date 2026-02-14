use crate::model::{ExecArtifactEncoding, ProcessExecArtifact};

const MAX_SCAN_BYTES: usize = 32 * 1024 * 1024; // hard cap to keep UI responsive on full dumps
const MAX_ARTIFACTS: usize = 200;

pub fn extract_exec_artifacts(
    dump: &minidump::Minidump<Vec<u8>>,
) -> Vec<ProcessExecArtifact> {
    // A minidump is a snapshot of a single process. It doesn't reliably contain
    // "child process list" data. We therefore do a best-effort scan for strings
    // that look like command-lines or LOLBin invocations.

    let mut out: Vec<ProcessExecArtifact> = Vec::new();
    let mut scanned = 0usize;

    // Prefer Memory64 when present (full dumps), otherwise MemoryList.
    if let Ok(mem64) = dump.get_stream::<minidump::MinidumpMemory64List>() {
        for region in mem64.iter() {
            if scanned >= MAX_SCAN_BYTES || out.len() >= MAX_ARTIFACTS {
                break;
            }
            let take = (MAX_SCAN_BYTES - scanned).min(region.bytes.len());
            scan_region(&region.bytes[..take], region.base_address, &mut out);
            scanned += take;
        }
    } else if let Ok(mem) = dump.get_stream::<minidump::MinidumpMemoryList>() {
        for region in mem.iter() {
            if scanned >= MAX_SCAN_BYTES || out.len() >= MAX_ARTIFACTS {
                break;
            }
            let take = (MAX_SCAN_BYTES - scanned).min(region.bytes.len());
            scan_region(&region.bytes[..take], region.base_address, &mut out);
            scanned += take;
        }
    }

    dedup_artifacts(out)
}

fn scan_region(bytes: &[u8], base: u64, out: &mut Vec<ProcessExecArtifact>) {
    if out.len() >= MAX_ARTIFACTS || bytes.is_empty() {
        return;
    }

    scan_ascii(bytes, base, out);
    if out.len() >= MAX_ARTIFACTS {
        return;
    }
    scan_utf16le(bytes, base, out);
}

fn scan_ascii(bytes: &[u8], base: u64, out: &mut Vec<ProcessExecArtifact>) {
    let mut i = 0usize;
    while i < bytes.len() && out.len() < MAX_ARTIFACTS {
        if !is_ascii_printable(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_ascii_printable(bytes[i]) {
            i += 1;
        }
        let s = &bytes[start..i];
        if s.len() >= 12 && s.len() <= 800 {
            if let Ok(text) = std::str::from_utf8(s) {
                let text = text.trim();
                if is_likely_command_line(text) {
                    out.push(ProcessExecArtifact {
                        image: parse_image(text),
                        command_line: text.to_string(),
                        encoding: ExecArtifactEncoding::Ascii,
                        address: Some(base + start as u64),
                    });
                }
            }
        }
        // Skip separator bytes (often NUL)
        while i < bytes.len() && !is_ascii_printable(bytes[i]) {
            i += 1;
        }
    }
}

fn scan_utf16le(bytes: &[u8], base: u64, out: &mut Vec<ProcessExecArtifact>) {
    // Look for (printable,0) (printable,0) ... sequences.
    let mut i = 0usize;
    while i + 1 < bytes.len() && out.len() < MAX_ARTIFACTS {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];
        if !(b1 == 0 && is_ascii_printable(b0)) {
            i += 1;
            continue;
        }

        let start = i;
        let mut j = i;
        let mut chars: Vec<u8> = Vec::new();
        while j + 1 < bytes.len() {
            let lo = bytes[j];
            let hi = bytes[j + 1];
            if hi != 0 || !is_ascii_printable(lo) {
                break;
            }
            chars.push(lo);
            if chars.len() > 800 {
                break;
            }
            j += 2;
        }

        if chars.len() >= 12 && chars.len() <= 800 {
            if let Ok(text) = std::str::from_utf8(&chars) {
                let text = text.trim();
                if is_likely_command_line(text) {
                    out.push(ProcessExecArtifact {
                        image: parse_image(text),
                        command_line: text.to_string(),
                        encoding: ExecArtifactEncoding::Utf16Le,
                        address: Some(base + start as u64),
                    });
                }
            }
        }

        i = j + 2;
    }
}

fn is_ascii_printable(b: u8) -> bool {
    matches!(b, b'\t' | b' '..=b'~')
}

fn is_likely_command_line(s: &str) -> bool {
    if s.len() < 12 || s.len() > 800 {
        return false;
    }
    let lc = s.to_ascii_lowercase();

    // Keep false positives low: require a strong indicator.
    let indicators = [
        ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi",
        "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta",
        "rundll32", "regsvr32", "schtasks", "wmic", "certutil", "bitsadmin",
        "curl ", "wget ", "msbuild", "installutil", "python", "node ",
        "dotnet", "java ", "bash", "/bin/sh",
    ];
    if !indicators.iter().any(|k| lc.contains(k)) {
        return false;
    }

    // Avoid obvious binary/garbage strings.
    let non_print = s.chars().filter(|c| !c.is_ascii() || c.is_control()).count();
    if non_print > 0 {
        return false;
    }

    true
}

fn parse_image(command_line: &str) -> String {
    let s = command_line.trim_start();
    if s.is_empty() {
        return String::new();
    }

    let mut img = String::new();
    if let Some(rest) = s.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            img.push_str(&rest[..end]);
            return normalize_image(img);
        }
    }

    let end = s
        .find(char::is_whitespace)
        .unwrap_or_else(|| s.len());
    img.push_str(&s[..end]);
    normalize_image(img)
}

fn normalize_image(mut img: String) -> String {
    // Strip common leading wrappers.
    let trimmed = img.trim().to_string();
    if trimmed.is_empty() {
        return trimmed;
    }
    img = trimmed;
    img
}

fn dedup_artifacts(mut artifacts: Vec<ProcessExecArtifact>) -> Vec<ProcessExecArtifact> {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    artifacts.retain(|a| {
        let key = normalize_cmd_key(&a.command_line);
        if seen.contains(&key) {
            return false;
        }
        seen.insert(key);
        true
    });
    artifacts.truncate(MAX_ARTIFACTS);
    artifacts
}

fn normalize_cmd_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_ws = false;
    for ch in s.trim().chars() {
        let ws = ch.is_whitespace();
        if ws {
            if !last_ws {
                out.push(' ');
            }
        } else {
            out.push(ch.to_ascii_lowercase());
        }
        last_ws = ws;
    }
    out
}

