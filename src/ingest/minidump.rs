use std::path::Path;

use anyhow::{Context, Result};

use crate::model::{
    Event, EventId, EventStore, ExceptionInfo, MinidumpReport, MinidumpSummary, ModuleInfo,
    ProcessInfo, Severity, StackwalkReport, ThreadInfo, ThreadStackTrace,
};

pub struct IngestedMinidump {
    pub summary: MinidumpSummary,
    pub report: MinidumpReport,
    pub events: EventStore,
}

pub fn ingest(path: &Path) -> Result<IngestedMinidump> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let file_size = data.len() as u64;
    let dump = minidump::Minidump::read(data).context("parse minidump")?;

    let mut summary = MinidumpSummary::default();
    summary.file_size = Some(file_size);
    summary.time_date_stamp = Some(dump.header.time_date_stamp);

    let mut report = MinidumpReport::default();

    // Streams (optional).
    if let Ok(sys) = dump.get_stream::<minidump::MinidumpSystemInfo>() {
        summary.os = Some(format!("{:?}", sys.os));
        summary.cpu = Some(format!("{:?}", sys.cpu));

        report.os = Some(format!("{:?}", sys.os));
        report.cpu = Some(format!("{:?}", sys.cpu));
    }

    if let Ok(threads) = dump.get_stream::<minidump::MinidumpThreadList>() {
        summary.thread_count = Some(threads.threads.len());
        report.threads = extract_threads(&dump, &threads);
    }

    if let Ok(modules) = dump.get_stream::<minidump::MinidumpModuleList>() {
        summary.module_count = Some(modules.iter().count());
        report.modules = extract_modules(&modules);
    }

    // Process info (best-effort, optional stream).
    report.process = extract_process_info(&dump, &report.modules);

    if let Ok(mem) = dump.get_stream::<minidump::MinidumpMemoryList>() {
        report.memory_region_count = Some(mem.iter().count());
    }

    if let Ok(mem64) = dump.get_stream::<minidump::MinidumpMemory64List>() {
        report.memory_region_64_count = Some(mem64.iter().count());
    }

    if let Ok(mi) = dump.get_stream::<minidump::MinidumpMemoryInfoList>() {
        report.memory_info_region_count = Some(mi.iter().count());
    }

    // Execution artifacts: best-effort string scan over dump memory.
    report.exec_artifacts = crate::ingest::minidump_exec::extract_exec_artifacts(&dump);

    report.injected_regions = crate::ingest::minidump_injection::detect_injected_regions(
        &dump,
        &report.modules,
        &report.threads,
        &report.exec_artifacts,
    );

    if let Ok(exc) = dump.get_stream::<minidump::MinidumpException>() {
        report.exception = Some(ExceptionInfo {
            thread_id: exc.thread_id,
            code: exc.raw.exception_record.exception_code,
            flags: exc.raw.exception_record.exception_flags,
            address: exc.raw.exception_record.exception_address,
            number_parameters: exc.raw.exception_record.number_parameters,
        });
        summary.exception = Some(format!(
            "thread_id={} code=0x{:08X} addr=0x{:016X}",
            exc.thread_id,
            exc.raw.exception_record.exception_code,
            exc.raw.exception_record.exception_address
        ));
    }

    match crate::ingest::minidump_stackwalk::extract_stackwalk(&dump) {
        Ok(stackwalk) => {
            report.stackwalk = Some(stackwalk);
        }
        Err(err) => {
            report.stackwalk_error = Some(err.to_string());
        }
    }

    let mut t_ms = 0u64;
    let mut events: Vec<Event> = Vec::new();

    events.push(Event {
        id: EventId(0),
        t_ms,
        severity: Severity::Info,
        title: "Minidump loaded".into(),
        details: format!("Path: {}\nSize: {} bytes", path.display(), file_size),
        source: "ingest::minidump".into(),
    });

    t_ms += 10;
    events.push(Event {
        id: EventId(0),
        t_ms,
        severity: Severity::Info,
        title: "Minidump summary".into(),
        details: summary.pretty(),
        source: "ingest::minidump".into(),
    });

    if let Some(proc) = &report.process {
        t_ms += 10;
        events.push(Event {
            id: EventId(0),
            t_ms,
            severity: Severity::Info,
            title: "Process info".into(),
            details: format_process_info(proc),
            source: "ingest::minidump".into(),
        });
    }

    if !report.exec_artifacts.is_empty() {
        t_ms += 10;
        events.push(Event {
            id: EventId(0),
            t_ms,
            severity: Severity::Warning,
            title: "Execution artifacts recovered".into(),
            details: format_exec_artifacts(&report.exec_artifacts, 12),
            source: "ingest::minidump".into(),
        });
    }

    // Note: we intentionally don't spam the timeline with "modules/threads enumerated".
    // Those are available in dedicated tabs (Overview/Modules/Threads).

    if let Some(exc) = &report.exception {
        t_ms += 10;
        events.push(Event {
            id: EventId(0),
            t_ms,
            severity: Severity::High,
            title: "Exception stream present".into(),
            details: format!(
                "thread_id={}\ncode=0x{:08X}\naddress=0x{:016X}",
                exc.thread_id, exc.code, exc.address
            ),
            source: "ingest::minidump".into(),
        });
    }

    if let Some(sw) = &report.stackwalk {
        t_ms += 10;
        events.push(Event {
            id: EventId(0),
            t_ms,
            severity: Severity::Info,
            title: "Stackwalk completed".into(),
            details: format_stackwalk_summary(sw),
            source: "ingest::stackwalk".into(),
        });

        if let Some(stack) = report.exception_stack()
            && !stack.frames.is_empty()
        {
            t_ms += 5;
            events.push(Event {
                id: EventId(0),
                t_ms,
                severity: Severity::Info,
                title: "Exception thread call stack".into(),
                details: format_exception_stack_preview(stack, 10),
                source: "ingest::stackwalk".into(),
            });
        }
    } else if let Some(err) = &report.stackwalk_error {
        t_ms += 10;
        events.push(Event {
            id: EventId(0),
            t_ms,
            severity: Severity::Warning,
            title: "Stackwalk failed".into(),
            details: err.clone(),
            source: "ingest::stackwalk".into(),
        });
    }

    // Detections derived from extracted info.
    for det in report.detections() {
        t_ms += 5;
        events.push(Event {
            id: EventId(0),
            t_ms,
            severity: det.severity,
            title: format!("Detection: {}", det.title),
            details: det.details,
            source: "detector::basic".into(),
        });
    }

    Ok(IngestedMinidump {
        summary,
        report,
        events: EventStore::from_events(events),
    })
}

fn extract_modules(list: &minidump::MinidumpModuleList) -> Vec<ModuleInfo> {
    list.iter()
        .map(|m| ModuleInfo {
            name: m.name.clone(),
            base: m.raw.base_of_image,
            size: m.raw.size_of_image as u64,
            checksum: m.raw.checksum,
            time_date_stamp: m.raw.time_date_stamp,
            file_version: format_file_version(&m.raw.version_info),
        })
        .collect()
}

fn format_file_version(v: &minidump::format::VS_FIXEDFILEINFO) -> Option<String> {
    let ms = v.file_version_hi;
    let ls = v.file_version_lo;
    if ms == 0 && ls == 0 {
        return None;
    }
    let major = ms >> 16;
    let minor = ms & 0xFFFF;
    let build = ls >> 16;
    let rev = ls & 0xFFFF;
    Some(format!("{major}.{minor}.{build}.{rev}"))
}

fn extract_threads(
    dump: &minidump::Minidump<Vec<u8>>,
    threads: &minidump::MinidumpThreadList<'_>,
) -> Vec<ThreadInfo> {
    let names = dump.get_stream::<minidump::MinidumpThreadNames>().ok();
    let infos = dump.get_stream::<minidump::MinidumpThreadInfoList>().ok();

    threads
        .threads
        .iter()
        .map(|t| {
            let tid = t.raw.thread_id;
            let (create_filetime, create_unix, start_address) = infos
                .as_ref()
                .and_then(|i| i.get_thread_info(tid))
                .map(|ti| {
                    let ft = ti.raw.create_time;
                    let unix = crate::util::time::filetime_to_unix_seconds(ft);
                    let start = (ti.raw.start_address != 0).then_some(ti.raw.start_address);
                    (Some(ft), unix, start)
                })
                .unwrap_or((None, None, None));

            ThreadInfo {
                thread_id: t.raw.thread_id,
                name: names
                    .as_ref()
                    .and_then(|n| n.get_name(t.raw.thread_id).map(|s| s.to_string())),
                create_time_filetime: create_filetime,
                create_time_unix: create_unix,
                start_address,
                suspend_count: t.raw.suspend_count,
                priority_class: t.raw.priority_class,
                priority: t.raw.priority,
                teb: t.raw.teb,
                stack_start: t.raw.stack.start_of_memory_range,
                stack_size: t.raw.stack.memory.data_size as u64,
            }
        })
        .collect()
}

fn extract_process_info(
    dump: &minidump::Minidump<Vec<u8>>,
    modules: &[ModuleInfo],
) -> Option<ProcessInfo> {
    let mut info = ProcessInfo {
        pid: None,
        create_time_unix: None,
        integrity_level: None,
        execute_flags: None,
        protected_process: None,
        main_image: modules.first().map(|m| m.name.clone()),
        main_image_version: modules
            .first()
            .and_then(|m| m.file_version.as_ref().map(|v| v.to_string())),
    };

    if let Ok(misc) = dump.get_stream::<minidump::MinidumpMiscInfo>() {
        // The accessors return references for numeric fields; normalize to owned values.
        info.pid = misc.raw.process_id().copied();
        info.create_time_unix = misc.raw.process_create_time().map(|t| *t as u64);
        info.integrity_level = misc.raw.process_integrity_level().copied();
        info.execute_flags = misc.raw.process_execute_flags().copied();
        info.protected_process = misc.raw.protected_process().copied();
    }

    if info.pid.is_none()
        && info.main_image.is_none()
        && info.integrity_level.is_none()
        && info.execute_flags.is_none()
        && info.protected_process.is_none()
    {
        return None;
    }

    Some(info)
}

fn format_process_info(p: &ProcessInfo) -> String {
    let mut lines: Vec<String> = Vec::new();
    if let Some(img) = &p.main_image {
        lines.push(format!("Main image: {img}"));
    }
    if let Some(v) = &p.main_image_version {
        lines.push(format!("Main version: {v}"));
    }
    if let Some(pid) = p.pid {
        lines.push(format!("PID: {pid}"));
    }
    if let Some(t) = p.create_time_unix {
        lines.push(format!("Create time (unix): {t}"));
        if let Some(utc) = crate::util::time::unix_seconds_to_utc_string(t) {
            lines.push(format!("Create time (utc): {utc}"));
        }
    }
    if let Some(il) = p.integrity_level {
        lines.push(format!("Integrity level: {il}"));
    }
    if let Some(f) = p.execute_flags {
        lines.push(format!("Execute flags: 0x{f:08X}"));
    }
    if let Some(pp) = p.protected_process {
        lines.push(format!("Protected process: {pp}"));
    }
    if lines.is_empty() {
        "<no process info>".into()
    } else {
        lines.join("\n")
    }
}

fn format_exec_artifacts(arts: &[crate::model::ProcessExecArtifact], limit: usize) -> String {
    let mut out = String::new();
    out.push_str(&format!("Recovered: {}\n\n", arts.len()));
    for (i, a) in arts.iter().take(limit).enumerate() {
        out.push_str(&format!(
            "{:>3}. [{}] {}\n     {}\n",
            i + 1,
            match a.encoding {
                crate::model::ExecArtifactEncoding::Ascii => "ascii",
                crate::model::ExecArtifactEncoding::Utf16Le => "utf16le",
            },
            a.image,
            a.command_line
        ));
    }
    if arts.len() > limit {
        out.push_str(&format!("... ({} more)\n", arts.len() - limit));
    }
    out
}

fn format_stackwalk_summary(sw: &StackwalkReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!("threads_walked={}", sw.threads.len()));
    lines.push(format!("total_frames={}", sw.total_frames()));
    lines.push(format!("symbolicated_frames={}", sw.symbolicated_frames));
    lines.push(format!("modules_with_symbols={}", sw.modules_with_symbols));
    if let Some(tid) = sw.requesting_thread_id {
        lines.push(format!("requesting_thread=0x{tid:X}"));
    }
    if !sw.symbol_paths.is_empty() {
        lines.push(format!("symbol_paths={}", sw.symbol_paths.join("; ")));
    }
    if !sw.notes.is_empty() {
        lines.push(String::new());
        lines.push("Notes:".to_string());
        for n in &sw.notes {
            lines.push(format!("- {n}"));
        }
    }
    lines.join("\n")
}

fn format_exception_stack_preview(stack: &ThreadStackTrace, limit: usize) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "thread_id=0x{:X} name={}\nframes={}\n\n",
        stack.thread_id,
        stack.thread_name.as_deref().unwrap_or("-"),
        stack.frames.len()
    ));

    for frame in stack.frames.iter().take(limit) {
        let func = frame.function.as_deref().unwrap_or("<unknown>");
        let module = frame.module.as_deref().unwrap_or("<no-module>");
        out.push_str(&format!(
            "#{:02} 0x{:016X} {}!{}",
            frame.index, frame.instruction, module, func
        ));
        if let Some(off) = frame.function_offset {
            out.push_str(&format!("+0x{off:X}"));
        } else if let Some(off) = frame.module_offset {
            out.push_str(&format!("+0x{off:X}"));
        }
        out.push('\n');
    }
    if stack.frames.len() > limit {
        out.push_str(&format!("... ({} more)\n", stack.frames.len() - limit));
    }
    out
}
