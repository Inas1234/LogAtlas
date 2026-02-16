use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use minidump::Module;

use crate::model::{StackFrameInfo, StackwalkReport, ThreadStackTrace};

const SYMBOL_PATH_ENV_VARS: [&str; 2] = ["LOG_ATLAS_SYMBOL_PATH", "MINIDUMP_SYMBOL_PATH"];

pub fn extract_stackwalk(dump: &minidump::Minidump<Vec<u8>>) -> Result<StackwalkReport> {
    let symbol_paths = discover_symbol_paths();
    let supplier = breakpad_symbols::SimpleSymbolSupplier::new(symbol_paths.clone());
    let symbolizer = breakpad_symbols::Symbolizer::new(supplier);

    let state =
        futures::executor::block_on(minidump_processor::process_minidump(dump, &symbolizer))
            .context("stackwalk + symbolication failed")?;

    Ok(from_process_state(state, symbol_paths))
}

fn from_process_state(
    state: minidump_processor::ProcessState,
    symbol_paths: Vec<PathBuf>,
) -> StackwalkReport {
    let requesting_thread_id = state
        .requesting_thread
        .and_then(|idx| state.threads.get(idx))
        .map(|t| t.thread_id);

    let modules_with_symbols = state
        .symbol_stats
        .values()
        .filter(|s| s.loaded_symbols)
        .count();

    let mut symbolicated_frames = 0usize;
    let threads: Vec<ThreadStackTrace> = state
        .threads
        .iter()
        .enumerate()
        .map(|(idx, t)| {
            let is_requesting_thread = state.requesting_thread == Some(idx);
            let frames = t
                .frames
                .iter()
                .enumerate()
                .map(|(frame_idx, f)| {
                    let module_base = f.module.as_ref().map(|m| m.base_address());
                    let module_offset = module_base.map(|base| f.instruction.saturating_sub(base));
                    let function_offset = f
                        .function_base
                        .map(|base| f.instruction.saturating_sub(base));
                    if f.function_name.is_some() {
                        symbolicated_frames += 1;
                    }
                    StackFrameInfo {
                        index: frame_idx,
                        instruction: f.instruction,
                        module: f.module.as_ref().map(|m| m.code_file().into_owned()),
                        module_base,
                        module_offset,
                        function: f.function_name.clone(),
                        function_offset,
                        source_file: f.source_file_name.clone(),
                        source_line: f.source_line,
                        trust: f.trust.as_str().to_string(),
                    }
                })
                .collect();

            ThreadStackTrace {
                thread_id: t.thread_id,
                thread_name: t.thread_name.clone(),
                status: format!("{:?}", t.info),
                is_requesting_thread,
                frames,
            }
        })
        .collect();

    let mut notes = Vec::new();
    if symbol_paths.is_empty() {
        notes.push(
            "No symbol paths configured. Set LOG_ATLAS_SYMBOL_PATH or MINIDUMP_SYMBOL_PATH for Breakpad .sym lookup."
                .to_string(),
        );
    }
    if modules_with_symbols == 0 {
        notes.push(
            "No symbol files were loaded; frames may only have module + offset information."
                .to_string(),
        );
    }

    StackwalkReport {
        requesting_thread_id,
        symbol_paths: symbol_paths
            .into_iter()
            .map(|p| p.display().to_string())
            .collect(),
        symbolicated_frames,
        modules_with_symbols,
        notes,
        threads,
    }
}

fn discover_symbol_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for key in SYMBOL_PATH_ENV_VARS {
        let Ok(raw) = std::env::var(key) else {
            continue;
        };
        for path in std::env::split_paths(&raw) {
            if path.as_os_str().is_empty() {
                continue;
            }
            if seen.insert(path.clone()) {
                out.push(path);
            }
        }
    }

    let local_symbols_dir = PathBuf::from("symbols");
    if local_symbols_dir.is_dir() && seen.insert(local_symbols_dir.clone()) {
        out.push(local_symbols_dir);
    }

    out
}
