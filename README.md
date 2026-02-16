# Log Atlas

Minidump-first log analysis engine with a thin `eframe/egui` UI.

The project's current focus is turning a Windows minidump (`.dmp` / `.mdmp`) into:

- A structured report (`MinidumpReport`) with extracted streams and derived signals
- A normalized event timeline (`EventStore`) suitable for UI rendering and later export
- A small set of detectors that emit human-readable findings (`Detection`)

The UI is intentionally simple: it loads a dump, shows an event timeline, and exposes the report in drill-down tabs. The long-term goal is a general log analyzer; minidumps are the first ingestion format.

## Quickstart

```powershell
cargo run
```

For a faster UI when opening large dumps:

```powershell
cargo run --release
```

Then use `File -> Open minidump...`.

## Engine Overview

The engine pipeline today is:

1. Read + parse the minidump (`minidump` crate).
2. Best-effort extract optional streams into a structured report:
   - system info, module list, thread list, exception stream, misc process info
3. Derive higher-level signals:
   - stackwalking for per-thread call stacks
   - optional symbolication from Breakpad `.sym` files
   - heuristic string scan for execution artifacts (command-lines / LOLBins)
   - heuristic detection of suspicious private executable allocations (injection-like)
   - simple detector rules over exception codes, module paths, recovered artifacts
4. Emit a normalized timeline of `Event`s (used by the UI and intended for future exporters).

Key entrypoint:

- `src/ingest/minidump.rs` (`ingest(path) -> IngestedMinidump`)

Key types:

- `src/model/minidump_summary.rs` (`MinidumpSummary`)
- `src/model/minidump_report.rs` (`MinidumpReport`, `Detection`, `InjectedRegion`, stackwalk types)
- `src/model/event.rs` + `src/model/store.rs` (`Event`, `EventStore`)

## What's Implemented (Current Signals)

- Stream extraction (best-effort):
  - `SystemInfo`, `ModuleList`, `ThreadList`, `ThreadNames`, `ThreadInfoList`,
    `MemoryList`, `Memory64List`, `MemoryInfoList`, `Exception`, `MiscInfo`
- Stackwalking and symbolication:
  - Uses `minidump-processor` to unwind thread call stacks.
  - Stores frame trust/module/function/source metadata where available.
  - Symbol lookup uses Breakpad `.sym` files from configured symbol paths.
- Execution artifact recovery:
  - Scans up to 32 MiB of dump memory and extracts ASCII / UTF-16LE strings that look like command lines.
- Injection-ish detection:
  - Flags committed private executable regions not overlapping modules.
  - Elevates risk when a thread start address is outside modules.
  - Adds context when recovered execution artifact strings point into a suspicious allocation.
- Basic detections:
  - Access violation exception (`0xC0000005`)
  - Modules loaded from temp-like paths
  - Suspicious LOLBin execution artifacts with simple reason tags

## Symbol Paths

To enable richer symbolicated stacks, set one of:

- `LOG_ATLAS_SYMBOL_PATH`
- `MINIDUMP_SYMBOL_PATH`

Both support OS path-list syntax (`;` on Windows, `:` on Unix-like systems).  
Each path should point to a Breakpad symbol directory tree.  
If `./symbols` exists, it is also searched automatically.

## Limitations (Known)

- Symbolication currently relies on Breakpad `.sym` files; direct PDB symbol-server flows are not wired yet.
- Timeline timestamps are currently synthetic (`t_ms` placeholders), not real capture time.
- Minidumps vary widely by type; many streams are optional and the engine is intentionally best-effort.
- Heuristics can produce false positives/negatives; treat output as triage hints, not proof.

## Project Layout

- `src/ingest/`: parsers and extractors (currently minidump-only)
- `src/model/`: normalized data model (summary/report/events/detections)
- `src/app/`: app state and "load minidump" wiring
- `src/ui/`: `egui` panels for timeline + details
- `docs/`: design notes and project direction

## Docs

- `docs/ARCHITECTURE.md`
- `docs/DATA_FORMATS.md`
- `docs/DETECTIONS.md`
- `docs/ROADMAP.md`
- `docs/DEVELOPMENT.md`
