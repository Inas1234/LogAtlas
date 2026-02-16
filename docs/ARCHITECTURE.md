# Architecture

## Goal

Log Atlas is structured as an ingestion + normalization engine with a UI on top.

The engine is designed to:

- Parse a source format (today: minidump)
- Extract raw facts into a structured report
- Derive higher-level signals/detections
- Emit a normalized timeline of events that any frontend can render

## Data Flow (Today)

1. `minidump file (.dmp/.mdmp)`
2. `src/ingest/minidump.rs`
   - stream extraction
   - stackwalking and optional symbolication
   - derived signals (exec artifacts, suspicious allocations)
   - detector pass (report -> detections)
   - event synthesis (summary/detections -> `EventStore`)
3. Outputs:
   - `MinidumpSummary` (lightweight)
   - `MinidumpReport` (structured details + derived fields)
   - `EventStore` (normalized timeline)
4. UI:
   - `src/ui/*` renders events + report tabs

## Modules

- `src/ingest/minidump.rs`
  - Orchestrator: read file, parse minidump, pull optional streams, build `MinidumpSummary` and `MinidumpReport`, then synthesize `EventStore`.
- `src/ingest/minidump_stackwalk.rs`
  - Runs `minidump-processor` stack unwinding and maps thread/frame output into app model types.
  - Uses Breakpad `.sym` paths from environment variables and local `./symbols` when present.
- `src/ingest/minidump_exec.rs`
  - Heuristic string scanning over dump memory to recover likely command-lines (ASCII + UTF-16LE).
- `src/ingest/minidump_injection.rs`
  - Heuristic analysis of `MemoryInfoListStream` to flag suspicious private executable allocations and correlate them with thread start addresses and recovered strings.
- `src/model/*`
  - Stable-ish internal model:
    - `MinidumpSummary`: small overview for initial triage.
    - `MinidumpReport`: deeper extracted facts + derived signals.
    - `Detection`: human-readable finding (severity + title + details).
    - `Event`/`EventStore`: normalized timeline for UI/export.
- `src/app/*`
  - UI-facing state + load/open wiring.
- `src/ui/*`
  - `egui` panels and selection state; intended to remain thin.

## Extension Points (Planned)

- Additional ingestion formats (e.g. text logs, JSON, ETW exports)
- Pluggable detectors:
  - rule-based detectors over normalized data
  - correlation across multiple sources (when the project grows beyond single dumps)
- Exporters:
  - JSON report/event export for automation and CI pipelines
