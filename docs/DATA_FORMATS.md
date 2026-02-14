# Data Formats

This document describes the internal model Log Atlas produces today. These types are intended to be the stable interface between ingestion/detectors and any UI/export layer.

## Normalized Events

`Event` (`src/model/event.rs`) is the unit rendered in the timeline:

- `id`: stable identifier within a session (`EventId`)
- `t_ms`: milliseconds from session start (currently synthetic placeholders)
- `severity`: `Info | Warning | High`
- `title`: one-line label
- `details`: multi-line text payload (human readable)
- `source`: component identifier string (e.g. `ingest::minidump`, `detector::basic`)

Events are stored in `EventStore` (`src/model/store.rs`), which assigns IDs and supports selection.

## Minidump Summary

`MinidumpSummary` (`src/model/minidump_summary.rs`) is a lightweight overview:

- file size
- header `TimeDateStamp` (raw + best-effort UTC formatting)
- OS/CPU (stringified)
- module/thread counts
- exception one-liner (if present)

Intended use: quick “overview” view and a cheap object to log/export.

## Minidump Report

`MinidumpReport` (`src/model/minidump_report.rs`) holds extracted facts plus derived signals:

- `os`, `cpu`
- `process`: best-effort process metadata (from `MinidumpMiscInfo` when present)
- `modules`: list of `ModuleInfo`
- `threads`: list of `ThreadInfo` (names + optional start address/timing when present)
- `exception`: `ExceptionInfo` if the exception stream is present
- memory region counts (when relevant streams exist)
- derived:
  - `exec_artifacts`: recovered command-line-like strings found in dump memory
  - `injected_regions`: suspicious allocations derived from `MemoryInfoListStream`

### Minidump Streams Used (Best-Effort)

The minidump format is stream-based; many streams are optional. The engine attempts to read:

- `MinidumpSystemInfo`
- `MinidumpThreadList`
- `MinidumpThreadNames` (optional)
- `MinidumpThreadInfoList` (optional; thread create time + start address)
- `MinidumpModuleList`
- `MinidumpMemoryList` and/or `MinidumpMemory64List`
- `MinidumpMemoryInfoList` (required for “injected regions” heuristics)
- `MinidumpException`
- `MinidumpMiscInfo` (process metadata)

If a stream is absent, the report leaves the corresponding field empty and detectors degrade gracefully.

