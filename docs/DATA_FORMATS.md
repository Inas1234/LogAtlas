# Data Formats

This document describes the internal model Log Atlas produces today.  
These types are intended to be the interface between ingestion/detectors and UI/export layers.

## Normalized Events

`Event` (`src/model/event.rs`) is the unit rendered in the timeline:

- `id`: stable identifier within a session (`EventId`)
- `t_ms`: milliseconds from session start (currently synthetic placeholders)
- `severity`: `Info | Warning | High`
- `title`: one-line label
- `details`: multi-line human-readable payload
- `source`: component identifier string (for example `ingest::minidump`, `detector::basic`)

Events are stored in `EventStore` (`src/model/store.rs`), which assigns IDs and supports selection.

## Minidump Summary

`MinidumpSummary` (`src/model/minidump_summary.rs`) is a lightweight overview:

- file size
- header `TimeDateStamp` (raw + best-effort UTC formatting)
- OS/CPU (stringified)
- module/thread counts
- exception one-liner (if present)

Intended use: quick overview and cheap export/log object.

## Minidump Report

`MinidumpReport` (`src/model/minidump_report.rs`) holds extracted facts plus derived signals:

- `os`, `cpu`
- `process`: best-effort process metadata (from `MinidumpMiscInfo` when present)
- `modules`: list of `ModuleInfo`
- `threads`: list of `ThreadInfo` (names + optional start address/timing when present)
- `exception`: `ExceptionInfo` if the exception stream is present
- memory region counts (when relevant streams exist)
- derived:
  - `exec_artifacts`: recovered command-line-like strings from dump memory
  - `injected_regions`: suspicious allocations derived from `MemoryInfoListStream`
  - `stackwalk`: `StackwalkReport` with per-thread call stacks and frame-level symbol data
  - `stackwalk_error`: non-fatal stackwalk failure detail

### Stackwalk Types

- `StackwalkReport`
  - requesting thread id
  - symbol path list used for lookup
  - symbolicated frame count
  - module-with-symbol count
  - notes and thread stacks
- `ThreadStackTrace`
  - thread id/name
  - stack status
  - whether it is the requesting/crashing thread
  - `frames: Vec<StackFrameInfo>`
- `StackFrameInfo`
  - instruction address
  - module/module-base/module-offset
  - function/function-offset
  - optional source file/line
  - trust label from unwinder

### Minidump Streams Used (Best-Effort)

The minidump format is stream-based and many streams are optional.  
The engine attempts to read:

- `MinidumpSystemInfo`
- `MinidumpThreadList`
- `MinidumpThreadNames` (optional)
- `MinidumpThreadInfoList` (optional; thread create time + start address)
- `MinidumpModuleList`
- `MinidumpMemoryList` and/or `MinidumpMemory64List`
- `MinidumpMemoryInfoList` (required for injected-region heuristics)
- `MinidumpException`
- `MinidumpMiscInfo` (process metadata)

If a stream is absent, the report leaves the corresponding field empty and detectors degrade gracefully.
