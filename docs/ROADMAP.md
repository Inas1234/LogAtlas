# Roadmap

This is a pragmatic direction for turning Log Atlas into a general log analyzer while keeping the “engine first” philosophy.

## Near Term

- Add export:
  - `MinidumpSummary` / `MinidumpReport` / `EventStore` to JSON
- Add a CLI mode:
  - `log-atlas <dump> --json out.json` (headless pipeline for automation)
- Improve timeline:
  - use real timestamps where available (thread create times, dump header fields)
  - keep synthetic `t_ms` only as a fallback

## Minidump Depth

- Stackwalking + symbolication (optional):
  - recover call stacks for the exception thread and selected threads
  - integrate symbol servers / local PDB caches (Windows) with a clear caching model
- More stream coverage:
  - handle additional streams when present (handles, unloaded modules, memory maps, etc.)
- Stronger detectors:
  - correlate exception address with module ranges
  - flag suspicious module metadata (odd timestamps, missing versions, etc.)
  - add “suspicious thread start” module resolution and context in UI

## General Log Analyzer

- New ingestion sources:
  - structured text logs (JSON lines)
  - Windows event log exports
  - security telemetry formats (where licensing permits)
- Normalization:
  - unify different inputs into the same `Event` model (plus source-specific report payloads)
- Correlation:
  - multi-file sessions and cross-source correlation using stable identifiers

