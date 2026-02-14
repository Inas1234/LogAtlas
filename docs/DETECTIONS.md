# Detections

Detections are intentionally “triage hints”. They are best-effort and may be noisy depending on the dump type and what streams are present.

Detections are produced by `MinidumpReport::detections()` (`src/model/minidump_report.rs`).

## Exception Signals

- Access violation:
  - Condition: exception stream present with code `0xC0000005`
  - Severity: `High`

## Module Path Signals

- Module loaded from temp-like paths:
  - Condition: module name/path contains common temp directories
  - Severity: `Warning`

## Execution Artifact Signals

“Execution artifacts” are strings that look like command-lines recovered by scanning dump memory (`src/ingest/minidump_exec.rs`).

- Suspicious execution artifact:
  - Condition: command-line/image matches common LOLBins (PowerShell, `rundll32`, `mshta`, etc.)
  - Severity:
    - `Warning` if no extra reasons matched
    - `High` if reasons matched (encoded command, in-memory patterns, temp path, URL indicator)

Notes:

- This is heuristic string detection, not process enumeration.
- Not all dumps include memory pages with meaningful strings.

## Suspicious Executable Memory (“Injection-ish”) Signals

Derived in `src/ingest/minidump_injection.rs`.

Primary shape (when `MemoryInfoListStream` exists):

- committed (`MEM_COMMIT`)
- private (`MEM_PRIVATE`)
- executable protection
- does not overlap any loaded module image range

Risk adjustments:

- RWX protection elevates to `High`
- thread start address outside modules elevates to `High`
- recovered execution artifact strings pointing into the same allocation add contextual reasons

Fallback (when `MemoryInfoListStream` is missing):

- Threads with a start address outside loaded modules are reported as high-risk regions with unknown memory metadata.

