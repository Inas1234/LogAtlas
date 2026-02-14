# Development

## Build and Run

```powershell
cargo run
```

Release build (recommended for large dumps):

```powershell
cargo run --release
```

## Code Organization

- Engine:
  - `src/ingest/` and `src/model/`
- UI:
  - `src/ui/` and `src/app/`

If you’re adding a new detector, prefer:

1. Extract/normalize new facts into `MinidumpReport`
2. Generate `Detection`s in `MinidumpReport::detections()`
3. Optionally add a concise `Event` summarizing the detection to the timeline

## Quality Checks

```powershell
cargo fmt
cargo clippy
cargo test
```

