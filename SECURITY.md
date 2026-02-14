# Security Notes

Log Atlas is intended to analyze untrusted inputs (minidumps and, later, other logs). A few pragmatic guidelines:

- Treat minidumps as sensitive:
  - They can contain memory pages with credentials, tokens, and private user data.
- Treat minidumps as untrusted:
  - They are arbitrary binary data; assume they may be malformed or adversarial.
- Current engine behavior:
  - The tool reads and parses dumps and performs in-process string scanning over dump bytes.
  - It does not execute code from the dump, load modules from the dump, or run scripts recovered from memory.
- Operational advice:
  - Prefer running analysis in an isolated environment when handling unknown samples.
  - Be deliberate about sharing dumps and any exported reports.

