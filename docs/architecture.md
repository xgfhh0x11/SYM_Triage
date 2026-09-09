# Architecture

SYM-Triage is a three-stage pipeline that takes a Windows kernel-mode
driver binary and emits a structured triage report identifying IOCTL
handlers that perform caller-controlled kernel memory or MSR access.

```
binary (.sys/.bin)
        │
        ▼
  [1] static analysis
        ├─ PE parse (header, sections, characteristics)
        ├─ string extraction (printable ASCII, IOCTL-related keywords)
        ├─ hex pattern matching (known CTL_CODE encodings)
        └─ dispatcher locator (IRP_MJ_DEVICE_CONTROL site)
        │
        ▼
  [2] symbolic IOCTL exploration
        ├─ ExecutionState (path + constraints + memory accesses)
        ├─ state forking on conditional branches
        ├─ per-IOCTL handler analyzer
        │     (write_memory, read_memory, write_msr, ...)
        ├─ Z3 imported as a scaffold (not yet invoked)
        └─ classification of suspicious memory accesses
        │
        ▼
  [3] report
        ├─ JSON: per-IOCTL findings, classification labels,
        │       constraint chains
        └─ Markdown summary (optional)
```

## Stage 1 — static analysis (`advanced_binary_analyzer.py`, `binary_ioctl_extractor.py`)

The analyzer loads the binary, sanity-checks the PE/COFF headers, and
scans for IOCTL codes using three complementary signals:

1. **Hex pattern scan.** Known `CTL_CODE` encodings (little- and big-
   endian) are searched as raw byte patterns.
2. **String scan.** Printable ASCII strings of length ≥ 4 are extracted
   and filtered by IOCTL-related keywords (`ioctl`, `device`, `control`,
   `dispatch`, `irp`, `msr`, `pci`, `port`).
3. **Call-site locator.** References to `DeviceIoControl`,
   `DispatchDeviceControl`, and `IRP_MJ_DEVICE_CONTROL` are located by
   string match; their offsets become handler-search anchors.

A `severity` and `description` are attached to each discovered IOCTL
code via a lookup table keyed by the known WinRing0 codes
(`0x9C402580`..`0x9C40259C`). Unknown codes are reported as such.

## Stage 2 — symbolic exploration (`custom_s2e_engine.py`)

This stage is pattern matching, not symbolic execution: branches are
matched against known conditions rather than solved. It works on the
discovered IOCTL surface, not on raw binary lifted to an IR. For each
IOCTL code it:

- Creates an `ExecutionState` with an initial empty constraint set.
- Models the dispatcher's branch on the IOCTL code as a fork point.
- Per-IOCTL handler analyzers parse the expected input-buffer layout
  (e.g. for `WRITE_MEMORY`: `[address(4) | size(4) | offset(4) | rsv(4)]`)
  and emit classifications when the parsed fields would direct a kernel
  memory access:

  - `ARBITRARY_WRITE` — caller-controlled `address` in kernel space.
  - `ARBITRARY_READ`  — caller-controlled read range in kernel space.
  - `PRIVILEGE_ESCALATION` — write to a critical MSR (e.g. MTRR).
  - `BUFFER_OVERFLOW` — declared write size exceeds the input buffer.

- Z3 (`z3-solver`) is imported and a `Solver` instance is constructed as
  `constraint_solver`, but it is a scaffold for a future
  constraint-solving backend: the current pass never adds constraints to
  it or calls it, matching the honest description in the README.

The engine bounds state explosion via `max_states` (default 1000) and
`max_depth` (default 50).

## Stage 3 — report

`custom_s2e_results.json` and the auxiliary `binary_ioctl_analysis.json` /
`advanced_binary_analysis.json` documents are written next to the binary.
Each finding records:

- the IOCTL code and its symbolic name,
- the classification label,
- the constraint chain that produced the finding,
- the path through the dispatcher (sequence of branch decisions).

## Case study — WinRing0.sys

The case-study target is `WinRing0.sys` — a publicly known build that
appears on Microsoft's Vulnerable Driver Blocklist. The repository does
not ship the binary; the README documents the expected MD5 / SHA-256
digests and points to public sources for retrieval. When the binary is
present alongside the engine scripts, the analyzer reproduces the
documented IOCTL surface and classifies the four write-class IOCTLs as
critical, the four read-class IOCTLs as high.

## Limitations

- The symbolic engine is intentionally lightweight: indirect calls,
  inlined dispatcher branches, and obfuscated code are not handled.
- IOCTL buffer schemas are recovered heuristically; manual confirmation
  is required before acting on a classification.
- Z3 is imported but not invoked; a future constraint-encoding pass and
  production-grade kernel ABI semantics are out of scope for now.
- The case-study coverage is a single binary; broader coverage
  (e.g. DBUtil_2_3.sys, RTCore64.sys) is part of the roadmap.
