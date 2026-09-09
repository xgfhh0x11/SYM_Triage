# SYM-Triage — Build & Verification

> *This file answers: "Is this project buildable, runnable, and behaving
> as documented?"*

## 1. Build

### 1.1 Primary build path

- **Platform**: Python 3.10 / 3.11 / 3.12 (CI matrix in `.github/workflows/python-tests.yml`). No OS lock-in — pure Python, no native build step.
- **Toolchain**: `pip` + `venv` (no `setup.py`, no `pyproject.toml`, no packaging — scripts run in place from the repo root).
- **Command** (Linux / macOS bash):
  ```bash
  python -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  # Acquire the case-study binary (see §1.3 / §2.3) and hash-verify it:
  python verify_binary.py WinRing0.sys    # exit 0 = match, 1 = not found, 2 = mismatch
  python custom_s2e_engine.py            # main pipeline — writes custom_s2e_results.json
  python advanced_binary_analyzer.py     # PE-aware static analyser — writes advanced_binary_analysis.json
  python binary_ioctl_extractor.py       # IOCTL hex/string scanner — writes binary_ioctl_analysis.json
  ```
- **Command** (Windows PowerShell):
  ```powershell
  python -m venv .venv
  .venv\Scripts\Activate.ps1
  pip install -r requirements.txt
  python verify_binary.py WinRing0.sys
  python custom_s2e_engine.py
  python advanced_binary_analyzer.py
  python binary_ioctl_extractor.py
  ```
- **Output**: Three JSON triage reports written into the project root:
  - `custom_s2e_results.json` — handler-classification findings (states, exploit classifications, payloads, per-IOCTL breakdown).
  - `advanced_binary_analysis.json` — PE structure + IOCTL surface + string/pattern analysis.
  - `binary_ioctl_analysis.json` — IOCTL code list + handler severity classification.

### 1.2 Alternative build paths

- **No packaging.** There is no `pyproject.toml`, `setup.py`, `setup.cfg`, `Makefile`, `Dockerfile`, or `tox.ini`. The project is a flat collection of scripts at the repo root — see §3.3 (roadmap: restructure to `src/`).
- **CI-only path**: `.github/workflows/python-tests.yml` is split into two jobs. `unit-tests` runs the Python 3.10/3.11/3.12 matrix with `pytest -m "not requires_binary"` and is the always-on gate. `binary-tests` depends on `unit-tests`, checks for a `WinRing0.sys` workspace file, runs `python verify_binary.py WinRing0.sys`, then `pytest -m "requires_binary"`. When the binary is absent the job emits a loud GitHub Actions `::notice` (no silent green).
- **Three scripts can run independently** — they are not chained by a driver. `custom_s2e_engine.py` *re-uses* `advanced_binary_analyzer.AdvancedBinaryAnalyzer` internally for IOCTL discovery, but each script has its own `main()` and writes its own JSON.

### 1.3 Dependencies

- **Required (runtime)**:
  - `z3-solver >= 4.12.0` (from `requirements.txt`) — imported and constructed as `CustomS2EEngine.constraint_solver`, but not yet invoked; a scaffold for a future constraint-solving backend (see §3.1).
  - Python ≥ 3.10 (uses `dataclasses`, `typing`, `enum` — all stdlib, but CI pins 3.10+).
  - PE parsing now prefers **`pefile`** when installed and falls back to the hand-rolled `struct` parser otherwise (`advanced_binary_analyzer.py`). `pefile` is an *optional* dependency (listed in `tests/requirements.txt` so CI exercises it); the tool runs without it. ✅ (was: hand-rolled only — see §3.1.)
- **Required (tests)**:
  - `pytest >= 7.0` (from `tests/requirements.txt`).
  - `z3-solver >= 4.12.0` (also in `tests/requirements.txt`).
- **Required (data — not committed)**:
  - `WinRing0.sys` case-study binary. Not shipped (see `.gitignore`: `*.sys`, `*.dll`, `*.exe`, `*.bin`). README documents expected hashes:
    - MD5: `828bb9cb1dd449cd65a29b18ec46055f`
    - SHA-256: `3ec5ad51e6879464dfbccb9f4ed76c6325056a42548d5994ba869da9c4c039a8`
  - Verify with `python verify_binary.py WinRing0.sys` (preferred — exits 0 on match, 1 on not-found, 2 on mismatch), or `sha256sum WinRing0.sys` (Linux) / `Get-FileHash WinRing0.sys -Algorithm SHA256` (PowerShell).
- **Optional**: None declared.

## 2. Expected behavior

### 2.1 What this project does

SYM-Triage is a triage classifier (not an exploit generator) for Windows kernel-mode driver IOCTL handlers, targeting the BYOVD ("Bring Your Own Vulnerable Driver") class. The pipeline is three stages (see `docs/architecture.md`):

1. **Static IOCTL discovery** (`binary_ioctl_extractor.py`, `advanced_binary_analyzer.py`) — parses the PE header, scans for known `CTL_CODE` hex encodings, IOCTL-related strings, and `DeviceIoControl` / `IRP_MJ_DEVICE_CONTROL` call-site references.
2. **Pattern-based IOCTL handler classification** (`custom_s2e_engine.py`) — for each discovered IOCTL, models the dispatcher's branch on the IOCTL code, parses the per-handler input-buffer schema, and emits classifications when caller-controlled fields would drive a kernel-space memory access or critical-MSR write. This is a pattern-matching pass, **not** symbolic execution — Z3 is imported as a scaffold but no constraints are added or solved (see §3.1).
3. **JSON report** — per-IOCTL findings with classification labels (`ARBITRARY_WRITE`, `ARBITRARY_READ`, `PRIVILEGE_ESCALATION`, `BUFFER_OVERFLOW`, `MEMORY_CORRUPTION`, `NULL_DEREFERENCE`), constraint chains, and dispatcher paths.

The shipped case study targets `WinRing0.sys` (CVE-2020-14979 family) and reproduces the documented IOCTL surface: 4 write-class IOCTLs classified `CRITICAL`, 4 read-class IOCTLs classified `HIGH`.

### 2.2 Acceptance criteria

- [ ] `pip install -r requirements.txt` completes on Python 3.10/3.11/3.12 without errors.
- [ ] `pip install -r tests/requirements.txt && python -m pytest tests/ -v` runs to completion (passing or skipping where the binary is absent).
- [ ] When `WinRing0.sys` is **absent**, the test suite skips the binary-dependent fixtures (per `pytest.skip` calls in `tests/conftest.py`-adjacent fixtures) and never fails on missing-binary grounds.
- [ ] When `WinRing0.sys` is **present and hash-matches**, `python custom_s2e_engine.py` produces `custom_s2e_results.json` containing at minimum:
  - `total_states >= 1`
  - `exploit_counts` keys including `ARBITRARY_WRITE`, `ARBITRARY_READ`, `PRIVILEGE_ESCALATION`, `BUFFER_OVERFLOW`
  - `ioctl_analysis` with all 8 WinRing0 IOCTL codes (`0x9C402580` .. `0x9C40259C`)
- [ ] `python advanced_binary_analyzer.py` produces `advanced_binary_analysis.json` with `ioctl_analysis.codes_found` of length 8 (the canonical WinRing0 set) when the canonical hex patterns are present.
- [ ] `python binary_ioctl_extractor.py` produces `binary_ioctl_analysis.json` with `handler_analysis` entries each having `ioctl_code`, `name`, `severity`, `description`.
- [ ] Severity classifier is a pure lookup: `WRITE_MSR` (`0x9C402584`) and `WRITE_MEMORY` (`0x9C402594`) → `CRITICAL`; `READ_MSR` (`0x9C402580`) and `READ_MEMORY` (`0x9C402590`) → `HIGH`; unknown → `MEDIUM`. (Pinned by `test_severity_classifier_pure_function`.)
- [ ] All three scripts run to completion even when no IOCTL codes are recovered from a given binary (report shape is stable — verified by `test_report_structure_is_well_formed` and by the committed `binary_ioctl_analysis.json` showing empty arrays).

### 2.3 Manual verification

The repository ships **provenance-marked placeholder JSONs** (for `binary_ioctl_analysis.json` and `advanced_binary_analysis.json`) and one **fallback-derived JSON** (`custom_s2e_results.json`, generated from the engine's `_get_known_ioctl_codes()` table — see its `_provenance` field). To produce real binary-derived outputs:

**Step 1 — obtain and verify the binary.**

```bash
# Acquire WinRing0.sys from a public blocklist source (LOLDrivers, VirusTotal,
# Microsoft Vulnerable Driver Blocklist project) and place it next to
# custom_s2e_engine.py. Then run the bundled verifier:
python verify_binary.py WinRing0.sys
# exit 0 = SHA-256 matches 3ec5ad51e6879464dfbccb9f4ed76c6325056a42548d5994ba869da9c4c039a8
# exit 1 = file not found
# exit 2 = hash mismatch
```

**Step 2 — run each entry script.**

```bash
python custom_s2e_engine.py        # writes custom_s2e_results.json
python advanced_binary_analyzer.py # writes advanced_binary_analysis.json
python binary_ioctl_extractor.py   # writes binary_ioctl_analysis.json
```

**Step 3 — expected JSON output structure** (sanity-check the produced files match these shapes):

`custom_s2e_results.json`:
```json
{
  "total_states": 23,
  "total_exploits": 5,
  "exploits": [ { "pattern": "PRIVILEGE_ESCALATION|ARBITRARY_READ|ARBITRARY_WRITE|BUFFER_OVERFLOW", "severity": "CRITICAL|HIGH", "path": [...], "constraints": [] } ],
  "exploit_counts": { "PRIVILEGE_ESCALATION": 2, "ARBITRARY_READ": 1, "ARBITRARY_WRITE": 1, "BUFFER_OVERFLOW": 1 },
  "payloads": [ { "ioctl_code": <int>, "buffer_schema": [ { "field": "...", "offset": <int>, "size": <int>, "role": "..." } ], "description": "...", "severity": "..." } ],
  "ioctl_analysis": { "0x9c402580": { "name": "WR0_READ_MSR", "exploit_count": <int>, "exploits": [...] }, ... },
  "fallback_ioctl_table_used": <bool>
}
```

`advanced_binary_analysis.json`:
```json
{
  "binary_info": { "file": "WinRing0.sys", "size": <int>, "pe_info": { ... } },
  "ioctl_analysis": { "codes_found": [<8 ints>], "total_codes": 8, "hex_patterns": [...] },
  "string_analysis": { "ioctl_strings": [...], "total_strings": <int> },
  "pattern_analysis": { "device_patterns": [...], "winring0_patterns": [...] },
  "summary": { "is_driver": <bool>, "ioctl_codes_found": 8, ... }
}
```

`binary_ioctl_analysis.json`:
```json
{
  "binary_info": { "file": "WinRing0.sys", "size": <int>, "analysis_timestamp": <float> },
  "ioctl_codes": [<8 ints>],
  "function_offsets": [...],
  "handler_analysis": [ { "ioctl_code": "0x9C40258X", "name": "WR0_...", "severity": "CRITICAL|HIGH|MEDIUM", "description": "..." } ],
  "summary": { "total_ioctls": 8, "critical_ioctls": 4, "high_ioctls": 4, "functions_found": <int> }
}
```

**Note on committed reference JSONs**: the previously misleading stub-derived outputs have been replaced. `binary_ioctl_analysis.json` and `advanced_binary_analysis.json` now contain explicit `_provenance` / `_expected_binary_sha256` / `_regenerate_command` fields and empty/`null` payload data — they are **placeholders**, not results. `custom_s2e_results.json` keeps its full body (codes/names are valid per public CVE references) but is prepended with a `_provenance` block stating the contents derive from the engine's `_get_known_ioctl_codes()` fallback, not from real binary parsing, and carries a top-level `fallback_ioctl_table_used: true` flag for the same reason. Constraint chains in that file are illustrative. See §3.1.

### 2.4 Automated verification

The test suite lives in `tests/` and runs through `pytest`:

```bash
pip install -r tests/requirements.txt
# Always-on (no binary required):
python -m pytest tests/ -v -m "not requires_binary"
# Binary-derived (requires hash-verified WinRing0.sys at repo root):
python verify_binary.py WinRing0.sys && python -m pytest tests/ -v -m "requires_binary"
```

CI: `.github/workflows/python-tests.yml` is split into two jobs on `ubuntu-latest` for every push and PR to `main`/`master`:

- **`unit-tests`** — matrix Python 3.10/3.11/3.12, runs `pytest -m "not requires_binary"`. Always runs; this is the gate.
- **`binary-tests`** — depends on `unit-tests`, Python 3.12 only. Checks for `WinRing0.sys` in the workspace, runs `python verify_binary.py WinRing0.sys` if present, then `pytest -m "requires_binary"`. If the binary is absent the job emits a `::notice` annotation in the run summary (loud skip, not silent green). A hash mismatch surfaces as a job failure via `verify_binary.py`'s non-zero exit code.

Test inventory:
- `tests/test_s2e_engine.py` — 4 smoke tests (engine init, IOCTL extraction fallback, kernel-region wellformedness, exploit-pattern table). Binary-dependent tests are marked `requires_binary`.
- `tests/test_binary_extractor.py` — 5 integration tests (binary load, IOCTL code list type, severity classifier purity, report shape, handler-entry wellformedness). Binary-dependent tests are marked `requires_binary`; the pure severity classifier runs unconditionally.
- `tests/conftest.py` — adds repo root to `sys.path` so tests can `import custom_s2e_engine` despite the flat layout.

## 3. Alternatives & improvements

### 3.1 Known fragilities

- ~~**Hand-rolled PE parser.** ... a brittle ≥22-byte slice check ... the `"Invalid COFF header size"` symptom was a *consequence* of running against a stub, not of a parser bug on a real driver.~~ **FIXED — and the earlier diagnosis was wrong.** The hand-rolled parser sliced the 20-byte `IMAGE_FILE_HEADER` (`pe_offset+4 : pe_offset+24`) but then required `len >= 22` and unpacked `'<HHIIIIH'` (22 bytes, with `SizeOfOptionalHeader` mistyped as a DWORD). So it returned `"Invalid COFF header size"` for **every** input, real driver or not — a genuine parser bug, not a stub artefact. The fix: correct the format to `'<HHIIIHH'` (20 bytes) with a `len >= 20` check, **and** prefer `pefile` when installed, falling back to the corrected struct parser. Both paths return the same dict shape plus a `parser` field. Covered by `tests/test_pe_parser.py` (builds a synthetic PE; previously this would have errored). The driver heuristic (`characteristics & 0x2000`) is preserved unchanged.
- ~~**Committed reference outputs were produced against a stub, not the real binary.**~~ **RESOLVED.** Stub-derived `binary_ioctl_analysis.json` and `advanced_binary_analysis.json` have been replaced with provenance-marked placeholders (`_provenance`, `_expected_binary_sha256`, `_regenerate_command`). They are now explicitly non-results; reviewers regenerate locally after hash-verifying `WinRing0.sys`.
- ~~**Reference results have unverifiable provenance.**~~ **RESOLVED.** `custom_s2e_results.json` keeps its body but is prepended with a `_provenance` block stating the contents are from the engine's `_get_known_ioctl_codes()` fallback (codes/names valid per public CVE references; constraint chains illustrative). Readers can no longer mistake it for real-binary output.
- ~~**Fallback masks binary failures.**~~ **RESOLVED.** `_extract_ioctl_codes_from_binary` still catches broadly and falls back to the hardcoded WinRing0 IOCTL table on any load/parse failure — that behaviour is unchanged — but it now sets `self.fallback_ioctl_table_used` and the engine surfaces it as a top-level `fallback_ioctl_table_used` boolean in `custom_s2e_results.json`, so a consumer running against an unrelated driver can tell canned findings from binary-derived ones.
- **`evaluate_condition` defaults to `True`.** The unknown-condition branch in `CustomS2EEngine.evaluate_condition` returns `True` unconditionally — paths are not actually being symbolically explored, only seeded inputs are dispatched to per-IOCTL analyzers. This is closer to fuzzing-with-fixed-inputs than to symbolic execution; Z3 is imported and a `Solver` is constructed but no constraints are added to it in the analysis path. `evaluate_condition` itself (and the three `_evaluate_*_condition` helpers it alone calls) is dead code — nothing in the current pipeline calls it; it is marked as such in the module. (Tracked under the Z3 model expansion roadmap item.)
- ~~**`generate_exploit_payloads` builds attack inputs.**~~ **RESOLVED.** `_generate_write_payload` / `_generate_read_payload` / `_generate_msr_payload` / `_generate_generic_payload` no longer `struct.pack` input buffers targeting `exploit["address"]`. They now emit classification descriptors — a `buffer_schema` listing field name, offset, size, and role (e.g. `kernel_write_target`) — with no packed exploit bytes. This reconciles `generate_exploit_payloads` with the README's "classifier, not exploit generator" posture.
- **Flat repo layout.** All Python scripts live at the project root alongside JSON outputs, `LICENSE`, `README.md`. There is no `src/`, no `__init__.py` at root, no package boundary. Imports work only because `tests/conftest.py` injects the root onto `sys.path`. Any tool that auto-discovers packages will struggle.
- ~~**`binary_ioctl_extractor.py:21`** retains the original Turkish docstring `"Binary dosyasını yükle"`.~~ **RESOLVED.** All Turkish docstrings/comments across the codebase have been translated to English.
- ~~**CI skips binary tests silently.**~~ **RESOLVED.** CI workflow is split into `unit-tests` (always runs the pytest matrix excluding `requires_binary`) and `binary-tests` (depends on unit-tests; emits a loud `::notice` if `WinRing0.sys` is absent, and fails on hash mismatch via `verify_binary.py`'s exit code).
- ~~**README contradicts itself on whether the case-study binary is committed.**~~ **RESOLVED.** Both the layout section and the usage section now consistently state the binary is NOT included; the documented flow is `verify_binary.py` → engine.
- **`fork_state` and `check_memory_access` are also dead code.** Neither is called by `run_analysis()` or anything else in the module; both are marked as unwired scaffolding in place, consistent with the state-forking design `docs/architecture.md` describes but the current pipeline does not exercise.

### 3.2 Fallbacks

- When PE parsing fails, the engine falls back to the hardcoded WinRing0 IOCTL table (`_get_known_ioctl_codes`) and proceeds with synthetic inputs. This is documented in the engine's print output (`"[CustomS2E] Using known IOCTL codes as fallback"`) and is now also surfaced as a top-level `fallback_ioctl_table_used` boolean in `custom_s2e_results.json`, so a consumer can tell whether IOCTLs were recovered from the binary or hardcoded.
- When the case-study binary is absent, pytest fixtures call `pytest.skip(...)`. The pure-function severity-classifier test still runs.

### 3.3 Roadmap

- **Short-term (≤1 day)**:
  - Add a `--binary` CLI flag to all three scripts so the WinRing0 default isn't a silent assumption.
  - ~~Surface "fallback IOCTL table used" as a top-level boolean in `custom_s2e_results.json` so consumers know whether findings are binary-derived or canned.~~ **DONE** — `CustomS2EEngine.fallback_ioctl_table_used` is now set wherever `_extract_ioctl_codes_from_binary` takes the fallback path and is included as a top-level key in the saved JSON.
  - ~~Regenerate the three committed reference JSONs against a hash-verified `WinRing0.sys` (or remove them, since they currently document a stub run).~~ **DONE** — stub-derived JSONs replaced with provenance-marked placeholders; the fallback-derived `custom_s2e_results.json` carries an explicit `_provenance` block and `fallback_ioctl_table_used: true`.
  - ~~Translate the remaining Turkish docstrings/comments.~~ **DONE** — all Turkish docstrings and comments in `binary_ioctl_extractor.py` and `custom_s2e_engine.py` are translated to English.
- **Medium-term (≤1 week)**:
  - **Restructure to `src/`**. Move the three Python scripts into `src/sym_triage/`, add a `pyproject.toml`, and expose them as console scripts (`sym-triage-engine`, `sym-triage-extract`, `sym-triage-analyze`). Eliminates the `conftest.py` `sys.path` hack and the namespace pollution at the repo root.
  - Replace the hand-rolled PE parser with `pefile` or `lief` (add to `requirements.txt`). Restores robustness against the COFF-header-size failure path.
  - ~~Make tests **fail** (not skip) when the binary is absent in CI, by fetching the case-study binary in the workflow and verifying its SHA-256 before running pytest.~~ **DONE** — workflow split into `unit-tests` (always-on, matrix) and `binary-tests` (gated on workspace presence of `WinRing0.sys`; loud `::notice` if absent; `verify_binary.py` exit-2 mismatch causes job failure). Outstanding: actually fetching the binary in CI is still left to forks/self-hosted runners.
  - Encode buffer-schema constraints into `z3.Solver` so the symbolic engine actually solves something rather than evaluating `True` on unknown conditions.
- **Long-term**:
  - Multi-driver corpus (`DBUtil_2_3.sys`, `RTCore64.sys`) as documented in the README roadmap.
  - Comparative baseline against `angr` / `Manticore`.
  - Schema-driven JSON output (JSON Schema in `docs/`) so reports diff cleanly across runs.
  - ~~Reconcile the "classifier not exploit generator" posture with `generate_exploit_payloads` — either drop the payload generator or rename it to a classification descriptor.~~ **DONE** — `generate_exploit_payloads` and its per-pattern helpers now emit `buffer_schema` classification descriptors with no packed exploit buffers.

## 4. Sanity check

| Check | Status | Notes |
|-------|--------|-------|
| README documents build | OK ✅ | Contradiction between "case-study binary is included" and "NOT committed" resolved — both sections now consistently state the binary is **not** committed; documented flow is `verify_binary.py` → engine. |
| Build files present | OK | `requirements.txt` (1 dep), `tests/requirements.txt` (2 deps), `.github/workflows/python-tests.yml` (now split into `unit-tests` + `binary-tests`), `verify_binary.py`. No `pyproject.toml`/`setup.py` — acceptable for a research script bundle. |
| Build files internally consistent | OK | `requirements.txt` and `tests/requirements.txt` both pin `z3-solver>=4.12.0` — no version skew. CI workflow installs from `tests/requirements.txt` which is a superset. |
| Source structure matches README | Partial ⚠️ | README's "Repository Layout" lists the three Python files at root, `docs/`, `tests/` — matches reality. But the flat layout (no `src/`) is undocumented as a deliberate choice and complicates packaging (see §3.3). |
| Tests exist | OK ✅ | `tests/test_s2e_engine.py` (4 tests) and `tests/test_binary_extractor.py` (5 tests). `conftest.py` handles import path. CI is now correctly gated: `unit-tests` always runs (matrix 3.10/3.11/3.12); `binary-tests` runs against a hash-verified `WinRing0.sys` and emits a loud `::notice` when the binary is absent (no silent green). |
| Test invocation documented | OK ✅ | Documented in CI workflow (split jobs, `-m "not requires_binary"` / `-m "requires_binary"`) and in §2.4 of this file. README still focuses on the engine invocation; pointer to §2.4 here is the canonical reference. |
| Output artifacts named in build files | Partial ⚠️ | Output filenames (`custom_s2e_results.json`, `advanced_binary_analysis.json`, `binary_ioctl_analysis.json`) are hardcoded in each script's `main()` / `save_results()` but are not declared in any build manifest. The committed JSONs are now provenance-marked placeholders (for the two stub-derived files) and an explicitly-fallback-flagged engine result (for `custom_s2e_results.json`) — reviewers can no longer mistake them for real-binary outputs. ⚠️ |
