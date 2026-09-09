# SYM-Triage — Static + Pattern-Based IOCTL Handler Triage for Windows Drivers

An automated triage tool that combines static binary analysis with
pattern-based handler classification to identify potentially vulnerable IOCTL handlers in
Windows kernel-mode drivers. The repository ships a case study against
`WinRing0.sys`, a publicly known vulnerable BYOVD ("Bring Your Own
Vulnerable Driver") sample, demonstrating the workflow end to end.

---

## Motivation

The BYOVD attack class — abusing a legitimately signed but vulnerable
third-party driver to gain kernel execution — has become a dominant
post-exploitation primitive in modern adversary tradecraft. Microsoft now
maintains a [Vulnerable Driver Blocklist][vdb] precisely because manual triage
of these drivers does not scale.

Most analysis flows for such drivers are manual: open the binary in IDA,
locate the `IRP_MJ_DEVICE_CONTROL` dispatcher, enumerate IOCTLs, reason
about each handler's input buffer parsing and memory access. This is slow,
inconsistent across analysts, and not reproducible.

SYM-Triage proposes a different posture: extract IOCTL codes statically from
the binary, then run a pattern-based classification pass across each
handler's input-buffer parsing, recording **classifications** (not exploit
payloads) of the form *"IOCTL X accepts a buffer whose contents reach a
kernel-memory write whose address and size are caller-controlled"*. The
output is a structured triage report.

[vdb]: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules

## Scope and Posture

This tool is intentionally **a triage classifier, not an exploit generator**.
Its output is a JSON report enumerating IOCTL codes, the buffer schemas
inferred for each, and the classification of any kernel-memory accesses
reachable from caller-controlled input. The shipped case study targets
`WinRing0.sys` and reproduces analysis of publicly disclosed
vulnerabilities (CVE-2020-14979 and related entries on the Microsoft
vulnerable driver list). The binary itself is not committed; see
[Obtaining the case-study sample](#obtaining-the-case-study-sample).

What this tool produces:
- Discovered IOCTL codes and their inferred handler entry points.
- Per-handler buffer schemas reconstructed from instruction patterns.
- Classification labels: `KERNEL_WRITE`, `KERNEL_READ`, `MSR_WRITE`,
  `BUFFER_SIZE_UNCHECKED`, etc.
- Reachability paths through the dispatcher recorded as condition sequences.

What this tool does not produce:
- Weaponised payloads.
- Privilege-escalation chains.
- Anti-detection or evasion tooling.

## Repository Layout

```
custom_s2e_engine.py           - pattern-based handler-classification engine
advanced_binary_analyzer.py    - PE-aware static analyser
binary_ioctl_extractor.py      - IOCTL discovery and labelling
*.json                         - example analysis outputs (WinRing0.sys)
docs/
  TECHNICAL_DEEP_DIVE.md       - extended technical write-up
  CRITICAL_FUNCTIONS_SCHEMA.md - engine and buffer-format reference
tests/
```

The repository **does not ship the case-study binary**. See
[Obtaining the case-study sample](#obtaining-the-case-study-sample)
below.

## Obtaining the case-study sample

The case study targets `WinRing0.sys` — a publicly documented
vulnerable driver (CVE-2020-14979 and related entries). The binary
is intentionally **not committed** to this repository. To reproduce
the shipped analysis outputs, obtain a copy from one of the public
sources that catalogue blocklisted drivers (e.g. the Microsoft
Vulnerable Driver Blocklist project, the LOLDrivers project, or
VirusTotal), verify it against the hash below, and place it next
to `custom_s2e_engine.py` as `WinRing0.sys`.

**Expected hashes** for the WinRing0.sys revision used to produce
the shipped `*.json` outputs:

| Algorithm | Digest                                                           |
|-----------|------------------------------------------------------------------|
| MD5       | `828bb9cb1dd449cd65a29b18ec46055f`                               |
| SHA-256   | `3ec5ad51e6879464dfbccb9f4ed76c6325056a42548d5994ba869da9c4c039a8` |

Verify before running:

```bash
sha256sum WinRing0.sys
# expect: 3ec5ad51e6879464dfbccb9f4ed76c6325056a42548d5994ba869da9c4c039a8
```

If your local copy does not match this digest, the shipped
analysis outputs will not be reproducible against it; the engine
will still run, but the IOCTL set and constraint chains may
differ.

## Approach

### Static IOCTL discovery

`binary_ioctl_extractor.py` and `advanced_binary_analyzer.py` parse the PE
binary, locate the `IRP_MJ_DEVICE_CONTROL` dispatcher, and discover IOCTL
codes using three complementary signals:

1. Hex pattern matching for known `CTL_CODE` encodings.
2. Printable-string scan for IOCTL-related symbol names.
3. Instruction-pattern matching around `DeviceIoControl`-style call sites.

### Handler classification pass

`custom_s2e_engine.py` models the dispatcher's branching on the IOCTL code
field and classifies each handler's input-buffer parsing using pattern
rules — it does **not** perform symbolic execution; branches are matched,
not solved. The engine tracks:

- Buffer field decomposition (address / size / offset / reserved).
- Conditional branches keyed on size or pointer validity.
- Memory accesses where the target address lies in kernel space.

Z3 is imported as a scaffold for a future constraint-solving backend, but
the current pass is purely pattern-based and does not invoke the solver.

### Triage output

The engine emits structured JSON enumerating discovered IOCTLs, classified
behaviours, and the constraint chain that produced each classification.
Sample outputs are included in the repository (`*.json`).

## Requirements and Usage

```bash
pip install z3-solver

# Verify the WinRing0.sys binary you obtained (see previous section).
python verify_binary.py WinRing0.sys

# Run the engine against the verified binary.
python custom_s2e_engine.py
```

**The case-study binary is NOT included in this repository** — see
[Obtaining the case-study sample](#obtaining-the-case-study-sample)
above for acquisition and hash verification.

The shipped `*.json` outputs are either (a) provenance-marked
placeholders that the user regenerates locally after acquiring the
binary, or (b) (in the case of `custom_s2e_results.json`) generated
from the engine's internal IOCTL knowledge base and explicitly
labelled as such in their `_provenance` field. Reviewers reproducing
the workflow should re-run the engine against their own
hash-verified copy of `WinRing0.sys`.

## Limitations

This is a research-grade triage tool. Known limitations:

- The symbolic engine is intentionally lightweight; complex obfuscation,
  indirect calls, and inlined dispatcher logic are not handled.
- Buffer schema reconstruction is heuristic; manual confirmation is
  required before any classification is acted on.
- The constraint solver currently encodes a simplified memory model;
  full kernel ABI semantics are out of scope.
- A single case study (WinRing0.sys) is shipped; broader coverage is part
  of the roadmap.

## Roadmap

1. **Multi-driver corpus.** Add triage runs against other publicly-known
   blocklisted drivers (e.g. `DBUtil_2_3.sys`, `RTCore64.sys`) to
   characterise generalisability.
2. **Comparative baseline.** Run the same drivers through `angr` and
   `Manticore`; compare classification agreement, runtime, and coverage.
3. **Z3 model expansion.** Replace the simplified constraint encoder with
   a documented kernel-address-space model.
4. **Schema-driven report.** Emit reports against a fixed schema so
   classifications are stable across runs and amenable to diffing.

## Status

Research / non-production. The repository documents an analysis workflow
and ships a reproducible case study against a publicly known vulnerable
driver. It is intended for defensive triage and academic study of BYOVD
analysis methodology.

## References

- Microsoft Security — *Vulnerable Driver Blocklist*. Public ruleset
  describing drivers blocked under Smart App Control.
- Cavallaro, L., Saxena, P., Sekar, R. — *On the Limits of Information Flow
  Techniques for Malware Analysis and Containment*. DIMVA, 2008.
- Cha, S. K., Avgerinos, T., Rebert, A., Brumley, D. — *Unleashing Mayhem on
  Binary Code*. IEEE S&P, 2012. (Foundational symbolic-execution-for-bug-
  finding paper.)
- Shoshitaishvili, Y. et al. — *(state of) The Art of War: Offensive
  Techniques in Binary Analysis*. IEEE S&P, 2016. (angr.)
- CVE-2020-14979 and related entries — publicly disclosed WinRing0 issues.
