#!/usr/bin/env python3
"""Verify the SHA-256 of a candidate WinRing0.sys against the digest
the shipped reference outputs were generated against.

Use this once after acquiring the case-study binary from a public
source (LOLDrivers, VirusTotal, Microsoft Vulnerable Driver Blocklist
archives). Mismatched binaries will produce different IOCTL sets,
function offsets, and constraint chains; the shipped JSON references
will not be reproducible against them.

Usage:
    python verify_binary.py [path-to-WinRing0.sys]

Default path: ./WinRing0.sys (relative to repo root).

Exit codes:
    0   Hash matches expected.
    1   File not found.
    2   Hash mismatch.
"""
from __future__ import annotations

import hashlib
import pathlib
import sys

EXPECTED_SHA256 = (
    "3ec5ad51e6879464dfbccb9f4ed76c6325056a42548d5994ba869da9c4c039a8"
)
EXPECTED_SIZE_RANGE = (14_000, 22_000)  # plausibility check; not authoritative


def sha256_of(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str]) -> int:
    target = pathlib.Path(argv[1]) if len(argv) > 1 else pathlib.Path("WinRing0.sys")

    if not target.exists():
        print(f"[verify_binary] File not found: {target}", file=sys.stderr)
        print(
            "[verify_binary] Acquire WinRing0.sys per README §"
            "'Obtaining the case-study sample' and place it next to the engine.",
            file=sys.stderr,
        )
        return 1

    size = target.stat().st_size
    lo, hi = EXPECTED_SIZE_RANGE
    if not (lo <= size <= hi):
        print(
            f"[verify_binary] WARNING: {target} is {size} bytes; expected ~{lo}-{hi}. "
            "This is likely a stub or a different version.",
            file=sys.stderr,
        )

    digest = sha256_of(target)
    if digest == EXPECTED_SHA256:
        print(f"[verify_binary] OK: {target} matches expected SHA-256.")
        print(f"[verify_binary]   digest = {digest}")
        return 0

    print(f"[verify_binary] HASH MISMATCH for {target}", file=sys.stderr)
    print(f"[verify_binary]   actual   = {digest}", file=sys.stderr)
    print(f"[verify_binary]   expected = {EXPECTED_SHA256}", file=sys.stderr)
    print(
        "[verify_binary] The engine will still run, but the IOCTL set, "
        "function offsets, and shipped reference JSONs will not be "
        "reproducible against this binary.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
