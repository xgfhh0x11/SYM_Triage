"""PE-parser tests for advanced_binary_analyzer.

These cover the hardened `analyze_pe_structure`:
  * the hand-rolled struct fallback now parses a valid PE (it previously
    sliced 20 bytes but required 22 and unpacked '<HHIIIIH', so it
    returned "Invalid COFF header size" for *every* input — a real bug,
    not merely a stub artefact);
  * the optional `pefile` path degrades gracefully and the analyzer
    falls back to struct when pefile rejects the input.

No real driver binary is required — a minimal synthetic PE header is
built in-memory.
"""
import struct

import pytest

import advanced_binary_analyzer as aba
from advanced_binary_analyzer import AdvancedBinaryAnalyzer


def _minimal_pe(machine=0x8664, num_sections=3, characteristics=0x2022, pe_off=0x80):
    """A buffer with a valid MZ stub, e_lfanew, PE signature, and a
    20-byte IMAGE_FILE_HEADER. Enough for the struct parser; pefile may
    reject it (no section table / optional header), which exercises the
    fallback."""
    buf = bytearray(pe_off + 4 + 20 + 16)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 60, pe_off)            # e_lfanew
    buf[pe_off:pe_off + 4] = b"PE\x00\x00"             # PE signature
    struct.pack_into(
        "<HHIIIHH", buf, pe_off + 4,
        machine, num_sections, 0, 0, 0, 0xF0, characteristics,
    )
    return bytes(buf)


def _analyzer(data):
    a = AdvancedBinaryAnalyzer("synthetic")
    a.binary_data = data
    return a


def test_struct_parser_parses_minimal_pe(monkeypatch):
    monkeypatch.setattr(aba, "pefile", None)  # force the struct path
    result = _analyzer(_minimal_pe()).analyze_pe_structure()
    assert "error" not in result, result
    assert result["parser"] == "struct"
    assert result["pe_offset"] == 0x80
    assert result["machine"] == 0x8664
    assert result["num_sections"] == 3
    assert result["characteristics"] == 0x2022


def test_too_small_buffer_errors(monkeypatch):
    monkeypatch.setattr(aba, "pefile", None)
    result = _analyzer(b"MZ" + b"\x00" * 10).analyze_pe_structure()
    assert "error" in result


def test_missing_dos_signature_errors(monkeypatch):
    monkeypatch.setattr(aba, "pefile", None)
    result = _analyzer(b"XX" + b"\x00" * 200).analyze_pe_structure()
    assert "error" in result


def test_analyze_falls_back_to_struct_when_pefile_unavailable_or_rejects():
    """Whether or not pefile is installed, a valid (struct-parseable) PE
    yields a parsed result — never the old always-on COFF-size error."""
    result = _analyzer(_minimal_pe(machine=0x14C)).analyze_pe_structure()
    assert "error" not in result, result
    assert result["machine"] == 0x14C
    assert result["parser"] in ("struct", "pefile")


def test_pefile_path_is_graceful_on_garbage():
    if aba.pefile is None:
        pytest.skip("pefile not installed")
    result = _analyzer(b"\x00" * 256)._analyze_pe_structure_pefile()
    assert "error" in result  # graceful error dict, not an exception
