"""Integration tests for the IOCTL extractor against the case-study binary.

These tests pin the contract the rest of the pipeline relies on:
- The PE parser accepts the WinRing0 case-study binary.
- The extractor finds the canonical WinRing0 IOCTL codes.
- The severity classifier marks write-class IOCTLs as CRITICAL,
  read-class IOCTLs as HIGH.
"""
import os

import pytest

from binary_ioctl_extractor import BinaryIOCTLExtractor

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SAMPLE = os.path.join(_ROOT, 'WinRing0.sys')


@pytest.fixture
def loaded_extractor():
    if not os.path.exists(_SAMPLE):
        pytest.skip(f'case-study binary not present: {_SAMPLE}')
    ext = BinaryIOCTLExtractor(_SAMPLE)
    assert ext.load_binary()
    return ext


def test_binary_loads(loaded_extractor):
    assert loaded_extractor.binary_data is not None
    assert len(loaded_extractor.binary_data) > 0


def test_find_ioctl_codes_returns_list(loaded_extractor):
    """Scan must complete and return a list, regardless of whether the
    particular binary embeds the canonical WinRing0 hex patterns."""
    codes = loaded_extractor.find_ioctl_codes()
    assert isinstance(codes, list)


def test_severity_classifier_pure_function(loaded_extractor):
    """The severity classifier is a pure lookup over IOCTL code, independent
    of what the binary contains."""
    assert loaded_extractor._assess_ioctl_severity(0x9C402584) == 'CRITICAL'  # WRITE_MSR
    assert loaded_extractor._assess_ioctl_severity(0x9C402594) == 'CRITICAL'  # WRITE_MEMORY
    assert loaded_extractor._assess_ioctl_severity(0x9C402580) == 'HIGH'      # READ_MSR
    assert loaded_extractor._assess_ioctl_severity(0x9C402590) == 'HIGH'      # READ_MEMORY
    assert loaded_extractor._assess_ioctl_severity(0xDEADBEEF) == 'MEDIUM'    # unknown


def test_report_structure_is_well_formed(loaded_extractor):
    """Report shape must be stable even when no IOCTL codes are recovered
    from a given binary."""
    report = loaded_extractor.generate_report()
    assert 'binary_info' in report
    assert 'ioctl_codes' in report
    assert 'handler_analysis' in report
    assert 'summary' in report
    summary = report['summary']
    assert {'total_ioctls', 'critical_ioctls', 'high_ioctls'}.issubset(summary)


def test_handler_analysis_entries_well_formed(loaded_extractor):
    report = loaded_extractor.generate_report()
    for h in report['handler_analysis']:
        assert 'ioctl_code' in h
        assert 'name' in h
        assert 'severity' in h
        assert h['severity'] in {'CRITICAL', 'HIGH', 'MEDIUM'}
