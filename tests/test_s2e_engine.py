"""Smoke tests for the custom S2E engine on the included case-study."""
import os

import pytest

from custom_s2e_engine import CustomS2EEngine

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SAMPLE = os.path.join(_ROOT, 'WinRing0.sys')


@pytest.fixture
def engine():
    if not os.path.exists(_SAMPLE):
        pytest.skip(f'case-study binary not present: {_SAMPLE}')
    return CustomS2EEngine(_SAMPLE)


def test_engine_initialises(engine):
    assert engine.binary_path == _SAMPLE
    assert engine.constraint_solver is not None
    assert engine.max_states == 1000


def test_ioctl_codes_extracted_or_fallback(engine):
    # Either we successfully extract IOCTL codes from the binary or fall back
    # to the known set; in either case there must be at least one code.
    assert len(engine.ioctl_codes) > 0


def test_kernel_regions_well_formed(engine):
    for start, end, name in engine.kernel_regions:
        assert isinstance(start, int)
        assert isinstance(end, int)
        assert start < end
        assert isinstance(name, str) and name


def test_exploit_pattern_table_populated(engine):
    for k, v in engine.exploit_patterns.items():
        assert v['severity'] in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}
        assert v['description']
