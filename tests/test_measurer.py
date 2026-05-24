"""Measurer tests — all three concrete implementations."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from vrt1_kwh.measurer import (
    MeasurementSample,
    RaplMeasurer,
    StubMeasurer,
    SubprocessMeasurer,
)


# ---------- StubMeasurer -------------------------------------------


def test_stub_returns_deterministic_kwh_when_no_jitter():
    s = StubMeasurer(kwh_per_second=0.001)
    sample = s.measure(10)
    assert sample.kwh == pytest.approx(0.01)
    assert sample.source == "stub"
    assert sample.model_id == "vrt1.kwh.stub.v1"
    assert sample.window_end >= sample.window_start


def test_stub_jitter_varies_within_bounds():
    s = StubMeasurer(kwh_per_second=1.0, jitter_fraction=0.1, seed=42)
    # 10 measurements of 1 second each at rate 1 kWh/s with ±10% jitter.
    values = [s.measure(1).kwh for _ in range(10)]
    assert all(0.9 <= v <= 1.1 for v in values)
    # With a fixed seed, two stubs produce identical sequences.
    s2 = StubMeasurer(kwh_per_second=1.0, jitter_fraction=0.1, seed=42)
    values2 = [s2.measure(1).kwh for _ in range(10)]
    assert values == values2


def test_stub_rejects_invalid_args():
    with pytest.raises(ValueError):
        StubMeasurer(kwh_per_second=-0.1)
    with pytest.raises(ValueError):
        StubMeasurer(jitter_fraction=1.0)
    with pytest.raises(ValueError):
        StubMeasurer().measure(-5)


def test_stub_clock_injection_makes_tests_deterministic():
    s = StubMeasurer(kwh_per_second=0.001)
    s.set_clock(lambda: 1_700_000_000)
    sample = s.measure(5)
    assert sample.window_start == 1_700_000_000
    assert sample.window_end == 1_700_000_005


# ---------- RaplMeasurer (Linux Intel/AMD) -------------------------


def test_rapl_missing_path_raises_filenotfound(tmp_path: Path):
    nowhere = tmp_path / "no-rapl-here"
    with pytest.raises(FileNotFoundError, match="RAPL"):
        RaplMeasurer(rapl_path=nowhere)


def test_rapl_reads_delta_and_converts_to_kwh(tmp_path: Path):
    rapl_dir = tmp_path / "rapl0"
    rapl_dir.mkdir()
    energy_uj = rapl_dir / "energy_uj"
    energy_uj.write_text("0\n")

    m = RaplMeasurer(rapl_path=rapl_dir)
    # Replace the sleep with a no-op AND advance the counter between reads.
    reads = iter(["0", "3600000000000"])  # 0 → 3.6e12 microjoules = 1 kWh
    m._read_uj = lambda: int(next(reads))
    m._sleep = lambda secs: None
    m._clock = lambda: 1_700_000_000.0

    sample = m.measure(1.0)
    # 3.6e12 microjoules / 1e6 = 3.6e6 joules / 3.6e6 = 1 kWh exactly.
    assert sample.kwh == pytest.approx(1.0)
    assert sample.source == "rapl"


def test_rapl_corrects_for_wrap_with_known_bound(tmp_path: Path):
    rapl_dir = tmp_path / "rapl0"
    rapl_dir.mkdir()
    (rapl_dir / "energy_uj").write_text("0\n")
    (rapl_dir / "max_energy_range_uj").write_text("100\n")

    m = RaplMeasurer(rapl_path=rapl_dir)
    reads = iter(["90", "10"])  # counter wrapped — 90 → 10 means real delta = 20 uj
    m._read_uj = lambda: int(next(reads))
    m._sleep = lambda secs: None

    sample = m.measure(1.0)
    expected_kwh = (20 / 1_000_000) / 3_600_000
    assert sample.kwh == pytest.approx(expected_kwh)


def test_rapl_clamps_negative_delta_to_zero_without_bound(tmp_path: Path):
    rapl_dir = tmp_path / "rapl0"
    rapl_dir.mkdir()
    (rapl_dir / "energy_uj").write_text("0\n")
    # No max_energy_range_uj exposed -> can't correct, must clamp.

    m = RaplMeasurer(rapl_path=rapl_dir)
    reads = iter(["100", "50"])
    m._read_uj = lambda: int(next(reads))
    m._sleep = lambda secs: None

    sample = m.measure(1.0)
    assert sample.kwh == 0.0


def test_rapl_rejects_zero_duration(tmp_path: Path):
    rapl_dir = tmp_path / "rapl0"
    rapl_dir.mkdir()
    (rapl_dir / "energy_uj").write_text("0\n")
    m = RaplMeasurer(rapl_path=rapl_dir)
    with pytest.raises(ValueError):
        m.measure(0)


# ---------- SubprocessMeasurer -------------------------------------


def test_subprocess_cumulative_returns_delta():
    outputs = iter(["10.0\n", "12.5\n"])

    class _Result:
        def __init__(self, stdout): self.stdout = stdout

    def fake_run(cmd, capture_output=True, text=True, timeout=10, check=True):
        return _Result(stdout=next(outputs))

    m = SubprocessMeasurer(
        cmd=["echo", "x"],
        parse=lambda out: float(out.strip()),
        model_id="vrt1.kwh.test.v1", source="subprocess:test",
        cumulative=True,
    )
    m._sleep = lambda secs: None
    with patch("vrt1_kwh.measurer.subprocess.run", side_effect=fake_run):
        sample = m.measure(60.0)
    assert sample.kwh == pytest.approx(2.5)


def test_subprocess_instantaneous_rate_multiplies_by_window():
    class _Result:
        stdout = "2.0\n"   # 2 kW instantaneous rate
    def fake_run(cmd, **kw):
        return _Result()

    m = SubprocessMeasurer(
        cmd=["echo", "x"],
        parse=lambda out: float(out.strip()),
        model_id="vrt1.kwh.shelly.v1", source="subprocess:shelly",
        cumulative=False,
    )
    m._sleep = lambda secs: None
    with patch("vrt1_kwh.measurer.subprocess.run", side_effect=fake_run):
        sample = m.measure(3600.0)  # one hour at 2 kW = 2 kWh
    assert sample.kwh == pytest.approx(2.0)


def test_subprocess_failed_command_raises_runtimeerror():
    def fake_run(cmd, **kw):
        raise subprocess.CalledProcessError(returncode=1, cmd=cmd, stderr="boom")
    m = SubprocessMeasurer(
        cmd=["false"], parse=lambda out: 0.0,
        model_id="x", source="x",
    )
    m._sleep = lambda secs: None
    with patch("vrt1_kwh.measurer.subprocess.run", side_effect=fake_run):
        with pytest.raises(RuntimeError, match="failed"):
            m.measure(1)


def test_subprocess_parse_failure_raises_runtimeerror():
    class _Result: stdout = "garbage that is not a number"
    def fake_run(cmd, **kw): return _Result()
    m = SubprocessMeasurer(
        cmd=["echo"], parse=lambda out: float(out),
        model_id="x", source="x",
    )
    m._sleep = lambda secs: None
    with patch("vrt1_kwh.measurer.subprocess.run", side_effect=fake_run):
        with pytest.raises(RuntimeError, match="parse"):
            m.measure(1)


def test_subprocess_rejects_empty_cmd():
    with pytest.raises(ValueError, match="non-empty"):
        SubprocessMeasurer(cmd=[], parse=lambda x: 0.0, model_id="m", source="s")
