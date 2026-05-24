"""Aggregator: device totals, coverage gaps, overlap fraud detection."""

from __future__ import annotations

import copy
import time

import pytest

from veritas.crypto import OracleKey

from vrt1_kwh.aggregator import (
    aggregate,
    coverage_gaps,
    detect_overlap_fraud,
    device_totals,
)
from vrt1_kwh.attestation import make_measurement, sign_measurement
from vrt1_kwh.measurer import MeasurementSample


def _sm(key, kwh: float, start: int, end: int, source: str = "stub"):
    """Build a SignedMeasurement with the given key, kwh, and window."""
    sample = MeasurementSample(
        window_start=start, window_end=end, kwh=kwh,
        source=source, model_id="vrt1.kwh.test.v1",
    )
    return sign_measurement(
        make_measurement(device_pubkey_hex=key.xonly_pubkey_hex, sample=sample),
        key,
    )


def test_device_totals_sums_kwh_per_device():
    a = OracleKey.generate()
    b = OracleKey.generate()
    corpus = [
        _sm(a, 0.001, 100, 200),
        _sm(a, 0.002, 300, 400),
        _sm(b, 0.005, 100, 200),
    ]
    totals = device_totals(corpus)
    assert totals[a.xonly_pubkey_hex].total_kwh == pytest.approx(0.003)
    assert totals[a.xonly_pubkey_hex].measurement_count == 2
    assert totals[b.xonly_pubkey_hex].total_kwh == pytest.approx(0.005)
    assert totals[b.xonly_pubkey_hex].measurement_count == 1


def test_device_totals_excludes_invalid_signatures():
    a = OracleKey.generate()
    valid = _sm(a, 0.001, 100, 200)
    bad = copy.deepcopy(valid)
    bad.measurement.kwh = 999.999   # tamper post-sign
    totals = device_totals([valid, bad])
    assert totals[a.xonly_pubkey_hex].total_kwh == pytest.approx(0.001)
    assert totals[a.xonly_pubkey_hex].measurement_count == 1
    assert totals[a.xonly_pubkey_hex].invalid_count == 1


def test_device_totals_reports_time_bounds():
    a = OracleKey.generate()
    corpus = [
        _sm(a, 0.001, 200, 300),
        _sm(a, 0.001, 1000, 2000),
        _sm(a, 0.001, 500, 600),
    ]
    totals = device_totals(corpus)
    dt = totals[a.xonly_pubkey_hex]
    assert dt.first_window_start == 200
    assert dt.last_window_end == 2000


def test_coverage_gaps_finds_silent_periods():
    a = OracleKey.generate()
    corpus = [
        _sm(a, 0.001, 100, 200),
        _sm(a, 0.001, 250, 350),    # 50s gap (≥ default 60s? no — exactly 50s, below)
        _sm(a, 0.001, 1000, 1100),  # 650s gap from prev end (350) — surfaces
    ]
    gaps = coverage_gaps(corpus, min_gap_seconds=60)
    assert len(gaps) == 1
    g = gaps[0]
    assert g.gap_start == 350
    assert g.gap_end == 1000
    assert g.duration_seconds == 650


def test_coverage_gaps_min_threshold_respected():
    a = OracleKey.generate()
    corpus = [
        _sm(a, 0.001, 100, 200),
        _sm(a, 0.001, 250, 350),    # 50s gap
    ]
    assert coverage_gaps(corpus, min_gap_seconds=60) == []
    gaps = coverage_gaps(corpus, min_gap_seconds=10)
    assert len(gaps) == 1
    assert gaps[0].duration_seconds == 50


def test_coverage_gaps_per_device_isolated():
    a = OracleKey.generate()
    b = OracleKey.generate()
    corpus = [
        _sm(a, 0.001, 100, 200),
        _sm(b, 0.001, 300, 400),   # different device — not a gap for a
        _sm(a, 0.001, 5000, 5100),
    ]
    gaps = coverage_gaps(corpus, min_gap_seconds=60)
    assert len(gaps) == 1
    assert gaps[0].device == a.xonly_pubkey_hex


def test_overlap_fraud_detected():
    a = OracleKey.generate()
    corpus = [
        _sm(a, 0.001, 100, 250),   # window 100–250
        _sm(a, 0.001, 200, 400),   # overlaps with previous by 50s
    ]
    fraud = detect_overlap_fraud(corpus)
    assert len(fraud) == 1
    assert fraud[0].overlap_seconds == 50
    assert fraud[0].device == a.xonly_pubkey_hex


def test_overlap_fraud_ignores_adjacent_windows():
    a = OracleKey.generate()
    corpus = [
        _sm(a, 0.001, 100, 200),
        _sm(a, 0.001, 200, 300),   # exactly adjacent — not an overlap
    ]
    assert detect_overlap_fraud(corpus) == []


def test_overlap_fraud_is_per_device():
    a = OracleKey.generate()
    b = OracleKey.generate()
    corpus = [
        _sm(a, 0.001, 100, 250),
        _sm(b, 0.001, 100, 250),   # different device — not fraud
    ]
    assert detect_overlap_fraud(corpus) == []


def test_overlap_fraud_ignores_invalid_signature_measurements():
    a = OracleKey.generate()
    real = _sm(a, 0.001, 100, 250)
    forged = copy.deepcopy(real)
    forged.measurement.window_start = 200
    forged.measurement.window_end = 400
    # forged.sig is no longer valid for the mutated content.
    assert forged.verify() is False
    fraud = detect_overlap_fraud([real, forged])
    assert fraud == [], "invalid-sig measurements must not generate overlap reports"


def test_aggregate_bundles_everything():
    a = OracleKey.generate()
    corpus = [
        _sm(a, 0.001, 100, 200),
        _sm(a, 0.001, 150, 250),  # overlap fraud (50s)
        _sm(a, 0.001, 1000, 1100),  # gap from 250→1000 (750s) — surfaces
    ]
    report = aggregate(corpus, min_gap_seconds=60)
    assert a.xonly_pubkey_hex in report.totals
    assert len(report.overlaps) == 1
    assert len(report.gaps) == 1
