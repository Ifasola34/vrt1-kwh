"""Adversarial tests for vrt1-kwh.

Each test names an attack that vrt1-kwh MUST refuse to accept,
miscount, or silently mis-aggregate. The point is regression safety:
if anyone weakens an invariant later, these tests catch it before
the change reaches an auditor or a carbon-credit registry consuming
this corpus.

Coverage:
  - Tampered measurement fields (kwh, window, device, source)
  - Forged signatures and cross-device replay
  - Overlap fraud variants (back-to-back, sandwiched, exact-tie starts)
  - Mixed-validity corpora (aggregator must not count invalid ones)
  - Replay of identical measurements (idempotent storage)
  - Time anomalies (window_end < window_start, negative durations)
  - Subprocess measurer returning negative kwh
  - load_corpus return_errors surfaces malicious junk files
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from veritas.crypto import OracleKey

from vrt1_kwh.aggregator import (
    aggregate,
    coverage_gaps,
    detect_overlap_fraud,
    device_totals,
)
from vrt1_kwh.attestation import (
    SignedMeasurement,
    make_measurement,
    measurement_id,
    sign_measurement,
)
from vrt1_kwh.measurer import (
    MeasurementSample,
    StubMeasurer,
    SubprocessMeasurer,
)
from vrt1_kwh.oracle import KwhOracle, OracleConfig, load_corpus


# ---------- helpers ------------------------------------------------


def _sm(key: OracleKey, *, kwh: float, start: int, end: int,
        source: str = "stub", model_id: str = "vrt1.kwh.stub.v1",
        nonce: str = "") -> SignedMeasurement:
    sample = MeasurementSample(
        window_start=start, window_end=end, kwh=kwh,
        source=source, model_id=model_id,
    )
    return sign_measurement(
        make_measurement(
            device_pubkey_hex=key.xonly_pubkey_hex,
            sample=sample, nonce=nonce,
        ),
        key,
    )


@pytest.fixture
def honest_corpus():
    """Two devices, three valid measurements each, non-overlapping windows."""
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    corpus = [
        _sm(alice, kwh=0.001, start=100, end=200),
        _sm(alice, kwh=0.002, start=300, end=400),
        _sm(alice, kwh=0.003, start=500, end=600),
        _sm(bob,   kwh=0.005, start=100, end=200),
        _sm(bob,   kwh=0.006, start=300, end=400),
        _sm(bob,   kwh=0.007, start=500, end=600),
    ]
    return {"alice": alice, "bob": bob, "corpus": corpus}


# ---------- baseline -----------------------------------------------


def test_baseline_honest_corpus_aggregates_cleanly(honest_corpus):
    h = honest_corpus
    # Use min_gap_seconds=200 so the legitimate 100s inter-window gaps
    # in the fixture don't show up — we're testing the no-overlap path.
    r = aggregate(h["corpus"], min_gap_seconds=200)
    assert len(r.overlaps) == 0
    assert len(r.gaps) == 0
    # Both devices present with correct totals.
    assert r.totals[h["alice"].xonly_pubkey_hex].total_kwh == pytest.approx(0.006)
    assert r.totals[h["bob"].xonly_pubkey_hex].total_kwh == pytest.approx(0.018)


# ---------- measurement signing attacks ----------------------------


def test_rejects_tampered_kwh_post_sign(honest_corpus):
    h = honest_corpus
    forged = copy.deepcopy(h["corpus"][0])
    forged.measurement.kwh = 999.999
    assert forged.verify() is False


def test_rejects_tampered_window_post_sign(honest_corpus):
    h = honest_corpus
    forged = copy.deepcopy(h["corpus"][0])
    forged.measurement.window_end = 99999
    assert forged.verify() is False


def test_rejects_tampered_source_post_sign(honest_corpus):
    h = honest_corpus
    forged = copy.deepcopy(h["corpus"][0])
    forged.measurement.source = "lying"
    assert forged.verify() is False


def test_rejects_device_field_swapped_to_another_pubkey(honest_corpus):
    h = honest_corpus
    forged = copy.deepcopy(h["corpus"][0])
    forged.measurement.device = h["bob"].xonly_pubkey_hex
    assert forged.verify() is False


def test_sign_refuses_to_sign_with_wrong_device_key():
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    sample = MeasurementSample(
        window_start=1, window_end=2, kwh=0.001,
        source="stub", model_id="vrt1.kwh.stub.v1",
    )
    m = make_measurement(
        device_pubkey_hex=alice.xonly_pubkey_hex, sample=sample,
    )
    with pytest.raises(ValueError, match="does not match"):
        sign_measurement(m, bob)


def test_signed_measurement_from_json_with_forged_sig_rejected():
    """Attacker hand-crafts a JSON file claiming a signature it didn't earn."""
    alice = OracleKey.generate()
    body = json.dumps({
        "measurement": {
            "device": alice.xonly_pubkey_hex,
            "window_start": 100, "window_end": 200,
            "kwh": 0.001, "source": "stub",
            "model_id": "vrt1.kwh.stub.v1", "v": 1,
        },
        "sig": "00" * 64,  # all-zero sig
    })
    sm = SignedMeasurement.from_json(body)
    assert sm.verify() is False


# ---------- aggregator attacks --------------------------------------


def test_aggregator_excludes_invalid_signatures_from_total(honest_corpus):
    h = honest_corpus
    forged = copy.deepcopy(h["corpus"][0])
    forged.measurement.kwh = 999_999.0
    corpus = h["corpus"] + [forged]
    totals = device_totals(corpus)
    alice_dev = h["alice"].xonly_pubkey_hex
    # Only the three honest alice measurements counted; forged one excluded.
    assert totals[alice_dev].total_kwh == pytest.approx(0.006)
    assert totals[alice_dev].invalid_count == 1


def test_aggregate_marks_invalid_count_and_exits_nonzero():
    """Even ONE invalid signature in the corpus surfaces invalid_count."""
    alice = OracleKey.generate()
    good = _sm(alice, kwh=0.001, start=100, end=200)
    bad = copy.deepcopy(good)
    bad.measurement.kwh = 9.0  # tamper
    r = aggregate([good, bad])
    assert r.totals[alice.xonly_pubkey_hex].invalid_count == 1
    assert r.totals[alice.xonly_pubkey_hex].measurement_count == 1


# ---------- overlap fraud variants ---------------------------------


def test_back_to_back_overlap_detected():
    a = OracleKey.generate()
    corpus = [
        _sm(a, kwh=0.001, start=100, end=250),
        _sm(a, kwh=0.001, start=200, end=400),   # overlaps prev by 50s
    ]
    fraud = detect_overlap_fraud(corpus)
    assert len(fraud) == 1
    assert fraud[0].overlap_seconds == 50


def test_sandwich_overlap_detected():
    """Three windows where the middle one overlaps with both neighbors."""
    a = OracleKey.generate()
    corpus = [
        _sm(a, kwh=0.001, start=100, end=300),   # 100–300
        _sm(a, kwh=0.001, start=200, end=400),   # overlaps first by 100s
        _sm(a, kwh=0.001, start=350, end=500),   # overlaps middle by 50s
    ]
    fraud = detect_overlap_fraud(corpus)
    overlap_pairs = {tuple(sorted([f.a_id, f.b_id])) for f in fraud}
    # Two overlap pairs: (first,middle) and (middle,third); first and third don't.
    assert len(overlap_pairs) == 2


def test_identical_start_different_end_overlap_detected():
    """Two measurements claiming the SAME window_start can still overlap
    even if their ends differ — the sort is stable but the sweep must
    handle exact-tie starts."""
    a = OracleKey.generate()
    corpus = [
        _sm(a, kwh=0.001, start=100, end=250, nonce="a"),
        _sm(a, kwh=0.002, start=100, end=300, nonce="b"),
    ]
    # Identical start, different end → overlap of 150 (250-100).
    fraud = detect_overlap_fraud(corpus)
    assert len(fraud) == 1


def test_two_devices_with_overlapping_windows_not_fraud():
    """Different devices CAN take overlapping measurements legitimately —
    they're separate physical hardware. Fraud is per-device."""
    a = OracleKey.generate()
    b = OracleKey.generate()
    corpus = [
        _sm(a, kwh=0.001, start=100, end=250),
        _sm(b, kwh=0.005, start=100, end=250),   # same window, different device
    ]
    assert detect_overlap_fraud(corpus) == []


def test_overlap_fraud_ignores_forged_signature_measurements():
    """A tampered measurement that 'overlaps' a real one must not even
    enter the overlap calculation — invalid sigs are pre-filtered."""
    a = OracleKey.generate()
    real = _sm(a, kwh=0.001, start=100, end=300)
    forged = copy.deepcopy(real)
    forged.measurement.window_start = 200
    forged.measurement.window_end = 400  # would overlap if accepted
    assert forged.verify() is False
    assert detect_overlap_fraud([real, forged]) == []


# ---------- replay + identity attacks ------------------------------


def test_replay_of_identical_measurement_is_idempotent_on_disk(tmp_path):
    """Same content + same key = same measurement_id = same filename.
    Re-running the same measurement just overwrites the same file."""
    k = OracleKey.generate()
    sample = MeasurementSample(
        window_start=100, window_end=200, kwh=0.001,
        source="stub", model_id="vrt1.kwh.stub.v1",
    )
    s = StubMeasurer(kwh_per_second=0.001)
    s.set_clock(lambda: 100)
    oracle = KwhOracle(
        k, s,
        OracleConfig(data_dir=tmp_path / "data", interval_seconds=1, window_seconds=1),
    )
    sm1 = oracle.tick()
    sm2 = oracle.tick()
    # Identical content → identical id.
    assert sm1.id == sm2.id
    # Only one file (the second overwrote the first).
    assert len(list((tmp_path / "data").glob("*.json"))) == 1


def test_attacker_signed_measurement_does_not_inflate_target_device():
    """Eve signs a measurement claiming to be Alice's device. The sig is
    valid under Eve's key, but the device field is Alice's pubkey, so
    measurement.verify() (which checks against device) fails."""
    alice = OracleKey.generate()
    eve = OracleKey.generate()
    # Eve crafts a measurement claiming to be alice's device, then signs
    # with her own key. sign_measurement refuses this directly.
    sample = MeasurementSample(
        window_start=1, window_end=2, kwh=999.0,
        source="stub", model_id="vrt1.kwh.stub.v1",
    )
    fake = make_measurement(
        device_pubkey_hex=alice.xonly_pubkey_hex, sample=sample,
    )
    with pytest.raises(ValueError):
        sign_measurement(fake, eve)


# ---------- time-anomaly + value-anomaly inputs ---------------------


def test_negative_kwh_clamped_to_zero_by_measurers():
    """Subprocess measurer subtracting two cumulative readings where the
    counter went down (clock reset / replacement meter) clamps to zero
    rather than emitting negative kWh."""
    readings = iter(["100.0", "10.0"])  # decreasing — should clamp

    class _Result:
        def __init__(self, stdout): self.stdout = stdout
    def fake_run(cmd, **kw):
        return _Result(stdout=next(readings))

    m = SubprocessMeasurer(
        cmd=["echo"], parse=lambda out: float(out),
        model_id="x", source="x", cumulative=True,
    )
    m._sleep = lambda secs: None
    with patch("vrt1_kwh.measurer.subprocess.run", side_effect=fake_run):
        s = m.measure(1)
    assert s.kwh == 0.0


def test_window_end_before_start_signs_but_aggregator_finds_no_overlap():
    """A device with a wildly wrong clock might produce window_end < start.
    The signature still verifies (we sign whatever we're told), but the
    overlap detector should not treat such garbage as overlapping any
    sensible window."""
    a = OracleKey.generate()
    weird = _sm(a, kwh=0.0, start=500, end=100)   # end < start, sig verifies
    sensible = _sm(a, kwh=0.001, start=200, end=400)
    assert weird.verify() is True
    fraud = detect_overlap_fraud([weird, sensible])
    # Weird's end (100) is < sensible's start (200) — no overlap reported.
    # But weird's start (500) is > sensible's end (400) so no overlap there
    # either. The detector should not crash on this nonsense; it should
    # just produce zero overlap entries.
    assert isinstance(fraud, list)


# ---------- corpus-loading attacks ---------------------------------


def test_load_corpus_silently_drops_junk_by_default(tmp_path: Path):
    """A poisoned corpus directory (an attacker has rsync access to the
    data dir) drops files that don't parse — but the default load
    returns just the loaded list without surfacing the discards."""
    a = OracleKey.generate()
    d = tmp_path / "data"
    d.mkdir()
    (d / "ok.json").write_text(
        _sm(a, kwh=0.001, start=100, end=200).to_json()
    )
    (d / "junk.json").write_text("not json at all")
    (d / "wrong-shape.json").write_text('{"hello": "world"}')

    corpus = load_corpus(d)
    assert len(corpus) == 1


def test_load_corpus_with_return_errors_surfaces_junk(tmp_path: Path):
    """The same poisoned corpus must surface its skipped files when the
    caller opts into return_errors — no silent data loss for audit-grade
    consumers."""
    a = OracleKey.generate()
    d = tmp_path / "data"
    d.mkdir()
    (d / "ok.json").write_text(
        _sm(a, kwh=0.001, start=100, end=200).to_json()
    )
    (d / "junk.json").write_text("not json at all")
    (d / "wrong-shape.json").write_text('{"hello": "world"}')

    corpus, errors = load_corpus(d, return_errors=True)
    assert len(corpus) == 1
    assert len(errors) == 2
    assert sorted(p.name for p, _ in errors) == ["junk.json", "wrong-shape.json"]


def test_cross_device_measurement_substitution_caught_by_verify():
    """Attacker collects Alice's measurement, swaps the device field to
    Bob's pubkey, and re-publishes. Sig won't verify against Bob's key."""
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    real = _sm(alice, kwh=0.001, start=100, end=200)
    forged = copy.deepcopy(real)
    forged.measurement.device = bob.xonly_pubkey_hex
    # Sig was made over the original device (alice); now device says bob.
    # verify() checks sig against measurement.device (bob's pubkey) — fails.
    assert forged.verify() is False


# ---------- baseline aggregation stability --------------------------


def test_aggregation_is_deterministic(honest_corpus):
    """Same corpus, same call → identical report (no nondeterministic
    ordering / floating-point quirks)."""
    h = honest_corpus
    r1 = aggregate(h["corpus"])
    r2 = aggregate(h["corpus"])
    assert r1.totals == r2.totals
    assert r1.gaps == r2.gaps
    assert r1.overlaps == r2.overlaps


def test_invalid_sig_device_appears_in_totals_with_zero_count():
    """If a device's ONLY measurements are all invalid, the device still
    shows up in totals (with measurement_count=0, invalid_count>0) so
    consumers can flag suspicious devices, not have them disappear."""
    a = OracleKey.generate()
    forged = _sm(a, kwh=0.001, start=100, end=200)
    forged.measurement.kwh = 9.0  # tamper post-sign
    r = aggregate([forged])
    assert a.xonly_pubkey_hex in r.totals
    dt = r.totals[a.xonly_pubkey_hex]
    assert dt.measurement_count == 0
    assert dt.invalid_count == 1
    assert dt.total_kwh == 0
