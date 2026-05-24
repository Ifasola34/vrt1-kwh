"""KwhOracle: tick, run loop, atomic persistence, corpus load."""

from __future__ import annotations

from pathlib import Path

import pytest

from veritas.crypto import OracleKey

from vrt1_kwh.measurer import StubMeasurer
from vrt1_kwh.oracle import KwhOracle, OracleConfig, load_corpus


def _stub_with_clock(ts_start: int = 1_700_000_000):
    s = StubMeasurer(kwh_per_second=0.001)
    advancing = {"now": ts_start}

    def clock():
        return advancing["now"]
    s.set_clock(clock)
    return s, advancing


def test_tick_writes_signed_measurement_to_disk(tmp_path: Path):
    k = OracleKey.generate()
    s, _ = _stub_with_clock()
    oracle = KwhOracle(k, s, OracleConfig(
        data_dir=tmp_path / "data", interval_seconds=10, window_seconds=30,
    ))
    signed = oracle.tick()
    assert signed.verify()
    # One JSON file should now live in the data dir.
    files = list((tmp_path / "data").glob("*.json"))
    assert len(files) == 1
    assert files[0].name.endswith(".json")
    assert files[0].name.startswith(f"{signed.measurement.window_start:020d}_")


def test_run_loop_stops_after_max_measurements(tmp_path: Path):
    k = OracleKey.generate()
    s, ticker = _stub_with_clock(1_700_000_000)
    oracle = KwhOracle(k, s, OracleConfig(
        data_dir=tmp_path / "data",
        interval_seconds=10, window_seconds=1,
        max_measurements=3,
    ))
    # Don't actually sleep — but DO advance the stub's clock between ticks
    # so each measurement has a distinct window_start (and therefore a
    # distinct digest/filename). In production this is automatic because
    # real RAPL reads accumulate noise; the stub is deterministic.
    def _fake_sleep(secs):
        ticker["now"] += secs
    oracle._sleep = _fake_sleep
    taken = oracle.run()
    assert taken == 3
    assert len(list((tmp_path / "data").glob("*.json"))) == 3


def test_run_loop_respects_stop_signal(tmp_path: Path):
    k = OracleKey.generate()
    s = StubMeasurer(kwh_per_second=0.001)
    oracle = KwhOracle(k, s, OracleConfig(
        data_dir=tmp_path / "data",
        interval_seconds=1, window_seconds=1,
        max_measurements=100,
    ))

    calls = {"n": 0}

    def fake_sleep(secs):
        calls["n"] += 1
        if calls["n"] >= 2:
            oracle.stop()
    oracle._sleep = fake_sleep

    taken = oracle.run()
    assert taken < 10, "oracle should stop early via stop()"


def test_atomic_write_no_tmp_files_left_on_success(tmp_path: Path):
    k = OracleKey.generate()
    oracle = KwhOracle(
        k, StubMeasurer(kwh_per_second=0.001),
        OracleConfig(data_dir=tmp_path / "data",
                     interval_seconds=10, window_seconds=1),
    )
    oracle.tick()
    tmp_files = list((tmp_path / "data").glob("*.tmp"))
    assert tmp_files == [], "tmp files must be renamed away on success"


def test_nonce_factory_is_invoked(tmp_path: Path):
    k = OracleKey.generate()
    seen = []

    def nonce_factory():
        n = f"nonce-{len(seen)}"
        seen.append(n)
        return n

    oracle = KwhOracle(
        k, StubMeasurer(kwh_per_second=0.001),
        OracleConfig(
            data_dir=tmp_path / "data", interval_seconds=1, window_seconds=1,
            max_measurements=3, nonce_factory=nonce_factory,
        ),
    )
    oracle._sleep = lambda secs: None
    oracle.run()
    assert len(seen) == 3
    # Each measurement file should carry its assigned nonce.
    nonces_on_disk = []
    for sm in load_corpus(tmp_path / "data"):
        nonces_on_disk.append(sm.measurement.nonce)
    assert sorted(nonces_on_disk) == sorted(seen)


def test_load_corpus_returns_sorted_by_window_start(tmp_path: Path):
    k = OracleKey.generate()
    s, ticker = _stub_with_clock(1_700_000_000)
    oracle = KwhOracle(
        k, s,
        OracleConfig(data_dir=tmp_path / "data", interval_seconds=1, window_seconds=10),
    )
    oracle.tick()
    ticker["now"] += 100
    oracle.tick()
    ticker["now"] += 100
    oracle.tick()

    corpus = load_corpus(tmp_path / "data")
    assert len(corpus) == 3
    starts = [sm.measurement.window_start for sm in corpus]
    assert starts == sorted(starts)


def test_load_corpus_skips_torn_json(tmp_path: Path):
    k = OracleKey.generate()
    oracle = KwhOracle(
        k, StubMeasurer(kwh_per_second=0.001),
        OracleConfig(data_dir=tmp_path / "data", interval_seconds=1, window_seconds=1),
    )
    oracle.tick()
    # Drop a truncated file alongside the real one.
    (tmp_path / "data" / "torn.json").write_text('{"measurement": {"dev')
    corpus = load_corpus(tmp_path / "data")
    assert len(corpus) == 1  # only the good one


def test_oracle_on_sign_callback_invoked(tmp_path: Path):
    k = OracleKey.generate()
    captured = []

    def on_sign(sm):
        captured.append(sm.id)

    oracle = KwhOracle(
        k, StubMeasurer(kwh_per_second=0.001),
        OracleConfig(data_dir=tmp_path / "data", interval_seconds=1, window_seconds=1),
        on_sign=on_sign,
    )
    sm = oracle.tick()
    assert captured == [sm.id]
