"""CLI: keygen, measure, run, verify, aggregate — end-to-end."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from veritas.crypto import OracleKey

from vrt1_kwh.attestation import make_measurement, sign_measurement
from vrt1_kwh.cli import cli
from vrt1_kwh.measurer import MeasurementSample


def _write_key(tmp_path: Path, key: OracleKey, name: str = "device.key") -> Path:
    p = tmp_path / name
    p.write_text(key.privkey.hex() + "\n")
    p.chmod(0o600)
    return p


def _sm(key, kwh=0.001, start=1_700_000_000, end=1_700_000_030):
    return sign_measurement(
        make_measurement(
            device_pubkey_hex=key.xonly_pubkey_hex,
            sample=MeasurementSample(
                window_start=start, window_end=end, kwh=kwh,
                source="stub", model_id="vrt1.kwh.stub.v1",
            ),
        ), key,
    )


def test_keygen_creates_mode_0600_file(tmp_path: Path):
    out = tmp_path / "dev.key"
    runner = CliRunner()
    r = runner.invoke(cli, ["keygen", "--out", str(out)])
    assert r.exit_code == 0, r.output
    assert out.exists()
    mode = oct(out.stat().st_mode)[-3:]
    assert mode == "600"
    assert "x-only pubkey" in r.output


def test_keygen_refuses_to_overwrite(tmp_path: Path):
    out = tmp_path / "dev.key"
    out.write_text("not a real key")
    runner = CliRunner()
    r = runner.invoke(cli, ["keygen", "--out", str(out)])
    assert r.exit_code != 0
    assert "refusing to overwrite" in r.output


def test_measure_signs_one_sample(tmp_path: Path):
    k = OracleKey.generate()
    key_path = _write_key(tmp_path, k)
    out = tmp_path / "signed.json"
    runner = CliRunner()
    r = runner.invoke(cli, [
        "measure", "--key", str(key_path),
        "--measurer", "stub", "--duration", "5",
        "--out", str(out),
    ])
    assert r.exit_code == 0, r.output
    body = json.loads(out.read_text())
    assert body["measurement"]["device"] == k.xonly_pubkey_hex
    assert body["measurement"]["source"] == "stub"
    assert len(body["sig"]) == 128


def test_measure_rapl_errors_when_unavailable(tmp_path: Path):
    """On a system without RAPL we should get a clean ClickException, not a traceback."""
    if Path("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj").exists():
        pytest.skip("system actually has RAPL — can't test the failure path")
    k = OracleKey.generate()
    key_path = _write_key(tmp_path, k)
    runner = CliRunner()
    r = runner.invoke(cli, [
        "measure", "--key", str(key_path), "--measurer", "rapl", "--duration", "1",
    ])
    assert r.exit_code != 0
    assert "RAPL" in r.output


def test_run_max_measurements_three_writes_three_files(tmp_path: Path):
    k = OracleKey.generate()
    key_path = _write_key(tmp_path, k)
    runner = CliRunner()
    r = runner.invoke(cli, [
        "run", "--key", str(key_path),
        "--data-dir", str(tmp_path / "data"),
        "--measurer", "stub",
        "--interval", "1", "--window", "1",
        "--max-measurements", "3",
    ])
    assert r.exit_code == 0, r.output
    files = list((tmp_path / "data").glob("*.json"))
    assert len(files) == 3


def test_verify_passes_on_honest_file(tmp_path: Path):
    k = OracleKey.generate()
    signed = _sm(k)
    p = tmp_path / "ok.json"
    p.write_text(signed.to_json())
    runner = CliRunner()
    r = runner.invoke(cli, ["verify", str(p)])
    assert r.exit_code == 0
    assert "VALID" in r.output


def test_verify_fails_on_tampered_file(tmp_path: Path):
    k = OracleKey.generate()
    signed = _sm(k)
    body = json.loads(signed.to_json())
    body["measurement"]["kwh"] = 999.999
    p = tmp_path / "tampered.json"
    p.write_text(json.dumps(body))
    runner = CliRunner()
    r = runner.invoke(cli, ["verify", str(p)])
    assert r.exit_code == 1
    assert "INVALID" in r.output


def test_aggregate_prints_totals_and_no_fraud(tmp_path: Path):
    k = OracleKey.generate()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "01.json").write_text(_sm(k, kwh=0.001, start=100, end=200).to_json())
    (corpus / "02.json").write_text(_sm(k, kwh=0.002, start=300, end=400).to_json())
    runner = CliRunner()
    r = runner.invoke(cli, ["aggregate", "--corpus", str(corpus)])
    assert r.exit_code == 0, r.output
    assert "device totals" in r.output
    assert "no overlap fraud detected" in r.output


def test_aggregate_surfaces_overlap_fraud(tmp_path: Path):
    k = OracleKey.generate()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "01.json").write_text(_sm(k, kwh=0.001, start=100, end=250).to_json())
    (corpus / "02.json").write_text(_sm(k, kwh=0.001, start=200, end=400).to_json())
    runner = CliRunner()
    r = runner.invoke(cli, ["aggregate", "--corpus", str(corpus)])
    # Exit 2 = overlap fraud (gated for CI / scripts).
    assert r.exit_code == 2
    assert "OVERLAP FRAUD" in r.output


def test_aggregate_exits_4_on_invalid_signature(tmp_path: Path):
    """Round-3 fix: exit code is now a BITMASK.
      2 = overlap fraud
      4 = invalid sigs present
      6 = both
    Previously fraud took precedence and silently swallowed the
    invalid-sig signal (operators watching only for exit=3 missed it).
    """
    k = OracleKey.generate()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "01.json").write_text(_sm(k, kwh=0.001, start=100, end=200).to_json())
    # A measurement whose signature is corrupted post-sign.
    bad = _sm(k, kwh=0.002, start=300, end=400)
    bad_body = json.loads(bad.to_json())
    bad_body["measurement"]["kwh"] = 999.0
    (corpus / "02_bad.json").write_text(json.dumps(bad_body))
    runner = CliRunner()
    r = runner.invoke(cli, ["aggregate", "--corpus", str(corpus)])
    # Exit 4 = invalid sigs present (no overlap fraud here).
    assert r.exit_code == 4


def test_aggregate_exits_6_when_both_fraud_and_invalid_sigs(tmp_path: Path):
    """Bitmask: 2 (fraud) | 4 (invalid sigs) = 6. CI rules that watch
    `if rc & 4` or `if rc & 2` both fire correctly. Previously only
    fraud would have surfaced and the invalid-sig signal was lost."""
    k = OracleKey.generate()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    # Two overlapping valid measurements = fraud (bit 2).
    (corpus / "01.json").write_text(_sm(k, kwh=0.001, start=100, end=250).to_json())
    (corpus / "02.json").write_text(_sm(k, kwh=0.001, start=200, end=400).to_json())
    # Plus an invalid-sig measurement = bit 4.
    bad = _sm(k, kwh=0.002, start=500, end=600)
    bad_body = json.loads(bad.to_json())
    bad_body["measurement"]["kwh"] = 999.0
    (corpus / "03_bad.json").write_text(json.dumps(bad_body))
    runner = CliRunner()
    r = runner.invoke(cli, ["aggregate", "--corpus", str(corpus)])
    assert r.exit_code == 6
    assert r.exit_code & 2  # fraud bit set
    assert r.exit_code & 4  # invalid-sig bit set


def test_aggregate_errors_on_empty_dir(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    runner = CliRunner()
    r = runner.invoke(cli, ["aggregate", "--corpus", str(empty)])
    assert r.exit_code != 0
    assert "no parseable" in r.output.lower()


def test_aggregate_device_filter(tmp_path: Path):
    a = OracleKey.generate()
    b = OracleKey.generate()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "01.json").write_text(_sm(a, start=100, end=200).to_json())
    (corpus / "02.json").write_text(_sm(b, start=100, end=200).to_json())
    runner = CliRunner()
    r = runner.invoke(cli, [
        "aggregate", "--corpus", str(corpus),
        "--device", a.xonly_pubkey_hex,
    ])
    assert r.exit_code == 0
    # Only one device row should show up.
    assert a.xonly_pubkey_hex[:16] in r.output
    assert b.xonly_pubkey_hex[:16] not in r.output
