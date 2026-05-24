"""KwhMeasurement: sign/verify, JSON roundtrip, tamper rejection."""

import copy

import pytest

from veritas.crypto import OracleKey

from vrt1_kwh.attestation import (
    KwhMeasurement,
    SignedMeasurement,
    canonical_json,
    make_measurement,
    measurement_digest,
    measurement_id,
    sign_measurement,
)
from vrt1_kwh.measurer import MeasurementSample


def _sample(kwh: float = 0.001, start: int = 1_700_000_000) -> MeasurementSample:
    return MeasurementSample(
        window_start=start, window_end=start + 30,
        kwh=kwh, source="stub", model_id="vrt1.kwh.stub.v1",
    )


def test_canonical_json_is_stable():
    a = {"kwh": 0.001, "device": "ab", "window_start": 1}
    b = {"window_start": 1, "device": "ab", "kwh": 0.001}
    assert canonical_json(a) == canonical_json(b)


def test_sign_and_verify_roundtrip():
    k = OracleKey.generate()
    m = make_measurement(device_pubkey_hex=k.xonly_pubkey_hex, sample=_sample())
    signed = sign_measurement(m, k)
    assert signed.verify()
    assert len(signed.sig) == 128


def test_sign_rejects_mismatched_device():
    k = OracleKey.generate()
    other = OracleKey.generate()
    m = make_measurement(device_pubkey_hex=other.xonly_pubkey_hex, sample=_sample())
    with pytest.raises(ValueError, match="does not match"):
        sign_measurement(m, k)


def test_tampered_kwh_fails_verification():
    k = OracleKey.generate()
    m = make_measurement(device_pubkey_hex=k.xonly_pubkey_hex, sample=_sample(kwh=0.001))
    signed = sign_measurement(m, k)
    assert signed.verify()
    signed.measurement.kwh = 999.999  # post-sign mutation
    assert signed.verify() is False


def test_kwh_is_rounded_to_9_decimals_before_signing():
    """Same physical measurement should sign identically across machines."""
    k = OracleKey.generate()
    raw_a = 1e-12 + 1e-15      # essentially the same as raw_b at 9 decimals
    raw_b = 1e-12 + 2e-15
    m_a = make_measurement(
        device_pubkey_hex=k.xonly_pubkey_hex,
        sample=_sample(kwh=raw_a),
    )
    m_b = make_measurement(
        device_pubkey_hex=k.xonly_pubkey_hex,
        sample=_sample(kwh=raw_b),
    )
    # Both digest to the same bytes (rounded to 1e-9).
    assert measurement_digest(m_a) == measurement_digest(m_b)


def test_measurement_id_is_deterministic():
    k = OracleKey.generate()
    m1 = make_measurement(device_pubkey_hex=k.xonly_pubkey_hex, sample=_sample())
    m2 = make_measurement(device_pubkey_hex=k.xonly_pubkey_hex, sample=_sample())
    assert measurement_id(m1) == measurement_id(m2)


def test_id_changes_when_any_field_changes():
    k = OracleKey.generate()
    base = measurement_id(make_measurement(
        device_pubkey_hex=k.xonly_pubkey_hex, sample=_sample(),
    ))
    assert measurement_id(make_measurement(
        device_pubkey_hex=k.xonly_pubkey_hex, sample=_sample(kwh=0.002),
    )) != base
    assert measurement_id(make_measurement(
        device_pubkey_hex=k.xonly_pubkey_hex, sample=_sample(start=1_700_000_001),
    )) != base


def test_json_roundtrip_preserves_signature():
    k = OracleKey.generate()
    m = make_measurement(device_pubkey_hex=k.xonly_pubkey_hex, sample=_sample())
    signed = sign_measurement(m, k)
    again = SignedMeasurement.from_json(signed.to_json())
    assert again.verify()
    assert again.id == signed.id
    assert again.measurement.kwh == signed.measurement.kwh


def test_nonce_supported_and_signed():
    k = OracleKey.generate()
    m = make_measurement(
        device_pubkey_hex=k.xonly_pubkey_hex, sample=_sample(),
        nonce="deadbeef",
    )
    signed = sign_measurement(m, k)
    assert signed.verify()
    # Changing the nonce after signing breaks verification.
    signed.measurement.nonce = "cafe1234"
    assert signed.verify() is False


def test_empty_nonce_omitted_from_payload():
    k = OracleKey.generate()
    m = make_measurement(device_pubkey_hex=k.xonly_pubkey_hex, sample=_sample())
    assert "nonce" not in m.to_payload()
