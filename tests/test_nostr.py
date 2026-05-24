"""Nostr publication: kind-1991 event roundtrip + tag shape."""

import pytest

from veritas.crypto import OracleKey
from veritas.nostr import NostrEvent

from vrt1_kwh.attestation import make_measurement, sign_measurement
from vrt1_kwh.measurer import MeasurementSample
from vrt1_kwh.nostr import (
    KIND_KWH_MEASUREMENT,
    build_measurement_event,
    decode_measurement_event,
)


def _signed(key):
    sample = MeasurementSample(
        window_start=1_700_000_000, window_end=1_700_000_030, kwh=0.001,
        source="stub", model_id="vrt1.kwh.stub.v1",
    )
    return sign_measurement(
        make_measurement(device_pubkey_hex=key.xonly_pubkey_hex, sample=sample),
        key,
    )


def test_event_roundtrip_preserves_signed_measurement():
    k = OracleKey.generate()
    signed = _signed(k)
    evt = build_measurement_event(signed, k)
    assert evt.verify()
    assert evt.kind == KIND_KWH_MEASUREMENT
    assert evt.pubkey == k.xonly_pubkey_hex
    decoded = decode_measurement_event(evt)
    assert decoded.id == signed.id
    assert decoded.verify()


def test_event_tags_include_d_p_source_window():
    k = OracleKey.generate()
    signed = _signed(k)
    evt = build_measurement_event(signed, k)
    tag_keys = {t[0] for t in evt.tags}
    assert {"d", "p", "source", "window"}.issubset(tag_keys)
    # Window tag carries start and end as strings.
    win = next(t for t in evt.tags if t[0] == "window")
    assert win[1:] == ["1700000000", "1700000030"]


def test_build_rejects_mismatched_key():
    k = OracleKey.generate()
    other = OracleKey.generate()
    signed = _signed(k)
    with pytest.raises(ValueError, match="does not match"):
        build_measurement_event(signed, other)


def test_decode_rejects_wrong_kind():
    k = OracleKey.generate()
    evt = NostrEvent(
        pubkey=k.xonly_pubkey_hex, created_at=1, kind=1, tags=[], content="ZZZZ",
    )
    with pytest.raises(ValueError, match="expected kind"):
        decode_measurement_event(evt)
