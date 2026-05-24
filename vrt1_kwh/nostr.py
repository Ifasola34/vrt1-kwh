"""Nostr publication format for kWh measurements.

Wrapped as NIP-01 regular events (kind 1991) — non-replaceable, because
energy measurements are non-repudiable: a device cannot revise its
past consumption claims, only emit corrections as new measurements.

Tags for relay-side filtering:
  ["d",      measurement_id]            deterministic event identifier
  ["source", source]                    query by measurer type
  ["window", start, end]                query by time range

We deliberately do NOT emit a `["p", device_pubkey]` tag — per NIP-01
"p" tags reference OTHER pubkeys (mentions/replies). The device is
already queryable via the standard `authors` REQ filter on the event's
pubkey field; a redundant p-tag pointing at self would confuse
relays that interpret p-tag matches as "event mentions X".
"""

from __future__ import annotations

import base64

from veritas.crypto import OracleKey
from veritas.nostr import NostrEvent

from .attestation import SignedMeasurement, measurement_id


KIND_KWH_MEASUREMENT = 1991


def build_measurement_event(
    signed: SignedMeasurement, key: OracleKey,
) -> NostrEvent:
    """Wrap a SignedMeasurement as a NIP-01 kind-1991 event."""
    if signed.measurement.device != key.xonly_pubkey_hex:
        raise ValueError("signing key pubkey does not match the device pubkey")
    mid = measurement_id(signed.measurement)
    tags: list[list[str]] = [
        ["d", mid],
        ["source", signed.measurement.source],
        ["window",
         str(signed.measurement.window_start),
         str(signed.measurement.window_end)],
    ]
    content = base64.b64encode(signed.to_json().encode("utf-8")).decode("ascii")
    evt = NostrEvent(
        pubkey=key.xonly_pubkey_hex,
        created_at=signed.measurement.window_end,
        kind=KIND_KWH_MEASUREMENT,
        tags=tags,
        content=content,
    )
    return evt.sign(key)


def decode_measurement_event(evt: NostrEvent) -> SignedMeasurement:
    """Inverse of build_measurement_event. Raises on malformed input."""
    if evt.kind != KIND_KWH_MEASUREMENT:
        raise ValueError(
            f"expected kind {KIND_KWH_MEASUREMENT}, got {evt.kind}"
        )
    raw = base64.b64decode(evt.content)
    return SignedMeasurement.from_json(raw)
