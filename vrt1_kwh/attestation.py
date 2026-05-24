"""KwhMeasurement — what a device signs.

Parallel primitive to VERITAS inference attestations and vrt1-agents
agent actions. Schema:

  {
    device:        x-only pubkey hex (32 bytes) of the signing device
    window_start:  unix seconds
    window_end:    unix seconds
    kwh:           float, kilowatt-hours consumed during the window
    source:        short identifier of the measurer ("rapl", "stub", …)
    model_id:      versioned tag of the measurement model
    v:             schema version (1)
    nonce:         optional random string for unlinkability
  }

Signed with the device's BIP-340 Schnorr key over
`tagged_hash("VRT1/kwh", canonical_bytes(payload))`. Same crypto stack
as VERITAS — different domain tag so signatures can never cross-confuse.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import Any

from veritas.crypto import (
    OracleKey,
    schnorr_sign,
    schnorr_verify,
    tagged_hash,
)

from .measurer import MeasurementSample


KWH_TAG = "VRT1/kwh"


def canonical_json(obj: Any) -> bytes:
    """Stable byte encoding — sorted keys, no whitespace.

    Floats are serialized with Python's repr, which is round-trippable
    but platform-dependent in edge cases. For interop across machines,
    callers should round/quantize kwh to a fixed precision before signing
    (the oracle layer does this — see DEFAULT_KWH_PRECISION).
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


# Round to 9 decimal places before signing so the same physical
# measurement signs identically on any IEEE-754 implementation
# (nanowatt-hour resolution is far below any real measurement noise).
DEFAULT_KWH_PRECISION = 9


def _round_kwh(value: float, precision: int = DEFAULT_KWH_PRECISION) -> float:
    return round(float(value), precision)


@dataclass
class KwhMeasurement:
    device: str
    window_start: int
    window_end: int
    kwh: float
    source: str
    model_id: str
    v: int = 1
    nonce: str = ""

    def to_payload(self) -> dict[str, Any]:
        d = asdict(self)
        if not d["nonce"]:
            d.pop("nonce")
        # Always round kwh to the deterministic precision before serializing.
        d["kwh"] = _round_kwh(d["kwh"])
        return d

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_payload())


def measurement_digest(m: KwhMeasurement) -> bytes:
    """32-byte BIP-340-tagged hash of the canonical payload — what gets signed."""
    return tagged_hash(KWH_TAG, m.canonical_bytes())


def measurement_id(m: KwhMeasurement) -> str:
    """Deterministic hex id for this measurement (same bytes → same id)."""
    return measurement_digest(m).hex()


@dataclass
class SignedMeasurement:
    measurement: KwhMeasurement
    sig: str  # 64-byte Schnorr sig, hex

    @property
    def id(self) -> str:
        return measurement_id(self.measurement)

    def verify(self) -> bool:
        msg = measurement_digest(self.measurement)
        try:
            sig = bytes.fromhex(self.sig)
            pk = bytes.fromhex(self.measurement.device)
        except ValueError:
            return False
        return schnorr_verify(msg, sig, pk)

    def to_json(self) -> str:
        return json.dumps(
            {"measurement": self.measurement.to_payload(), "sig": self.sig},
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> "SignedMeasurement":
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        d = json.loads(raw)
        m = d["measurement"]
        return cls(
            measurement=KwhMeasurement(
                device=m["device"],
                window_start=int(m["window_start"]),
                window_end=int(m["window_end"]),
                kwh=float(m["kwh"]),
                source=m["source"],
                model_id=m["model_id"],
                v=int(m.get("v", 1)),
                nonce=m.get("nonce", ""),
            ),
            sig=d["sig"],
        )


def make_measurement(
    *,
    device_pubkey_hex: str,
    sample: MeasurementSample,
    nonce: str = "",
) -> KwhMeasurement:
    """Build a KwhMeasurement from a measurer's raw sample + device pubkey."""
    return KwhMeasurement(
        device=device_pubkey_hex,
        window_start=sample.window_start,
        window_end=sample.window_end,
        kwh=sample.kwh,
        source=sample.source,
        model_id=sample.model_id,
        nonce=nonce,
    )


def sign_measurement(
    measurement: KwhMeasurement, key: OracleKey,
) -> SignedMeasurement:
    """Sign a KwhMeasurement with the device's BIP-340 key.

    Enforces that the measurement.device pubkey matches the signing
    key. Mismatch is almost always a bug.
    """
    if measurement.device != key.xonly_pubkey_hex:
        raise ValueError(
            f"measurement.device does not match signing key "
            f"(device={measurement.device[:8]}…, "
            f"key={key.xonly_pubkey_hex[:8]}…)"
        )
    sig = schnorr_sign(measurement_digest(measurement), key)
    return SignedMeasurement(measurement=measurement, sig=sig.hex())
