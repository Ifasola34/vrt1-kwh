"""Long-running kWh oracle daemon.

The daemon owns a Measurer and a signing key. On each tick it asks the
measurer for a sample over the configured window, signs the result,
persists it to a per-device data directory, and optionally hands it to
a Nostr publisher (caller supplies the relay wiring; the oracle stays
network-agnostic).

Persistence is one JSON file per signed measurement, named by
`{window_start}_{id_short}.json` so the disk layout is human-browsable
and lexically time-sorted. Atomic writes via tmpfile + os.replace —
crash-safe on SIGKILL.

The daemon is single-threaded by design: kWh measurements are slow
relative to anything else the daemon does, and concurrent measurement
windows would overlap (which the aggregator rejects as fraud).
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from veritas.crypto import OracleKey

from .attestation import (
    SignedMeasurement,
    make_measurement,
    sign_measurement,
)
from .measurer import Measurer


@dataclass
class OracleConfig:
    """Daemon configuration.

    `interval_seconds` is the wall-clock cadence between measurement
    starts. `window_seconds` is how long each measurement window is.
    These can differ: e.g. measure for 30s every 5min (interval=300,
    window=30) to reduce data volume.

    `nonce_factory` returns the nonce string for each measurement. The
    default returns "" — measurements are linkable across windows by
    the device pubkey. For unlinkability-per-window, pass a function
    that returns random bytes hex.
    """
    data_dir: Path
    interval_seconds: int = 300
    window_seconds: int = 30
    max_measurements: int | None = None   # None = run forever
    nonce_factory: Callable[[], str] = field(default=lambda: "")


class KwhOracle:
    """A thin orchestration layer over Measurer + signing key + disk.

    Usage:
        oracle = KwhOracle(device_key, StubMeasurer(), OracleConfig(...))
        oracle.run()           # blocks until max_measurements (or forever)

    Or step-wise for tests/integration:
        signed = oracle.tick()  # one measurement + sign + persist
    """

    def __init__(
        self,
        key: OracleKey,
        measurer: Measurer,
        config: OracleConfig,
        *,
        on_sign: Callable[[SignedMeasurement], None] | None = None,
    ) -> None:
        self.key = key
        self.measurer = measurer
        self.config = config
        self.on_sign = on_sign
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self._stop = threading.Event()
        # Test hook for the sleep between ticks.
        self._sleep: Callable[[float], None] = time.sleep

    @property
    def device_pubkey_hex(self) -> str:
        return self.key.xonly_pubkey_hex

    def stop(self) -> None:
        """Signal the run loop to exit after the current tick."""
        self._stop.set()

    def tick(self) -> SignedMeasurement:
        """Run one measurement → sign → persist cycle. Returns the signed result."""
        sample = self.measurer.measure(self.config.window_seconds)
        m = make_measurement(
            device_pubkey_hex=self.device_pubkey_hex,
            sample=sample,
            nonce=self.config.nonce_factory(),
        )
        signed = sign_measurement(m, self.key)
        self._persist(signed)
        if self.on_sign is not None:
            self.on_sign(signed)
        return signed

    def run(self) -> int:
        """Tick repeatedly. Returns the number of measurements taken.

        Blocks for `interval_seconds` between ticks. Sleeps in 1-second
        chunks so stop() can interrupt cleanly.
        """
        taken = 0
        while not self._stop.is_set():
            if (
                self.config.max_measurements is not None
                and taken >= self.config.max_measurements
            ):
                break
            self.tick()
            taken += 1
            # Sleep up to interval_seconds, breakable on stop.
            slept = 0
            while slept < self.config.interval_seconds and not self._stop.is_set():
                step = min(1.0, self.config.interval_seconds - slept)
                self._sleep(step)
                slept += step
        return taken

    # ---------- persistence ----------------------------------------

    def _persist(self, signed: SignedMeasurement) -> None:
        ts = signed.measurement.window_start
        short = signed.id[:12]
        fname = f"{ts:020d}_{short}.json"
        path = self.config.data_dir / fname
        _atomic_write(path, signed.to_json())


def _atomic_write(path: Path, data: str) -> None:
    """Tmp file + fsync + os.replace. Crash-safe."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def load_corpus(data_dir: Path) -> list[SignedMeasurement]:
    """Load every signed measurement under `data_dir`, sorted by window_start.

    Skips files that don't parse (torn writes, junk).
    """
    out: list[SignedMeasurement] = []
    if not data_dir.exists():
        return out
    for p in sorted(data_dir.glob("*.json")):
        try:
            sm = SignedMeasurement.from_json(p.read_text())
        except (json.JSONDecodeError, KeyError, ValueError, OSError):
            continue
        out.append(sm)
    out.sort(key=lambda s: s.measurement.window_start)
    return out
