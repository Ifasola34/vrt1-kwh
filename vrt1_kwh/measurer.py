"""Energy measurement sources.

A `Measurer` knows how to read energy consumption over a window and
return kilowatt-hours. Implementations vary wildly by platform and by
what hardware you have access to:

  - StubMeasurer        deterministic / random — for tests and demos
  - RaplMeasurer        Linux Intel/AMD via /sys/class/powercap RAPL
  - SubprocessMeasurer  shell command + parse callback — universal
                        escape hatch (smart plugs, utility APIs, etc.)

To add a new measurer (powermetrics on macOS, nvidia-smi for GPU,
Shelly smart-plug HTTP API, Tuya cloud API, etc.) implement the
Measurer protocol and pass an instance to the oracle.

Each measurer returns a `MeasurementSample` — raw measurement plus
provenance (which source, which model_id, the window bounds). The
attestation layer wraps that sample with a signature and a digest.
"""

from __future__ import annotations

import os
import random
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol


# ---------- shared value type --------------------------------------


@dataclass(frozen=True)
class MeasurementSample:
    """Raw output of one measurement window."""
    window_start: int     # unix seconds
    window_end: int       # unix seconds
    kwh: float
    source: str           # short identifier of the measurer that produced this
    model_id: str         # versioned tag, e.g. "vrt1.kwh.rapl.v1"


# ---------- protocol -----------------------------------------------


class Measurer(Protocol):
    """The two things every measurer must do:

      .model_id   stable string identifying the measurement model
      .measure(duration_seconds)  block for `duration_seconds`, return a sample
    """
    model_id: str

    def measure(self, duration_seconds: float) -> MeasurementSample: ...


# ---------- StubMeasurer -------------------------------------------


class StubMeasurer:
    """Deterministic or seeded-random measurer for tests and demos.

    `kwh_per_second` is the constant rate this stub will report. If
    `jitter_fraction > 0`, each measurement is multiplied by
    `1 + uniform(-jitter, +jitter)` for slight per-window variation.
    """

    def __init__(
        self,
        kwh_per_second: float = 0.00001,   # 0.01 Wh/s ≈ 36 W laptop idle
        jitter_fraction: float = 0.0,
        seed: int | None = None,
        model_id: str = "vrt1.kwh.stub.v1",
        source: str = "stub",
    ) -> None:
        if kwh_per_second < 0:
            raise ValueError("kwh_per_second must be non-negative")
        if not 0 <= jitter_fraction < 1:
            raise ValueError("jitter_fraction must be in [0, 1)")
        self.kwh_per_second = kwh_per_second
        self.jitter_fraction = jitter_fraction
        self.model_id = model_id
        self.source = source
        self._rng = random.Random(seed)
        # Allow tests to override the clock; default to time.time.
        self._clock: Callable[[], float] = time.time

    def set_clock(self, clock: Callable[[], float]) -> None:
        """Test helper — inject a deterministic clock."""
        self._clock = clock

    def measure(self, duration_seconds: float) -> MeasurementSample:
        if duration_seconds < 0:
            raise ValueError("duration_seconds must be non-negative")
        start = int(self._clock())
        # Don't actually sleep — the stub is for tests; callers that
        # want real wall-clock delay can sleep themselves between calls.
        end = start + int(duration_seconds)
        base = self.kwh_per_second * duration_seconds
        if self.jitter_fraction > 0:
            factor = 1 + self._rng.uniform(
                -self.jitter_fraction, self.jitter_fraction,
            )
            base *= factor
        return MeasurementSample(
            window_start=start, window_end=end, kwh=max(0.0, base),
            source=self.source, model_id=self.model_id,
        )


# ---------- RaplMeasurer (Linux Intel/AMD) -------------------------


class RaplMeasurer:
    """Read CPU package energy via Intel/AMD RAPL.

    /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj exposes
    accumulated microjoules. Difference over the measurement window
    converted to kWh:

        kwh = (delta_microjoules / 1_000_000) / 3_600_000

    The counter wraps; we detect and correct via max_energy_range_uj
    if it's available.

    On systems without RAPL (non-Intel/AMD, no kernel support,
    container without /sys access) construction raises FileNotFoundError
    immediately — caller can catch and fall back to StubMeasurer.
    """

    DEFAULT_PATH = Path("/sys/class/powercap/intel-rapl/intel-rapl:0")

    def __init__(
        self,
        rapl_path: str | Path | None = None,
        model_id: str = "vrt1.kwh.rapl.v1",
        source: str = "rapl",
    ) -> None:
        self.rapl_path = Path(rapl_path or self.DEFAULT_PATH)
        self.model_id = model_id
        self.source = source
        if not (self.rapl_path / "energy_uj").exists():
            raise FileNotFoundError(
                f"RAPL energy counter not found at {self.rapl_path / 'energy_uj'}; "
                "this measurer requires Linux with Intel/AMD RAPL support"
            )
        # Cache the wrap-around bound, if exposed.
        bound_path = self.rapl_path / "max_energy_range_uj"
        self._max_uj: int | None = None
        if bound_path.exists():
            try:
                self._max_uj = int(bound_path.read_text().strip())
            except (ValueError, OSError):
                self._max_uj = None
        self._sleep: Callable[[float], None] = time.sleep
        self._clock: Callable[[], float] = time.time

    def _read_uj(self) -> int:
        return int((self.rapl_path / "energy_uj").read_text().strip())

    def measure(self, duration_seconds: float) -> MeasurementSample:
        if duration_seconds <= 0:
            raise ValueError("duration_seconds must be positive")
        start_ts = int(self._clock())
        start_uj = self._read_uj()
        self._sleep(duration_seconds)
        end_uj = self._read_uj()
        end_ts = int(self._clock())

        delta_uj = end_uj - start_uj
        if delta_uj < 0 and self._max_uj:
            # Counter wrapped during the window. Loop until non-negative
            # in case it wrapped MULTIPLE times — on older CPUs with a
            # ~4.3kJ range, sustained ~150W can wrap every ~28s.
            while delta_uj < 0:
                delta_uj += self._max_uj
        elif delta_uj < 0:
            # No bound info, can't correct safely; clamp to zero.
            delta_uj = 0
        joules = delta_uj / 1_000_000
        kwh = joules / 3_600_000

        return MeasurementSample(
            window_start=start_ts, window_end=end_ts, kwh=kwh,
            source=self.source, model_id=self.model_id,
        )


# ---------- SubprocessMeasurer (universal) -------------------------


class SubprocessMeasurer:
    """Wrap any shell command + a parse function to extract kWh.

    Use this for measurement sources that don't have a native Python
    integration: smart plugs with curl APIs, utility provider CLIs,
    custom hardware running ipmitool, etc.

    Example — a Shelly plug exposing /status with `aenergy.total` in
    watt-hours:

        def parse_shelly(out: str) -> float:
            data = json.loads(out)
            wh = data["aenergy"]["total"]
            return wh / 1000  # Wh -> kWh

        m = SubprocessMeasurer(
            cmd=["curl", "-s", "http://192.168.1.50/rpc/Switch.GetStatus?id=0"],
            parse=parse_shelly,
            model_id="vrt1.kwh.shelly-plus-plug-s.v1",
            source="subprocess:shelly",
        )

    Note: SubprocessMeasurer reads a CUMULATIVE counter twice (before
    and after `duration_seconds`) by default and reports the delta.
    For sources that return an instantaneous-rate value (watts), use
    `cumulative=False` — the rate will be multiplied by the window.
    """

    def __init__(
        self,
        cmd: list[str],
        parse: Callable[[str], float],
        *,
        model_id: str,
        source: str,
        cumulative: bool = True,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not cmd:
            raise ValueError("cmd must be a non-empty list")
        self.cmd = list(cmd)
        self.parse = parse
        self.model_id = model_id
        self.source = source
        self.cumulative = cumulative
        self.timeout = timeout_seconds
        self._sleep: Callable[[float], None] = time.sleep
        self._clock: Callable[[], float] = time.time

    def _run(self) -> float:
        try:
            out = subprocess.run(
                self.cmd, capture_output=True, text=True,
                timeout=self.timeout, check=True,
            ).stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"measurement command failed: {' '.join(self.cmd)!r} "
                f"exit={e.returncode} stderr={e.stderr.strip()!r}"
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"measurement command timed out after {self.timeout}s: "
                f"{' '.join(self.cmd)!r}"
            )
        try:
            return float(self.parse(out))
        except (ValueError, KeyError, TypeError) as e:
            raise RuntimeError(
                f"parse function failed for command output: {e}"
            )

    def measure(self, duration_seconds: float) -> MeasurementSample:
        if duration_seconds <= 0:
            raise ValueError("duration_seconds must be positive")
        if self.cumulative:
            # Capture start_ts AFTER the first _run() returns so the
            # signed window reflects the physical measurement bounds
            # (NOT the time we spent waiting on the subprocess). Without
            # this, two back-to-back cumulative measurements can produce
            # signed windows that overlap on disk even though physical
            # readings are disjoint — triggering false-positive
            # OverlapFraud reports.
            start_val = self._run()
            start_ts = int(self._clock())
            self._sleep(duration_seconds)
            end_ts = int(self._clock())
            end_val = self._run()
            kwh = max(0.0, end_val - start_val)
        else:
            # Instantaneous rate (kW); multiply by hours in window.
            start_ts = int(self._clock())
            rate_kw = self._run()
            self._sleep(duration_seconds)
            end_ts = int(self._clock())
            hours = duration_seconds / 3600
            kwh = max(0.0, rate_kw * hours)

        return MeasurementSample(
            window_start=start_ts, window_end=end_ts, kwh=kwh,
            source=self.source, model_id=self.model_id,
        )
