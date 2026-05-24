"""Aggregation over a corpus of signed kWh measurements.

Pure functions — no I/O, no network. Caller supplies the corpus from
wherever (oracle data dir, Nostr fetch, multiple devices merged, etc.)
and asks what they want to know.

Three primitive outputs:

  1. DeviceTotal      — total kWh, count of measurements, time bounds,
                         per-device. Invalid-signature measurements are
                         flagged and excluded from the total.
  2. CoverageGap      — periods within a device's reported timeline
                         that have NO measurements. Useful for spotting
                         "the oracle was offline from T1 to T2."
  3. OverlapFraud     — two valid-signature measurements from the SAME
                         device whose windows overlap. A device cannot
                         physically measure two overlapping windows;
                         finding any is evidence of either a clock skew
                         bug or intentional double-counting.

We deliberately do NOT compute a "trust score" or "carbon credit
amount" — that's policy, not primitive. Consumers apply their own
rules on top of these facts.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from .attestation import SignedMeasurement


@dataclass
class DeviceTotal:
    device: str
    total_kwh: float
    measurement_count: int           # valid-sig only
    invalid_count: int               # flagged for the consumer
    first_window_start: int | None
    last_window_end: int | None


def device_totals(
    corpus: Iterable[SignedMeasurement],
) -> dict[str, DeviceTotal]:
    """Per-device totals over the corpus.

    Returns one DeviceTotal per device pubkey appearing in the corpus
    (including devices whose measurements were all invalid — caller
    can tell from invalid_count > 0 and measurement_count == 0).
    """
    by_device: dict[str, list[SignedMeasurement]] = defaultdict(list)
    for sm in corpus:
        by_device[sm.measurement.device].append(sm)

    out: dict[str, DeviceTotal] = {}
    for device, sms in by_device.items():
        valid = [sm for sm in sms if sm.verify()]
        invalid_count = len(sms) - len(valid)
        total = sum(sm.measurement.kwh for sm in valid)
        first = min((sm.measurement.window_start for sm in valid), default=None)
        last = max((sm.measurement.window_end for sm in valid), default=None)
        out[device] = DeviceTotal(
            device=device,
            total_kwh=total,
            measurement_count=len(valid),
            invalid_count=invalid_count,
            first_window_start=first,
            last_window_end=last,
        )
    return out


@dataclass
class CoverageGap:
    device: str
    gap_start: int        # unix seconds, end of previous window
    gap_end: int          # unix seconds, start of next window
    duration_seconds: int


def coverage_gaps(
    corpus: Iterable[SignedMeasurement],
    *,
    min_gap_seconds: int = 60,
) -> list[CoverageGap]:
    """Find gaps between consecutive valid-signature measurements per device.

    Reports gaps where window_n.end < window_{n+1}.start by at least
    `min_gap_seconds`. Useful for "when was the oracle silent?" audits.
    """
    by_device: dict[str, list[SignedMeasurement]] = defaultdict(list)
    for sm in corpus:
        if sm.verify():
            by_device[sm.measurement.device].append(sm)

    gaps: list[CoverageGap] = []
    for device, sms in by_device.items():
        sms.sort(key=lambda s: s.measurement.window_start)
        for prev, curr in zip(sms, sms[1:]):
            gap = curr.measurement.window_start - prev.measurement.window_end
            if gap >= min_gap_seconds:
                gaps.append(CoverageGap(
                    device=device,
                    gap_start=prev.measurement.window_end,
                    gap_end=curr.measurement.window_start,
                    duration_seconds=gap,
                ))
    return gaps


@dataclass
class OverlapFraud:
    device: str
    a_id: str                # measurement_id of first signed measurement
    b_id: str                # measurement_id of second
    overlap_seconds: int


def detect_overlap_fraud(
    corpus: Iterable[SignedMeasurement],
) -> list[OverlapFraud]:
    """Find any same-device pair whose valid-signature windows overlap.

    A device cannot physically take two simultaneous measurements
    (the measurer is single-threaded per device). Two overlapping
    valid-signature measurements means either:
      - a clock-skew bug on the device
      - intentional double-counting (claim the same kWh twice for credit)

    Either way the consumer should refuse to count both.
    """
    by_device: dict[str, list[SignedMeasurement]] = defaultdict(list)
    for sm in corpus:
        if sm.verify():
            by_device[sm.measurement.device].append(sm)

    fraud: list[OverlapFraud] = []
    for device, sms in by_device.items():
        sms.sort(key=lambda s: s.measurement.window_start)
        # Sweep: for each measurement, find any LATER one whose start
        # is before this one's end. O(n^2) worst case but realistic
        # data is sparse — a 24h corpus at one measurement per 5min is
        # 288 entries; the sweep is microseconds.
        for i, a in enumerate(sms):
            a_end = a.measurement.window_end
            for b in sms[i + 1:]:
                if b.measurement.window_start >= a_end:
                    break  # sorted by start, so no further overlap possible
                overlap = a_end - b.measurement.window_start
                if overlap > 0:
                    fraud.append(OverlapFraud(
                        device=device,
                        a_id=a.id,
                        b_id=b.id,
                        overlap_seconds=overlap,
                    ))
    return fraud


@dataclass
class AggregateReport:
    """Bundle the three primitive outputs into one report.

    Consumers can either pull device_totals/coverage_gaps/overlaps
    individually, or grab the whole report in one call.
    """
    totals: dict[str, DeviceTotal] = field(default_factory=dict)
    gaps: list[CoverageGap] = field(default_factory=list)
    overlaps: list[OverlapFraud] = field(default_factory=list)


def aggregate(
    corpus: Iterable[SignedMeasurement],
    *,
    min_gap_seconds: int = 60,
) -> AggregateReport:
    """Full aggregation in one call. Iterates the corpus once where possible."""
    corpus = list(corpus)
    return AggregateReport(
        totals=device_totals(corpus),
        gaps=coverage_gaps(corpus, min_gap_seconds=min_gap_seconds),
        overlaps=detect_overlap_fraud(corpus),
    )
