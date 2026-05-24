# vrt1-kwh

**Signed kWh (energy consumption) attestations for the [VERITAS](https://github.com/Ifasola34/veritas) (VRT1) protocol.**

Devices measure their own power consumption, sign each measurement with a BIP-340 Schnorr key, and publish cryptographically verifiable, peer-aggregatable records of how much energy they used in which window. The substrate for proof-of-energy systems, Bitcoin mining attestation, IoT power telemetry, carbon-credit primitives, and agent compute receipts.

If VERITAS signs *AI inference outputs* and [vrt1-agents](https://github.com/Ifasola34/vrt1-agents) signs *agent actions*, this signs **physical energy consumption** — the most boring, most real, most universally measurable signal in the entire stack.

---

## What an attestation contains

```python
@dataclass
class KwhMeasurement:
    device: str         # x-only pubkey of the measuring device (hex)
    window_start: int   # unix seconds
    window_end: int     # unix seconds
    kwh: float          # consumption during the window
    source: str         # "stub" | "rapl" | "subprocess:my-meter" | …
    model_id: str       # versioned tag, e.g. "vrt1.kwh.rapl.v1"
    v: int = 1
    nonce: str = ""     # optional, for per-window unlinkability
```

Signed via `tagged_hash("VRT1/kwh", canonical_bytes)` + Schnorr — exactly the same crypto stack as VERITAS attestations and vrt1-agents actions, with a different domain tag so signatures can never be cross-confused. `kwh` is rounded to 9 decimal places before signing so the same physical measurement signs identically across platforms.

---

## How it works end-to-end

```
   ┌─────────────────────────────────┐
   │  Measurer.measure(duration)     │  → MeasurementSample
   │    Stub | Rapl | Subprocess     │
   └────────────┬────────────────────┘
                │
                ▼
   ┌─────────────────────────────────┐
   │  make_measurement + sign        │
   │  tagged_hash("VRT1/kwh", …)     │  → 32-byte digest
   │  schnorr_sign(device_key)       │  → 64-byte sig
   └────────────┬────────────────────┘
                │
                ▼
   ┌─────────────────────────────────┐
   │  SignedMeasurement              │
   │   .to_json() — portable artifact│
   │   .verify() — anyone can run    │
   └────────────┬────────────────────┘
                │  (optional)
                ▼
   ┌─────────────────────────────────┐
   │  Nostr publication (kind 1991)  │
   │    relay-side filterable by     │
   │    device, source, window range │
   └─────────────────────────────────┘
```

A corpus of these can be aggregated for totals, gap analysis, and fraud detection — all pure functions in `vrt1_kwh.aggregator`.

---

## Measurement sources

| | What it reads | Where it works |
|---|---|---|
| `StubMeasurer(kwh_per_second, jitter_fraction, seed)` | Deterministic or seeded-random rate | Everywhere — for tests and demos |
| `RaplMeasurer(rapl_path)` | `/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj` | Linux with Intel/AMD RAPL kernel support |
| `SubprocessMeasurer(cmd, parse, cumulative=True/False)` | Any shell command — smart plug curl, utility CLI, ipmitool, … | Universal escape hatch |

Implementing your own measurer is a two-method interface: `model_id` (string), `measure(duration_seconds) -> MeasurementSample`. Powermetrics on macOS, `nvidia-smi` for GPUs, Shelly/Tuya smart plug HTTP APIs, BTCPay's lightning-meter integrations, smart-meter ZigBee bridges — all are 30-line wrappers around `SubprocessMeasurer`.

---

## Quickstart

```bash
git clone https://github.com/Ifasola34/vrt1-kwh.git
cd vrt1-kwh
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# 1. Generate a device identity (atomic, mode 0600)
vrt1-kwh keygen --out device.key

# 2. Single measurement with the stub measurer (sanity check)
vrt1-kwh measure --key device.key --measurer stub --duration 5

# 3. Run the daemon for 3 ticks (use --measurer rapl on Linux with Intel/AMD)
vrt1-kwh run --key device.key --data-dir ./kwh-data \
    --measurer stub --interval 5 --window 5 --max-measurements 3

# 4. Aggregate the corpus
vrt1-kwh aggregate --corpus ./kwh-data
```

Output (truncated):
```
device totals
device                 kwh           count   first         last
abcd1234ef5678…        0.000150000   3       1700000000    1700000045

no coverage gaps
no overlap fraud detected
```

---

## The aggregator answers three questions

```python
from vrt1_kwh import aggregate

report = aggregate(signed_measurements_corpus)

report.totals      # dict[device_pubkey, DeviceTotal] — kWh, count, time bounds
report.gaps        # list[CoverageGap] — periods the oracle was silent
report.overlaps    # list[OverlapFraud] — same-device measurements whose windows overlap
```

**`device_totals`** — sums valid-signature kWh per device. Flags invalid measurements separately so the consumer can tell forgery from accounting.

**`coverage_gaps`** — between consecutive valid measurements per device, finds any silence period over a configurable threshold. Useful for "was the oracle online when it claimed it was?" audits.

**`detect_overlap_fraud`** — a device cannot physically take two simultaneous measurements (single measurer per device). Finding two same-device valid-signature windows that overlap is evidence of either clock-skew bugs or intentional double-counting. The consumer should refuse to count both.

---

## Honest about fraud resistance

**v0.1 ships the cryptographic substrate, not the enforcement layer.**

What `SignedMeasurement.verify()` proves: this measurement was signed by this device's key, hasn't been tampered with since, and the signature is BIP-340 valid.

What it does NOT prove: that the measurement is *physically true*. A rogue device can sign `{kwh: 999999.0}` and the signature will verify just fine — they signed garbage with their own key.

Real fraud resistance requires one of:
- **TEE attestation** — the measurer runs inside an enclave that can prove what code produced the reading (longer-term roadmap).
- **Utility-meter integration** — the measurement comes from a regulated smart meter, not the device itself.
- **Reputation graphs** — the device's measurements are weighted by external trust signals (see [vrt1-agents](https://github.com/Ifasola34/vrt1-agents) for primitives).
- **Cost-to-fake economics** — consumers reject measurements above plausible bounds for the device type.

`detect_overlap_fraud` catches the simplest double-counting attack. Beyond that, fraud resistance is the consumer's problem, by design — this library is the receipts layer, not the enforcement layer.

---

## Use cases

| Use case | What this library gives you |
|---|---|
| **Bitcoin mining attestation** | Miners sign their power draw per window; pools or buyers verify without trusting reported hashrate-per-watt. |
| **IoT power telemetry** | Devices emit signed kWh records; central aggregator detects gaps and fraud without trusting any single device. |
| **Carbon-credit primitives** | Renewable-source devices (solar inverters, wind turbines) emit signed generation records — substrate for verifiable carbon offsets. |
| **Agent compute receipts** | Compute providers sign per-task energy use; consumers pay per measured kWh of inference, not per opaque "credit." |
| **Energy market data oracles** | Sign price-vs-consumption observations for use in DLCs or other Bitcoin-anchored derivatives. |

---

## Tests

```bash
$ pytest -q
58 passed in ~3s
```

All measurement sources are mocked at the I/O boundary (RAPL via fake `/sys` files, subprocess via `unittest.mock.patch`, stub clock injectable) so the suite runs fully offline. Coverage:

- **Measurer (14):** stub determinism, jitter bounds + reproducibility, arg validation, clock injection; RAPL missing-path error, delta-to-kWh conversion, wrap correction with bound, clamp-to-zero without bound, zero-duration rejection; subprocess cumulative delta, instantaneous-rate multiplication, command failure, parse failure, empty-cmd rejection.
- **Attestation (10):** canonical JSON stability, sign+verify, mismatched-device rejection, post-sign tamper rejection, 9-decimal rounding (cross-platform digest stability), deterministic measurement_id, id changes on any field, JSON roundtrip, nonce signed correctly, empty nonce omitted.
- **Oracle (8):** tick writes to disk, run loop respects max_measurements, run loop respects stop(), atomic writes leave no .tmp files, nonce_factory invocation, load_corpus sorting, load_corpus skips torn JSON, on_sign callback invocation.
- **Aggregator (11):** sum per device, exclude invalid signatures, report time bounds, gaps surfaced + per-device isolated + min-threshold respected, overlap fraud detection + adjacent-not-overlap + per-device isolation + invalid-sig exclusion, full aggregate bundle.
- **Nostr (4):** kind-1991 roundtrip preserves signed measurement, tags include d/p/source/window, mismatched key rejection on build, wrong-kind rejection on decode.
- **CLI (11):** keygen mode 0600, refuse-overwrite, measure stub success, measure RAPL fails cleanly when unavailable, run produces N files, verify pass + fail, aggregate prints totals + no-fraud + surfaces fraud + empty-dir error + device filter.

---

## Where this sits in the VRT1 ecosystem

| Repo | Signs… | Actor |
|---|---|---|
| [veritas](https://github.com/Ifasola34/veritas) | AI inference outputs | Oracle's key |
| [vrt1-agents](https://github.com/Ifasola34/vrt1-agents) | Agent actions (reviews, vouches, trades) | Agent's key |
| **vrt1-kwh** | **Physical energy consumption** | **Device's key** |
| [vrt1-verifier](https://github.com/Ifasola34/vrt1-verifier) | (verifies the above) | Anyone |
| [l402-py](https://github.com/Ifasola34/l402-py) | (Lightning paywall for any of the above) | — |

Five repos, one BIP-340 + Nostr crypto stack, one MIT license, no overlap in scope.

---

## License

MIT — see [`LICENSE`](LICENSE).
