"""vrt1-kwh — signed kWh attestations for the VERITAS (VRT1) protocol.

Devices measure their own power consumption and emit cryptographically
signed, peer-verifiable records. Substrate for proof-of-energy systems
(Bitcoin mining attestation, carbon credits, agent compute receipts,
IoT power telemetry).

Top-level imports:
    from vrt1_kwh import (
        # Measurement sources
        StubMeasurer, RaplMeasurer, SubprocessMeasurer, MeasurementSample,
        # Attestation
        KwhMeasurement, SignedMeasurement,
        make_measurement, sign_measurement,
        measurement_digest, measurement_id,
        # Oracle daemon
        KwhOracle, OracleConfig, load_corpus,
        # Aggregation
        DeviceTotal, CoverageGap, OverlapFraud, AggregateReport,
        device_totals, coverage_gaps, detect_overlap_fraud, aggregate,
        # Nostr publication
        KIND_KWH_MEASUREMENT, build_measurement_event, decode_measurement_event,
    )
"""

__version__ = "0.1.0"

from .aggregator import (
    AggregateReport,
    CoverageGap,
    DeviceTotal,
    OverlapFraud,
    aggregate,
    coverage_gaps,
    detect_overlap_fraud,
    device_totals,
)
from .attestation import (
    KWH_TAG,
    KwhMeasurement,
    SignedMeasurement,
    canonical_json,
    make_measurement,
    measurement_digest,
    measurement_id,
    sign_measurement,
)
from .measurer import (
    MeasurementSample,
    Measurer,
    RaplMeasurer,
    StubMeasurer,
    SubprocessMeasurer,
)
from .nostr import (
    KIND_KWH_MEASUREMENT,
    build_measurement_event,
    decode_measurement_event,
)
from .oracle import (
    KwhOracle,
    OracleConfig,
    load_corpus,
)

__all__ = [
    "__version__",
    # measurer
    "MeasurementSample", "Measurer",
    "StubMeasurer", "RaplMeasurer", "SubprocessMeasurer",
    # attestation
    "KWH_TAG", "canonical_json",
    "KwhMeasurement", "SignedMeasurement",
    "make_measurement", "sign_measurement",
    "measurement_digest", "measurement_id",
    # oracle
    "KwhOracle", "OracleConfig", "load_corpus",
    # aggregator
    "DeviceTotal", "CoverageGap", "OverlapFraud", "AggregateReport",
    "device_totals", "coverage_gaps", "detect_overlap_fraud", "aggregate",
    # nostr
    "KIND_KWH_MEASUREMENT",
    "build_measurement_event", "decode_measurement_event",
]
