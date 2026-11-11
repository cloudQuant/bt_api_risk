"""bt_api_risk: durable pre-trade admission primitives plus optional analytics.

Three parts (see README.md for the evidence level of each):

1. Admission primitives: ``DurableRiskGate`` (SQLite ledger of reservations,
   dispatch claims, STOP_NEW causes and dispatch in-flight latches) and the
   iteration-60 managed adapters built on it.
2. Pre-trade service catalog ``bt_api_risk.pretrade`` (iteration 64, R-01..R-11;
   REVIEW_PENDING).
3. Analytics and ML helpers (``RiskAssessor``, ``RiskCalculator``,
   ``AnomalyDetector``, ``RiskEnsembleModel``). They are not admission controls
   and never gate an order.

The package performs no provider or network I/O and makes no regulatory
compliance claim.
"""

from __future__ import annotations

from importlib import import_module

from .containers.risk_events import RiskEvent, RiskEventType, RiskLevel
from .containers.risk_metrics import RiskMetrics
from .core.admission import (
    AccountScope,
    CancelDispatchResolutionProof,
    CancelDispatchResolutionReceipt,
    CancelDispatchResolutionReceiptStatus,
    CancelDispatchSource,
    CancelDispatchTerminalState,
    CancelTargetPostcondition,
    DispatchClaimBinding,
    DispatchEvidenceClass,
    DispatchExposureResolutionProof,
    DispatchExposureResolutionReceipt,
    DispatchExposureResolutionReceiptStatus,
    DispatchRecoveryAttestation,
    DispatchResolutionProof,
    DispatchResolutionReceipt,
    DispatchResolutionReceiptStatus,
    DispatchTerminalProof,
    DispatchTerminalResolutionReceipt,
    DispatchTerminalResolutionReceiptStatus,
    DispatchTerminalState,
    DispatchTrackedOrderProof,
    DurableRiskGate,
    DurableRiskPolicyBinding,
    IntentAction,
    PermitInvalidError,
    RecoveryCloseSourceProof,
    RecoveryReductionAllocation,
    RiskDeniedError,
    RiskExposureDimension,
    RiskExposureKind,
    RiskExposureLimit,
    RiskGateError,
    RiskGroupLegClaimReceipt,
    RiskGroupLegIntent,
    RiskGroupReservationLeg,
    RiskGroupReservationReceipt,
    RiskGroupReservationState,
    RiskIntent,
    RiskLedgerSchemaError,
    RiskPermit,
    RiskPolicy,
    StopNewActivationResult,
    StopNewActivationStatus,
    StopNewResolution,
    StopNewResolutionStatus,
    StrategyAllocationSnapshot,
    VerifiedCancelDispatchResolution,
    VerifiedCancellationJournalAuthority,
    VerifiedDispatchExposureJournalAuthority,
    VerifiedDispatchExposureResolution,
    VerifiedDispatchRecoveryResolution,
    VerifiedDispatchResolution,
    VerifiedExecutionJournalAuthority,
    VerifiedRecoveredExecutionJournalAuthority,
    VerifiedRecoveryCloseJournalAuthority,
    VerifiedRecoveryCloseSource,
)
from .core.closable_position_rebase import (
    ClosablePositionCloseReceiptV1,
    ClosablePositionRebaseV1,
)
from .core.exposure import (
    ExposureAccountingMode,
    GrossExposureAuthority,
    GrossExposureBaselineProof,
    OrderExposureObservationProof,
    OrderExposureSnapshot,
    OrderExposureState,
    OrderFillFact,
    PositionSnapshotCoverage,
    StrategyGrossBaseline,
    VerifiedGrossExposureBaseline,
    VerifiedOrderExposureObservation,
    fill_ids_sha256,
)
from .core.instrument import (
    INSTRUMENT_METADATA_DIGEST_TAG,
    AccountPositionRiskFact,
    InstrumentRiskAdmissionMapper,
    InstrumentRiskAssessment,
    InstrumentRiskFxRate,
    InstrumentRiskGreeks,
    InstrumentRiskMetadata,
    InstrumentRiskOrder,
    InstrumentRiskRegistry,
)

_ANALYSIS_EXPORTS = {
    "RiskAssessor": ".core.risk_assessor",
    "AnomalyDetector": ".ml_models.anomaly_detector",
    "RiskEnsembleModel": ".ml_models.ensemble_model",
}

_ADMISSION_EXPORTS = {
    "DurableRiskAdmissionAdapter": ".order_admission",
    "RiskAdmissionPolicyBinding": ".order_admission",
    "RiskAdmissionAdapterError": ".order_admission",
    "RiskAdmissionDeniedError": ".order_admission",
}

# Optional features whose implementation imports live outside the base
# dependency set. Requesting them without the extra must fail explicitly
# instead of surfacing a bare module-not-found from deep inside the package.
_OPTIONAL_EXTRAS = {
    "AnomalyDetector": "ml",
    "RiskEnsembleModel": "ml",
}


def __getattr__(name: str):
    """Load optional features only when explicitly requested by the caller."""
    module = _ANALYSIS_EXPORTS.get(name) or _ADMISSION_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    try:
        value = getattr(import_module(module, __name__), name)
    except ImportError as error:
        extra = _OPTIONAL_EXTRAS.get(name)
        if extra is None:
            raise
        raise ImportError(
            f"{name} requires the {extra!r} extra of bt_api_risk "
            f"(install bt_api_risk[{extra}]): {error}"
        ) from error
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Keep the established public exports discoverable without loading them."""
    return sorted(set(globals()) | set(__all__))


__all__ = [
    # Analytics (not admission)
    "RiskAssessor",
    # ML Models
    "RiskEnsembleModel",
    "AnomalyDetector",
    # Data Containers
    "RiskMetrics",
    "RiskEvent",
    "RiskEventType",
    "RiskLevel",
    # Durable execution-boundary admission
    "AccountScope",
    "ClosablePositionCloseReceiptV1",
    "ClosablePositionRebaseV1",
    "CancelDispatchResolutionProof",
    "CancelDispatchResolutionReceipt",
    "CancelDispatchResolutionReceiptStatus",
    "CancelDispatchSource",
    "CancelDispatchTerminalState",
    "CancelTargetPostcondition",
    "DispatchClaimBinding",
    "DispatchExposureResolutionProof",
    "DispatchExposureResolutionReceipt",
    "DispatchExposureResolutionReceiptStatus",
    "DispatchEvidenceClass",
    "DispatchRecoveryAttestation",
    "DispatchResolutionReceipt",
    "DispatchResolutionReceiptStatus",
    "DispatchResolutionProof",
    "DispatchTerminalProof",
    "DispatchTerminalResolutionReceipt",
    "DispatchTerminalResolutionReceiptStatus",
    "DispatchTerminalState",
    "DispatchTrackedOrderProof",
    "StopNewActivationResult",
    "StopNewActivationStatus",
    "StopNewResolution",
    "StopNewResolutionStatus",
    "ExposureAccountingMode",
    "GrossExposureAuthority",
    "GrossExposureBaselineProof",
    "PositionSnapshotCoverage",
    "OrderExposureObservationProof",
    "OrderExposureSnapshot",
    "OrderExposureState",
    "OrderFillFact",
    "StrategyGrossBaseline",
    "VerifiedGrossExposureBaseline",
    "VerifiedOrderExposureObservation",
    "fill_ids_sha256",
    "VerifiedDispatchResolution",
    "VerifiedDispatchExposureResolution",
    "VerifiedDispatchExposureJournalAuthority",
    "VerifiedDispatchRecoveryResolution",
    "VerifiedCancelDispatchResolution",
    "VerifiedCancellationJournalAuthority",
    "DurableRiskGate",
    "DurableRiskPolicyBinding",
    "IntentAction",
    "PermitInvalidError",
    "RiskDeniedError",
    "RiskExposureDimension",
    "RiskExposureKind",
    "RiskExposureLimit",
    "RiskGateError",
    "RiskLedgerSchemaError",
    "RiskGroupLegClaimReceipt",
    "RiskGroupLegIntent",
    "RiskGroupReservationLeg",
    "RiskGroupReservationReceipt",
    "RiskGroupReservationState",
    "RecoveryCloseSourceProof",
    "RecoveryReductionAllocation",
    "RiskIntent",
    "RiskPermit",
    "RiskPolicy",
    "StrategyAllocationSnapshot",
    "VerifiedExecutionJournalAuthority",
    "VerifiedRecoveredExecutionJournalAuthority",
    "VerifiedRecoveryCloseJournalAuthority",
    "VerifiedRecoveryCloseSource",
    "INSTRUMENT_METADATA_DIGEST_TAG",
    "AccountPositionRiskFact",
    "InstrumentRiskAdmissionMapper",
    "InstrumentRiskAssessment",
    "InstrumentRiskFxRate",
    "InstrumentRiskGreeks",
    "InstrumentRiskMetadata",
    "InstrumentRiskOrder",
    "InstrumentRiskRegistry",
    "DurableRiskAdmissionAdapter",
    "RiskAdmissionPolicyBinding",
    "RiskAdmissionAdapterError",
    "RiskAdmissionDeniedError",
]

# 版本信息
__version__ = "0.1.1.dev64"
__compliance_standards__ = [
    "MiFID II",
    "SEC Rule 606",
    "Market Abuse Regulation (MAR)",
    "Anti-Money Laundering (AML)",
    "KYC",
    "Basel III",
    "IOSCO Principles",
]

# 默认配置
DEFAULT_RISK_CONFIG = {
    "risk_thresholds": {
        "low": 0.3,
        "medium": 0.6,
        "high": 0.8,
        "critical": 0.9,
    },
    "monitoring": {
        "real_time_enabled": True,
        "batch_processing_interval": 60,  # seconds
        "alert_cooldown": 300,  # seconds
    },
    "ml_models": {
        "ensemble_weights": {"rf": 0.4, "nn": 0.4, "xgb": 0.2},
        "retraining_interval": 86400,  # 24 hours
        "min_samples": 1000,
    },
    "compliance": {
        "market_manipulation_detection": True,
        "aml_monitoring": True,
        "position_limits": True,
        "reporting_requirements": True,
    },
    "performance": {
        "max_processing_time_ms": 100,
        "memory_limit_mb": 1024,
        "concurrency_limit": 10,
    },
}
