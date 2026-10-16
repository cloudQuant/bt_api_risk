"""风险管理核心模块

包含风险管理器的核心组件和基础功能
"""

from __future__ import annotations

from importlib import import_module

from .admission import (
    AccountScope,
    CancelDispatchResolutionProof,
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
    FreezeActivationResult,
    FreezeActivationStatus,
    FreezeResolution,
    FreezeResolutionStatus,
    IntentAction,
    PermitInvalidError,
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
    RiskPermit,
    RiskPolicy,
    StrategyAllocationSnapshot,
    VerifiedCancelDispatchResolution,
    VerifiedCancellationJournalAuthority,
    VerifiedDispatchExposureJournalAuthority,
    VerifiedDispatchExposureResolution,
    VerifiedDispatchRecoveryResolution,
    VerifiedDispatchResolution,
    VerifiedExecutionJournalAuthority,
    VerifiedRecoveredExecutionJournalAuthority,
)
from .exposure import (
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
from .instrument import (
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
    "LimitsManager": ".limits_manager",
    "PolicyEngine": ".policy_engine",
    "RiskAssessor": ".risk_assessor",
    "RiskCalculator": ".risk_calculator",
    "RiskManager": ".risk_manager",
}


def __getattr__(name: str):
    """Keep deterministic admission independent of analytical imports."""
    module = _ANALYSIS_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Expose lazy public names to introspection without importing features."""
    return sorted(set(globals()) | set(__all__))


__all__ = [
    "RiskManager",
    "RiskAssessor",
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
    "RiskCalculator",
    "LimitsManager",
    "PolicyEngine",
    "AccountScope",
    "CancelDispatchResolutionProof",
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
    "FreezeActivationResult",
    "FreezeActivationStatus",
    "FreezeResolution",
    "FreezeResolutionStatus",
    "VerifiedDispatchResolution",
    "VerifiedDispatchExposureResolution",
    "VerifiedDispatchExposureJournalAuthority",
    "VerifiedDispatchRecoveryResolution",
    "VerifiedCancelDispatchResolution",
    "VerifiedCancellationJournalAuthority",
    "DurableRiskGate",
    "IntentAction",
    "PermitInvalidError",
    "RiskDeniedError",
    "RiskExposureDimension",
    "RiskExposureKind",
    "RiskExposureLimit",
    "RiskGateError",
    "RiskGroupLegClaimReceipt",
    "RiskGroupLegIntent",
    "RiskGroupReservationLeg",
    "RiskGroupReservationReceipt",
    "RiskGroupReservationState",
    "RiskIntent",
    "RiskPermit",
    "RiskPolicy",
    "StrategyAllocationSnapshot",
    "VerifiedExecutionJournalAuthority",
    "VerifiedRecoveredExecutionJournalAuthority",
    "INSTRUMENT_METADATA_DIGEST_TAG",
    "AccountPositionRiskFact",
    "InstrumentRiskAdmissionMapper",
    "InstrumentRiskAssessment",
    "InstrumentRiskFxRate",
    "InstrumentRiskGreeks",
    "InstrumentRiskMetadata",
    "InstrumentRiskOrder",
    "InstrumentRiskRegistry",
]
