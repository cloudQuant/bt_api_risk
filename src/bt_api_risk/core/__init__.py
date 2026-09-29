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
    DispatchResolutionProof,
    DispatchTerminalProof,
    DispatchTerminalState,
    DispatchTrackedOrderProof,
    DurableRiskGate,
    IntentAction,
    PermitInvalidError,
    RiskDeniedError,
    RiskGateError,
    RiskIntent,
    RiskPermit,
    RiskPolicy,
    StrategyAllocationSnapshot,
    VerifiedCancelDispatchResolution,
    VerifiedCancellationJournalAuthority,
    VerifiedDispatchResolution,
    VerifiedExecutionJournalAuthority,
)
from .instrument import (
    INSTRUMENT_METADATA_DIGEST_TAG,
    InstrumentRiskAdmissionMapper,
    InstrumentRiskAssessment,
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
    "RiskCalculator",
    "LimitsManager",
    "PolicyEngine",
    "AccountScope",
    "CancelDispatchResolutionProof",
    "CancelDispatchSource",
    "CancelDispatchTerminalState",
    "CancelTargetPostcondition",
    "DispatchClaimBinding",
    "DispatchEvidenceClass",
    "DispatchResolutionProof",
    "DispatchTerminalProof",
    "DispatchTerminalState",
    "DispatchTrackedOrderProof",
    "VerifiedDispatchResolution",
    "VerifiedCancelDispatchResolution",
    "VerifiedCancellationJournalAuthority",
    "DurableRiskGate",
    "IntentAction",
    "PermitInvalidError",
    "RiskDeniedError",
    "RiskGateError",
    "RiskIntent",
    "RiskPermit",
    "RiskPolicy",
    "StrategyAllocationSnapshot",
    "VerifiedExecutionJournalAuthority",
    "INSTRUMENT_METADATA_DIGEST_TAG",
    "InstrumentRiskAdmissionMapper",
    "InstrumentRiskAssessment",
    "InstrumentRiskMetadata",
    "InstrumentRiskOrder",
    "InstrumentRiskRegistry",
]
