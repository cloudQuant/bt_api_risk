"""风险管理核心模块

包含风险管理器的核心组件和基础功能
"""

from __future__ import annotations

from .admission import (
    AccountScope,
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
from .limits_manager import LimitsManager
from .policy_engine import PolicyEngine
from .risk_assessor import RiskAssessor
from .risk_calculator import RiskCalculator
from .risk_manager import RiskManager

__all__ = [
    "RiskManager",
    "RiskAssessor",
    "RiskCalculator",
    "LimitsManager",
    "PolicyEngine",
    "AccountScope",
    "DispatchClaimBinding",
    "DispatchEvidenceClass",
    "DispatchResolutionProof",
    "DispatchTerminalProof",
    "DispatchTerminalState",
    "DispatchTrackedOrderProof",
    "VerifiedDispatchResolution",
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
