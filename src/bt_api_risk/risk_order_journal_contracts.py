"""Risk-order journal records and their finite validation error.

These values describe journal records; constructing one does not issue a
writer fence or establish account, provider, or execution authority.
"""
from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .core.admission import (
    AccountScope,
    DispatchClaimBinding,
    DispatchRecoveryAttestation,
    DispatchTrackedOrderProof,
)

_SHA256_LENGTH = 64
_DATACLASS_SLOTS = {"slots": True} if sys.version_info >= (3, 10) else {}


class RiskOrderJournalError(RuntimeError):
    """Finite, payload-free journal error."""

    def __init__(self, code: str) -> None:
        if type(code) is not str or not code or len(code) > 96:
            raise ValueError("invalid journal error code")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, **_DATACLASS_SLOTS)
class RiskOrderWriterFence:
    """One current, account-wide process fence held by the caller."""

    scope: AccountScope
    owner_id: str
    fencing_token: int
    fence_sha256: str

    def __post_init__(self) -> None:
        if type(self.scope) is not AccountScope:
            raise ValueError("invalid risk-order writer scope")
        if type(self.owner_id) is not str or not self.owner_id:
            raise ValueError("invalid risk-order writer owner")
        if type(self.fencing_token) is not int or self.fencing_token <= 0:
            raise ValueError("invalid risk-order fencing token")
        _require_sha256(self.fence_sha256, "writer fence digest")


@dataclass(frozen=True, **_DATACLASS_SLOTS)
class RiskOrderCommand:
    """Immutable command identity plus its latest append-only journal event."""

    scope: AccountScope
    principal_ref: str
    intent_id: str
    risk_intent_id: str
    payload_sha256: str
    canonical_payload: Mapping[str, Any]
    wire_scope: Mapping[str, Any]
    exchange_name: str
    provider_account_id: str
    client_order_id: str
    permit_id: str | None
    order_request: Mapping[str, Any]
    order_request_sha256: str
    created_revision: int
    created_record_sha256: str
    created_at_ns: int
    updated_at_ns: int
    state: str
    latest_revision: int
    latest_record_sha256: str
    latest_event: Mapping[str, Any]


@dataclass(frozen=True, **_DATACLASS_SLOTS)
class RiskOrderJournalEvent:
    scope: AccountScope
    principal_ref: str
    intent_id: str
    revision: int
    event_type: str
    payload: Mapping[str, Any]
    previous_account_sha256: str
    previous_command_sha256: str
    record_sha256: str
    writer_owner_id: str
    writer_fencing_token: int
    writer_fence_sha256: str


@dataclass(frozen=True)
class CancelResolutionTargetBindingV1:
    """Exact Risk target command selected by a durable owner-cancel source."""

    scope: AccountScope
    execution_scope_key: str
    cancel_id: str
    target_intent_id: str
    provider_order_id: str
    principal_ref: str
    risk_intent_id: str
    permit_id: str
    order_request_sha256: str
    wire_scope_sha256: str

    def __post_init__(self) -> None:
        if type(self.scope) is not AccountScope:
            raise ValueError("invalid cancel target binding scope")
        for name in (
            "execution_scope_key",
            "cancel_id",
            "target_intent_id",
            "provider_order_id",
            "principal_ref",
            "risk_intent_id",
            "permit_id",
        ):
            value = getattr(self, name)
            if type(value) is not str or not value or value != value.strip():
                raise ValueError("invalid cancel target binding " + name)
        for name in ("order_request_sha256", "wire_scope_sha256"):
            _require_sha256(getattr(self, name), name)


@dataclass(frozen=True, **_DATACLASS_SLOTS)
class DispatchProofRecoverySource:
    """Verified immutable source rows needed to recover a proof-ready order.

    The original ``PROOF_READY`` event and its exposure reference are never
    rewritten under a later writer fence. Recovery appends a separate event
    that binds those original rows to the current fence.
    """

    command: RiskOrderCommand
    claim: DispatchClaimBinding
    proof: DispatchTrackedOrderProof
    proof_ready_event: RiskOrderJournalEvent
    order_observation_event: RiskOrderJournalEvent
    fill_observation_event: RiskOrderJournalEvent
    exposure_reference: Mapping[str, Any]
    exposure_reference_id: str
    exposure_reference_sha256: str
    recovery_events: tuple[RiskOrderJournalEvent, ...]
    recovery_attestations: tuple[DispatchRecoveryAttestation, ...]


def _require_sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != _SHA256_LENGTH
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError("invalid " + label)
    return value


