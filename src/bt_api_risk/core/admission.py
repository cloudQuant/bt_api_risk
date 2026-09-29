"""Durable, provider-independent pre-trade admission primitives.

The older :mod:`bt_api_risk` classes calculate and describe risk, but they do
not own an account-scoped, durable decision at the dispatch boundary.  This
module provides that small boundary without importing a provider, Backtrader,
or the execution package.  An execution adapter can reserve a permit before it
performs provider I/O and must validate the permit again immediately before
dispatch.

SQLite is deliberately used here because it is part of the Python standard
library, provides an atomic ``BEGIN IMMEDIATE`` transaction across local
processes, and keeps the first implementation usable on Windows and Linux.
It is an account-admission store, not an order ledger or a position book.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import Enum
from fractions import Fraction
from pathlib import Path
from typing import Callable, Optional, Protocol, Union


class RiskGateError(RuntimeError):
    """Base error raised by the durable admission gate."""


class RiskDeniedError(RiskGateError):
    """A deterministic policy or safety condition rejected an intent."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PermitInvalidError(RiskGateError):
    """A permit cannot be used at the execution boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_NOTIONAL_UNIT = re.compile(r"^[A-Z][A-Z0-9]{2,11}$")
_ALLOCATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ALLOCATION_INSTRUMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")


def _require_sha256(value: object, name: str) -> str:
    if type(value) is not str or not _SHA256_HEX.fullmatch(value):
        raise ValueError("invalid " + name)
    return value


class IntentAction(str, Enum):
    """The risk meaning of an execution request."""

    INCREASE = "increase"
    REDUCE = "reduce"
    CANCEL = "cancel"
    UNKNOWN_EFFECT = "unknown_effect"


@dataclass(frozen=True)
class AccountScope:
    """The immutable account/environment boundary of a permit."""

    provider: str
    account_id: str
    environment: str

    def __post_init__(self) -> None:
        if (
            not self.provider.strip()
            or not self.account_id.strip()
            or not self.environment.strip()
        ):
            raise ValueError("provider, account_id, and environment are required")

    @property
    def key(self) -> str:
        return _canonical_json(
            {
                "account_id": self.account_id,
                "environment": self.environment,
                "provider": self.provider,
            }
        )


@dataclass(frozen=True)
class RiskPolicy:
    """Fail-closed limits used for one account scope.

    ``max_increase_notional`` and ``max_increase_count`` apply to outstanding
    reservations.  A filled position is deliberately not inferred from this
    store; a later account/position authority must reconcile it before a
    production integration makes broader exposure claims.
    """

    policy_id: str
    max_increase_notional: Decimal
    max_increase_count: int
    permit_ttl_seconds: float = 30.0
    require_strategy_allocation: bool = False
    notional_unit: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.

    def __post_init__(self) -> None:
        try:
            limit = _as_decimal(self.max_increase_notional)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError(
                "max_increase_notional must be a non-negative decimal"
            ) from exc
        if not self.policy_id.strip():
            raise ValueError("policy_id is required")
        if limit < Decimal("0"):
            raise ValueError("max_increase_notional cannot be negative")
        if type(self.max_increase_count) is not int or self.max_increase_count < 0:
            raise ValueError("max_increase_count must be a non-negative integer")
        if (
            isinstance(self.permit_ttl_seconds, bool)
            or not math.isfinite(self.permit_ttl_seconds)
            or self.permit_ttl_seconds <= 0
        ):
            raise ValueError("permit_ttl_seconds must be positive and finite")
        if type(self.require_strategy_allocation) is not bool:
            raise ValueError("require_strategy_allocation must be a boolean")
        if self.notional_unit is not None and (
            not isinstance(self.notional_unit, str)
            or not _NOTIONAL_UNIT.fullmatch(self.notional_unit)
        ):
            raise ValueError("notional_unit must be a canonical uppercase unit code")
        object.__setattr__(self, "max_increase_notional", limit)

    @property
    def fingerprint(self) -> str:
        payload: dict[str, object] = {
            "max_increase_count": self.max_increase_count,
            "max_increase_notional": _decimal_text(self.max_increase_notional),
            "permit_ttl_seconds": self.permit_ttl_seconds,
            "policy_id": self.policy_id,
        }
        if self.require_strategy_allocation:
            payload["require_strategy_allocation"] = True
        if self.notional_unit is not None:
            payload["notional_unit"] = self.notional_unit
        return _sha256(_canonical_json(payload))


@dataclass(frozen=True)
class RiskIntent:
    """A provider-neutral request after the account owner derived its effect.

    ``REDUCE`` is a trusted classification, never a client's reduce-only flag.
    This primitive has no position book and cannot prove that classification.
    """

    intent_id: str
    scope: AccountScope
    action: IntentAction
    notional: Decimal = Decimal("0")
    payload_fingerprint: str = ""
    strategy_id: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.
    allocation_version: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.
    instrument: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.
    quantity: Optional[Decimal] = None  # noqa: UP045 -- Python 3.9 is supported.
    quantity_unit: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.
    notional_unit: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.

    def __post_init__(self) -> None:
        if not self.intent_id.strip():
            raise ValueError("intent_id is required")
        if not isinstance(self.action, IntentAction):
            raise ValueError("action must be an IntentAction")
        if not isinstance(self.scope, AccountScope):
            raise ValueError("scope must be an AccountScope")
        if not isinstance(self.payload_fingerprint, str):
            raise ValueError("payload_fingerprint must be an immutable string")
        if self.notional_unit is not None and (
            not isinstance(self.notional_unit, str)
            or not _NOTIONAL_UNIT.fullmatch(self.notional_unit)
        ):
            raise ValueError("notional_unit must be a canonical uppercase unit code")
        if (self.strategy_id is None) != (self.allocation_version is None):
            raise ValueError(
                "strategy_id and allocation_version must be supplied together"
            )
        for name in ("strategy_id", "allocation_version"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, str) or not _ALLOCATION_ID.fullmatch(value)
            ):
                raise ValueError("invalid " + name)
        position_fields = (self.instrument, self.quantity, self.quantity_unit)
        if any(value is not None for value in position_fields) and not all(
            value is not None for value in position_fields
        ):
            raise ValueError(
                "instrument, quantity, and quantity_unit must be supplied together"
            )
        if self.instrument is not None and (
            not isinstance(self.instrument, str)
            or not _ALLOCATION_INSTRUMENT.fullmatch(self.instrument)
        ):
            raise ValueError("invalid instrument")
        if self.quantity_unit is not None and (
            not isinstance(self.quantity_unit, str)
            or not _ALLOCATION_ID.fullmatch(self.quantity_unit)
        ):
            raise ValueError("invalid quantity_unit")
        quantity = None
        if self.quantity is not None:
            try:
                quantity = _as_decimal(self.quantity)
            except (InvalidOperation, ValueError) as exc:
                raise ValueError("quantity must be a positive finite decimal") from exc
            if quantity <= Decimal("0"):
                raise ValueError("quantity must be a positive finite decimal")
        try:
            notional = _as_decimal(self.notional)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("notional must be a non-negative decimal") from exc
        if notional < Decimal("0"):
            raise ValueError("notional cannot be negative")
        if self.action is IntentAction.INCREASE and notional <= Decimal("0"):
            raise ValueError("increase intents require positive notional")
        object.__setattr__(self, "notional", notional)
        if quantity is not None:
            object.__setattr__(self, "quantity", quantity)

    @property
    def fingerprint(self) -> str:
        payload: dict[str, object] = {
            "action": self.action.value,
            "notional": _decimal_text(self.notional),
            "payload_fingerprint": self.payload_fingerprint,
            "scope": self.scope.key,
        }
        if self.strategy_id is not None:
            payload["strategy_id"] = self.strategy_id
            payload["allocation_version"] = self.allocation_version
        if (
            self.instrument is not None
            and self.quantity is not None
            and self.quantity_unit is not None
        ):
            payload["instrument"] = self.instrument
            payload["quantity"] = _decimal_text(self.quantity)
            payload["quantity_unit"] = self.quantity_unit
        if self.notional_unit is not None:
            payload["notional_unit"] = self.notional_unit
        return _sha256(_canonical_json(payload))


@dataclass(frozen=True)
class RiskPermit:
    """An opaque, account-bound admission artifact returned by ``reserve``."""

    permit_id: str
    intent_id: str
    scope: AccountScope
    action: IntentAction
    notional: Decimal
    policy_fingerprint: str
    generation: int
    issued_at: float
    expires_at: float
    strategy_id: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.
    allocation_version: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.
    instrument: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.
    quantity: Optional[Decimal] = None  # noqa: UP045 -- Python 3.9 is supported.
    quantity_unit: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.
    notional_unit: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.


@dataclass(frozen=True)
class StrategyAllocationSnapshot:
    """Immutable local-ledger view of one installed strategy allowance.

    Completeness describes only this risk package's SQLite reservation ledger.
    It is not provider-account, cash, margin, or position-book evidence.
    """

    scope: AccountScope
    strategy_id: str
    revision: str
    allocated_notional: Optional[Decimal]  # noqa: UP045 -- Python 3.9 is supported.
    used_notional: Optional[Decimal]  # noqa: UP045 -- Python 3.9 is supported.
    reserved_notional: Optional[Decimal]  # noqa: UP045 -- Python 3.9 is supported.
    available_notional: Optional[Decimal]  # noqa: UP045 -- Python 3.9 is supported.
    notional_unit: Optional[str]  # noqa: UP045 -- Python 3.9 is supported.
    max_position: Optional[Decimal]  # noqa: UP045 -- Python 3.9 is supported.
    position_instrument: Optional[str]  # noqa: UP045 -- Python 3.9 is supported.
    position_unit: Optional[str]  # noqa: UP045 -- Python 3.9 is supported.
    as_of: float
    source: str = field(default="local_risk_reservation_ledger", init=False)
    completeness: str = "LOCAL_LEDGER_COMPLETE"
    reason: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.


class DispatchTerminalState(str, Enum):
    """Only no-fill terminal outcomes that can release a dispatch latch."""

    REJECTED_NO_FILL = "REJECTED_NO_FILL"
    CANCELED_NO_FILL = "CANCELED_NO_FILL"


class DispatchEvidenceClass(str, Enum):
    """Distinguish local simulation evidence from native provider evidence."""

    SIMULATION_JOURNAL = "SIMULATION_JOURNAL"
    NATIVE_PROVIDER_JOURNAL = "NATIVE_PROVIDER_JOURNAL"


def _validate_dispatch_evidence_class(
    scope: AccountScope, evidence_class: DispatchEvidenceClass
) -> None:
    if type(evidence_class) is not DispatchEvidenceClass:
        raise ValueError("invalid dispatch evidence class")
    simulation_providers = {"fake", "fixture"}
    if evidence_class is DispatchEvidenceClass.SIMULATION_JOURNAL:
        if scope.provider not in simulation_providers:
            raise ValueError(
                "simulation evidence cannot bind a non-simulation provider scope"
            )
    elif scope.provider in simulation_providers:
        raise ValueError("native evidence cannot bind a fake or fixture provider scope")


@dataclass(frozen=True)
class DispatchClaimBinding:
    """Read-only identity of one durable dispatch claim."""

    scope: AccountScope
    permit_id: str
    intent_id: str
    intent_hash: str
    cause_id: str
    claimed_at: float
    claim_digest: str

    def __post_init__(self) -> None:
        if type(self.scope) is not AccountScope:
            raise ValueError("invalid dispatch claim scope")
        for name in ("permit_id", "intent_id", "cause_id"):
            value = getattr(self, name)
            if type(value) is not str or not value or value != value.strip():
                raise ValueError("invalid dispatch claim " + name)
        if self.cause_id != "dispatch-inflight:" + self.intent_id:
            raise ValueError("dispatch claim cause does not match intent")
        _require_sha256(self.intent_hash, "intent_hash")
        _require_sha256(self.claim_digest, "claim_digest")
        if not isinstance(self.claimed_at, (int, float)) or not math.isfinite(
            self.claimed_at
        ):
            raise ValueError("invalid dispatch claim timestamp")


@dataclass(frozen=True)
class DispatchTerminalProof:
    """Immutable journal evidence proposed for one no-fill dispatch resolution.

    Constructing this value does not make it authoritative. The injected
    journal authority must verify its immutable row and hold the account-wide
    writer fence while the risk gate records the one-time resolution.
    """

    scope: AccountScope
    permit_id: str
    intent_id: str
    intent_hash: str
    cause_id: str
    claim_digest: str
    evidence_class: DispatchEvidenceClass
    terminal_state: DispatchTerminalState
    dispatch_attempt_count: int
    journal_revision: int
    journal_record_sha256: str
    reconciliation_evidence_sha256: str
    writer_fence_sha256: str
    filled_quantity: int = 0
    trade_count: int = 0

    def __post_init__(self) -> None:
        if type(self.scope) is not AccountScope:
            raise ValueError("invalid terminal proof scope")
        _validate_dispatch_evidence_class(self.scope, self.evidence_class)
        for name in ("permit_id", "intent_id", "cause_id"):
            value = getattr(self, name)
            if type(value) is not str or not value or value != value.strip():
                raise ValueError("invalid terminal proof " + name)
        if self.cause_id != "dispatch-inflight:" + self.intent_id:
            raise ValueError("terminal proof cause does not match intent")
        for name in (
            "intent_hash",
            "claim_digest",
            "journal_record_sha256",
            "reconciliation_evidence_sha256",
            "writer_fence_sha256",
        ):
            _require_sha256(getattr(self, name), name)
        if type(self.terminal_state) is not DispatchTerminalState:
            raise ValueError(
                "terminal proof must name an allowed no-fill terminal state"
            )
        if (
            type(self.dispatch_attempt_count) is not int
            or self.dispatch_attempt_count != 1
        ):
            raise ValueError(
                "terminal proof must establish exactly one dispatch attempt"
            )
        if type(self.journal_revision) is not int or self.journal_revision <= 0:
            raise ValueError("invalid terminal proof journal revision")
        if type(self.filled_quantity) is not int or self.filled_quantity != 0:
            raise ValueError("terminal proof requires zero filled quantity")
        if type(self.trade_count) is not int or self.trade_count != 0:
            raise ValueError("terminal proof requires zero verified trades")

    @property
    def fingerprint(self) -> str:
        """Stable digest of every immutable terminal-proof field."""
        return _dispatch_resolution_proof_sha256(self)


@dataclass(frozen=True)
class DispatchTrackedOrderProof:
    """Proof that an ACKED order moved into a durable exposure reservation.

    This clears dispatch uncertainty only. The settled risk reservation stays
    counted until a separate reviewed exposure lifecycle can account for later
    fills and terminal order state.
    """

    scope: AccountScope
    permit_id: str
    intent_id: str
    intent_hash: str
    cause_id: str
    claim_digest: str
    evidence_class: DispatchEvidenceClass
    dispatch_attempt_count: int
    journal_revision: int
    journal_record_sha256: str
    reconciliation_evidence_sha256: str
    writer_fence_sha256: str
    provider_order_id: str
    accepted_request_sha256: str
    exposure_reservation_id: str
    exposure_reservation_sha256: str
    filled_quantity: int = 0
    trade_count: int = 0

    def __post_init__(self) -> None:
        if type(self.scope) is not AccountScope:
            raise ValueError("invalid tracked-order proof scope")
        _validate_dispatch_evidence_class(self.scope, self.evidence_class)
        for name in ("permit_id", "intent_id", "cause_id", "provider_order_id"):
            value = getattr(self, name)
            if type(value) is not str or not value or value != value.strip():
                raise ValueError("invalid tracked-order proof " + name)
        if self.cause_id != "dispatch-inflight:" + self.intent_id:
            raise ValueError("tracked-order proof cause does not match intent")
        if (
            type(self.exposure_reservation_id) is not str
            or not self.exposure_reservation_id
            or self.exposure_reservation_id != self.exposure_reservation_id.strip()
        ):
            raise ValueError("invalid tracked-order exposure reservation id")
        for name in (
            "intent_hash",
            "claim_digest",
            "journal_record_sha256",
            "reconciliation_evidence_sha256",
            "writer_fence_sha256",
            "accepted_request_sha256",
            "exposure_reservation_sha256",
        ):
            _require_sha256(getattr(self, name), name)
        if (
            type(self.dispatch_attempt_count) is not int
            or self.dispatch_attempt_count != 1
        ):
            raise ValueError(
                "tracked-order proof must establish exactly one dispatch attempt"
            )
        if type(self.journal_revision) is not int or self.journal_revision <= 0:
            raise ValueError("invalid tracked-order journal revision")
        if type(self.filled_quantity) is not int or self.filled_quantity != 0:
            raise ValueError(
                "tracked-order transfer cannot use synthetic or partial fills"
            )
        if type(self.trade_count) is not int or self.trade_count != 0:
            raise ValueError("tracked-order transfer requires zero verified trades")

    @property
    def fingerprint(self) -> str:
        """Stable digest of every immutable tracked-order proof field."""
        return _dispatch_resolution_proof_sha256(self)


DispatchResolutionProof = Union[DispatchTerminalProof, DispatchTrackedOrderProof]


def _dispatch_resolution_proof_sha256(proof: DispatchResolutionProof) -> str:
    payload: dict[str, object] = {
        "cause_id": proof.cause_id,
        "claim_digest": proof.claim_digest,
        "dispatch_attempt_count": proof.dispatch_attempt_count,
        "evidence_class": proof.evidence_class.value,
        "filled_quantity": proof.filled_quantity,
        "intent_hash": proof.intent_hash,
        "intent_id": proof.intent_id,
        "journal_record_sha256": proof.journal_record_sha256,
        "journal_revision": proof.journal_revision,
        "permit_id": proof.permit_id,
        "reconciliation_evidence_sha256": proof.reconciliation_evidence_sha256,
        "scope_key": proof.scope.key,
        "trade_count": proof.trade_count,
        "writer_fence_sha256": proof.writer_fence_sha256,
    }
    if type(proof) is DispatchTerminalProof:
        payload.update(kind="TERMINAL", terminal_state=proof.terminal_state.value)
    else:
        payload.update(
            kind="ACKED_TRACKED",
            accepted_request_sha256=proof.accepted_request_sha256,
            exposure_reservation_id=proof.exposure_reservation_id,
            exposure_reservation_sha256=proof.exposure_reservation_sha256,
            provider_order_id=proof.provider_order_id,
        )
    return _sha256(_canonical_json(payload))


@dataclass(frozen=True)
class VerifiedDispatchResolution:
    """Typed attestation yielded while the trusted account writer fence is held.

    The risk gate compares this receipt with the exact proof and durable claim.
    It is not a signature and cannot establish journal truth by itself; only the
    injected authority can yield one after verifying its journal and fence.
    """

    scope: AccountScope
    permit_id: str
    intent_id: str
    intent_hash: str
    claim_digest: str
    proof_sha256: str
    journal_revision: int
    journal_record_sha256: str
    writer_fence_sha256: str

    def __post_init__(self) -> None:
        if type(self.scope) is not AccountScope:
            raise ValueError("invalid verified dispatch resolution scope")
        for name in ("permit_id", "intent_id"):
            value = getattr(self, name)
            if type(value) is not str or not value or value != value.strip():
                raise ValueError("invalid verified dispatch resolution " + name)
        for name in (
            "intent_hash",
            "claim_digest",
            "proof_sha256",
            "journal_record_sha256",
            "writer_fence_sha256",
        ):
            _require_sha256(getattr(self, name), name)
        if type(self.journal_revision) is not int or self.journal_revision <= 0:
            raise ValueError("invalid verified dispatch resolution revision")


class VerifiedExecutionJournalAuthority(Protocol):
    """Trusted application authority for a current dispatch resolution row.

    The context manager must verify the exact immutable journal row, prove one
    dispatch attempt and either a zero-fill terminal result or an ACKED order
    transferred to a durable per-order exposure reservation. It must hold the
    external account-wide writer fence for the entire context and reject stale
    or unknown revisions, duplicate attempts, ambiguous native query evidence,
    missing exposure reservations, and any scope mismatch.
    """

    def dispatch_resolution_guard(
        self,
        proof: DispatchResolutionProof,
        *,
        claim: DispatchClaimBinding,
    ) -> AbstractContextManager[
        Optional[VerifiedDispatchResolution]  # noqa: UP045 -- Python 3.9 is supported.
    ]:
        ...


class DurableRiskGate:
    """SQLite-backed account admission gate with fail-closed semantics.

    The gate intentionally has no provider client and never performs network
    I/O.  Callers own the provider dispatch, but must call
    :meth:`validate_permit` immediately before it. The gate does not allow a
    previously issued increase permit to bypass a subsequently raised freeze.
    Dispatch latches can be cleared only through an injected execution-journal
    authority that holds the account writer fence and proves an exact no-fill
    terminal result. No authority is installed by default.
    """

    _ACTIVE = "active"
    _SETTLED = "settled"
    _NO_FILL = "no_fill_terminal"
    _RELEASED = "released"
    _EXPIRED = "expired"

    def __init__(
        self,
        database_path: Union[Path, str],  # noqa: UP007 -- Python 3.9 is supported.
        policy: RiskPolicy,
        clock: Optional[  # noqa: UP045 -- Python 3.9 is supported.
            Callable[[], float]
        ] = None,
        timeout_seconds: float = 5.0,
        *,
        execution_journal_authority: Optional[  # noqa: UP045 -- Python 3.9 is supported.
            VerifiedExecutionJournalAuthority
        ] = None,
    ) -> None:
        self._database_path = Path(database_path)
        self._policy = policy
        self._clock = clock or _wall_clock
        self._timeout_seconds = timeout_seconds
        self._execution_journal_authority = execution_journal_authority
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    @property
    def policy(self) -> RiskPolicy:
        """Return the immutable policy configured for this gate instance."""
        return self._policy

    def set_strategy_allocation(
        self,
        scope: AccountScope,
        strategy_id: str,
        allocation_version: str,
        *,
        max_notional: Optional[  # noqa: UP045 -- Python 3.9 is supported.
            Decimal
        ] = None,
        max_position: Optional[  # noqa: UP045 -- Python 3.9 is supported.
            Decimal
        ] = None,
        position_instrument: Optional[  # noqa: UP045 -- Python 3.9 is supported.
            str
        ] = None,
        position_unit: Optional[str] = None,  # noqa: UP045 -- Python 3.9 is supported.
        notional_unit: Optional[str] = None,  # noqa: UP045 -- Python 3.9 is supported.
    ) -> None:
        """Install one local allocation revision for a strategy in this account.

        This is an administrative storage seam, not an authenticated account
        authority.  A deployment must keep it out of strategy-facing objects
        and bind it to its own reviewed owner.  Versions are immutable and
        cannot be replayed after a later version has replaced them.  Position
        limits are reserved quantity bounds for one exact instrument/unit;
        this gate has no live position book and does not call them holdings.
        """

        if not isinstance(scope, AccountScope):
            raise ValueError("scope must be an AccountScope")
        for name, value in (
            ("strategy_id", strategy_id),
            ("allocation_version", allocation_version),
        ):
            if not isinstance(value, str) or not _ALLOCATION_ID.fullmatch(value):
                raise ValueError("invalid " + name)
        if notional_unit is None and self._policy.notional_unit is not None:
            notional_unit = self._policy.notional_unit

        normalized_notional = None
        if max_notional is not None:
            try:
                normalized_notional = _as_decimal(max_notional)
            except (InvalidOperation, ValueError) as exc:
                raise ValueError(
                    "max_notional must be a non-negative finite decimal"
                ) from exc
            if normalized_notional < Decimal("0"):
                raise ValueError("max_notional must be a non-negative finite decimal")
            if not isinstance(notional_unit, str) or not _NOTIONAL_UNIT.fullmatch(
                notional_unit
            ):
                raise ValueError("max_notional requires a canonical notional_unit")
        elif notional_unit is not None and (
            not isinstance(notional_unit, str)
            or not _NOTIONAL_UNIT.fullmatch(notional_unit)
        ):
            raise ValueError("notional_unit must be a canonical uppercase unit code")
        if (
            self._policy.notional_unit is not None
            and notional_unit != self._policy.notional_unit
        ):
            raise ValueError("allocation notional_unit must match the account policy")
        if normalized_notional is not None and self._policy.notional_unit is None:
            raise ValueError(
                "notional allocation requires a fixed account policy notional_unit"
            )
        if (
            self._policy.require_strategy_allocation
            and self._policy.notional_unit is None
        ):
            raise ValueError("strategy allocation policy needs a notional_unit")

        normalized_position = None
        if max_position is not None:
            try:
                normalized_position = _as_decimal(max_position)
            except (InvalidOperation, ValueError) as exc:
                raise ValueError(
                    "max_position must be a positive finite decimal"
                ) from exc
            if normalized_position <= Decimal("0"):
                raise ValueError("max_position must be a positive finite decimal")
            if not isinstance(
                position_instrument, str
            ) or not _ALLOCATION_INSTRUMENT.fullmatch(position_instrument):
                raise ValueError("max_position requires an exact position_instrument")
            if not isinstance(position_unit, str) or not _ALLOCATION_ID.fullmatch(
                position_unit
            ):
                raise ValueError("max_position requires an exact position_unit")
        elif position_instrument is not None or position_unit is not None:
            raise ValueError("position instrument/unit require max_position")
        if normalized_notional is None and normalized_position is None:
            raise ValueError("an allocation needs at least one supported limit")

        now = self._clock()
        with self._transaction() as connection:
            self._ensure_policy_binding(connection, scope.key)
            current = connection.execute(
                "SELECT * FROM risk_strategy_allocations WHERE scope_key = ? AND strategy_id = ?",
                (scope.key, strategy_id),
            ).fetchone()
            if (
                current is not None
                and current["allocation_version"] == allocation_version
            ):
                same_facts = (
                    current["max_notional"]
                    == (
                        None
                        if normalized_notional is None
                        else _decimal_text(normalized_notional)
                    )
                    and current["max_position"]
                    == (
                        None
                        if normalized_position is None
                        else _decimal_text(normalized_position)
                    )
                    and current["position_instrument"] == position_instrument
                    and current["position_unit"] == position_unit
                    and current["notional_unit"] == notional_unit
                )
                if same_facts:
                    return
                raise ValueError(
                    "allocation version cannot be reused with changed limits"
                )

            prior_version = connection.execute(
                """SELECT 1 FROM risk_strategy_allocation_versions
                   WHERE scope_key = ? AND strategy_id = ? AND allocation_version = ?""",
                (scope.key, strategy_id, allocation_version),
            ).fetchone()
            if prior_version is not None:
                raise ValueError("allocation version cannot be reused")

            unresolved_claim = connection.execute(
                """SELECT 1 FROM risk_reservations AS reservation
                   JOIN risk_dispatch_claims AS claim
                     ON claim.permit_id = reservation.permit_id
                   LEFT JOIN risk_dispatch_resolutions AS resolution
                     ON resolution.permit_id = reservation.permit_id
                   WHERE reservation.scope_key = ? AND reservation.strategy_id = ?
                     AND reservation.status IN (?, ?) AND resolution.permit_id IS NULL
                   LIMIT 1""",
                (scope.key, strategy_id, self._ACTIVE, self._SETTLED),
            ).fetchone()
            if unresolved_claim is not None:
                raise RiskDeniedError(
                    "STRATEGY_ALLOCATION_DISPATCH_IN_FLIGHT",
                    "allocation cannot change while a strategy dispatch is unresolved",
                )

            # When applying a position limit to prior strategy reservations,
            # prove they all used the same quantity unit.  Never add unlike
            # instrument units or silently reset their occupied budget.
            if normalized_position is not None:
                occupied = connection.execute(
                    """SELECT instrument, quantity_unit, quantity FROM risk_reservations
                       WHERE scope_key = ? AND strategy_id = ? AND action = ?
                         AND status IN (?, ?)""",
                    (
                        scope.key,
                        strategy_id,
                        IntentAction.INCREASE.value,
                        self._ACTIVE,
                        self._SETTLED,
                    ),
                ).fetchall()
                for row in occupied:
                    if (
                        row["instrument"] != position_instrument
                        or row["quantity_unit"] != position_unit
                        or row["quantity"] is None
                    ):
                        raise RiskDeniedError(
                            "STRATEGY_POSITION_USAGE_UNAVAILABLE",
                            "existing strategy reservations cannot be valued in this position unit",
                        )

            # Earlier account-only reservations carry no strategy identity, so
            # there is no safe way to decide whether they already consume this
            # strategy's allowance.  Do not silently start the strategy meter
            # at zero while such account exposure is outstanding.
            unallocated_usage = connection.execute(
                """SELECT 1 FROM risk_reservations
                   WHERE scope_key = ? AND strategy_id IS NULL AND action = ?
                     AND status IN (?, ?) LIMIT 1""",
                (scope.key, IntentAction.INCREASE.value, self._ACTIVE, self._SETTLED),
            ).fetchone()
            if unallocated_usage is not None:
                raise RiskDeniedError(
                    "STRATEGY_ALLOCATION_USAGE_UNAVAILABLE",
                    "account has active reservations without a strategy identity",
                )

            connection.execute(
                """INSERT INTO risk_strategy_allocation_versions (
                       scope_key, strategy_id, allocation_version, max_notional,
                       max_position, position_instrument, position_unit, notional_unit, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scope.key,
                    strategy_id,
                    allocation_version,
                    None
                    if normalized_notional is None
                    else _decimal_text(normalized_notional),
                    None
                    if normalized_position is None
                    else _decimal_text(normalized_position),
                    position_instrument,
                    position_unit,
                    notional_unit,
                    now,
                ),
            )
            connection.execute(
                """INSERT INTO risk_strategy_allocations (
                       scope_key, strategy_id, allocation_version, max_notional,
                       max_position, position_instrument, position_unit, notional_unit, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(scope_key, strategy_id) DO UPDATE SET
                       allocation_version = excluded.allocation_version,
                       max_notional = excluded.max_notional,
                       max_position = excluded.max_position,
                       position_instrument = excluded.position_instrument,
                       position_unit = excluded.position_unit,
                       notional_unit = excluded.notional_unit,
                       updated_at = excluded.updated_at""",
                (
                    scope.key,
                    strategy_id,
                    allocation_version,
                    None
                    if normalized_notional is None
                    else _decimal_text(normalized_notional),
                    None
                    if normalized_position is None
                    else _decimal_text(normalized_position),
                    position_instrument,
                    position_unit,
                    notional_unit,
                    now,
                ),
            )

    def get_strategy_allocation(
        self, scope: AccountScope, strategy_id: str
    ) -> StrategyAllocationSnapshot:
        """Read an immutable allowance and local reservation-ledger snapshot.

        Numeric ``available_notional`` is returned only when the strategy
        ceiling, account ceiling, and every active/settled reservation share
        the exact fixed policy unit. This is never cash, margin, or provider
        account availability. The read does not expire reservations or mutate
        allocation/claim state; an expired but still ACTIVE reservation is
        conservatively shown as reserved until a separate write operation
        performs the existing TTL transition.
        """

        if not isinstance(scope, AccountScope):
            raise ValueError("scope must be an AccountScope")
        if not isinstance(strategy_id, str) or not _ALLOCATION_ID.fullmatch(
            strategy_id
        ):
            raise ValueError("invalid strategy_id")
        with self._connection() as connection:
            connection.execute("BEGIN")
            try:
                policy_error = self._policy_binding_read_error(connection, scope.key)
                allocation = connection.execute(
                    """SELECT * FROM risk_strategy_allocations
                   WHERE scope_key = ? AND strategy_id = ?""",
                    (scope.key, strategy_id),
                ).fetchone()
                if allocation is None:
                    raise RiskDeniedError(
                        "STRATEGY_ALLOCATION_UNAVAILABLE",
                        "strategy has no installed allocation",
                    )
                strategy_rows = connection.execute(
                    """SELECT notional, notional_unit, status FROM risk_reservations
                   WHERE scope_key = ? AND strategy_id = ? AND action = ?
                     AND status IN (?, ?)""",
                    (
                        scope.key,
                        strategy_id,
                        IntentAction.INCREASE.value,
                        self._ACTIVE,
                        self._SETTLED,
                    ),
                ).fetchall()
                account_rows = connection.execute(
                    """SELECT notional, notional_unit, status FROM risk_reservations
                   WHERE scope_key = ? AND action = ? AND status IN (?, ?)""",
                    (
                        scope.key,
                        IntentAction.INCREASE.value,
                        self._ACTIVE,
                        self._SETTLED,
                    ),
                ).fetchall()
                as_of = float(self._clock())
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

        policy_unit = self._policy.notional_unit
        allocation_unit = allocation["notional_unit"]
        strategy_units_match = (
            policy_unit is not None
            and allocation_unit == policy_unit
            and all(row["notional_unit"] == policy_unit for row in strategy_rows)
        )
        account_units_match = policy_unit is not None and all(
            row["notional_unit"] == policy_unit for row in account_rows
        )

        used: Optional[Decimal] = None  # noqa: UP045 -- Python 3.9 is supported.
        reserved: Optional[Decimal] = None  # noqa: UP045 -- Python 3.9 is supported.
        account_used: Optional[  # noqa: UP045 -- Python 3.9 is supported.
            Decimal
        ] = None
        account_reserved: Optional[  # noqa: UP045 -- Python 3.9 is supported.
            Decimal
        ] = None
        if strategy_units_match:
            used = _sum_decimal_exact(
                _as_decimal(row["notional"])
                for row in strategy_rows
                if row["status"] == self._SETTLED
            )
            reserved = _sum_decimal_exact(
                _as_decimal(row["notional"])
                for row in strategy_rows
                if row["status"] == self._ACTIVE
            )
        if account_units_match:
            account_used = _sum_decimal_exact(
                _as_decimal(row["notional"])
                for row in account_rows
                if row["status"] == self._SETTLED
            )
            account_reserved = _sum_decimal_exact(
                _as_decimal(row["notional"])
                for row in account_rows
                if row["status"] == self._ACTIVE
            )

        allocated = (
            None
            if allocation["max_notional"] is None
            else _as_decimal(allocation["max_notional"])
        )
        available = None
        reason = None
        if policy_unit is None:
            reason = "NOTIONAL_UNIT_UNBOUND"
        elif policy_error is not None:
            reason = policy_error
        elif allocation_unit != policy_unit:
            reason = "ALLOCATION_NOTIONAL_UNIT_MISMATCH"
        elif not strategy_units_match:
            reason = "STRATEGY_NOTIONAL_USAGE_UNIT_MISMATCH"
        elif not account_units_match:
            reason = "ACCOUNT_NOTIONAL_USAGE_UNIT_MISMATCH"
        elif allocated is None:
            reason = "STRATEGY_NOTIONAL_LIMIT_UNAVAILABLE"
        else:
            assert used is not None and reserved is not None
            assert account_used is not None and account_reserved is not None
            strategy_remaining = max(
                Fraction(0),
                Fraction(allocated) - Fraction(used) - Fraction(reserved),
            )
            account_remaining = max(
                Fraction(0),
                Fraction(self._policy.max_increase_notional)
                - Fraction(account_used)
                - Fraction(account_reserved),
            )
            available = _decimal_from_fraction(
                min(strategy_remaining, account_remaining)
            )

        return StrategyAllocationSnapshot(
            scope=scope,
            strategy_id=strategy_id,
            revision=str(allocation["allocation_version"]),
            allocated_notional=allocated,
            used_notional=used,
            reserved_notional=reserved,
            available_notional=available,
            notional_unit=allocation_unit,
            max_position=(
                None
                if allocation["max_position"] is None
                else _as_decimal(allocation["max_position"])
            ),
            position_instrument=allocation["position_instrument"],
            position_unit=allocation["position_unit"],
            as_of=as_of,
            completeness="LOCAL_LEDGER_COMPLETE"
            if available is not None
            else "LOCAL_LEDGER_INCOMPLETE",
            reason=reason,
        )

    def reserve(self, intent: RiskIntent) -> RiskPermit:
        """Atomically reserve an account-scoped permit for ``intent``.

        Calling this method repeatedly with an identical pending intent is
        idempotent.  Reusing an intent id with another payload, or after it has
        settled/released/expired, is rejected rather than producing a second
        provider dispatch opportunity.
        """
        now = self._clock()
        with self._transaction() as connection:
            self._ensure_policy_binding(connection, intent.scope.key)
            self._expire_active(connection, now)
            existing = connection.execute(
                "SELECT * FROM risk_reservations WHERE intent_id = ?",
                (intent.intent_id,),
            ).fetchone()
            if existing is not None:
                permit = self._existing_permit_or_raise(existing, intent, now)
                self._assert_reservation_allocation_current(connection, existing)
                if permit.action is IntentAction.INCREASE:
                    self._assert_not_frozen(connection, permit.scope)
                return permit

            if intent.action is IntentAction.UNKNOWN_EFFECT:
                raise RiskDeniedError(
                    "UNKNOWN_EFFECT",
                    "intents with unknown effect are not eligible for admission",
                )
            if intent.action is IntentAction.INCREASE:
                self._assert_not_frozen(connection, intent.scope)
                self._assert_intent_notional_unit(intent)
                self._assert_increase_limit(connection, intent)
                self._assert_strategy_allocation_limit(connection, intent)

            generation = self._next_generation(connection, intent.scope.key)
            permit = RiskPermit(
                permit_id=str(uuid.uuid4()),
                intent_id=intent.intent_id,
                scope=intent.scope,
                action=intent.action,
                notional=intent.notional,
                policy_fingerprint=self._policy.fingerprint,
                generation=generation,
                issued_at=now,
                expires_at=now + self._policy.permit_ttl_seconds,
                strategy_id=intent.strategy_id,
                allocation_version=intent.allocation_version,
                instrument=intent.instrument,
                quantity=intent.quantity,
                quantity_unit=intent.quantity_unit,
                notional_unit=intent.notional_unit,
            )
            connection.execute(
                """
                INSERT INTO risk_reservations (
                    permit_id, intent_id, intent_hash, scope_key, provider, account_id, environment,
                    action, notional, policy_hash, generation, issued_at, expires_at, status, reason,
                    strategy_id, allocation_version, instrument, quantity, quantity_unit,
                    notional_unit
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)
                """,
                (
                    permit.permit_id,
                    permit.intent_id,
                    intent.fingerprint,
                    intent.scope.key,
                    intent.scope.provider,
                    intent.scope.account_id,
                    intent.scope.environment,
                    intent.action.value,
                    _decimal_text(intent.notional),
                    permit.policy_fingerprint,
                    permit.generation,
                    permit.issued_at,
                    permit.expires_at,
                    self._ACTIVE,
                    permit.strategy_id,
                    permit.allocation_version,
                    permit.instrument,
                    None if permit.quantity is None else _decimal_text(permit.quantity),
                    permit.quantity_unit,
                    permit.notional_unit,
                ),
            )
            return permit

    def validate_permit(
        self,
        permit_id: str,
        intent: Optional[RiskIntent] = None,  # noqa: UP045 -- Python 3.9 is supported.
    ) -> RiskPermit:
        """Validate a pending permit before dispatch; this is not a dispatch claim.

        Execution still needs its own durable single-use claim. This local
        transaction cannot make risk, intent and outbox writes atomic across
        independently owned connections or databases.
        """
        now = self._clock()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM risk_reservations WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            if row is None:
                raise PermitInvalidError("PERMIT_UNKNOWN", "permit does not exist")
            permit = self._permit_from_row(row)
            if permit.policy_fingerprint != self._policy.fingerprint:
                raise PermitInvalidError(
                    "POLICY_CHANGED", "permit was issued under another policy"
                )
            self._ensure_policy_binding(connection, permit.scope.key)
            self._expire_active(connection, now)
            row = connection.execute(
                "SELECT * FROM risk_reservations WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            assert row is not None
            permit = self._permit_from_row(row)
            if row["status"] != self._ACTIVE:
                raise PermitInvalidError(
                    "PERMIT_NOT_ACTIVE", "permit is no longer active"
                )
            self._assert_reservation_allocation_current(connection, row, invalid=True)
            if intent is not None:
                if intent.intent_id != permit.intent_id or intent.scope != permit.scope:
                    raise PermitInvalidError(
                        "PERMIT_SCOPE_MISMATCH", "permit does not match intent scope"
                    )
                if intent.fingerprint != row["intent_hash"]:
                    raise PermitInvalidError(
                        "PERMIT_INTENT_MISMATCH", "permit does not match intent payload"
                    )
            if permit.action is IntentAction.INCREASE:
                self._assert_not_frozen(connection, permit.scope)
            return permit

    def claim_for_dispatch(self, permit_id: str, intent: RiskIntent) -> RiskPermit:
        """Atomically validate a permit and install its dispatch safety latch.

        ``validate_permit`` is intentionally a read/validation boundary.  It
        cannot prevent two independent processes from both validating an
        opening permit just before one of them installs a freeze.  A provider
        capable composition must instead use this method immediately before
        its dispatch port: one ``BEGIN IMMEDIATE`` transaction validates the
        permit, rejects any already-active account freeze for an increase, and
        persists ``dispatch-inflight:<intent_id>`` before the provider may be
        called.

        A dispatch claim is single-use.  Repeating it is rejected even when
        the arguments match, so callers cannot mistake an idempotent claim
        result for permission to make another provider attempt.  The latch is
        not cleared when a caller later releases a permit: release only proves
        a local admission failure, while an independent reconciliation path
        owns any safety-latch resolution.
        """

        if not isinstance(intent, RiskIntent):
            raise ValueError("intent must be a RiskIntent")
        cause_id = self._dispatch_freeze_cause(intent.intent_id)
        now = self._clock()
        with self._transaction() as connection:
            self._ensure_policy_binding(connection, intent.scope.key)
            self._expire_active(connection, now)
            claim = connection.execute(
                "SELECT intent_id, intent_hash, scope_key, cause_id "
                "FROM risk_dispatch_claims WHERE permit_id = ?",
                (permit_id,),
            ).fetchone()
            if claim is not None:
                if (
                    claim["intent_id"] != intent.intent_id
                    or claim["intent_hash"] != intent.fingerprint
                    or claim["scope_key"] != intent.scope.key
                    or claim["cause_id"] != cause_id
                ):
                    raise PermitInvalidError(
                        "DISPATCH_CLAIM_CONFLICT",
                        "permit is already bound to another dispatch claim",
                    )
                raise PermitInvalidError(
                    "DISPATCH_CLAIM_ALREADY_ISSUED",
                    "a dispatch claim is single-use and cannot authorize a retry",
                )

            permit = self._validate_active_permit(connection, permit_id, intent)

            if permit.action is IntentAction.INCREASE:
                self._assert_not_frozen(connection, permit.scope)
            connection.execute(
                """
                INSERT INTO risk_dispatch_claims (
                    permit_id, intent_id, intent_hash, scope_key, cause_id, claimed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    permit_id,
                    intent.intent_id,
                    intent.fingerprint,
                    intent.scope.key,
                    cause_id,
                    now,
                ),
            )
            self._freeze_in_transaction(
                connection, permit.scope, cause_id, cause_id, now
            )
            return permit

    def dispatch_claim_binding(self, permit_id: str) -> DispatchClaimBinding:
        """Return the exact durable claim identity while its latch is active.

        This read-only value helps an injected journal authority bind its
        evidence to the claim.  It grants no dispatch permission and becomes
        unusable for resolution if the claim, permit, or active latch differs.
        """
        with self._connection() as connection:
            reservation = connection.execute(
                "SELECT * FROM risk_reservations WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            if reservation is None:
                raise PermitInvalidError("PERMIT_UNKNOWN", "permit does not exist")
            policy_error = self._policy_binding_read_error(
                connection, str(reservation["scope_key"])
            )
            if policy_error is not None:
                raise PermitInvalidError(
                    policy_error, "risk database is bound to another or unknown policy"
                )
            claim = self._require_dispatch_claim(connection, reservation)
            return self._dispatch_claim_binding(reservation, claim)

    def settle(self, permit_id: str) -> RiskPermit:
        """Consume a dispatch-claimed permit after its outcome is durably known."""
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM risk_reservations WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            if row is None:
                raise PermitInvalidError("PERMIT_UNKNOWN", "permit does not exist")
            self._ensure_policy_binding(connection, str(row["scope_key"]))
            self._require_dispatch_claim(connection, row)
            if row["status"] != self._ACTIVE:
                raise PermitInvalidError(
                    "PERMIT_NOT_ACTIVE", "only an active permit can settle"
                )
            connection.execute(
                "UPDATE risk_reservations SET status = ? WHERE permit_id = ?",
                (self._SETTLED, permit_id),
            )
            return self._permit_from_row(row)

    def ensure_settled(self, permit_id: str) -> RiskPermit:
        """Atomically prove a dispatch-claimed permit is settled.

        A managed runtime can crash after its execution record becomes known
        but before the separate risk database records ``settled``.  Repeating
        a normal :meth:`settle` would mistake an already-settled permit for a
        failure, while allowing an expired or released permit would hide a
        risk-accounting gap.  This recovery-only primitive accepts exactly an
        active or already settled reservation; every other status remains a
        fail-closed error. It also requires the original active dispatch latch;
        settling the reservation does not clear that latch. This package does
        not yet expose an evidence-bound reconciliation operation.
        """

        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM risk_reservations WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            if row is None:
                raise PermitInvalidError("PERMIT_UNKNOWN", "permit does not exist")
            self._ensure_policy_binding(connection, str(row["scope_key"]))
            self._require_dispatch_claim(connection, row)
            status = str(row["status"])
            if status == self._ACTIVE:
                connection.execute(
                    "UPDATE risk_reservations SET status = ? WHERE permit_id = ?",
                    (self._SETTLED, permit_id),
                )
                return self._permit_from_row(row)
            if status == self._SETTLED:
                return self._permit_from_row(row)
            raise PermitInvalidError(
                "PERMIT_NOT_SETTLEABLE",
                "only an active or settled permit can prove recovery settlement",
            )

    def release(self, permit_id: str, reason: str) -> None:
        """Release a reservation that was proven not to have been dispatched."""
        if not reason.strip():
            raise ValueError("release reason is required")
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT scope_key, status,
                    EXISTS (
                        SELECT 1 FROM risk_dispatch_claims
                        WHERE risk_dispatch_claims.permit_id = risk_reservations.permit_id
                    ) AS dispatch_claimed
                FROM risk_reservations WHERE permit_id = ?
                """,
                (permit_id,),
            ).fetchone()
            if row is None:
                raise PermitInvalidError("PERMIT_UNKNOWN", "permit does not exist")
            self._ensure_policy_binding(connection, str(row["scope_key"]))
            if row["dispatch_claimed"]:
                raise PermitInvalidError(
                    "PERMIT_DISPATCH_CLAIMED",
                    "a dispatch-claimed permit cannot be released",
                )
            if row["status"] != self._ACTIVE:
                raise PermitInvalidError(
                    "PERMIT_NOT_ACTIVE", "only an active permit can release"
                )
            connection.execute(
                "UPDATE risk_reservations SET status = ?, reason = ? WHERE permit_id = ?",
                (self._RELEASED, reason, permit_id),
            )

    def freeze(self, scope: AccountScope, cause_id: str, reason: str) -> None:
        """Persist one independent freeze cause for a scope."""
        if not cause_id.strip() or not reason.strip():
            raise ValueError("freeze cause_id and reason are required")
        if self._is_dispatch_freeze_cause(cause_id):
            raise ValueError(
                "dispatch-inflight freeze causes are reserved for dispatch claims"
            )
        with self._transaction() as connection:
            self._ensure_policy_binding(connection, scope.key)
            self._freeze_in_transaction(
                connection, scope, cause_id, reason, self._clock()
            )

    def resolve_freeze(self, scope: AccountScope, cause_id: str) -> None:
        """Resolve an ordinary freeze; dispatch latches need reconciliation."""
        if self._is_dispatch_freeze_cause(cause_id):
            raise PermitInvalidError(
                "DISPATCH_FREEZE_REQUIRES_RECONCILIATION",
                "a dispatch-inflight freeze cannot be cleared by the generic resolver",
            )
        with self._transaction() as connection:
            self._ensure_policy_binding(connection, scope.key)
            connection.execute(
                """
                UPDATE risk_freezes SET active = 0, updated_at = ?
                WHERE scope_key = ? AND cause_id = ?
                """,
                (self._clock(), scope.key, cause_id),
            )

    def resolve_dispatch_freeze(self, proof: DispatchResolutionProof) -> None:
        """Resolve dispatch uncertainty under a verified execution-journal fence.

        The injected authority must hold its account-wide writer fence while
        this method rechecks the risk claim and commits the one-time proof ID.
        It may attest either a zero-fill terminal rejection/cancellation or an
        ACKED order transferred to a durable exposure reservation. The latter
        clears only the uncertainty latch: the settled permit remains counted.
        Filled/partial callbacks, open orders without tracked exposure, unknown
        or ambiguous evidence are not accepted.
        """
        if type(proof) not in (DispatchTerminalProof, DispatchTrackedOrderProof):
            raise PermitInvalidError(
                "DISPATCH_RESOLUTION_PROOF_REQUIRED",
                "dispatch-latch resolution requires a typed journal proof",
            )
        authority = self._execution_journal_authority
        guard_factory = getattr(authority, "dispatch_resolution_guard", None)
        if not callable(guard_factory):
            raise PermitInvalidError(
                "DISPATCH_RESOLUTION_AUTHORITY_REQUIRED",
                "a verified execution-journal authority is required",
            )

        binding = self._load_dispatch_claim_binding(
            proof.permit_id, proof.journal_record_sha256
        )
        self._assert_dispatch_proof_matches_claim(proof, binding)
        try:
            guard = guard_factory(proof, claim=binding)
            with guard as attestation:
                if type(attestation) is not VerifiedDispatchResolution or not (
                    attestation.scope == binding.scope == proof.scope
                    and attestation.permit_id == binding.permit_id == proof.permit_id
                    and attestation.intent_id == binding.intent_id == proof.intent_id
                    and attestation.intent_hash
                    == binding.intent_hash
                    == proof.intent_hash
                    and attestation.claim_digest
                    == binding.claim_digest
                    == proof.claim_digest
                    and attestation.proof_sha256 == proof.fingerprint
                    and attestation.journal_revision == proof.journal_revision
                    and attestation.journal_record_sha256 == proof.journal_record_sha256
                    and attestation.writer_fence_sha256 == proof.writer_fence_sha256
                ):
                    raise PermitInvalidError(
                        "DISPATCH_RESOLUTION_PROOF_REJECTED",
                        "the journal authority did not attest this exact proof and claim",
                    )
                with self._transaction() as connection:
                    prior = connection.execute(
                        "SELECT permit_id FROM risk_dispatch_resolutions "
                        "WHERE journal_record_sha256 = ?",
                        (proof.journal_record_sha256,),
                    ).fetchone()
                    if prior is not None:
                        raise PermitInvalidError(
                            "DISPATCH_PROOF_REPLAYED",
                            "this immutable journal proof was already consumed",
                        )
                    prior = connection.execute(
                        "SELECT journal_record_sha256 FROM risk_dispatch_resolutions "
                        "WHERE permit_id = ?",
                        (proof.permit_id,),
                    ).fetchone()
                    if prior is not None:
                        raise PermitInvalidError(
                            "DISPATCH_ALREADY_RECONCILED",
                            "this dispatch claim already has a terminal resolution",
                        )
                    reservation = connection.execute(
                        "SELECT * FROM risk_reservations WHERE permit_id = ?",
                        (proof.permit_id,),
                    ).fetchone()
                    if reservation is None:
                        raise PermitInvalidError(
                            "PERMIT_UNKNOWN", "permit does not exist"
                        )
                    self._ensure_policy_binding(
                        connection, str(reservation["scope_key"])
                    )
                    claim = self._require_dispatch_claim(connection, reservation)
                    current_binding = self._dispatch_claim_binding(reservation, claim)
                    self._assert_dispatch_proof_matches_claim(proof, current_binding)
                    if reservation["status"] != self._SETTLED:
                        raise PermitInvalidError(
                            "PERMIT_NOT_SETTLED",
                            "dispatch proof requires a settled reservation",
                        )
                    if type(proof) is DispatchTerminalProof:
                        proof_kind = proof.terminal_state.value
                        provider_order_id = None
                        accepted_request_sha256 = None
                        exposure_reservation_id = None
                        exposure_reservation_sha256 = None
                        filled_quantity = proof.filled_quantity
                        trade_count = proof.trade_count
                    else:
                        proof_kind = "ACKED_TRACKED"
                        provider_order_id = proof.provider_order_id
                        accepted_request_sha256 = proof.accepted_request_sha256
                        exposure_reservation_id = proof.exposure_reservation_id
                        exposure_reservation_sha256 = proof.exposure_reservation_sha256
                        filled_quantity = proof.filled_quantity
                        trade_count = proof.trade_count
                    connection.execute(
                        """
                        INSERT INTO risk_dispatch_resolutions (
                            permit_id, scope_key, intent_id, intent_hash, cause_id,
                            claim_digest, proof_kind, evidence_class,
                            dispatch_attempt_count, journal_revision,
                            journal_record_sha256,
                            reconciliation_evidence_sha256, writer_fence_sha256,
                            provider_order_id, accepted_request_sha256,
                            exposure_reservation_id, exposure_reservation_sha256,
                            filled_quantity, trade_count, resolved_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            proof.permit_id,
                            current_binding.scope.key,
                            proof.intent_id,
                            proof.intent_hash,
                            proof.cause_id,
                            proof.claim_digest,
                            proof_kind,
                            proof.evidence_class.value,
                            proof.dispatch_attempt_count,
                            proof.journal_revision,
                            proof.journal_record_sha256,
                            proof.reconciliation_evidence_sha256,
                            proof.writer_fence_sha256,
                            provider_order_id,
                            accepted_request_sha256,
                            exposure_reservation_id,
                            exposure_reservation_sha256,
                            filled_quantity,
                            trade_count,
                            self._clock(),
                        ),
                    )
                    if type(proof) is DispatchTerminalProof:
                        settled = connection.execute(
                            "UPDATE risk_reservations SET status = ?, reason = ? "
                            "WHERE permit_id = ? AND status = ?",
                            (self._NO_FILL, proof_kind, proof.permit_id, self._SETTLED),
                        )
                        if settled.rowcount != 1:
                            raise PermitInvalidError(
                                "PERMIT_NOT_SETTLED",
                                "no-fill proof did not consume the settled reservation",
                            )
                    result = connection.execute(
                        """
                        UPDATE risk_freezes SET active = 0, updated_at = ?
                        WHERE scope_key = ? AND cause_id = ? AND active = 1
                        """,
                        (self._clock(), current_binding.scope.key, proof.cause_id),
                    )
                    if result.rowcount != 1:
                        raise PermitInvalidError(
                            "DISPATCH_FREEZE_MISSING",
                            "the exact dispatch latch was not active at commit",
                        )
        except PermitInvalidError:
            raise
        except Exception as exc:
            raise PermitInvalidError(
                "DISPATCH_RESOLUTION_PROOF_REJECTED",
                "the execution-journal authority could not verify this proof",
            ) from exc

    def active_freeze_reasons(self, scope: AccountScope) -> list[str]:
        """Return current independent freeze causes for the scope."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT reason FROM risk_freezes WHERE scope_key = ? AND active = 1 ORDER BY cause_id",
                (scope.key,),
            ).fetchall()
        return [str(row["reason"]) for row in rows]

    def snapshot(self, scope: AccountScope) -> dict[str, object]:
        """Return a local, provider-free view of outstanding reservations."""
        now = self._clock()
        with self._transaction() as connection:
            self._ensure_policy_binding(connection, scope.key)
            self._expire_active(connection, now)
            rows = connection.execute(
                """
                SELECT action, status, notional FROM risk_reservations
                WHERE scope_key = ? AND status IN (?, ?)
                """,
                (scope.key, self._ACTIVE, self._SETTLED),
            ).fetchall()
            increase_rows = [
                row for row in rows if row["action"] == IntentAction.INCREASE.value
            ]
            return {
                "active_freeze_reasons": self._freeze_reasons(connection, scope),
                "increase_count": len(increase_rows),
                "increase_notional": _sum_decimal_exact(
                    _as_decimal(row["notional"]) for row in increase_rows
                ),
                "policy_fingerprint": self._policy.fingerprint,
            }

    def close(self) -> None:
        """Provide a symmetry hook; connections are per-operation and already closed."""

    def _existing_permit_or_raise(
        self, row: sqlite3.Row, intent: RiskIntent, now: float
    ) -> RiskPermit:
        if row["intent_hash"] != intent.fingerprint:
            raise RiskDeniedError(
                "INTENT_ID_REUSED", "intent id was reused with another payload"
            )
        if row["status"] != self._ACTIVE:
            raise RiskDeniedError("INTENT_NOT_REUSABLE", "intent was already finalized")
        permit = self._permit_from_row(row)
        if permit.expires_at <= now:
            raise RiskDeniedError("INTENT_EXPIRED", "intent permit has expired")
        if permit.policy_fingerprint != self._policy.fingerprint:
            raise RiskDeniedError(
                "POLICY_CHANGED", "intent was admitted by another policy"
            )
        return permit

    def _assert_increase_limit(
        self, connection: sqlite3.Connection, intent: RiskIntent
    ) -> None:
        rows = connection.execute(
            """
            SELECT notional, notional_unit FROM risk_reservations
            WHERE scope_key = ? AND action = ? AND status IN (?, ?)
            """,
            (
                intent.scope.key,
                IntentAction.INCREASE.value,
                self._ACTIVE,
                self._SETTLED,
            ),
        ).fetchall()
        if self._policy.notional_unit is not None and any(
            row["notional_unit"] != self._policy.notional_unit for row in rows
        ):
            raise RiskDeniedError(
                "NOTIONAL_UNIT_USAGE_UNAVAILABLE",
                "existing account reservations do not use the fixed policy unit",
            )
        reserved_notional = sum(
            (Fraction(_as_decimal(row["notional"])) for row in rows), Fraction(0)
        )
        if len(rows) >= self._policy.max_increase_count:
            raise RiskDeniedError(
                "ACCOUNT_LIMIT_EXHAUSTED",
                "account increase reservation count limit reached",
            )
        if reserved_notional + Fraction(intent.notional) > Fraction(
            self._policy.max_increase_notional
        ):
            raise RiskDeniedError(
                "ACCOUNT_LIMIT_EXHAUSTED", "account increase notional limit exceeded"
            )

    def _policy_binding_facts(self) -> tuple[object, ...]:
        """Return every policy fact that changes the meaning of one scope ledger."""

        return (
            self._policy.fingerprint,
            self._policy.policy_id,
            _decimal_text(self._policy.max_increase_notional),
            self._policy.max_increase_count,
            format(float(self._policy.permit_ttl_seconds), ".17g"),
            int(self._policy.require_strategy_allocation),
            self._policy.notional_unit,
        )

    def _policy_binding_read_error(
        self, connection: sqlite3.Connection, scope_key: str
    ) -> Optional[str]:  # noqa: UP045 -- Python 3.9 is supported.
        """Check a policy binding without creating or modifying one."""

        facts = self._policy_binding_facts()
        row = connection.execute(
            "SELECT * FROM risk_policy_bindings WHERE scope_key = ?", (scope_key,)
        ).fetchone()
        if row is not None:
            stored = (
                row["policy_hash"],
                row["policy_id"],
                row["max_increase_notional"],
                row["max_increase_count"],
                row["permit_ttl_seconds"],
                row["require_strategy_allocation"],
                row["notional_unit"],
            )
            return None if stored == facts else "RISK_POLICY_BINDING_MISMATCH"

        historical = connection.execute(
            "SELECT DISTINCT policy_hash FROM risk_reservations WHERE scope_key = ?",
            (scope_key,),
        ).fetchall()
        hashes = {str(item["policy_hash"]) for item in historical}
        if len(hashes) > 1:
            return "RISK_POLICY_BINDING_UNAVAILABLE"
        if hashes:
            return (
                None
                if next(iter(hashes)) == self._policy.fingerprint
                else "RISK_POLICY_BINDING_MISMATCH"
            )
        has_allocation = connection.execute(
            "SELECT 1 FROM risk_strategy_allocations WHERE scope_key = ? LIMIT 1",
            (scope_key,),
        ).fetchone()
        if has_allocation is not None:
            return "RISK_POLICY_BINDING_UNAVAILABLE"
        return "RISK_POLICY_BINDING_UNAVAILABLE"

    def _ensure_policy_binding(
        self, connection: sqlite3.Connection, scope_key: str
    ) -> None:
        """Persist or enforce the immutable policy selected for an account ledger.

        This is called only while ``BEGIN IMMEDIATE`` is held. Existing history
        is never interpreted under a different policy, and there is deliberately
        no in-place rotation or permissive-policy selection path.
        """

        facts = self._policy_binding_facts()
        row = connection.execute(
            "SELECT * FROM risk_policy_bindings WHERE scope_key = ?", (scope_key,)
        ).fetchone()
        if row is not None:
            stored = (
                row["policy_hash"],
                row["policy_id"],
                row["max_increase_notional"],
                row["max_increase_count"],
                row["permit_ttl_seconds"],
                row["require_strategy_allocation"],
                row["notional_unit"],
            )
            if stored != facts:
                raise RiskDeniedError(
                    "RISK_POLICY_BINDING_MISMATCH",
                    "account ledger is bound to another immutable risk policy",
                )
            return

        historical = connection.execute(
            "SELECT DISTINCT policy_hash FROM risk_reservations WHERE scope_key = ?",
            (scope_key,),
        ).fetchall()
        hashes = {str(item["policy_hash"]) for item in historical}
        if len(hashes) > 1:
            raise RiskDeniedError(
                "RISK_POLICY_BINDING_UNAVAILABLE",
                "legacy account ledger contains conflicting policy fingerprints",
            )
        if hashes and next(iter(hashes)) != self._policy.fingerprint:
            raise RiskDeniedError(
                "RISK_POLICY_BINDING_MISMATCH",
                "legacy account ledger was created under another risk policy",
            )
        has_allocation = connection.execute(
            "SELECT 1 FROM risk_strategy_allocations WHERE scope_key = ? LIMIT 1",
            (scope_key,),
        ).fetchone()
        if has_allocation is not None and not hashes:
            raise RiskDeniedError(
                "RISK_POLICY_BINDING_UNAVAILABLE",
                "legacy strategy allocation has no policy history to verify",
            )

        connection.execute(
            """INSERT INTO risk_policy_bindings (
                   scope_key, policy_hash, policy_id, max_increase_notional,
                   max_increase_count, permit_ttl_seconds,
                   require_strategy_allocation, notional_unit, updated_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scope_key,
                *facts,
                float(self._clock()),
            ),
        )

    def _assert_intent_notional_unit(self, intent: RiskIntent) -> None:
        """Require one policy-owned denomination before summing notional amounts."""

        if self._policy.notional_unit is None:
            if (
                self._policy.require_strategy_allocation
                or intent.notional_unit is not None
            ):
                raise RiskDeniedError(
                    "NOTIONAL_UNIT_UNBOUND", "account policy has no fixed notional unit"
                )
            return
        if intent.notional_unit != self._policy.notional_unit:
            raise RiskDeniedError(
                "NOTIONAL_UNIT_MISMATCH",
                "intent notional unit does not match the account policy",
            )

    def _assert_strategy_allocation_limit(
        self, connection: sqlite3.Connection, intent: RiskIntent
    ) -> None:
        """Apply the current strategy allowance inside the reservation transaction."""

        if intent.action is not IntentAction.INCREASE:
            return
        if intent.strategy_id is None:
            if self._policy.require_strategy_allocation:
                raise RiskDeniedError(
                    "STRATEGY_ALLOCATION_REQUIRED",
                    "risk-increasing intent has no strategy allocation identity",
                )
            return

        allocation = connection.execute(
            """SELECT * FROM risk_strategy_allocations
               WHERE scope_key = ? AND strategy_id = ?""",
            (intent.scope.key, intent.strategy_id),
        ).fetchone()
        if allocation is None:
            raise RiskDeniedError(
                "STRATEGY_ALLOCATION_REQUIRED", "strategy has no installed allocation"
            )
        if allocation["allocation_version"] != intent.allocation_version:
            raise RiskDeniedError(
                "STRATEGY_ALLOCATION_VERSION_CHANGED",
                "intent does not use the current strategy allocation version",
            )
        if self._policy.require_strategy_allocation and (
            self._policy.notional_unit is None
            or allocation["notional_unit"] != self._policy.notional_unit
            or intent.notional_unit != self._policy.notional_unit
        ):
            raise RiskDeniedError(
                "NOTIONAL_UNIT_MISMATCH",
                "strategy allocation, intent, and account policy must share one fixed notional unit",
            )
        if allocation["max_notional"] is not None and (
            allocation["notional_unit"] != self._policy.notional_unit
            or intent.notional_unit != allocation["notional_unit"]
        ):
            raise RiskDeniedError(
                "NOTIONAL_UNIT_MISMATCH",
                "strategy allocation and intent notional units do not match",
            )

        if allocation["max_notional"] is not None:
            rows = connection.execute(
                """SELECT notional FROM risk_reservations
                   WHERE scope_key = ? AND strategy_id = ? AND action = ?
                     AND status IN (?, ?)""",
                (
                    intent.scope.key,
                    intent.strategy_id,
                    IntentAction.INCREASE.value,
                    self._ACTIVE,
                    self._SETTLED,
                ),
            ).fetchall()
            used_notional = sum(
                (Fraction(_as_decimal(row["notional"])) for row in rows), Fraction(0)
            )
            cap = Fraction(_as_decimal(allocation["max_notional"]))
            if used_notional + Fraction(intent.notional) > cap:
                raise RiskDeniedError(
                    "STRATEGY_ALLOCATION_EXHAUSTED",
                    "strategy increase notional allocation is exhausted",
                )

        if allocation["max_position"] is not None:
            if (
                intent.instrument != allocation["position_instrument"]
                or intent.quantity_unit != allocation["position_unit"]
                or intent.quantity is None
            ):
                raise RiskDeniedError(
                    "STRATEGY_POSITION_SCOPE_MISMATCH",
                    "intent quantity is not expressed in the allocation's exact instrument unit",
                )
            rows = connection.execute(
                """SELECT instrument, quantity_unit, quantity FROM risk_reservations
                   WHERE scope_key = ? AND strategy_id = ? AND action = ?
                     AND status IN (?, ?)""",
                (
                    intent.scope.key,
                    intent.strategy_id,
                    IntentAction.INCREASE.value,
                    self._ACTIVE,
                    self._SETTLED,
                ),
            ).fetchall()
            used_quantity = Fraction(0)
            for row in rows:
                if (
                    row["instrument"] != allocation["position_instrument"]
                    or row["quantity_unit"] != allocation["position_unit"]
                    or row["quantity"] is None
                ):
                    raise RiskDeniedError(
                        "STRATEGY_POSITION_USAGE_UNAVAILABLE",
                        "strategy reservations cannot be summed in one exact instrument unit",
                    )
                used_quantity += Fraction(_as_decimal(row["quantity"]))
            if used_quantity + Fraction(intent.quantity) > Fraction(
                _as_decimal(allocation["max_position"])
            ):
                raise RiskDeniedError(
                    "STRATEGY_ALLOCATION_EXHAUSTED",
                    "strategy reserved quantity allocation is exhausted",
                )

    def _assert_reservation_allocation_current(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        invalid: bool = False,
    ) -> None:
        """Reject a previously issued permit after its allocation revision changes."""

        strategy_id = row["strategy_id"]
        version = row["allocation_version"]
        if strategy_id is None:
            if (
                self._policy.require_strategy_allocation
                and row["action"] == IntentAction.INCREASE.value
            ):
                raise PermitInvalidError(
                    "STRATEGY_ALLOCATION_REQUIRED",
                    "permit has no strategy allocation identity",
                )
            return
        allocation = connection.execute(
            """SELECT allocation_version FROM risk_strategy_allocations
               WHERE scope_key = ? AND strategy_id = ?""",
            (row["scope_key"], strategy_id),
        ).fetchone()
        if allocation is not None and allocation["allocation_version"] == version:
            return
        error = PermitInvalidError if invalid else RiskDeniedError
        code = (
            "STRATEGY_ALLOCATION_VERSION_CHANGED"
            if allocation is not None
            else "STRATEGY_ALLOCATION_UNAVAILABLE"
        )
        raise error(code, "permit allocation version is no longer current")

    def _assert_not_frozen(
        self, connection: sqlite3.Connection, scope: AccountScope
    ) -> None:
        reasons = self._freeze_reasons(connection, scope)
        if reasons:
            raise RiskDeniedError(
                "FROZEN",
                "new risk-increasing intents are frozen: " + "; ".join(reasons),
            )

    def _validate_active_permit(
        self,
        connection: sqlite3.Connection,
        permit_id: str,
        intent: RiskIntent,
    ) -> RiskPermit:
        """Validate immutable permit binding while an admission transaction is held."""

        row = connection.execute(
            "SELECT * FROM risk_reservations WHERE permit_id = ?", (permit_id,)
        ).fetchone()
        if row is None:
            raise PermitInvalidError("PERMIT_UNKNOWN", "permit does not exist")
        permit = self._permit_from_row(row)
        if row["status"] != self._ACTIVE:
            raise PermitInvalidError("PERMIT_NOT_ACTIVE", "permit is no longer active")
        if permit.policy_fingerprint != self._policy.fingerprint:
            raise PermitInvalidError(
                "POLICY_CHANGED", "permit was issued under another policy"
            )
        self._ensure_policy_binding(connection, permit.scope.key)
        self._assert_reservation_allocation_current(connection, row, invalid=True)
        if intent.intent_id != permit.intent_id or intent.scope != permit.scope:
            raise PermitInvalidError(
                "PERMIT_SCOPE_MISMATCH", "permit does not match intent scope"
            )
        if intent.fingerprint != row["intent_hash"]:
            raise PermitInvalidError(
                "PERMIT_INTENT_MISMATCH", "permit does not match intent payload"
            )
        return permit

    @staticmethod
    def _dispatch_freeze_cause(intent_id: str) -> str:
        return "dispatch-inflight:" + intent_id

    @staticmethod
    def _dispatch_claim_digest(
        *,
        permit_id: str,
        intent_id: str,
        intent_hash: str,
        scope_key: str,
        cause_id: str,
        claimed_at: float,
    ) -> str:
        return _sha256(
            _canonical_json(
                {
                    "cause_id": cause_id,
                    "claimed_at": format(float(claimed_at), ".17g"),
                    "intent_hash": intent_hash,
                    "intent_id": intent_id,
                    "permit_id": permit_id,
                    "scope_key": scope_key,
                    "schema": "bt-api-risk-dispatch-claim-v1",
                }
            )
        )

    @staticmethod
    def _is_dispatch_freeze_cause(cause_id: str) -> bool:
        return isinstance(cause_id, str) and cause_id.startswith("dispatch-inflight:")

    def _require_dispatch_claim(
        self, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> sqlite3.Row:
        """Require the exact durable claim and still-active safety latch."""
        claim = connection.execute(
            "SELECT * FROM risk_dispatch_claims WHERE permit_id = ?",
            (row["permit_id"],),
        ).fetchone()
        expected_cause = self._dispatch_freeze_cause(str(row["intent_id"]))
        if (
            claim is None
            or claim["intent_id"] != row["intent_id"]
            or claim["intent_hash"] != row["intent_hash"]
            or claim["scope_key"] != row["scope_key"]
            or claim["cause_id"] != expected_cause
        ):
            raise PermitInvalidError(
                "PERMIT_NOT_DISPATCH_CLAIMED",
                "settlement requires the exact durable dispatch claim",
            )
        freeze = connection.execute(
            "SELECT active FROM risk_freezes WHERE scope_key = ? AND cause_id = ?",
            (row["scope_key"], expected_cause),
        ).fetchone()
        if freeze is None or freeze["active"] != 1:
            raise PermitInvalidError(
                "DISPATCH_FREEZE_MISSING",
                "the dispatch claim is missing its active safety latch",
            )
        return claim

    def _dispatch_claim_binding(
        self, reservation: sqlite3.Row, claim: sqlite3.Row
    ) -> DispatchClaimBinding:
        scope = AccountScope(
            provider=str(reservation["provider"]),
            account_id=str(reservation["account_id"]),
            environment=str(reservation["environment"]),
        )
        claimed_at = float(claim["claimed_at"])
        return DispatchClaimBinding(
            scope=scope,
            permit_id=str(reservation["permit_id"]),
            intent_id=str(reservation["intent_id"]),
            intent_hash=str(reservation["intent_hash"]),
            cause_id=str(claim["cause_id"]),
            claimed_at=claimed_at,
            claim_digest=self._dispatch_claim_digest(
                permit_id=str(reservation["permit_id"]),
                intent_id=str(reservation["intent_id"]),
                intent_hash=str(reservation["intent_hash"]),
                scope_key=str(reservation["scope_key"]),
                cause_id=str(claim["cause_id"]),
                claimed_at=claimed_at,
            ),
        )

    def _load_dispatch_claim_binding(
        self, permit_id: str, journal_record_sha256: str
    ) -> DispatchClaimBinding:
        with self._connection() as connection:
            prior_proof = connection.execute(
                "SELECT permit_id FROM risk_dispatch_resolutions WHERE journal_record_sha256 = ?",
                (journal_record_sha256,),
            ).fetchone()
            if prior_proof is not None:
                raise PermitInvalidError(
                    "DISPATCH_PROOF_REPLAYED",
                    "this immutable journal proof was already consumed",
                )
            reservation = connection.execute(
                "SELECT * FROM risk_reservations WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            if reservation is None:
                raise PermitInvalidError("PERMIT_UNKNOWN", "permit does not exist")
            policy_error = self._policy_binding_read_error(
                connection, str(reservation["scope_key"])
            )
            if policy_error is not None:
                raise PermitInvalidError(
                    policy_error, "risk database is bound to another or unknown policy"
                )
            claim = connection.execute(
                "SELECT * FROM risk_dispatch_claims WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            if claim is None:
                raise PermitInvalidError(
                    "PERMIT_NOT_DISPATCH_CLAIMED",
                    "dispatch resolution requires a durable dispatch claim",
                )
            expected_cause = self._dispatch_freeze_cause(str(reservation["intent_id"]))
            if (
                claim["intent_id"] != reservation["intent_id"]
                or claim["intent_hash"] != reservation["intent_hash"]
                or claim["scope_key"] != reservation["scope_key"]
                or claim["cause_id"] != expected_cause
            ):
                raise PermitInvalidError(
                    "DISPATCH_CLAIM_CONFLICT",
                    "the durable dispatch claim no longer matches its reservation",
                )
            prior = connection.execute(
                "SELECT journal_record_sha256 FROM risk_dispatch_resolutions WHERE permit_id = ?",
                (permit_id,),
            ).fetchone()
            if prior is not None:
                raise PermitInvalidError(
                    "DISPATCH_ALREADY_RECONCILED",
                    "this dispatch claim already has a terminal resolution",
                )
            freeze = connection.execute(
                "SELECT active FROM risk_freezes WHERE scope_key = ? AND cause_id = ?",
                (reservation["scope_key"], expected_cause),
            ).fetchone()
            if freeze is None or freeze["active"] != 1:
                raise PermitInvalidError(
                    "DISPATCH_FREEZE_MISSING",
                    "the exact dispatch latch is not active",
                )
            if reservation["status"] != self._SETTLED:
                raise PermitInvalidError(
                    "PERMIT_NOT_SETTLED",
                    "dispatch proof requires a settled reservation",
                )
            return self._dispatch_claim_binding(reservation, claim)

    @staticmethod
    def _assert_dispatch_proof_matches_claim(
        proof: DispatchResolutionProof, claim: DispatchClaimBinding
    ) -> None:
        if (
            proof.scope != claim.scope
            or proof.permit_id != claim.permit_id
            or proof.intent_id != claim.intent_id
            or proof.intent_hash != claim.intent_hash
            or proof.cause_id != claim.cause_id
            or proof.claim_digest != claim.claim_digest
        ):
            raise PermitInvalidError(
                "DISPATCH_RESOLUTION_PROOF_SCOPE_MISMATCH",
                "dispatch proof does not match the exact account, intent, permit and claim",
            )

    @staticmethod
    def _freeze_in_transaction(
        connection: sqlite3.Connection,
        scope: AccountScope,
        cause_id: str,
        reason: str,
        updated_at: float,
    ) -> None:
        connection.execute(
            """
            INSERT INTO risk_freezes (scope_key, cause_id, reason, active, updated_at)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(scope_key, cause_id) DO UPDATE SET
                reason = excluded.reason, active = 1, updated_at = excluded.updated_at
            """,
            (scope.key, cause_id, reason, updated_at),
        )

    def _freeze_reasons(
        self, connection: sqlite3.Connection, scope: AccountScope
    ) -> list[str]:
        rows = connection.execute(
            "SELECT reason FROM risk_freezes WHERE scope_key = ? AND active = 1 ORDER BY cause_id",
            (scope.key,),
        ).fetchall()
        return [str(row["reason"]) for row in rows]

    def _next_generation(self, connection: sqlite3.Connection, scope_key: str) -> int:
        row = connection.execute(
            "SELECT generation FROM risk_generations WHERE scope_key = ?", (scope_key,)
        ).fetchone()
        generation = int(row["generation"]) + 1 if row is not None else 1
        connection.execute(
            """
            INSERT INTO risk_generations (scope_key, generation) VALUES (?, ?)
            ON CONFLICT(scope_key) DO UPDATE SET generation = excluded.generation
            """,
            (scope_key, generation),
        )
        return generation

    def _expire_active(self, connection: sqlite3.Connection, now: float) -> None:
        # A provider-capable managed path has persisted a dispatch claim before
        # it can call the provider.  That claim is evidence of possible market
        # exposure, so TTL must never erase its reservation from account risk
        # accounting.  It stays active until a known result is settled or an
        # explicit audited reconciliation path deals with it.
        connection.execute(
            """
            UPDATE risk_reservations SET status = ?, reason = ?
            WHERE status = ? AND expires_at <= ?
              AND NOT EXISTS (
                  SELECT 1 FROM risk_dispatch_claims
                  WHERE risk_dispatch_claims.permit_id = risk_reservations.permit_id
              )
            """,
            (self._EXPIRED, "permit_ttl_elapsed", self._ACTIVE, now),
        )

    def _permit_from_row(self, row: sqlite3.Row) -> RiskPermit:
        return RiskPermit(
            permit_id=str(row["permit_id"]),
            intent_id=str(row["intent_id"]),
            scope=AccountScope(
                provider=str(row["provider"]),
                account_id=str(row["account_id"]),
                environment=str(row["environment"]),
            ),
            action=IntentAction(str(row["action"])),
            notional=_as_decimal(row["notional"]),
            policy_fingerprint=str(row["policy_hash"]),
            generation=int(row["generation"]),
            issued_at=float(row["issued_at"]),
            expires_at=float(row["expires_at"]),
            strategy_id=row["strategy_id"],
            allocation_version=row["allocation_version"],
            instrument=row["instrument"],
            quantity=None if row["quantity"] is None else _as_decimal(row["quantity"]),
            quantity_unit=row["quantity_unit"],
            notional_unit=row["notional_unit"],
        )

    def _initialize_schema(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS risk_reservations (
                    permit_id TEXT PRIMARY KEY,
                    intent_id TEXT NOT NULL UNIQUE,
                    intent_hash TEXT NOT NULL,
                    scope_key TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    action TEXT NOT NULL,
                    notional TEXT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT,
                    strategy_id TEXT,
                    allocation_version TEXT,
                    instrument TEXT,
                    quantity TEXT,
                    quantity_unit TEXT,
                    notional_unit TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_risk_reservations_scope_status
                    ON risk_reservations(scope_key, status, action);
                CREATE TABLE IF NOT EXISTS risk_freezes (
                    scope_key TEXT NOT NULL,
                    cause_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(scope_key, cause_id)
                );
                CREATE TABLE IF NOT EXISTS risk_dispatch_claims (
                    permit_id TEXT PRIMARY KEY,
                    intent_id TEXT NOT NULL,
                    intent_hash TEXT NOT NULL,
                    scope_key TEXT NOT NULL,
                    cause_id TEXT NOT NULL,
                    claimed_at REAL NOT NULL,
                    FOREIGN KEY(permit_id) REFERENCES risk_reservations(permit_id)
                );
                CREATE INDEX IF NOT EXISTS idx_risk_dispatch_claims_scope
                    ON risk_dispatch_claims(scope_key, intent_id);
                CREATE TABLE IF NOT EXISTS risk_dispatch_resolutions (
                    permit_id TEXT PRIMARY KEY,
                    scope_key TEXT NOT NULL,
                    intent_id TEXT NOT NULL,
                    intent_hash TEXT NOT NULL,
                    cause_id TEXT NOT NULL,
                    claim_digest TEXT NOT NULL,
                    proof_kind TEXT NOT NULL,
                    evidence_class TEXT NOT NULL,
                    dispatch_attempt_count INTEGER NOT NULL,
                    journal_revision INTEGER NOT NULL,
                    journal_record_sha256 TEXT NOT NULL UNIQUE,
                    reconciliation_evidence_sha256 TEXT NOT NULL,
                    writer_fence_sha256 TEXT NOT NULL,
                    provider_order_id TEXT,
                    accepted_request_sha256 TEXT,
                    exposure_reservation_id TEXT,
                    exposure_reservation_sha256 TEXT,
                    filled_quantity INTEGER NOT NULL,
                    trade_count INTEGER NOT NULL,
                    resolved_at REAL NOT NULL,
                    FOREIGN KEY(permit_id) REFERENCES risk_reservations(permit_id)
                );
                CREATE TABLE IF NOT EXISTS risk_generations (
                    scope_key TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS risk_policy_bindings (
                    scope_key TEXT PRIMARY KEY,
                    policy_hash TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    max_increase_notional TEXT NOT NULL,
                    max_increase_count INTEGER NOT NULL,
                    permit_ttl_seconds TEXT NOT NULL,
                    require_strategy_allocation INTEGER NOT NULL,
                    notional_unit TEXT,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS risk_strategy_allocations (
                    scope_key TEXT NOT NULL,
                    strategy_id TEXT NOT NULL,
                    allocation_version TEXT NOT NULL,
                    max_notional TEXT,
                    max_position TEXT,
                    position_instrument TEXT,
                    position_unit TEXT,
                    notional_unit TEXT,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(scope_key, strategy_id)
                );
                CREATE TABLE IF NOT EXISTS risk_strategy_allocation_versions (
                    scope_key TEXT NOT NULL,
                    strategy_id TEXT NOT NULL,
                    allocation_version TEXT NOT NULL,
                    max_notional TEXT,
                    max_position TEXT,
                    position_instrument TEXT,
                    position_unit TEXT,
                    notional_unit TEXT,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(scope_key, strategy_id, allocation_version)
                );
                """
            )
            reservation_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(risk_reservations)"
                ).fetchall()
            }
            for name, column_type in (
                ("strategy_id", "TEXT"),
                ("allocation_version", "TEXT"),
                ("instrument", "TEXT"),
                ("quantity", "TEXT"),
                ("quantity_unit", "TEXT"),
                ("notional_unit", "TEXT"),
            ):
                if name not in reservation_columns:
                    connection.execute(
                        "ALTER TABLE risk_reservations ADD COLUMN "
                        + name
                        + " "
                        + column_type
                    )
            for table in (
                "risk_strategy_allocations",
                "risk_strategy_allocation_versions",
            ):
                allocation_columns = {
                    str(row["name"])
                    for row in connection.execute(
                        "PRAGMA table_info(" + table + ")"
                    ).fetchall()
                }
                if "notional_unit" not in allocation_columns:
                    connection.execute(
                        "ALTER TABLE " + table + " ADD COLUMN notional_unit TEXT"
                    )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_risk_reservations_strategy_status
                   ON risk_reservations(scope_key, strategy_id, status, action)"""
            )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            str(self._database_path),
            timeout=self._timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            # SQLite foreign-key enforcement is connection-local.
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")


def _as_decimal(value: object) -> Decimal:
    if isinstance(value, bool):
        raise ValueError("boolean is not a decimal amount")
    result = value if isinstance(value, Decimal) else Decimal(str(value))
    if not result.is_finite():
        raise ValueError("decimal amount must be finite")
    return result


def _sum_decimal_exact(values: Iterator[Decimal]) -> Decimal:
    """Sum finite Decimal values without the ambient context precision."""

    return _decimal_from_fraction(
        sum((Fraction(value) for value in values), Fraction(0))
    )


def _decimal_from_fraction(value: Fraction) -> Decimal:
    """Convert a terminating rational to Decimal exactly and context-free."""

    numerator = value.numerator
    denominator = value.denominator
    twos = 0
    fives = 0
    while denominator % 2 == 0:
        twos += 1
        denominator //= 2
    while denominator % 5 == 0:
        fives += 1
        denominator //= 5
    if denominator != 1:
        raise ValueError("risk ledger arithmetic did not produce a finite decimal")
    places = max(twos, fives)
    scaled = abs(numerator) * (2 ** (places - twos)) * (5 ** (places - fives))
    digits = tuple(int(character) for character in str(scaled))
    sign = 1 if numerator < 0 else 0
    return Decimal((sign, digits, -places))


def _decimal_text(value: Decimal) -> str:
    return format(value, "f")


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _wall_clock() -> float:
    import time

    return time.time()


__all__ = [
    "AccountScope",
    "DurableRiskGate",
    "IntentAction",
    "PermitInvalidError",
    "RiskDeniedError",
    "RiskGateError",
    "RiskIntent",
    "RiskPermit",
    "RiskPolicy",
]
