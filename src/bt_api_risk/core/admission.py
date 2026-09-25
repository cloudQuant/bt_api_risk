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
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, Union


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
        if not self.provider.strip() or not self.account_id.strip() or not self.environment.strip():
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

    def __post_init__(self) -> None:
        try:
            limit = _as_decimal(self.max_increase_notional)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("max_increase_notional must be a non-negative decimal") from exc
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
        object.__setattr__(self, "max_increase_notional", limit)

    @property
    def fingerprint(self) -> str:
        return _sha256(
            _canonical_json(
                {
                    "max_increase_count": self.max_increase_count,
                    "max_increase_notional": _decimal_text(self.max_increase_notional),
                    "permit_ttl_seconds": self.permit_ttl_seconds,
                    "policy_id": self.policy_id,
                }
            )
        )


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

    def __post_init__(self) -> None:
        if not self.intent_id.strip():
            raise ValueError("intent_id is required")
        if not isinstance(self.action, IntentAction):
            raise ValueError("action must be an IntentAction")
        if not isinstance(self.scope, AccountScope):
            raise ValueError("scope must be an AccountScope")
        if not isinstance(self.payload_fingerprint, str):
            raise ValueError("payload_fingerprint must be an immutable string")
        try:
            notional = _as_decimal(self.notional)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("notional must be a non-negative decimal") from exc
        if notional < Decimal("0"):
            raise ValueError("notional cannot be negative")
        if self.action is IntentAction.INCREASE and notional <= Decimal("0"):
            raise ValueError("increase intents require positive notional")
        object.__setattr__(self, "notional", notional)

    @property
    def fingerprint(self) -> str:
        return _sha256(
            _canonical_json(
                {
                    "action": self.action.value,
                    "notional": _decimal_text(self.notional),
                    "payload_fingerprint": self.payload_fingerprint,
                    "scope": self.scope.key,
                }
            )
        )


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


class DurableRiskGate:
    """SQLite-backed account admission gate with fail-closed semantics.

    The gate intentionally has no provider client and never performs network
    I/O.  Callers own the provider dispatch, but must call
    :meth:`validate_permit` immediately before it.  The gate does not allow a
    previously issued increase permit to bypass a subsequently raised freeze.
    """

    _ACTIVE = "active"
    _SETTLED = "settled"
    _RELEASED = "released"
    _EXPIRED = "expired"

    def __init__(
        self,
        database_path: Union[Path, str],  # noqa: UP007 -- Python 3.9 is supported.
        policy: RiskPolicy,
        clock: Optional[Callable[[], float]] = None,  # noqa: UP045 -- Python 3.9 is supported.
        timeout_seconds: float = 5.0,
    ) -> None:
        self._database_path = Path(database_path)
        self._policy = policy
        self._clock = clock or _wall_clock
        self._timeout_seconds = timeout_seconds
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    @property
    def policy(self) -> RiskPolicy:
        """Return the immutable policy configured for this gate instance."""
        return self._policy

    def reserve(self, intent: RiskIntent) -> RiskPermit:
        """Atomically reserve an account-scoped permit for ``intent``.

        Calling this method repeatedly with an identical pending intent is
        idempotent.  Reusing an intent id with another payload, or after it has
        settled/released/expired, is rejected rather than producing a second
        provider dispatch opportunity.
        """
        now = self._clock()
        with self._transaction() as connection:
            self._expire_active(connection, now)
            existing = connection.execute(
                "SELECT * FROM risk_reservations WHERE intent_id = ?", (intent.intent_id,)
            ).fetchone()
            if existing is not None:
                permit = self._existing_permit_or_raise(existing, intent, now)
                if permit.action is IntentAction.INCREASE:
                    self._assert_not_frozen(connection, permit.scope)
                return permit

            if intent.action is IntentAction.UNKNOWN_EFFECT:
                raise RiskDeniedError(
                    "UNKNOWN_EFFECT", "intents with unknown effect are not eligible for admission"
                )
            if intent.action is IntentAction.INCREASE:
                self._assert_not_frozen(connection, intent.scope)
                self._assert_increase_limit(connection, intent)

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
            )
            connection.execute(
                """
                INSERT INTO risk_reservations (
                    permit_id, intent_id, intent_hash, scope_key, provider, account_id, environment,
                    action, notional, policy_hash, generation, issued_at, expires_at, status, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
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
            self._expire_active(connection, now)
            row = connection.execute(
                "SELECT * FROM risk_reservations WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            if row is None:
                raise PermitInvalidError("PERMIT_UNKNOWN", "permit does not exist")
            permit = self._permit_from_row(row)
            if row["status"] != self._ACTIVE:
                raise PermitInvalidError("PERMIT_NOT_ACTIVE", "permit is no longer active")
            if permit.policy_fingerprint != self._policy.fingerprint:
                raise PermitInvalidError("POLICY_CHANGED", "permit was issued under another policy")
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

        The durable claim is idempotent only for the same immutable permit,
        intent, scope and latch.  It intentionally does not clear a latch
        when a caller later releases a permit: release only proves a local
        admission failure, while an independent reconciliation/control path
        owns any safety-latch resolution.
        """

        if not isinstance(intent, RiskIntent):
            raise ValueError("intent must be a RiskIntent")
        cause_id = self._dispatch_freeze_cause(intent.intent_id)
        now = self._clock()
        with self._transaction() as connection:
            self._expire_active(connection, now)
            permit = self._validate_active_permit(connection, permit_id, intent)
            claim = connection.execute(
                "SELECT intent_id, scope_key, cause_id FROM risk_dispatch_claims WHERE permit_id = ?",
                (permit_id,),
            ).fetchone()
            if claim is not None:
                if (
                    claim["intent_id"] != intent.intent_id
                    or claim["scope_key"] != intent.scope.key
                    or claim["cause_id"] != cause_id
                ):
                    raise PermitInvalidError(
                        "DISPATCH_CLAIM_CONFLICT",
                        "permit is already bound to another dispatch claim",
                    )
                # A duplicate call cannot create a second provider permission.
                # The execution ledger still owns the single provider attempt.
                return permit

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
            self._freeze_in_transaction(connection, permit.scope, cause_id, cause_id, now)
            return permit

    def settle(self, permit_id: str) -> RiskPermit:
        """Consume a dispatch-claimed permit after its outcome is durably known."""
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM risk_reservations WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            if row is None:
                raise PermitInvalidError("PERMIT_UNKNOWN", "permit does not exist")
            self._require_dispatch_claim(connection, row)
            if row["status"] != self._ACTIVE:
                raise PermitInvalidError("PERMIT_NOT_ACTIVE", "only an active permit can settle")
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
                SELECT status,
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
            if row["dispatch_claimed"]:
                raise PermitInvalidError(
                    "PERMIT_DISPATCH_CLAIMED",
                    "a dispatch-claimed permit cannot be released",
                )
            if row["status"] != self._ACTIVE:
                raise PermitInvalidError("PERMIT_NOT_ACTIVE", "only an active permit can release")
            connection.execute(
                "UPDATE risk_reservations SET status = ?, reason = ? WHERE permit_id = ?",
                (self._RELEASED, reason, permit_id),
            )

    def freeze(self, scope: AccountScope, cause_id: str, reason: str) -> None:
        """Persist one independent freeze cause for a scope."""
        if not cause_id.strip() or not reason.strip():
            raise ValueError("freeze cause_id and reason are required")
        if self._is_dispatch_freeze_cause(cause_id):
            raise ValueError("dispatch-inflight freeze causes are reserved for dispatch claims")
        with self._transaction() as connection:
            self._freeze_in_transaction(connection, scope, cause_id, reason, self._clock())

    def resolve_freeze(self, scope: AccountScope, cause_id: str) -> None:
        """Resolve an ordinary freeze; dispatch latches need reconciliation."""
        if self._is_dispatch_freeze_cause(cause_id):
            raise PermitInvalidError(
                "DISPATCH_FREEZE_REQUIRES_RECONCILIATION",
                "a dispatch-inflight freeze cannot be cleared by the generic resolver",
            )
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE risk_freezes SET active = 0, updated_at = ?
                WHERE scope_key = ? AND cause_id = ?
                """,
                (self._clock(), scope.key, cause_id),
            )

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
            self._expire_active(connection, now)
            rows = connection.execute(
                """
                SELECT action, status, notional FROM risk_reservations
                WHERE scope_key = ? AND status IN (?, ?)
                """,
                (scope.key, self._ACTIVE, self._SETTLED),
            ).fetchall()
            increase_rows = [row for row in rows if row["action"] == IntentAction.INCREASE.value]
            return {
                "active_freeze_reasons": self._freeze_reasons(connection, scope),
                "increase_count": len(increase_rows),
                "increase_notional": sum(
                    (_as_decimal(row["notional"]) for row in increase_rows), Decimal("0")
                ),
                "policy_fingerprint": self._policy.fingerprint,
            }

    def close(self) -> None:
        """Provide a symmetry hook; connections are per-operation and already closed."""

    def _existing_permit_or_raise(
        self, row: sqlite3.Row, intent: RiskIntent, now: float
    ) -> RiskPermit:
        if row["intent_hash"] != intent.fingerprint:
            raise RiskDeniedError("INTENT_ID_REUSED", "intent id was reused with another payload")
        if row["status"] != self._ACTIVE:
            raise RiskDeniedError("INTENT_NOT_REUSABLE", "intent was already finalized")
        permit = self._permit_from_row(row)
        if permit.expires_at <= now:
            raise RiskDeniedError("INTENT_EXPIRED", "intent permit has expired")
        if permit.policy_fingerprint != self._policy.fingerprint:
            raise RiskDeniedError("POLICY_CHANGED", "intent was admitted by another policy")
        return permit

    def _assert_increase_limit(self, connection: sqlite3.Connection, intent: RiskIntent) -> None:
        rows = connection.execute(
            """
            SELECT notional FROM risk_reservations
            WHERE scope_key = ? AND action = ? AND status IN (?, ?)
            """,
            (intent.scope.key, IntentAction.INCREASE.value, self._ACTIVE, self._SETTLED),
        ).fetchall()
        reserved_notional = sum((_as_decimal(row["notional"]) for row in rows), Decimal("0"))
        if len(rows) >= self._policy.max_increase_count:
            raise RiskDeniedError(
                "INCREASE_COUNT_LIMIT", "increase reservation count limit reached"
            )
        if reserved_notional + intent.notional > self._policy.max_increase_notional:
            raise RiskDeniedError("INCREASE_NOTIONAL_LIMIT", "increase notional limit exceeded")

    def _assert_not_frozen(self, connection: sqlite3.Connection, scope: AccountScope) -> None:
        reasons = self._freeze_reasons(connection, scope)
        if reasons:
            raise RiskDeniedError(
                "FROZEN", "new risk-increasing intents are frozen: " + "; ".join(reasons)
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
            raise PermitInvalidError("POLICY_CHANGED", "permit was issued under another policy")
        if intent.intent_id != permit.intent_id or intent.scope != permit.scope:
            raise PermitInvalidError("PERMIT_SCOPE_MISMATCH", "permit does not match intent scope")
        if intent.fingerprint != row["intent_hash"]:
            raise PermitInvalidError(
                "PERMIT_INTENT_MISMATCH", "permit does not match intent payload"
            )
        return permit

    @staticmethod
    def _dispatch_freeze_cause(intent_id: str) -> str:
        return "dispatch-inflight:" + intent_id

    @staticmethod
    def _is_dispatch_freeze_cause(cause_id: str) -> bool:
        return isinstance(cause_id, str) and cause_id.startswith("dispatch-inflight:")

    def _require_dispatch_claim(
        self, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> sqlite3.Row:
        """Require the exact durable claim and still-active safety latch."""
        claim = connection.execute(
            "SELECT * FROM risk_dispatch_claims WHERE permit_id = ?", (row["permit_id"],)
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

    def _freeze_reasons(self, connection: sqlite3.Connection, scope: AccountScope) -> list[str]:
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
                    reason TEXT
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
                CREATE TABLE IF NOT EXISTS risk_generations (
                    scope_key TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL
                );
                """
            )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            str(self._database_path), timeout=self._timeout_seconds, isolation_level=None
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
