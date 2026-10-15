"""Apply one durable freeze cause at most once through the Risk gate.

This helper deliberately uses the existing ``risk_freezes`` rows and the gate's
write transaction.  It adds no second ledger and does not change the explicit
upsert behavior of ``DurableRiskGate.freeze``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .admission import AccountScope, DurableRiskGate


class FreezeActivationStatus(str, Enum):
    """Outcome of applying one exact freeze cause through the once API."""

    CREATED = "CREATED"
    ALREADY_ACTIVE = "ALREADY_ACTIVE"
    ALREADY_RESOLVED = "ALREADY_RESOLVED"


@dataclass(frozen=True)
class FreezeActivationResult:
    """Typed freeze outcome with same-transaction remaining-cause state."""

    status: FreezeActivationStatus
    has_other_active_freezes: bool

    def __post_init__(self) -> None:
        if type(self.status) is not FreezeActivationStatus:
            raise ValueError("status must be a FreezeActivationStatus")
        if type(self.has_other_active_freezes) is not bool:
            raise ValueError("has_other_active_freezes must be a boolean")


def activate_freeze_once(
    gate: DurableRiskGate,
    scope: AccountScope,
    cause_id: str,
    reason: str,
) -> FreezeActivationResult:
    """Insert one exact cause if absent; never reactivate it on API replay.

    The guarantee is scoped to calls through this API.  The legacy ``freeze``
    operation intentionally remains an upsert for existing callers.
    """
    from .admission import AccountScope, RiskGateError

    if not isinstance(scope, AccountScope):
        raise ValueError("scope must be an AccountScope")
    if not isinstance(cause_id, str) or not cause_id.strip():
        raise ValueError("freeze cause_id is required")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("freeze reason is required")
    if gate._is_dispatch_freeze_cause(cause_id):
        raise ValueError("dispatch-inflight freeze causes are reserved for dispatch claims")

    with gate._transaction() as connection:
        gate._ensure_policy_binding(connection, scope.key)
        row = connection.execute(
            "SELECT active FROM risk_freezes WHERE scope_key = ? AND cause_id = ?",
            (scope.key, cause_id),
        ).fetchone()
        if row is None:
            gate._freeze_in_transaction(
                connection, scope, cause_id, reason, gate._clock()
            )
            status = FreezeActivationStatus.CREATED
        elif row["active"] == 1:
            # The first reason is immutable to this operation: duplicate or
            # delayed owners cannot overwrite the current explanation.
            status = FreezeActivationStatus.ALREADY_ACTIVE
        elif row["active"] == 0:
            status = FreezeActivationStatus.ALREADY_RESOLVED
        else:
            raise RiskGateError("persisted freeze active state is invalid")

        other_active = connection.execute(
            """SELECT 1 FROM risk_freezes
               WHERE scope_key = ? AND cause_id <> ? AND active = 1 LIMIT 1""",
            (scope.key, cause_id),
        ).fetchone()
        return FreezeActivationResult(
            status=status,
            has_other_active_freezes=other_active is not None,
        )
