"""Apply one durable STOP_NEW cause at most once through the Risk gate.

A STOP_NEW cause blocks new risk-increasing reservations for one account scope;
reductions, cancels and settlement continue.  This helper deliberately uses the
existing ``risk_entry_blocks`` rows and the gate's write transaction.  It adds no
second ledger and does not change the explicit upsert behavior of
``DurableRiskGate.stop_new``.

The result field ``has_other_active_freezes`` keeps its historical name: Monitor
``effect_result`` records already persisted it, and renaming it needs a
coordinated receipt-schema migration (iteration 64 design freeze, section 15).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .admission import AccountScope, DurableRiskGate


class StopNewActivationStatus(str, Enum):
    """Outcome of applying one exact STOP_NEW cause through the once API."""

    CREATED = "CREATED"
    ALREADY_ACTIVE = "ALREADY_ACTIVE"
    ALREADY_RESOLVED = "ALREADY_RESOLVED"


@dataclass(frozen=True)
class StopNewActivationResult:
    """Typed STOP_NEW outcome with same-transaction remaining-cause state."""

    status: StopNewActivationStatus
    has_other_active_freezes: bool

    def __post_init__(self) -> None:
        if type(self.status) is not StopNewActivationStatus:
            raise ValueError("status must be a StopNewActivationStatus")
        if type(self.has_other_active_freezes) is not bool:
            raise ValueError("has_other_active_freezes must be a boolean")


def activate_stop_new_once(
    gate: DurableRiskGate,
    scope: AccountScope,
    cause_id: str,
    reason: str,
) -> StopNewActivationResult:
    """Insert one exact cause if absent; never reactivate it on API replay.

    The guarantee is scoped to calls through this API.  ``DurableRiskGate.stop_new``
    intentionally remains an upsert for existing callers.
    """
    from .admission import AccountScope, RiskGateError

    if not isinstance(scope, AccountScope):
        raise ValueError("scope must be an AccountScope")
    if not isinstance(cause_id, str) or not cause_id.strip():
        raise ValueError("stop-new cause_id is required")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("stop-new reason is required")
    if gate._is_dispatch_inflight_cause(cause_id):
        raise ValueError("dispatch-inflight causes are reserved for dispatch claims")

    with gate._transaction() as connection:
        gate._ensure_policy_binding(connection, scope.key)
        row = connection.execute(
            "SELECT active FROM risk_entry_blocks WHERE scope_key = ? AND cause_id = ?",
            (scope.key, cause_id),
        ).fetchone()
        if row is None:
            gate._block_entry_in_transaction(
                connection, scope, cause_id, reason, gate._clock()
            )
            status = StopNewActivationStatus.CREATED
        elif row["active"] == 1:
            # The first reason is immutable to this operation: duplicate or
            # delayed owners cannot overwrite the current explanation.
            status = StopNewActivationStatus.ALREADY_ACTIVE
        elif row["active"] == 0:
            status = StopNewActivationStatus.ALREADY_RESOLVED
        else:
            raise RiskGateError("persisted entry-block active state is invalid")

        other_active = connection.execute(
            """SELECT 1 FROM risk_entry_blocks
               WHERE scope_key = ? AND cause_id <> ? AND active = 1 LIMIT 1""",
            (scope.key, cause_id),
        ).fetchone()
        return StopNewActivationResult(
            status=status,
            has_other_active_freezes=other_active is not None,
        )
