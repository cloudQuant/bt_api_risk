from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Barrier

import pytest

from bt_api_risk import FreezeResolution as PublicFreezeResolution
from bt_api_risk import FreezeResolutionStatus as PublicFreezeResolutionStatus
from bt_api_risk.core import FreezeResolution as CoreFreezeResolution
from bt_api_risk.core import FreezeResolutionStatus as CoreFreezeResolutionStatus
from bt_api_risk.core.admission import (
    AccountScope,
    DurableRiskGate,
    FreezeResolution,
    FreezeResolutionStatus,
    IntentAction,
    PermitInvalidError,
    RiskIntent,
    RiskPolicy,
)


def _policy() -> RiskPolicy:
    return RiskPolicy("freeze-resolution", Decimal("100"), max_increase_count=10)


def _scope(account_id: str = "account-a") -> AccountScope:
    return AccountScope("fixture", account_id, "sandbox")


def test_exact_resolution_is_typed_idempotent_and_scope_bound(tmp_path) -> None:
    assert PublicFreezeResolution is CoreFreezeResolution is FreezeResolution
    assert PublicFreezeResolutionStatus is CoreFreezeResolutionStatus is FreezeResolutionStatus

    gate = DurableRiskGate(tmp_path / "freezes.sqlite3", _policy())
    first_scope = _scope()
    second_scope = _scope("account-b")
    target = "market-data-stale"
    gate.freeze(first_scope, target, "feed is stale")
    gate.freeze(first_scope, "operator-hold", "operator hold")
    gate.freeze(second_scope, target, "second account feed is stale")

    cleared = gate.resolve_freeze_exact(first_scope, target)
    assert cleared == FreezeResolution(FreezeResolutionStatus.CLEARED, True)
    assert gate.active_freeze_reasons(first_scope) == ["operator hold"]
    assert gate.active_freeze_reasons(second_scope) == ["second account feed is stale"]

    retried = gate.resolve_freeze_exact(first_scope, target)
    assert retried == FreezeResolution(FreezeResolutionStatus.ALREADY_RESOLVED, True)

    missing_with_other_freeze = gate.resolve_freeze_exact(first_scope, "never-created")
    assert missing_with_other_freeze == FreezeResolution(FreezeResolutionStatus.NOT_FOUND, True)

    second_scope_result = gate.resolve_freeze_exact(second_scope, target)
    assert second_scope_result == FreezeResolution(FreezeResolutionStatus.CLEARED, False)
    missing_without_freezes = gate.resolve_freeze_exact(second_scope, "also-never-created")
    assert missing_without_freezes == FreezeResolution(FreezeResolutionStatus.NOT_FOUND, False)

    gate.freeze(first_scope, "legacy-cause", "legacy resolution remains supported")
    assert gate.resolve_freeze(first_scope, "legacy-cause") is None
    assert gate.active_freeze_reasons(first_scope) == ["operator hold"]


def test_concurrent_exact_retries_return_one_clear_and_one_already_resolved(tmp_path) -> None:
    database = tmp_path / "concurrent-freezes.sqlite3"
    policy = _policy()
    scope = _scope()
    target = "manual-control-17"
    setup_gate = DurableRiskGate(database, policy)
    setup_gate.freeze(scope, target, "target freeze")
    setup_gate.freeze(scope, "independent-hold", "independent hold")

    gates = [DurableRiskGate(database, policy), DurableRiskGate(database, policy)]
    barrier = Barrier(2)

    def resolve(gate: DurableRiskGate) -> FreezeResolution:
        barrier.wait(timeout=10)
        return gate.resolve_freeze_exact(scope, target)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(resolve, gates))

    assert sorted(result.status.value for result in results) == [
        FreezeResolutionStatus.ALREADY_RESOLVED.value,
        FreezeResolutionStatus.CLEARED.value,
    ]
    assert all(result.has_other_active_freezes for result in results)
    assert setup_gate.active_freeze_reasons(scope) == ["independent hold"]


def test_exact_resolution_preserves_dispatch_latch_refusal(tmp_path) -> None:
    scope = _scope()
    gate = DurableRiskGate(tmp_path / "dispatch-freeze.sqlite3", _policy())
    intent = RiskIntent(
        intent_id="dispatch-claim",
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal("10"),
        payload_fingerprint="synthetic-order",
    )
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)
    cause_id = "dispatch-inflight:" + intent.intent_id

    with pytest.raises(PermitInvalidError) as blocked:
        gate.resolve_freeze_exact(scope, cause_id)
    assert blocked.value.code == "DISPATCH_FREEZE_REQUIRES_RECONCILIATION"
    assert gate.active_freeze_reasons(scope) == [cause_id]

    with pytest.raises(PermitInvalidError) as legacy_blocked:
        gate.resolve_freeze(scope, cause_id)
    assert legacy_blocked.value.code == "DISPATCH_FREEZE_REQUIRES_RECONCILIATION"
    assert gate.active_freeze_reasons(scope) == [cause_id]
