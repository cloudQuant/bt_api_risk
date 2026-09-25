"""Unit tests for the provider-independent durable risk admission boundary."""

from __future__ import annotations

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Barrier

import pytest

from bt_api_risk import (
    AccountScope,
    DurableRiskGate,
    IntentAction,
    PermitInvalidError,
    RiskDeniedError,
    RiskIntent,
    RiskPolicy,
)


class MutableClock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


@pytest.fixture
def scope() -> AccountScope:
    return AccountScope(provider="fake", account_id="account-1", environment="sandbox")


@pytest.fixture
def policy() -> RiskPolicy:
    return RiskPolicy(
        policy_id="unit-policy",
        max_increase_notional=Decimal("100"),
        max_increase_count=3,
        permit_ttl_seconds=10.0,
    )


def make_intent(
    scope: AccountScope,
    intent_id: str,
    action: IntentAction = IntentAction.INCREASE,
    notional: str = "40",
) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=action,
        notional=Decimal(notional),
        payload_fingerprint="deterministic-test-payload",
    )


def test_reservation_is_idempotent_and_enforces_shared_limit(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    clock = MutableClock()
    database = tmp_path / "risk.db"
    first_gate = DurableRiskGate(database, policy, clock=clock)
    second_gate = DurableRiskGate(database, policy, clock=clock)

    first = first_gate.reserve(make_intent(scope, "intent-1"))
    duplicate = second_gate.reserve(make_intent(scope, "intent-1"))
    assert duplicate.permit_id == first.permit_id

    second_gate.reserve(make_intent(scope, "intent-2", notional="60"))
    with pytest.raises(RiskDeniedError, match="notional limit") as error:
        first_gate.reserve(make_intent(scope, "intent-3", notional="1"))
    assert error.value.code == "INCREASE_NOTIONAL_LIMIT"
    assert first_gate.snapshot(scope)["increase_notional"] == Decimal("100")


def test_reused_id_with_different_payload_is_rejected(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    gate.reserve(make_intent(scope, "intent-1", notional="20"))

    with pytest.raises(RiskDeniedError) as error:
        gate.reserve(make_intent(scope, "intent-1", notional="21"))
    assert error.value.code == "INTENT_ID_REUSED"


def test_freeze_blocks_increase_but_not_cancel_or_reduce(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    gate.freeze(scope, "market-data-stale", "market data is stale")

    with pytest.raises(RiskDeniedError) as error:
        gate.reserve(make_intent(scope, "open", IntentAction.INCREASE))
    assert error.value.code == "FROZEN"

    cancel = gate.reserve(make_intent(scope, "cancel", IntentAction.CANCEL, notional="0"))
    reduce = gate.reserve(make_intent(scope, "reduce", IntentAction.REDUCE, notional="0"))
    assert cancel.action is IntentAction.CANCEL
    assert reduce.action is IntentAction.REDUCE

    gate.resolve_freeze(scope, "market-data-stale")
    assert gate.active_freeze_reasons(scope) == []
    assert (
        gate.reserve(make_intent(scope, "open-after", IntentAction.INCREASE)).intent_id
        == "open-after"
    )


def test_freeze_after_reservation_invalidates_increase_at_dispatch(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    intent = make_intent(scope, "open")
    permit = gate.reserve(intent)
    gate.freeze(scope, "operator", "operator freeze")

    with pytest.raises(RiskDeniedError) as error:
        gate.validate_permit(permit.permit_id, intent)
    assert error.value.code == "FROZEN"


def test_expired_and_policy_changed_permits_cannot_dispatch(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    clock = MutableClock()
    database = tmp_path / "risk.db"
    initial_gate = DurableRiskGate(database, policy, clock=clock)
    intent = make_intent(scope, "open")
    permit = initial_gate.reserve(intent)

    changed_policy = RiskPolicy(
        policy_id="changed", max_increase_notional=Decimal("100"), max_increase_count=2
    )
    changed_gate = DurableRiskGate(database, changed_policy, clock=clock)
    with pytest.raises(PermitInvalidError) as policy_error:
        changed_gate.validate_permit(permit.permit_id, intent)
    assert policy_error.value.code == "POLICY_CHANGED"

    clock.value += 11.0
    with pytest.raises(PermitInvalidError) as expiry_error:
        initial_gate.validate_permit(permit.permit_id, intent)
    assert expiry_error.value.code == "PERMIT_NOT_ACTIVE"


def test_settle_and_release_only_allow_pending_permits(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    settled = gate.reserve(make_intent(scope, "settle"))
    gate.settle(settled.permit_id)
    with pytest.raises(PermitInvalidError):
        gate.release(settled.permit_id, "cannot release dispatched request")

    released = gate.reserve(make_intent(scope, "release"))
    gate.release(released.permit_id, "provider was never contacted")
    with pytest.raises(PermitInvalidError):
        gate.validate_permit(released.permit_id)


def test_dispatch_claimed_permit_cannot_be_released(tmp_path, scope, policy):
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    intent = make_intent(scope, "claimed")
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)

    with pytest.raises(PermitInvalidError) as caught:
        gate.release(permit.permit_id, "dispatch outcome is uncertain")

    assert caught.value.code == "PERMIT_DISPATCH_CLAIMED"
    snapshot = gate.snapshot(scope)
    assert snapshot["increase_count"] == 1
    assert snapshot["increase_notional"] == Decimal("40")


@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity"), True])
def test_nonfinite_and_boolean_amounts_are_not_risk_limits_or_intents(value, scope):
    with pytest.raises(ValueError):
        RiskPolicy("unsafe", value, 1)
    with pytest.raises(ValueError):
        RiskIntent("unsafe", scope, IntentAction.INCREASE, value)


@pytest.mark.parametrize("count", [float("nan"), float("inf"), 1.5, True])
def test_increase_count_cannot_disable_limit_using_nan_or_fraction(count):
    with pytest.raises(ValueError, match="integer"):
        RiskPolicy("unsafe", Decimal("100"), count)


@pytest.mark.parametrize("ttl", [float("nan"), float("inf"), True])
def test_permit_expiry_must_be_finite(ttl):
    with pytest.raises(ValueError):
        RiskPolicy("unsafe", Decimal("100"), 1, ttl)


def test_exact_retry_after_freeze_does_not_return_an_admitted_increase(tmp_path, scope, policy):
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    intent = make_intent(scope, "same")
    gate.reserve(intent)
    gate.freeze(scope, "disconnect", "connection lost")
    gate.freeze(scope, "operator", "operator hold")
    gate.resolve_freeze(scope, "disconnect")
    with pytest.raises(RiskDeniedError) as denied:
        gate.reserve(intent)
    assert denied.value.code == "FROZEN"
    assert gate.active_freeze_reasons(scope) == ["operator hold"]


def test_concurrent_connections_cannot_oversubscribe_account_budget(tmp_path, scope, policy):
    database = tmp_path / "risk.db"
    gates = [DurableRiskGate(database, policy), DurableRiskGate(database, policy)]
    barrier = Barrier(8)

    def reserve(index):
        barrier.wait(timeout=10)
        try:
            gates[index % 2].reserve(make_intent(scope, "concurrent-" + str(index)))
            return "admitted"
        except RiskDeniedError as denied:
            return denied.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve, range(8)))
    assert results.count("admitted") == 2
    assert results.count("INCREASE_NOTIONAL_LIMIT") == 6
    reopened = DurableRiskGate(database, policy)
    assert reopened.snapshot(scope)["increase_notional"] == Decimal("80")


def test_public_exports_are_defined():
    import bt_api_risk

    assert all(hasattr(bt_api_risk, name) for name in bt_api_risk.__all__)
    assert "DurableRiskGate" in bt_api_risk.__all__


def test_risk_payload_binding_is_immutable(scope):
    from dataclasses import FrozenInstanceError

    intent = make_intent(scope, "immutable")
    fingerprint = intent.fingerprint
    with pytest.raises(FrozenInstanceError):
        intent.payload_fingerprint = "changed"
    with pytest.raises(ValueError, match="immutable"):
        RiskIntent("mutable", scope, IntentAction.INCREASE, Decimal("1"), {"quantity": 1})
    assert intent.fingerprint == fingerprint


def test_separate_processes_share_the_same_account_budget(tmp_path, scope, policy):
    database = tmp_path / "risk.db"
    gate = DurableRiskGate(database, policy)
    program = """
import socket
import sys
def no_network(*args, **kwargs):
    raise AssertionError('risk worker attempted external I/O')
socket.create_connection = no_network
socket.socket.connect = no_network
from decimal import Decimal
from bt_api_risk import AccountScope, DurableRiskGate, IntentAction, RiskDeniedError, RiskIntent, RiskPolicy
gate = DurableRiskGate(sys.argv[1], RiskPolicy('unit-policy', Decimal('100'), 3, 10.0))
intent = RiskIntent(sys.argv[2], AccountScope('fake', 'account-1', 'sandbox'), IntentAction.INCREASE, Decimal('40'))
try:
    gate.reserve(intent)
except RiskDeniedError as error:
    print(error.code)
else:
    print('admitted')
"""

    def run_worker(index):
        result = subprocess.run(  # noqa: S603 -- fixed local Python worker, no shell.
            [sys.executable, "-c", program, str(database), "process-" + str(index)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(run_worker, range(4)))
    assert results.count("admitted") == 2
    assert results.count("INCREASE_NOTIONAL_LIMIT") == 2
    assert gate.snapshot(scope)["increase_notional"] == Decimal("80")


def test_atomic_dispatch_claim_fences_two_prevalidated_processes(tmp_path, scope, policy):
    """A check-then-freeze race must admit at most one provider boundary.

    Both permits are intentionally reserved before either child begins.  The
    assertion therefore exercises the dispatch-time transaction rather than
    the easier reservation-time freeze check.
    """

    database = tmp_path / "risk.db"
    gate = DurableRiskGate(database, policy)
    first = gate.reserve(make_intent(scope, "dispatch-process-1", notional="10"))
    second = gate.reserve(make_intent(scope, "dispatch-process-2", notional="10"))
    program = """
import socket
import sys
def no_network(*args, **kwargs):
    raise AssertionError('risk worker attempted external I/O')
socket.create_connection = no_network
socket.socket.connect = no_network
from decimal import Decimal
from bt_api_risk import AccountScope, DurableRiskGate, IntentAction, RiskDeniedError, RiskIntent, RiskPolicy
gate = DurableRiskGate(sys.argv[1], RiskPolicy('unit-policy', Decimal('100'), 3, 10.0))
intent = RiskIntent(
    sys.argv[2],
    AccountScope('fake', 'account-1', 'sandbox'),
    IntentAction.INCREASE,
    Decimal('10'),
    'deterministic-test-payload',
)
try:
    gate.claim_for_dispatch(sys.argv[3], intent)
except RiskDeniedError as error:
    print(error.code)
else:
    print('claimed')
"""

    def claim(intent_id: str, permit_id: str) -> str:
        result = subprocess.run(  # noqa: S603 -- fixed local Python worker, no shell.
            [sys.executable, "-c", program, str(database), intent_id, permit_id],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda values: claim(*values),
                (
                    ("dispatch-process-1", first.permit_id),
                    ("dispatch-process-2", second.permit_id),
                ),
            )
        )

    assert results.count("claimed") == 1
    assert results.count("FROZEN") == 1
    active = gate.active_freeze_reasons(scope)
    assert len(active) == 1
    assert active[0] in {
        "dispatch-inflight:dispatch-process-1",
        "dispatch-inflight:dispatch-process-2",
    }
