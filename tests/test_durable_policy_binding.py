from __future__ import annotations

import sqlite3
from contextlib import closing
from decimal import Decimal
from pathlib import Path

import pytest

from bt_api_risk import DurableRiskPolicyBinding
from bt_api_risk.core.admission import (
    AccountScope,
    DurableRiskGate,
    IntentAction,
    RiskDeniedError,
    RiskIntent,
    RiskPolicy,
)


def _policy(policy_id: str, maximum: str) -> RiskPolicy:
    return RiskPolicy(
        policy_id=policy_id,
        max_increase_notional=Decimal(maximum),
        max_increase_count=3,
        notional_unit="USD",
    )


def test_policy_binding_is_idempotent_and_rejects_replacement_with_active_reservation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "account-risk.sqlite3"
    scope = AccountScope(provider="paper", account_id="account-a", environment="paper")
    policy = _policy("policy-v1", "25")

    original_gate = DurableRiskGate(database, policy)
    original_binding = original_gate.bind_policy(scope)
    assert type(original_binding) is DurableRiskPolicyBinding
    assert original_binding.scope == scope
    assert original_binding.policy_id == policy.policy_id
    assert original_binding.policy_fingerprint == policy.fingerprint
    assert original_binding.ledger_identity_ref == original_gate.ledger_identity_ref

    permit = original_gate.reserve(
        RiskIntent(
            intent_id="active-under-v1",
            scope=scope,
            action=IntentAction.INCREASE,
            notional=Decimal("10"),
            payload_fingerprint="synthetic-policy-binding-regression",
            notional_unit="USD",
        )
    )
    before = original_gate.snapshot(scope)
    assert before["increase_notional"] == Decimal("10")

    restarted_gate = DurableRiskGate(database, policy)
    assert restarted_gate.bind_policy(scope) == original_binding
    assert restarted_gate.snapshot(scope) == before

    replacement_gate = DurableRiskGate(database, _policy("policy-v2", "40"))
    with pytest.raises(RiskDeniedError) as mismatch:
        replacement_gate.bind_policy(scope)
    assert mismatch.value.code == "RISK_POLICY_BINDING_MISMATCH"

    # The rejected replacement leaves both the immutable policy binding and
    # its already active reservation intact.
    with closing(sqlite3.connect(database)) as connection:
        binding_row = connection.execute(
            "SELECT policy_id, policy_hash FROM risk_policy_bindings WHERE scope_key=?",
            (scope.key,),
        ).fetchone()
        reservation_row = connection.execute(
            "SELECT permit_id, status, notional, policy_hash FROM risk_reservations "
            "WHERE permit_id=?",
            (permit.permit_id,),
        ).fetchone()

    assert binding_row == (policy.policy_id, policy.fingerprint)
    assert reservation_row == (
        permit.permit_id,
        "active",
        "10",
        policy.fingerprint,
    )
    assert original_gate.snapshot(scope) == before


def test_policy_binding_rejects_non_account_scope_before_creating_binding(
    tmp_path: Path,
) -> None:
    database = tmp_path / "account-risk.sqlite3"
    gate = DurableRiskGate(database, _policy("policy-v1", "25"))

    with pytest.raises(RiskDeniedError) as invalid_scope:
        gate.bind_policy(object())  # type: ignore[arg-type]
    assert invalid_scope.value.code == "RISK_POLICY_BINDING_SCOPE_INVALID"

    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute(
            "SELECT scope_key, policy_id FROM risk_policy_bindings"
        ).fetchall()
    assert rows == []
