"""Focused P5A tests for atomic Risk-owned group vectors and bounded claims."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from decimal import Decimal
from types import SimpleNamespace

import pytest

from bt_api_risk import (
    AccountScope,
    DurableRiskAdmissionAdapter,
    DurableRiskGate,
    InstrumentRiskAdmissionMapper,
    InstrumentRiskMetadata,
    InstrumentRiskRegistry,
    IntentAction,
    PermitInvalidError,
    RiskDeniedError,
    RiskGroupReservationState,
    RiskIntent,
    RiskPolicy,
)


class _Clock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _intent(
    scope: AccountScope,
    intent_id: str,
    quantity: str,
    notional: str,
    *,
    profile: str = "a" * 64,
    observed_at_ns: int = 100_000_000_000,
    valid_until_ns: int = 1_000_000_000_000,
) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal(notional),
        payload_fingerprint=_sha(f"{intent_id}|{quantity}|{notional}"),
        strategy_id="strategy-1",
        allocation_version="allocation-v1",
        instrument="venue/contract-a",
        quantity=Decimal(quantity),
        quantity_unit="contract",
        notional_unit="USD",
        exposure_profile_fingerprint=profile,
        instrument_facts_observed_at_ns=observed_at_ns,
        instrument_facts_valid_until_ns=valid_until_ns,
    )


def _gate(
    tmp_path,
    *,
    clock: _Clock | None = None,
    notional_cap: str = "1000",
    count_cap: int = 8,
    strategy_cap: str = "1000",
    ttl: float = 5.0,
    database: str = "risk.sqlite3",
) -> tuple[DurableRiskGate, AccountScope, _Clock]:
    clock = clock or _Clock()
    scope = AccountScope("fixture", "account-1", "sandbox")
    gate = DurableRiskGate(
        tmp_path / database,
        RiskPolicy(
            "group-policy",
            Decimal(notional_cap),
            count_cap,
            permit_ttl_seconds=ttl,
            require_strategy_allocation=True,
            notional_unit="USD",
        ),
        clock=clock,
    )
    gate.set_strategy_allocation(
        scope,
        "strategy-1",
        "allocation-v1",
        max_notional=Decimal(strategy_cap),
        notional_unit="USD",
    )
    return gate, scope, clock


def _reserve(gate, scope, group_id="group-1", *, legs=None, deadline_ns=1_200_000_000_000):
    legs = legs or (
        ("leg-a", _intent(scope, "intent-a", "2", "200")),
        ("leg-b", _intent(scope, "intent-b", "1", "100")),
    )
    from bt_api_risk import RiskGroupLegIntent

    return gate.reserve_group_vector(
        scope,
        group_id,
        tuple(RiskGroupLegIntent(leg_id=leg_id, intent=intent) for leg_id, intent in legs),
        deadline_ns=deadline_ns,
    )


def test_full_vector_budget_failure_rolls_back_every_leg_and_scope_isolation(tmp_path):
    gate, scope, _ = _gate(tmp_path, notional_cap="250", count_cap=4, strategy_cap="250")
    legs = (
        ("leg-a", _intent(scope, "intent-a", "1", "150")),
        ("leg-b", _intent(scope, "intent-b", "1", "150")),
    )

    with pytest.raises(RiskDeniedError) as denied:
        _reserve(gate, scope, legs=legs)
    assert denied.value.code == "ACCOUNT_LIMIT_EXHAUSTED"
    assert gate.snapshot(scope)["increase_count"] == 0
    assert gate.snapshot(scope)["increase_notional"] == Decimal("0")
    with pytest.raises(RiskDeniedError) as absent:
        gate.query_group_vector(scope, "group-1")
    assert absent.value.code == "GROUP_NOT_FOUND"

    # The same group identifier is independently scoped to another account.
    other = AccountScope("fixture", "account-2", "sandbox")
    from bt_api_risk import RiskGroupLegIntent

    other_leg = replace(_intent(other, "intent-other", "1", "50"), strategy_id="strategy-2")
    other_leg = replace(other_leg, allocation_version="allocation-v2")
    gate.set_strategy_allocation(
        other, "strategy-2", "allocation-v2", max_notional=Decimal("100"), notional_unit="USD"
    )
    receipt = gate.reserve_group_vector(
        other,
        "group-1",
        (RiskGroupLegIntent("leg-a", other_leg),),
        deadline_ns=1_200_000_000_000,
    )
    assert receipt.scope == other
    assert receipt.group_id == "group-1"
    assert gate.snapshot(scope)["increase_count"] == 0
    gate.close()


def test_group_reservation_is_idempotent_and_reuse_cannot_replace_vector(tmp_path):
    gate, scope, clock = _gate(tmp_path)
    first = _reserve(gate, scope)
    clock.value += 1.0
    replay = _reserve(gate, scope)
    assert replay == first
    assert tuple(leg.expires_at_ns for leg in replay.legs) == tuple(
        leg.expires_at_ns for leg in first.legs
    )

    changed = (
        ("leg-a", _intent(scope, "intent-a", "1", "100")),
        ("leg-b", _intent(scope, "intent-b", "1", "100")),
    )
    with pytest.raises(RiskDeniedError) as reused:
        _reserve(gate, scope, legs=changed)
    assert reused.value.code == "GROUP_ID_REUSED"
    assert gate.query_group_vector(scope, "group-1") == first
    gate.close()


def test_strategy_allocation_failure_rolls_back_full_vector(tmp_path):
    gate, scope, _ = _gate(
        tmp_path,
        notional_cap="1000",
        count_cap=8,
        strategy_cap="250",
    )
    legs = (
        ("leg-a", _intent(scope, "intent-a", "1", "150")),
        ("leg-b", _intent(scope, "intent-b", "1", "150")),
    )
    with pytest.raises(RiskDeniedError) as denied:
        _reserve(gate, scope, legs=legs)
    assert denied.value.code == "STRATEGY_ALLOCATION_EXHAUSTED"
    assert gate.snapshot(scope)["increase_count"] == 0
    assert gate.snapshot(scope)["increase_notional"] == Decimal("0")
    with pytest.raises(RiskDeniedError) as absent:
        gate.query_group_vector(scope, "group-1")
    assert absent.value.code == "GROUP_NOT_FOUND"
    gate.close()


def test_account_count_limit_rolls_back_full_vector(tmp_path):
    gate, scope, _ = _gate(
        tmp_path,
        notional_cap="1000",
        count_cap=1,
        strategy_cap="1000",
    )
    legs = (
        ("leg-a", _intent(scope, "intent-a", "1", "50")),
        ("leg-b", _intent(scope, "intent-b", "1", "50")),
    )
    with pytest.raises(RiskDeniedError) as denied:
        _reserve(gate, scope, legs=legs)
    assert denied.value.code == "ACCOUNT_LIMIT_EXHAUSTED"
    assert gate.snapshot(scope)["increase_count"] == 0
    with pytest.raises(RiskDeniedError) as absent:
        gate.query_group_vector(scope, "group-1")
    assert absent.value.code == "GROUP_NOT_FOUND"
    gate.close()


def test_bounded_child_claim_keeps_reserved_identity_and_blocks_singleton_paths(tmp_path):
    gate, scope, _ = _gate(tmp_path)
    receipt = _reserve(gate, scope)
    reserved = receipt.legs[0]

    too_large = _intent(scope, "intent-a", "3", "300")
    with pytest.raises(RiskDeniedError) as oversized:
        gate.claim_group_leg(
            scope,
            receipt.group_id,
            reserved.leg_id,
            reserved.permit_id,
            too_large,
            expected_group_fingerprint=receipt.group_fingerprint,
            expected_deadline_ns=receipt.deadline_ns,
        )
    assert oversized.value.code == "GROUP_LEG_EXCEEDS_RESERVED"

    wrong_profile = _intent(scope, "intent-a", "1", "100", profile="b" * 64)
    with pytest.raises(RiskDeniedError) as profile_mismatch:
        gate.claim_group_leg(
            scope,
            receipt.group_id,
            reserved.leg_id,
            reserved.permit_id,
            wrong_profile,
            expected_group_fingerprint=receipt.group_fingerprint,
            expected_deadline_ns=receipt.deadline_ns,
        )
    assert profile_mismatch.value.code == "GROUP_LEG_PROFILE_MISMATCH"

    child = _intent(scope, "intent-a", "1", "100")
    claim = gate.claim_group_leg(
        scope,
        receipt.group_id,
        reserved.leg_id,
        reserved.permit_id,
        child,
        expected_group_fingerprint=receipt.group_fingerprint,
        expected_deadline_ns=receipt.deadline_ns,
    )
    assert claim.permit_reference == reserved.permit_id
    assert claim.claimed is True and claim.resolved is False
    assert claim.reserved_intent_hash == reserved.reserved_intent_hash
    assert claim.claim.intent_hash == reserved.reserved_intent_hash
    assert claim.actual_intent_hash == child.fingerprint
    assert claim.actual_intent_hash != claim.reserved_intent_hash
    assert claim.actual_quantity == Decimal("1")
    assert claim.actual_notional == Decimal("100")

    with pytest.raises(PermitInvalidError) as singleton_validate:
        gate.validate_permit(reserved.permit_id)
    assert singleton_validate.value.code == "GROUP_PERMIT_REQUIRED"
    with pytest.raises(PermitInvalidError) as singleton_claim:
        gate.claim_for_dispatch(reserved.permit_id, _intent(scope, "intent-a", "2", "200"))
    assert singleton_claim.value.code == "GROUP_CLAIM_REQUIRED"
    with pytest.raises(PermitInvalidError) as singleton_release:
        gate.release(reserved.permit_id, "not-a-group-release")
    assert singleton_release.value.code == "GROUP_RELEASE_REQUIRED"

    with pytest.raises(PermitInvalidError) as replay_changed_child:
        gate.claim_group_leg(
            scope,
            receipt.group_id,
            reserved.leg_id,
            reserved.permit_id,
            _intent(scope, "intent-a", "0.5", "50"),
            expected_group_fingerprint=receipt.group_fingerprint,
            expected_deadline_ns=receipt.deadline_ns,
        )
    assert replay_changed_child.value.code == "GROUP_CLAIM_REPLAY_MISMATCH"

    gate.settle(reserved.permit_id)
    projected = gate.query_group_vector(scope, receipt.group_id)
    assert projected.legs[0].claimed is True
    assert projected.legs[0].resolved is False
    assert projected.legs[0].actual_intent_hash == child.fingerprint
    assert projected.legs[0].state is RiskGroupReservationState.SETTLED
    with pytest.raises(RiskDeniedError) as unresolved:
        gate.release_group_unclaimed(scope, receipt.group_id, "owner-stopped")
    assert unresolved.value.code == "GROUP_CLAIM_UNRESOLVED"
    gate.close()


def test_unclaimed_vector_expiry_is_absolute_and_restart_does_not_renew(tmp_path):
    gate, scope, clock = _gate(tmp_path, ttl=5.0)
    receipt = _reserve(gate, scope, deadline_ns=1_200_000_000_000)
    expected_expiry = 105_000_000_000
    assert {leg.expires_at_ns for leg in receipt.legs} == {expected_expiry}
    clock.value = 106.0
    expired = gate.query_group_vector(scope, receipt.group_id)
    assert {leg.state for leg in expired.legs} == {RiskGroupReservationState.EXPIRED}
    gate.close()

    restarted = DurableRiskGate(tmp_path / "risk.sqlite3", gate.policy, clock=clock)
    after_restart = restarted.query_group_vector(scope, receipt.group_id)
    assert after_restart == expired
    with pytest.raises(PermitInvalidError) as cannot_claim:
        restarted.claim_group_leg(
            scope,
            receipt.group_id,
            receipt.legs[0].leg_id,
            receipt.legs[0].permit_id,
            _intent(scope, "intent-a", "1", "100"),
            expected_group_fingerprint=receipt.group_fingerprint,
            expected_deadline_ns=receipt.deadline_ns,
        )
    assert cannot_claim.value.code == "PERMIT_NOT_ACTIVE"
    restarted.close()


def test_only_explicit_release_releases_unclaimed_vector_members(tmp_path):
    gate, scope, _ = _gate(tmp_path)
    receipt = _reserve(gate, scope)
    released = gate.release_group_unclaimed(scope, receipt.group_id, "coordinator-aborted")
    assert {leg.state for leg in released.legs} == {RiskGroupReservationState.RELEASED}
    assert all(not leg.claimed for leg in released.legs)
    assert gate.snapshot(scope)["increase_count"] == 0
    assert gate.release_group_unclaimed(scope, receipt.group_id, "idempotent-retry") == released
    gate.close()


def test_claimed_member_holds_siblings_across_ttl_and_restart(tmp_path):
    gate, scope, clock = _gate(tmp_path, ttl=5.0)
    receipt = _reserve(gate, scope, deadline_ns=1_200_000_000_000)
    first = receipt.legs[0]
    gate.claim_group_leg(
        scope,
        receipt.group_id,
        first.leg_id,
        first.permit_id,
        _intent(scope, first.intent_id, "1", "100"),
        expected_group_fingerprint=receipt.group_fingerprint,
        expected_deadline_ns=receipt.deadline_ns,
    )
    clock.value = 106.0
    gate.close()

    restarted = DurableRiskGate(tmp_path / "risk.sqlite3", gate.policy, clock=clock)
    after_restart = restarted.query_group_vector(scope, receipt.group_id)
    assert after_restart.legs[0].claimed is True
    assert after_restart.legs[0].state is RiskGroupReservationState.ACTIVE
    assert after_restart.legs[1].claimed is False
    assert after_restart.legs[1].state is RiskGroupReservationState.ACTIVE
    with pytest.raises(PermitInvalidError) as expired_sibling:
        restarted.claim_group_leg(
            scope,
            receipt.group_id,
            after_restart.legs[1].leg_id,
            after_restart.legs[1].permit_id,
            _intent(scope, after_restart.legs[1].intent_id, "1", "100"),
            expected_group_fingerprint=receipt.group_fingerprint,
            expected_deadline_ns=receipt.deadline_ns,
        )
    assert expired_sibling.value.code == "GROUP_PERMIT_EXPIRED"
    with pytest.raises(RiskDeniedError) as unresolved:
        restarted.release_group_unclaimed(scope, receipt.group_id, "timeout")
    assert unresolved.value.code == "GROUP_CLAIM_UNRESOLVED"
    snapshot = restarted.snapshot(scope)
    assert snapshot["increase_count"] == 2
    assert snapshot["increase_notional"] == Decimal("300")
    restarted.close()


def test_group_expiry_uses_facts_at_commit_boundary_and_rolls_back(tmp_path):
    class AdvancingClock(_Clock):
        advance = False
        calls = 0

        def __call__(self) -> float:
            if self.advance:
                self.calls += 1
                if self.calls >= 2:
                    return 106.0
            return self.value

    clock = AdvancingClock()
    gate, scope, _ = _gate(tmp_path, clock=clock, ttl=30.0)
    legs = (
        (
            "leg-a",
            _intent(
                scope,
                "intent-a",
                "1",
                "100",
                valid_until_ns=105_000_000_000,
            ),
        ),
    )
    clock.advance = True
    with pytest.raises(RiskDeniedError) as stale:
        _reserve(gate, scope, legs=legs, deadline_ns=1_200_000_000_000)
    assert stale.value.code == "GROUP_EXPOSURE_FACTS_STALE"
    assert gate.snapshot(scope)["increase_count"] == 0
    with pytest.raises(RiskDeniedError) as absent:
        gate.query_group_vector(scope, "group-1")
    assert absent.value.code == "GROUP_NOT_FOUND"
    gate.close()


class _BoundMapper:
    def __init__(self, scope: AccountScope) -> None:
        self.scope = scope
        self.calls = 0

    def __call__(self, order) -> RiskIntent:
        return order.regular_intent

    def map_group_intent(self, order) -> RiskIntent:
        self.calls += 1
        return order.group_intent


def _raw_order(scope: AccountScope, risk_intent: RiskIntent):
    return SimpleNamespace(
        intent_id=risk_intent.intent_id,
        scope=SimpleNamespace(
            provider=scope.provider,
            account_ref=scope.account_id,
            environment=scope.environment,
            strategy_id=risk_intent.strategy_id,
        ),
        regular_intent=risk_intent,
        group_intent=risk_intent,
    )


def test_account_adapter_maps_group_reserve_and_actual_child_without_execution_import(tmp_path):
    gate, scope, _ = _gate(tmp_path)
    mapper = _BoundMapper(scope)
    adapter = DurableRiskAdmissionAdapter(gate, mapper)
    reserved_order = _raw_order(scope, _intent(scope, "intent-a", "2", "200"))
    receipt = adapter.reserve_group_vector(
        scope,
        "group-adapter",
        (("leg-a", reserved_order),),
        deadline_ns=1_200_000_000_000,
    )
    actual_order = _raw_order(scope, _intent(scope, "intent-a", "1", "100"))
    claim = adapter.claim_group_leg(
        actual_order,
        scope=scope,
        group_id=receipt.group_id,
        leg_id="leg-a",
        permit_reference=receipt.legs[0].permit_id,
        group_fingerprint=receipt.group_fingerprint,
        deadline_ns=receipt.deadline_ns,
    )
    assert mapper.calls == 2
    assert claim.permit_reference == receipt.legs[0].permit_id
    assert claim.reserved_intent_hash == receipt.legs[0].reserved_intent_hash
    assert claim.actual_intent_hash == actual_order.group_intent.fingerprint
    assert adapter.query_group_vector(scope, receipt.group_id).legs[0].claimed is True
    gate.close()


def test_real_instrument_mapper_and_durable_gate_share_group_vector_path(tmp_path):
    scope = AccountScope("fixture", "account-1", "sandbox")
    metadata = InstrumentRiskMetadata(
        instrument="venue/contract-a",
        metadata_version="real-map-v1",
        as_of_ns=100,
        expires_at_ns=10_000,
        tick_size=Decimal("0.1"),
        quantity_step=Decimal("0.5"),
        contract_multiplier=Decimal("1"),
        max_gross_notional=Decimal("500"),
        taker_fee_bps=Decimal("0"),
        fixed_fee=Decimal("0"),
        max_slippage_bps=Decimal("0"),
        quantity_unit="contract",
        valuation_unit="USD",
    )
    clock = _Clock(0.0000005)
    gate = DurableRiskGate(
        tmp_path / "real-mapper.sqlite3",
        RiskPolicy(
            "real-mapper-policy",
            Decimal("1000"),
            4,
            permit_ttl_seconds=5.0,
            require_strategy_allocation=True,
            notional_unit="USD",
        ),
        clock=clock,
    )
    gate.set_strategy_allocation(
        scope,
        "strategy-1",
        "allocation-v1",
        max_notional=Decimal("1000"),
        max_position=Decimal("10"),
        position_instrument=metadata.instrument,
        position_unit="contract",
        notional_unit="USD",
    )
    execution_scope = SimpleNamespace(
        provider="fixture",
        account_ref="account-1",
        environment="sandbox",
        strategy_id="strategy-1",
    )
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: 500,
        allocation_reader=lambda order_scope: gate.get_strategy_allocation(
            scope, order_scope.strategy_id
        ),
    )

    def order(intent_id: str, quantity: str):
        return SimpleNamespace(
            intent_id=intent_id,
            fingerprint=_sha(f"{intent_id}|{quantity}"),
            instrument=metadata.instrument,
            quantity=Decimal(quantity),
            price=Decimal("10"),
            metadata_version=metadata.metadata_version,
            tags={"instrument_metadata_digest": metadata.digest},
            position_effect=SimpleNamespace(value="OPEN"),
            side=SimpleNamespace(value="BUY"),
            scope=execution_scope,
        )

    adapter = DurableRiskAdmissionAdapter(gate, mapper)
    reserved_order = order("stable-leg", "2")
    receipt = adapter.reserve_group_vector(
        scope,
        "real-mapped-group",
        (("leg-a", reserved_order),),
        deadline_ns=1_000_000_000,
    )
    assert (
        receipt.legs[0].reserved_intent_hash == mapper.map_group_intent(reserved_order).fingerprint
    )
    child = order("stable-leg", "1")
    claim = adapter.claim_group_leg(
        child,
        scope=scope,
        group_id=receipt.group_id,
        leg_id="leg-a",
        permit_reference=receipt.legs[0].permit_id,
        group_fingerprint=receipt.group_fingerprint,
        deadline_ns=receipt.deadline_ns,
    )
    assert claim.actual_quantity == Decimal("1")
    assert claim.actual_notional == Decimal("10")
    assert claim.actual_intent_hash != receipt.legs[0].reserved_intent_hash
    gate.close()


def test_instrument_mapper_group_profile_excludes_size_but_binds_side_and_freshness():
    metadata = InstrumentRiskMetadata(
        instrument="venue/contract-a",
        metadata_version="profile-v1",
        as_of_ns=100,
        expires_at_ns=10_000,
        tick_size=Decimal("0.1"),
        quantity_step=Decimal("0.5"),
        contract_multiplier=Decimal("2"),
        max_gross_notional=Decimal("100000"),
        taker_fee_bps=Decimal("1"),
        fixed_fee=Decimal("0"),
        max_slippage_bps=Decimal("0"),
        quantity_unit="contract",
        valuation_unit="USD",
    )
    scope = AccountScope("fixture", "account-1", "sandbox")
    execution_scope = SimpleNamespace(
        provider="fixture", account_ref="account-1", environment="sandbox", strategy_id="strategy-1"
    )
    allocation = SimpleNamespace(
        scope=execution_scope,
        allocation_version="allocation-v1",
        max_notional=Decimal("100000"),
        max_position=Decimal("100"),
        notional_unit="USD",
        position_instrument=metadata.instrument,
        position_unit="contract",
    )
    now = [500]
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: now[0],
        allocation_reader=lambda _: allocation,
    )

    def order(intent_id: str, quantity: str, price: str, side: str = "BUY"):
        return SimpleNamespace(
            intent_id=intent_id,
            fingerprint=_sha(f"{intent_id}|{quantity}|{price}|{side}"),
            instrument=metadata.instrument,
            quantity=Decimal(quantity),
            price=Decimal(price),
            metadata_version=metadata.metadata_version,
            tags={"instrument_metadata_digest": metadata.digest},
            position_effect=SimpleNamespace(value="OPEN"),
            side=SimpleNamespace(value=side),
            scope=execution_scope,
        )

    original = order("stable-leg", "2", "10")
    ordinary = mapper(original)
    assert ordinary.exposure_profile_fingerprint is None
    grouped = mapper.map_group_intent(original)
    assert grouped.instrument_facts_observed_at_ns == 500
    assert grouped.instrument_facts_valid_until_ns == 10_000

    now[0] = 501
    smaller = mapper.map_group_intent(order("stable-leg", "1.5", "12"))
    assert smaller.exposure_profile_fingerprint == grouped.exposure_profile_fingerprint
    assert smaller.fingerprint != grouped.fingerprint
    assert smaller.notional < grouped.notional
    same_order_new_observation = mapper.map_group_intent(original)
    assert same_order_new_observation.instrument_facts_observed_at_ns == 501
    assert same_order_new_observation.fingerprint == grouped.fingerprint

    opposite_side = mapper.map_group_intent(order("stable-leg", "2", "10", "SELL"))
    assert opposite_side.exposure_profile_fingerprint != grouped.exposure_profile_fingerprint
