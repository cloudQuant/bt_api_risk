from __future__ import annotations

import hashlib
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal

import pytest

import bt_api_risk.core.admission as admission_module
from bt_api_risk import (
    AccountScope,
    DispatchEvidenceClass,
    DispatchExposureResolutionProof,
    DispatchExposureResolutionReceiptStatus,
    DispatchTrackedOrderProof,
    DurableRiskGate,
    ExposureAccountingMode,
    GrossExposureBaselineProof,
    IntentAction,
    OrderExposureObservationProof,
    OrderExposureState,
    OrderFillFact,
    RiskDeniedError,
    RiskGroupLegIntent,
    RiskIntent,
    RiskPolicy,
    VerifiedDispatchExposureResolution,
    VerifiedDispatchResolution,
    VerifiedGrossExposureBaseline,
    VerifiedOrderExposureObservation,
    fill_ids_sha256,
)

_NOW_NS = 1_700_000_000_123_456_789
_NOW_SECONDS = _NOW_NS / 1_000_000_000
_OWNER = "integer-clock-test-owner"
_FENCE_SHA256 = hashlib.sha256(b"integer-clock-writer-fence").hexdigest()


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class _NanosecondClock:
    def __init__(self, value: int = _NOW_NS) -> None:
        self.value = value
        self.script: tuple[int, ...] | None = None
        self.calls = 0

    def __call__(self) -> int:
        if self.script is None:
            return self.value
        index = self.calls
        self.calls += 1
        return self.script[min(index, len(self.script) - 1)]


class _SourceBoundAuthority:
    """Faithful typed journal receipts for the real Risk SQLite paths."""

    def __init__(self) -> None:
        self.baseline_calls = 0
        self.order_calls = 0
        self.terminal_calls = 0

    @contextmanager
    def baseline_guard(self, proof):
        self.baseline_calls += 1
        yield VerifiedGrossExposureBaseline(
            scope=proof.scope,
            proof_sha256=proof.fingerprint,
            account_revision=proof.account_revision,
            writer_owner_id=proof.writer_owner_id,
            writer_fencing_token=proof.writer_fencing_token,
            writer_fence_sha256=proof.writer_fence_sha256,
        )

    @contextmanager
    def dispatch_resolution_guard(self, proof, *, claim):
        yield VerifiedDispatchResolution(
            scope=claim.scope,
            permit_id=claim.permit_id,
            intent_id=claim.intent_id,
            intent_hash=claim.intent_hash,
            claim_digest=claim.claim_digest,
            proof_sha256=proof.fingerprint,
            journal_revision=proof.journal_revision,
            journal_record_sha256=proof.journal_record_sha256,
            writer_fence_sha256=proof.writer_fence_sha256,
        )

    @contextmanager
    def order_observation_guard(self, proof, *, claim, tracked_order):
        self.order_calls += 1
        yield VerifiedOrderExposureObservation(
            scope=proof.scope,
            permit_id=proof.permit_id,
            intent_id=proof.intent_id,
            proof_sha256=proof.fingerprint,
            dispatch_claim_digest=proof.dispatch_claim_digest,
            dispatch_proof_sha256=proof.dispatch_proof_sha256,
            order_revision=proof.order_revision,
            journal_revision=proof.journal_revision,
            writer_owner_id=proof.writer_owner_id,
            writer_fencing_token=proof.writer_fencing_token,
            writer_fence_sha256=proof.writer_fence_sha256,
        )

    @contextmanager
    def dispatch_exposure_resolution_guard(self, proof, *, claim):
        self.terminal_calls += 1
        observation = proof.observation
        yield VerifiedDispatchExposureResolution(
            scope=claim.scope,
            permit_id=claim.permit_id,
            intent_id=claim.intent_id,
            intent_hash=claim.intent_hash,
            cause_id=claim.cause_id,
            claim_digest=claim.claim_digest,
            proof_sha256=proof.fingerprint,
            exposure_proof_sha256=observation.fingerprint,
            provider_order_id=observation.provider_order_id,
            accepted_request_sha256=observation.accepted_request_sha256,
            exposure_reservation_id=observation.exposure_reservation_id,
            exposure_reservation_sha256=observation.exposure_reservation_sha256,
            final_state=observation.state,
            requested_quantity=observation.requested_quantity,
            filled_quantity=observation.cumulative_filled_quantity,
            trade_count=observation.fill_trade_count,
            order_revision=observation.order_revision,
            journal_revision=observation.journal_revision,
            journal_record_sha256=observation.journal_record_sha256,
            writer_owner_id=observation.writer_owner_id,
            writer_fencing_token=observation.writer_fencing_token,
            writer_fence_sha256=observation.writer_fence_sha256,
        )


def _baseline(
    scope: AccountScope,
    *,
    observed_at_ns: int = _NOW_NS,
    valid_until_ns: int = _NOW_NS + 3_600_000_000_000,
) -> GrossExposureBaselineProof:
    return GrossExposureBaselineProof(
        scope=scope,
        account_revision=1,
        notional_unit="USD",
        account_gross_notional=Decimal(0),
        account_active_increase_intent_count=0,
        strategy_baselines=(),
        unmanaged_open_order_count=0,
        complete_positions=True,
        complete_open_orders=True,
        source_snapshot_sha256=_sha("baseline-snapshot"),
        positions_sha256=_sha("baseline-positions"),
        open_orders_sha256=_sha("baseline-open-orders"),
        valuation_facts_sha256=_sha("baseline-valuation"),
        source_schema_version="integer-clock-baseline-v1",
        observed_at_ns=observed_at_ns,
        valid_until_ns=valid_until_ns,
        writer_owner_id=_OWNER,
        writer_fencing_token=1,
        writer_fence_sha256=_sha("baseline-fence"),
    )


def _open_gate(tmp_path, clock_ns, authority, *, install_baseline=True, clock=None):
    scope = AccountScope("fixture", "integer-clock-account", "sandbox")
    policy = RiskPolicy(
        "integer-clock-policy",
        Decimal("1000"),
        max_increase_count=8,
        permit_ttl_seconds=3600,
        require_strategy_allocation=True,
        notional_unit="USD",
        exposure_accounting_mode=ExposureAccountingMode.LIVE_GROSS,
        max_gross_occupancy_notional=Decimal("1000"),
        max_gross_occupancy_intent_count=8,
        max_exposure_facts_age_seconds=3600,
    )
    options = {}
    if clock is not None:
        options["clock"] = clock
    if clock_ns is not None:
        options["clock_ns"] = clock_ns
    gate = DurableRiskGate(
        tmp_path / "risk.sqlite3",
        policy,
        execution_journal_authority=authority,
        gross_exposure_authority=authority,
        **options,
    )
    gate.set_strategy_allocation(
        scope,
        "strategy-a",
        "allocation-v1",
        max_notional=Decimal("1000"),
        notional_unit="USD",
        max_gross_occupancy_notional=Decimal("1000"),
        max_gross_occupancy_intent_count=8,
    )
    if install_baseline:
        gate.install_gross_exposure_baseline(_baseline(scope))
    return gate, scope, authority


def _intent(scope: AccountScope) -> RiskIntent:
    return RiskIntent(
        intent_id="integer-clock-order",
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal("100"),
        payload_fingerprint=_sha("integer-clock-order-request"),
        strategy_id="strategy-a",
        allocation_version="allocation-v1",
        instrument="BTC-USDT",
        quantity=Decimal("5"),
        quantity_unit="BTC",
        notional_unit="USD",
    )


def _prepare_tracked_order(gate: DurableRiskGate, scope: AccountScope):
    intent = _intent(scope)
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)
    claim = gate.dispatch_claim_binding(permit.permit_id)
    gate.settle(permit.permit_id)
    tracked = DispatchTrackedOrderProof(
        scope=scope,
        permit_id=permit.permit_id,
        intent_id=intent.intent_id,
        intent_hash=claim.intent_hash,
        cause_id=claim.cause_id,
        claim_digest=claim.claim_digest,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        dispatch_attempt_count=1,
        journal_revision=2,
        journal_record_sha256=_sha("tracked-order-record"),
        reconciliation_evidence_sha256=_sha("tracked-order-reconciliation"),
        writer_fence_sha256=_FENCE_SHA256,
        provider_order_id="provider-order-integer-clock",
        accepted_request_sha256=_sha("accepted-request"),
        exposure_reservation_id="risk-exposure-integer-clock",
        exposure_reservation_sha256=_sha("risk-exposure-digest"),
    )
    gate.resolve_dispatch_freeze(tracked)
    return intent, claim, tracked


def _order_observation(
    scope: AccountScope,
    claim,
    tracked: DispatchTrackedOrderProof,
    *,
    observed_at_ns: int = _NOW_NS,
    valid_until_ns: int = _NOW_NS + 3_600_000_000_000,
) -> OrderExposureObservationProof:
    return OrderExposureObservationProof(
        scope=scope,
        permit_id=claim.permit_id,
        intent_id=claim.intent_id,
        intent_hash=claim.intent_hash,
        dispatch_claim_digest=claim.claim_digest,
        dispatch_proof_sha256=tracked.fingerprint,
        provider_order_id="provider-order-integer-clock",
        accepted_request_sha256=_sha("accepted-request"),
        exposure_reservation_id="risk-exposure-integer-clock",
        exposure_reservation_sha256=_sha("risk-exposure-digest"),
        order_revision=1,
        journal_revision=3,
        journal_record_sha256=_sha("order-record"),
        observation_sha256=_sha("order-observation"),
        fill_history_sha256=_sha("empty-fill-history"),
        source_alias_map_sha256=_sha("order-aliases"),
        state=OrderExposureState.ACKED,
        requested_quantity=Decimal("5"),
        cumulative_filled_quantity=Decimal(0),
        leaves_quantity=Decimal("5"),
        filled_gross_notional=Decimal(0),
        leaves_gross_notional=Decimal("100"),
        leaves_valuation_price=Decimal("20"),
        notional_unit="USD",
        complete_order_snapshot=True,
        complete_fill_history=True,
        fill_watermark_revision=1,
        source_contract_ref="fixture/BTC-USDT",
        source_contract_version="contract-v1",
        provider_profile_version="profile-v1",
        normalizer_schema_version="normalizer-v1",
        order_side="BUY",
        position_effect="OPEN",
        fills=(),
        fill_trade_count=0,
        fill_ids_sha256=fill_ids_sha256(()),
        instrument_id="BTC-USDT",
        instrument_version="metadata-v1",
        instrument_multiplier=Decimal(1),
        quote_currency="USD",
        valuation_unit="USD",
        instrument_metadata_sha256=_sha("instrument-metadata"),
        instrument_metadata_observed_at_ns=observed_at_ns,
        instrument_metadata_valid_until_ns=valid_until_ns,
        valuation_facts_sha256=_sha("valuation-facts"),
        valuation_observed_at_ns=observed_at_ns,
        valuation_valid_until_ns=valid_until_ns,
        fx_pair=None,
        fx_rate=None,
        fx_observed_at_ns=None,
        fx_valid_until_ns=None,
        observed_at_ns=observed_at_ns,
        valid_until_ns=valid_until_ns,
        writer_owner_id=_OWNER,
        writer_fencing_token=2,
        writer_fence_sha256=_FENCE_SHA256,
    )


def _terminal_proof(
    scope: AccountScope,
    claim,
    *,
    observed_at_ns: int = _NOW_NS,
    valid_until_ns: int = _NOW_NS + 3_600_000_000_000,
) -> DispatchExposureResolutionProof:
    fill = OrderFillFact(
        trade_id="integer-clock-terminal-trade",
        quantity=Decimal("5"),
        price=Decimal("20"),
        side="BUY",
        position_effect="OPEN",
        fee_amount=Decimal(0),
        fee_currency="USD",
        source_record_sha256=_sha("terminal-fill-record"),
        source_revision=3,
    )
    observation = OrderExposureObservationProof(
        scope=scope,
        permit_id=claim.permit_id,
        intent_id=claim.intent_id,
        intent_hash=claim.intent_hash,
        dispatch_claim_digest=claim.claim_digest,
        dispatch_proof_sha256=None,
        provider_order_id="provider-order-integer-clock",
        accepted_request_sha256=_sha("accepted-request"),
        exposure_reservation_id="risk-exposure-integer-clock",
        exposure_reservation_sha256=_sha("risk-exposure-digest"),
        order_revision=2,
        journal_revision=3,
        journal_record_sha256=_sha("terminal-order-record"),
        observation_sha256=_sha("terminal-order-observation"),
        fill_history_sha256=_sha("terminal-fill-history"),
        source_alias_map_sha256=_sha("terminal-aliases"),
        state=OrderExposureState.FILLED,
        requested_quantity=Decimal("5"),
        cumulative_filled_quantity=Decimal("5"),
        leaves_quantity=Decimal(0),
        filled_gross_notional=Decimal("100"),
        leaves_gross_notional=Decimal(0),
        leaves_valuation_price=None,
        notional_unit="USD",
        complete_order_snapshot=True,
        complete_fill_history=True,
        fill_watermark_revision=3,
        source_contract_ref="fixture/BTC-USDT",
        source_contract_version="contract-v1",
        provider_profile_version="profile-v1",
        normalizer_schema_version="normalizer-v1",
        order_side="BUY",
        position_effect="OPEN",
        fills=(fill,),
        fill_trade_count=1,
        fill_ids_sha256=fill_ids_sha256((fill,)),
        instrument_id="BTC-USDT",
        instrument_version="metadata-v1",
        instrument_multiplier=Decimal(1),
        quote_currency="USD",
        valuation_unit="USD",
        instrument_metadata_sha256=_sha("instrument-metadata"),
        instrument_metadata_observed_at_ns=observed_at_ns,
        instrument_metadata_valid_until_ns=valid_until_ns,
        valuation_facts_sha256=_sha("valuation-facts"),
        valuation_observed_at_ns=observed_at_ns,
        valuation_valid_until_ns=valid_until_ns,
        fx_pair=None,
        fx_rate=None,
        fx_observed_at_ns=None,
        fx_valid_until_ns=None,
        observed_at_ns=observed_at_ns,
        valid_until_ns=valid_until_ns,
        writer_owner_id=_OWNER,
        writer_fencing_token=2,
        writer_fence_sha256=_FENCE_SHA256,
    )
    return DispatchExposureResolutionProof(
        claim=claim,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        dispatch_attempt_count=1,
        reconciliation_evidence_sha256=_sha("terminal-reconciliation"),
        observation=observation,
    )


def test_default_clock_uses_integer_time_ns_for_baseline_freshness(tmp_path, monkeypatch):
    monkeypatch.setattr(admission_module.time, "time", lambda: _NOW_SECONDS)
    monkeypatch.setattr(admission_module.time, "time_ns", lambda: _NOW_NS)
    authority = _SourceBoundAuthority()
    gate, scope, _ = _open_gate(tmp_path, None, authority, install_baseline=False, clock=None)

    gate.install_gross_exposure_baseline(_baseline(scope))

    assert authority.baseline_calls == 1
    assert gate.gross_exposure_snapshot(scope)["account_baseline_notional"] == Decimal(0)
    gate.close()


def test_legacy_seconds_clock_still_drives_nanosecond_freshness(tmp_path):
    authority = _SourceBoundAuthority()
    gate, scope, _ = _open_gate(
        tmp_path,
        None,
        authority,
        install_baseline=False,
        clock=lambda: _NOW_SECONDS,
    )

    legacy_now_ns = int(float(_NOW_SECONDS) * 1_000_000_000)
    gate.install_gross_exposure_baseline(
        _baseline(
            scope,
            observed_at_ns=legacy_now_ns,
            valid_until_ns=legacy_now_ns + 3_600_000_000_000,
        )
    )

    assert authority.baseline_calls == 1
    gate.close()


@pytest.mark.parametrize(
    ("observed_at_ns", "valid_until_ns"),
    ((_NOW_NS + 1, _NOW_NS + 10), (_NOW_NS - 1, _NOW_NS)),
    ids=("one-ns-future", "expiry-equals-now"),
)
def test_baseline_rejects_strict_future_and_expiry_edges(tmp_path, observed_at_ns, valid_until_ns):
    clock_ns = _NanosecondClock()
    authority = _SourceBoundAuthority()
    gate, scope, _ = _open_gate(tmp_path, clock_ns, authority, install_baseline=False)

    with pytest.raises(RiskDeniedError) as rejected:
        gate.install_gross_exposure_baseline(
            _baseline(scope, observed_at_ns=observed_at_ns, valid_until_ns=valid_until_ns)
        )

    assert rejected.value.code == "GROSS_EXPOSURE_BASELINE_STALE"
    assert authority.baseline_calls == 0
    assert gate.gross_exposure_snapshot(scope)["account_baseline_notional"] is None
    gate.close()


@pytest.mark.parametrize("clock_value", (True, 1.0, -1), ids=("bool", "float", "negative"))
def test_invalid_integer_clock_results_fail_before_baseline_authority(tmp_path, clock_value):
    authority = _SourceBoundAuthority()
    gate, scope, _ = _open_gate(tmp_path, lambda: clock_value, authority, install_baseline=False)

    with pytest.raises(ValueError, match="clock_ns must return a non-negative integer"):
        gate.install_gross_exposure_baseline(_baseline(scope))

    assert authority.baseline_calls == 0
    assert gate.gross_exposure_snapshot(scope)["account_baseline_notional"] is None
    gate.close()


def test_baseline_expiring_at_commit_boundary_rolls_back(tmp_path):
    clock_ns = _NanosecondClock()
    authority = _SourceBoundAuthority()
    gate, scope, _ = _open_gate(tmp_path, clock_ns, authority, install_baseline=False)
    clock_ns.script = (_NOW_NS, _NOW_NS, _NOW_NS + 3)

    with pytest.raises(RiskDeniedError) as rejected:
        gate.install_gross_exposure_baseline(_baseline(scope, valid_until_ns=_NOW_NS + 3))

    assert rejected.value.code == "GROSS_EXPOSURE_BASELINE_STALE"
    assert clock_ns.calls == 3
    assert gate.gross_exposure_snapshot(scope)["account_baseline_notional"] is None
    gate.close()


def test_group_facts_expiring_at_commit_boundary_roll_back_full_vector(tmp_path):
    clock_ns = _NanosecondClock()
    scope = AccountScope("fixture", "integer-clock-group-account", "sandbox")
    gate = DurableRiskGate(
        tmp_path / "group-risk.sqlite3",
        RiskPolicy(
            "integer-clock-group-policy",
            Decimal("1000"),
            max_increase_count=8,
            permit_ttl_seconds=3600,
            require_strategy_allocation=True,
            notional_unit="USD",
        ),
        clock_ns=clock_ns,
    )
    gate.set_strategy_allocation(
        scope,
        "strategy-a",
        "allocation-v1",
        max_notional=Decimal("1000"),
        notional_unit="USD",
    )
    intent = replace(
        _intent(scope),
        exposure_profile_fingerprint=_sha("group-profile"),
        instrument_facts_observed_at_ns=_NOW_NS,
        instrument_facts_valid_until_ns=_NOW_NS + 10,
    )
    clock_ns.calls = 0
    clock_ns.script = (_NOW_NS, _NOW_NS, _NOW_NS, _NOW_NS + 10)

    with pytest.raises(RiskDeniedError) as rejected:
        gate.reserve_group_vector(
            scope,
            "integer-clock-group",
            (RiskGroupLegIntent("leg-a", intent),),
            deadline_ns=_NOW_NS + 100,
        )

    assert rejected.value.code == "GROUP_EXPOSURE_FACTS_STALE"
    assert clock_ns.calls == 4
    assert gate.snapshot(scope)["increase_count"] == 0
    with pytest.raises(RiskDeniedError) as absent:
        gate.read_group_vector_snapshot(scope, "integer-clock-group")
    assert absent.value.code == "GROUP_NOT_FOUND"
    gate.close()


def test_live_gross_group_facts_expiring_after_gross_scan_roll_back_full_vector(tmp_path):
    clock_ns = _NanosecondClock()
    authority = _SourceBoundAuthority()
    gate, scope, _ = _open_gate(tmp_path, clock_ns, authority)
    intent = replace(
        _intent(scope),
        exposure_profile_fingerprint=_sha("live-gross-group-profile"),
        instrument_facts_observed_at_ns=_NOW_NS,
        instrument_facts_valid_until_ns=_NOW_NS + 10,
    )
    clock_ns.calls = 0
    clock_ns.script = (
        _NOW_NS,
        _NOW_NS,
        _NOW_NS,
        _NOW_NS,
        _NOW_NS,
        _NOW_NS,
        _NOW_NS + 10,
    )

    with pytest.raises(RiskDeniedError) as rejected:
        gate.reserve_group_vector(
            scope,
            "integer-clock-live-gross-group",
            (RiskGroupLegIntent("leg-a", intent),),
            deadline_ns=_NOW_NS + 100,
        )

    assert rejected.value.code == "GROUP_EXPOSURE_FACTS_STALE"
    assert clock_ns.calls == 7
    assert gate.snapshot(scope)["increase_count"] == 0
    with pytest.raises(RiskDeniedError) as absent:
        gate.read_group_vector_snapshot(scope, "integer-clock-live-gross-group")
    assert absent.value.code == "GROUP_NOT_FOUND"
    assert gate.gross_exposure_snapshot(scope)["orders"] == []
    gate.close()


def test_order_observation_accepts_observed_at_exactly_now_through_sqlite_gate(tmp_path):
    clock_ns = _NanosecondClock()
    authority = _SourceBoundAuthority()
    gate, scope, _ = _open_gate(tmp_path, clock_ns, authority)
    _, claim, tracked = _prepare_tracked_order(gate, scope)

    snapshot = gate.apply_order_exposure_observation(_order_observation(scope, claim, tracked))

    assert snapshot.observed_at_ns == _NOW_NS
    assert snapshot.open_gross_notional == Decimal("100")
    assert authority.order_calls == 1
    assert len(gate.gross_exposure_snapshot(scope)["orders"]) == 1
    gate.close()


@pytest.mark.parametrize(
    ("observed_at_ns", "valid_until_ns"),
    ((_NOW_NS + 1, _NOW_NS + 10), (_NOW_NS - 1, _NOW_NS)),
    ids=("one-ns-future", "expiry-equals-now"),
)
def test_order_observation_rejects_strict_future_and_expiry_edges(
    tmp_path, observed_at_ns, valid_until_ns
):
    clock_ns = _NanosecondClock()
    authority = _SourceBoundAuthority()
    gate, scope, _ = _open_gate(tmp_path, clock_ns, authority)
    _, claim, tracked = _prepare_tracked_order(gate, scope)

    with pytest.raises(RiskDeniedError) as rejected:
        gate.apply_order_exposure_observation(
            _order_observation(
                scope,
                claim,
                tracked,
                observed_at_ns=observed_at_ns,
                valid_until_ns=valid_until_ns,
            )
        )

    assert rejected.value.code == "ORDER_EXPOSURE_OBSERVATION_STALE"
    assert authority.order_calls == 0
    assert gate.gross_exposure_snapshot(scope)["orders"] == []
    gate.close()


def test_order_observation_expiry_at_transaction_commit_rolls_back(tmp_path):
    clock_ns = _NanosecondClock()
    authority = _SourceBoundAuthority()
    gate, scope, _ = _open_gate(tmp_path, clock_ns, authority)
    _, claim, tracked = _prepare_tracked_order(gate, scope)
    observation = _order_observation(
        scope,
        claim,
        tracked,
        valid_until_ns=_NOW_NS + 10,
    )
    clock_ns.calls = 0
    clock_ns.script = (_NOW_NS, _NOW_NS, _NOW_NS + 10)

    with pytest.raises(RiskDeniedError) as rejected:
        gate.apply_order_exposure_observation(observation)

    assert rejected.value.code == "ORDER_EXPOSURE_OBSERVATION_STALE"
    assert clock_ns.calls == 3
    assert gate.gross_exposure_snapshot(scope)["orders"] == []
    gate.close()


def test_terminal_exposure_accepts_observed_at_exactly_now(tmp_path):
    clock_ns = _NanosecondClock()
    authority = _SourceBoundAuthority()
    gate, scope, _ = _open_gate(tmp_path, clock_ns, authority)
    intent = _intent(scope)
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)
    claim = gate.dispatch_claim_binding(permit.permit_id)
    gate.settle(permit.permit_id)
    proof = _terminal_proof(scope, claim)

    receipt = gate.resolve_dispatch_exposure(proof)

    assert receipt.status is DispatchExposureResolutionReceiptStatus.TERMINAL_EXPOSURE_RESOLVED
    assert receipt.exposure_proof_sha256 == proof.observation.fingerprint
    assert receipt.filled_quantity == Decimal("5")
    assert authority.terminal_calls == 1
    assert len(gate.gross_exposure_snapshot(scope)["orders"]) == 1
    gate.close()


def test_terminal_exposure_expiring_at_commit_boundary_rolls_back(tmp_path):
    clock_ns = _NanosecondClock()
    authority = _SourceBoundAuthority()
    gate, scope, _ = _open_gate(tmp_path, clock_ns, authority)
    intent = _intent(scope)
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)
    claim = gate.dispatch_claim_binding(permit.permit_id)
    gate.settle(permit.permit_id)
    proof = _terminal_proof(scope, claim, valid_until_ns=_NOW_NS + 10)
    clock_ns.calls = 0
    clock_ns.script = (_NOW_NS, _NOW_NS, _NOW_NS + 10)

    with pytest.raises(RiskDeniedError) as rejected:
        gate.resolve_dispatch_exposure(proof)

    assert rejected.value.code == "ORDER_EXPOSURE_OBSERVATION_STALE"
    assert clock_ns.calls == 3
    receipt = gate.dispatch_exposure_resolution_receipt(permit.permit_id)
    assert receipt.status is DispatchExposureResolutionReceiptStatus.UNRESOLVED_ACTIVE
    assert receipt.dispatch_latch_active is True
    assert gate.gross_exposure_snapshot(scope)["orders"] == []
    gate.close()
