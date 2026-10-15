"""First positive-fill terminal evidence resolves a Risk dispatch latch atomically."""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
from types import SimpleNamespace

import pytest

from bt_api_risk import (
    AccountScope,
    DispatchEvidenceClass,
    DispatchExposureResolutionProof,
    DispatchExposureResolutionReceiptStatus,
    DurableRiskAdmissionAdapter,
    DurableRiskGate,
    ExposureAccountingMode,
    GrossExposureBaselineProof,
    IntentAction,
    OrderExposureObservationProof,
    OrderExposureState,
    OrderFillFact,
    PermitInvalidError,
    RiskAdmissionDeniedError,
    RiskDeniedError,
    RiskGroupLegIntent,
    RiskGroupReservationState,
    RiskIntent,
    RiskPolicy,
    VerifiedDispatchExposureResolution,
    VerifiedGrossExposureBaseline,
    fill_ids_sha256,
)

_NOW = 100.0
_NOW_NS = int(_NOW * 1_000_000_000)
_OWNER = "synthetic-account-writer"
_FENCE_TOKEN = 2
_FENCE_SHA256 = hashlib.sha256(b"current-account-fence").hexdigest()


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class _Clock:
    def __init__(self) -> None:
        self.value = _NOW

    def __call__(self) -> float:
        return self.value


class _SourceBoundAuthority:
    """Synthetic journal authority for the local SQLite state tests only."""

    def __init__(self) -> None:
        self.tamper_fence = False

    @contextmanager
    def baseline_guard(self, proof):
        yield VerifiedGrossExposureBaseline(
            scope=proof.scope,
            proof_sha256=proof.fingerprint,
            account_revision=proof.account_revision,
            writer_owner_id=proof.writer_owner_id,
            writer_fencing_token=proof.writer_fencing_token,
            writer_fence_sha256=proof.writer_fence_sha256,
        )

    @contextmanager
    def dispatch_exposure_resolution_guard(self, proof, *, claim):
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
            writer_fencing_token=(
                observation.writer_fencing_token + 1
                if self.tamper_fence
                else observation.writer_fencing_token
            ),
            writer_fence_sha256=(
                _sha("wrong-fence") if self.tamper_fence else observation.writer_fence_sha256
            ),
        )


def _risk(tmp_path, *, live_gross: bool = False):
    clock = _Clock()
    authority = _SourceBoundAuthority()
    scope = AccountScope("fixture", "synthetic-risk-account", "sandbox")
    mode = (
        ExposureAccountingMode.LIVE_GROSS
        if live_gross
        else ExposureAccountingMode.RESERVATIONS_ONLY
    )
    policy = RiskPolicy(
        "terminal-exposure-test",
        Decimal("5000"),
        max_increase_count=8,
        permit_ttl_seconds=10_000,
        require_strategy_allocation=True,
        notional_unit="USD",
        exposure_accounting_mode=mode,
        max_gross_occupancy_notional=Decimal("1000") if live_gross else None,
        max_gross_occupancy_intent_count=8 if live_gross else None,
        max_exposure_facts_age_seconds=3600 if live_gross else None,
    )
    gate = DurableRiskGate(
        tmp_path / "risk.sqlite3",
        policy,
        clock=clock,
        execution_journal_authority=authority,
        gross_exposure_authority=authority if live_gross else None,
    )
    gate.set_strategy_allocation(
        scope,
        "strategy-a",
        "allocation-v1",
        max_notional=Decimal("5000"),
        notional_unit="USD",
        max_gross_occupancy_notional=Decimal("1000") if live_gross else None,
        max_gross_occupancy_intent_count=8 if live_gross else None,
    )
    if live_gross:
        baseline = GrossExposureBaselineProof(
            scope=scope,
            account_revision=1,
            notional_unit="USD",
            account_gross_notional=Decimal(0),
            account_active_increase_intent_count=0,
            strategy_baselines=(),
            unmanaged_open_order_count=0,
            complete_positions=True,
            complete_open_orders=True,
            source_snapshot_sha256=_sha("complete-empty-baseline"),
            positions_sha256=_sha("empty-positions"),
            open_orders_sha256=_sha("empty-open-orders"),
            valuation_facts_sha256=_sha("baseline-valuation"),
            source_schema_version="synthetic-baseline-v1",
            observed_at_ns=_NOW_NS,
            valid_until_ns=_NOW_NS + 3_600_000_000_000,
            writer_owner_id=_OWNER,
            writer_fencing_token=1,
            writer_fence_sha256=_sha("baseline-fence"),
        )
        gate.install_gross_exposure_baseline(baseline)
    return gate, scope, clock, authority


def _intent(scope: AccountScope, intent_id: str, quantity: str, notional: str) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal(notional),
        payload_fingerprint=_sha(f"{intent_id}|{quantity}|{notional}"),
        strategy_id="strategy-a",
        allocation_version="allocation-v1",
        instrument="venue/contract-a",
        quantity=Decimal(quantity),
        quantity_unit="contract",
        notional_unit="USD",
        exposure_profile_fingerprint="a" * 64,
        instrument_facts_observed_at_ns=_NOW_NS,
        instrument_facts_valid_until_ns=_NOW_NS + 3_600_000_000_000,
    )


def _prepare_claim(gate: DurableRiskGate, scope: AccountScope):
    vector = gate.reserve_group_vector(
        scope,
        "hedge-group",
        (
            RiskGroupLegIntent("first", _intent(scope, "first-intent", "5", "500")),
            RiskGroupLegIntent("second", _intent(scope, "second-intent", "1", "100")),
        ),
        deadline_ns=_NOW_NS + 100_000_000_000,
    )
    first = vector.legs[0]
    actual = _intent(scope, "first-intent", "3", "300")
    gate.claim_group_leg(
        scope,
        vector.group_id,
        first.leg_id,
        first.permit_id,
        actual,
        expected_group_fingerprint=vector.group_fingerprint,
        expected_deadline_ns=vector.deadline_ns,
    )
    claim = gate.dispatch_claim_binding(first.permit_id)
    gate.settle(first.permit_id)
    return vector, first, actual, claim


def _fill(trade_id: str, *, revision: int) -> OrderFillFact:
    return OrderFillFact(
        trade_id=trade_id,
        quantity=Decimal("1"),
        price=Decimal("100"),
        side="BUY",
        position_effect="OPEN",
        fee_amount=Decimal("0.01"),
        fee_currency="USD",
        source_record_sha256=_sha("fill-source:" + trade_id),
        source_revision=revision,
    )


def _observation(claim, *, state=OrderExposureState.CANCELLED, complete=True):
    if state is OrderExposureState.FILLED:
        fills = (
            _fill("trade-1", revision=3),
            _fill("trade-2", revision=4),
            _fill("trade-3", revision=5),
        )
        cumulative_filled_quantity = Decimal("3")
        fill_watermark_revision = 5
    else:
        fills = (_fill("trade-1", revision=3), _fill("trade-2", revision=4))
        cumulative_filled_quantity = Decimal("2")
        fill_watermark_revision = 4 if complete else 0
    return OrderExposureObservationProof(
        scope=claim.scope,
        permit_id=claim.permit_id,
        intent_id=claim.intent_id,
        intent_hash=claim.intent_hash,
        dispatch_claim_digest=claim.claim_digest,
        dispatch_proof_sha256=None,
        provider_order_id="provider-order-first",
        accepted_request_sha256=_sha("accepted-child-request"),
        exposure_reservation_id="risk-exposure-first",
        exposure_reservation_sha256=_sha("risk-exposure-first-digest"),
        order_revision=2,
        journal_revision=6,
        journal_record_sha256=_sha("terminal-observation-record"),
        observation_sha256=_sha("terminal-order-snapshot"),
        fill_history_sha256=_sha("complete-fill-history"),
        source_alias_map_sha256=_sha("explicit-source-aliases"),
        state=state,
        requested_quantity=Decimal("3"),
        cumulative_filled_quantity=cumulative_filled_quantity,
        leaves_quantity=Decimal("0"),
        # Deliberately understate the source valuation: Risk must derive the
        # conservative gross amount from the immutable two $100 fill facts.
        filled_gross_notional=Decimal("1"),
        leaves_gross_notional=Decimal("0"),
        leaves_valuation_price=None,
        notional_unit="USD",
        complete_order_snapshot=complete and state is not OrderExposureState.UNKNOWN,
        complete_fill_history=complete and state is not OrderExposureState.UNKNOWN,
        fill_watermark_revision=fill_watermark_revision,
        source_contract_ref="synthetic/contract-a",
        source_contract_version="contract-v1",
        provider_profile_version="source-v1",
        normalizer_schema_version="normalizer-v1",
        order_side="BUY",
        position_effect="OPEN",
        fills=fills,
        fill_trade_count=len(fills),
        fill_ids_sha256=fill_ids_sha256(fills),
        instrument_id="venue/contract-a",
        instrument_version="metadata-v1",
        instrument_multiplier=Decimal("1"),
        quote_currency="USD",
        valuation_unit="USD",
        instrument_metadata_sha256=_sha("instrument-metadata"),
        instrument_metadata_observed_at_ns=_NOW_NS,
        instrument_metadata_valid_until_ns=_NOW_NS + 3_600_000_000_000,
        valuation_facts_sha256=_sha("valuation-facts"),
        valuation_observed_at_ns=_NOW_NS,
        valuation_valid_until_ns=_NOW_NS + 3_600_000_000_000,
        fx_pair=None,
        fx_rate=None,
        fx_observed_at_ns=None,
        fx_valid_until_ns=None,
        observed_at_ns=_NOW_NS,
        valid_until_ns=_NOW_NS + 3_600_000_000_000,
        writer_owner_id=_OWNER,
        writer_fencing_token=_FENCE_TOKEN,
        writer_fence_sha256=_FENCE_SHA256,
    )


def _proof(claim, observation) -> DispatchExposureResolutionProof:
    return DispatchExposureResolutionProof(
        claim=claim,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        dispatch_attempt_count=1,
        reconciliation_evidence_sha256=_sha("complete-terminal-reconciliation"),
        observation=observation,
    )


@pytest.mark.parametrize("live_gross", (False, True), ids=("reservations-only", "live-gross"))
@pytest.mark.parametrize(
    ("state", "filled"),
    ((OrderExposureState.CANCELLED, Decimal("2")), (OrderExposureState.FILLED, Decimal("3"))),
    ids=("partial-fill-cancel", "full-fill"),
)
def test_first_terminal_positive_fill_resolves_group_leg_and_seeds_once(
    tmp_path, live_gross, state, filled
):
    gate, scope, _, _ = _risk(tmp_path, live_gross=live_gross)
    vector, first, actual, claim = _prepare_claim(gate, scope)
    observation = _observation(claim, state=state)
    proof = _proof(claim, observation)
    adapter = DurableRiskAdmissionAdapter(gate, lambda _order: actual)

    receipt = adapter.resolve_dispatch_exposure(proof)
    assert receipt.status is DispatchExposureResolutionReceiptStatus.TERMINAL_EXPOSURE_RESOLVED
    assert receipt.claim == claim
    assert receipt.proof_sha256 == proof.fingerprint
    assert receipt.exposure_proof_sha256 == observation.fingerprint
    assert receipt.final_state is state
    assert receipt.requested_quantity == Decimal("3")  # actual child, not reserved max 5
    assert receipt.filled_quantity == filled
    assert receipt.trade_count == len(observation.fills)
    assert receipt.order_revision == 2
    assert receipt.journal_revision == 6
    assert receipt.dispatch_latch_active is False
    assert receipt.has_other_active_freezes is False

    group = gate.query_group_vector(scope, vector.group_id)
    first_after = group.legs[0]
    assert first_after.permit_id == first.permit_id
    assert first_after.resolved is True
    assert first_after.claimed is True
    assert first_after.state is RiskGroupReservationState.SETTLED
    assert first_after.reserved_intent_hash == first.reserved_intent_hash
    assert first_after.actual_intent_hash == actual.fingerprint
    read_snapshot = gate.read_group_vector_snapshot(scope, vector.group_id)
    assert read_snapshot.legs[0].claimed is True
    assert read_snapshot.legs[0].resolved is True
    assert read_snapshot.legs[0].state is RiskGroupReservationState.SETTLED
    assert read_snapshot.legs[0].actual_intent_hash == actual.fingerprint
    assert gate.dispatch_exposure_resolution_receipt(first.permit_id) == receipt

    projection = gate.gross_exposure_snapshot(scope)["orders"]
    assert len(projection) == 1
    assert projection[0].requested_quantity == Decimal("3")
    assert projection[0].cumulative_filled_quantity == filled
    assert projection[0].open_gross_notional == 0
    assert projection[0].filled_gross_notional == filled * Decimal("100")

    # Neither repeated queries nor an attempted legacy post-ACK update may
    # insert a second exposure or reinterpret this nonzero proof as ACKED.
    assert adapter.dispatch_exposure_resolution_receipt(first.permit_id) == receipt
    with pytest.raises(PermitInvalidError) as duplicate:
        gate.resolve_dispatch_exposure(proof)
    assert duplicate.value.code == "DISPATCH_PROOF_REPLAYED"
    if live_gross:
        with pytest.raises(RiskDeniedError) as missing_acked_proof:
            gate.apply_order_exposure_observation(observation)
        assert missing_acked_proof.value.code == "ORDER_EXPOSURE_TRACKED_PROOF_REQUIRED"
        assert len(gate.gross_exposure_snapshot(scope)["orders"]) == 1
    gate.close()


def test_resolver_preserves_other_freezes_and_reports_them_in_transaction(tmp_path):
    gate, scope, _, _ = _risk(tmp_path, live_gross=True)
    vector, first, _, claim = _prepare_claim(gate, scope)
    gate.freeze(scope, "manual-review", "manual review remains required")

    receipt = gate.resolve_dispatch_exposure(_proof(claim, _observation(claim)))
    assert receipt.dispatch_latch_active is False
    assert receipt.has_other_active_freezes is True
    assert "manual review remains required" in gate.active_freeze_reasons(scope)
    assert gate.query_group_vector(scope, vector.group_id).legs[0].resolved is True
    gate.close()


def test_group_adapter_uses_explicit_trusted_risk_scope_not_wire_account_ref(tmp_path):
    gate, trusted_scope, _, _ = _risk(tmp_path)

    def raw_order(intent_id: str, quantity: str, notional: str):
        return SimpleNamespace(
            intent_id=intent_id,
            quantity=quantity,
            notional=notional,
            scope=SimpleNamespace(
                provider=trusted_scope.provider,
                account_ref="wire-account-reference",
                environment=trusted_scope.environment,
                strategy_id="strategy-a",
            ),
        )

    def trusted_mapper(order):
        return _intent(trusted_scope, order.intent_id, order.quantity, order.notional)

    trusted_mapper.wire_account_ref = "wire-account-reference"

    adapter = DurableRiskAdmissionAdapter(gate, trusted_mapper)
    vector = adapter.reserve_group_vector(
        trusted_scope,
        "wire-account-mapped-group",
        (("first", raw_order("first-intent", "5", "500")),),
        deadline_ns=_NOW_NS + 100_000_000_000,
    )
    leg = vector.legs[0]
    claim = adapter.claim_group_leg(
        raw_order("first-intent", "3", "300"),
        scope=trusted_scope,
        group_id=vector.group_id,
        leg_id=leg.leg_id,
        permit_reference=leg.permit_id,
        group_fingerprint=vector.group_fingerprint,
        deadline_ns=vector.deadline_ns,
    )
    assert claim.claim.scope == trusted_scope
    assert claim.actual_quantity == Decimal("3")

    wrong_scope = AccountScope(
        trusted_scope.provider, "wire-account-reference", trusted_scope.environment
    )
    with pytest.raises(RiskAdmissionDeniedError) as rejected:
        adapter.claim_group_leg(
            raw_order("first-intent", "3", "300"),
            scope=wrong_scope,
            group_id=vector.group_id,
            leg_id=leg.leg_id,
            permit_reference=leg.permit_id,
            group_fingerprint=vector.group_fingerprint,
            deadline_ns=vector.deadline_ns,
        )
    assert rejected.value.code == "GROUP_SCOPE_MISMATCH"
    assert adapter.query_group_vector(trusted_scope, vector.group_id).legs[0].claimed is True
    gate.close()


def test_source_authority_fence_mismatch_leaves_claim_latched_and_unresolved(tmp_path):
    gate, scope, _, authority = _risk(tmp_path, live_gross=True)
    vector, first, _, claim = _prepare_claim(gate, scope)
    authority.tamper_fence = True

    with pytest.raises(PermitInvalidError) as rejected:
        gate.resolve_dispatch_exposure(_proof(claim, _observation(claim)))
    assert rejected.value.code == "DISPATCH_EXPOSURE_PROOF_REJECTED"
    unresolved = gate.dispatch_exposure_resolution_receipt(first.permit_id)
    assert unresolved.status is DispatchExposureResolutionReceiptStatus.UNRESOLVED_ACTIVE
    assert unresolved.dispatch_latch_active is True
    assert unresolved.has_other_active_freezes is False
    assert gate.query_group_vector(scope, vector.group_id).legs[0].resolved is False
    assert gate.gross_exposure_snapshot(scope)["orders"] == []
    gate.close()


def test_live_gross_resolver_uses_execution_authority_if_gross_adapter_has_no_terminal_guard(
    tmp_path,
):
    gate, scope, _, _ = _risk(tmp_path, live_gross=True)
    vector, first, _, claim = _prepare_claim(gate, scope)
    gate._gross_exposure_authority = object()

    receipt = gate.resolve_dispatch_exposure(_proof(claim, _observation(claim)))
    assert receipt.status is DispatchExposureResolutionReceiptStatus.TERMINAL_EXPOSURE_RESOLVED
    assert gate.query_group_vector(scope, vector.group_id).legs[0].resolved is True
    gate.close()


def test_incomplete_stale_unknown_and_mismatched_terminal_facts_are_rejected(tmp_path):
    gate, scope, clock, _ = _risk(tmp_path, live_gross=True)
    _, first, _, claim = _prepare_claim(gate, scope)

    with pytest.raises(ValueError, match="complete order and fill evidence"):
        replace(_observation(claim), complete_order_snapshot=False)

    unknown = _observation(claim, state=OrderExposureState.UNKNOWN, complete=False)
    with pytest.raises(ValueError, match="known terminal order state"):
        _proof(claim, unknown)

    changed_claim = replace(_observation(claim), dispatch_claim_digest=_sha("wrong-claim"))
    with pytest.raises(ValueError, match="does not bind the exact dispatch claim"):
        _proof(claim, changed_claim)

    wrong_unit = replace(
        _observation(claim),
        notional_unit="EUR",
        quote_currency="EUR",
        valuation_unit="EUR",
    )
    with pytest.raises(RiskDeniedError) as unit_mismatch:
        gate.resolve_dispatch_exposure(_proof(claim, wrong_unit))
    assert unit_mismatch.value.code == "ORDER_EXPOSURE_UNIT_MISMATCH"

    mismatched_quantity = replace(
        _observation(claim), requested_quantity=Decimal("5")
    )
    with pytest.raises(RiskDeniedError) as mismatch:
        gate.resolve_dispatch_exposure(_proof(claim, mismatched_quantity))
    assert mismatch.value.code == "ORDER_EXPOSURE_REQUEST_MISMATCH"

    stale = _proof(claim, _observation(claim))
    clock.value += 3601
    with pytest.raises(RiskDeniedError) as expired:
        gate.resolve_dispatch_exposure(stale)
    assert expired.value.code == "ORDER_EXPOSURE_OBSERVATION_STALE"
    assert gate.dispatch_exposure_resolution_receipt(first.permit_id).status is (
        DispatchExposureResolutionReceiptStatus.UNRESOLVED_ACTIVE
    )
    assert gate.gross_exposure_snapshot(scope)["orders"] == []
    gate.close()


def test_partial_resolution_rolls_back_seed_fills_resolution_and_latch_together(
    tmp_path, monkeypatch
):
    gate, scope, _, _ = _risk(tmp_path, live_gross=True)
    vector, first, _, claim = _prepare_claim(gate, scope)
    proof = _proof(claim, _observation(claim))

    def fail_after_exposure_seed(_connection, _proof):
        raise RuntimeError("synthetic failure after exposure row write")

    monkeypatch.setattr(gate, "_persist_order_fill_facts", fail_after_exposure_seed)
    with pytest.raises(PermitInvalidError) as rolled_back:
        gate.resolve_dispatch_exposure(proof)
    assert rolled_back.value.code == "DISPATCH_EXPOSURE_PROOF_REJECTED"
    assert gate.query_group_vector(scope, vector.group_id).legs[0].resolved is False
    assert gate.dispatch_exposure_resolution_receipt(first.permit_id).status is (
        DispatchExposureResolutionReceiptStatus.UNRESOLVED_ACTIVE
    )
    assert gate.gross_exposure_snapshot(scope)["orders"] == []
    assert "dispatch-inflight:first-intent" in gate.active_freeze_reasons(scope)
    gate.close()

