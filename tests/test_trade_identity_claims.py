"""DIM01 trade-identity declaration, mode binding, and atomic occupancy.

These focused package tests drive the durable Risk gate directly (no Host, no
entry module).  Declared proofs occupy ``(trade_id_domain_ref, identity_scope,
trade_id)`` inside the exact fill-persistence transaction of both the terminal
first-fill path and the incremental post-ACK path; undeclared proofs keep the
legacy semantics byte for byte.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from decimal import Decimal

import pytest

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
    PermitInvalidError,
    RiskDeniedError,
    RiskIntent,
    RiskPolicy,
    VerifiedDispatchExposureResolution,
    VerifiedDispatchResolution,
    VerifiedGrossExposureBaseline,
    VerifiedOrderExposureObservation,
    fill_ids_sha256,
)

_NOW = 100.0
_NOW_NS = int(_NOW * 1_000_000_000)
_OWNER = "synthetic-account-writer"
_FENCE_TOKEN = 2
_FENCE_SHA256 = hashlib.sha256(b"current-account-fence").hexdigest()
_DOMAIN_A = "fixture-domain-a-trades-v1"
_DOMAIN_B = "fixture-domain-b-trades-v1"


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class _Clock:
    def __init__(self) -> None:
        self.value = _NOW

    def __call__(self) -> float:
        return self.value


class _LocalAuthority:
    """Synthetic source authority for the local SQLite gate tests only."""

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
            writer_fencing_token=observation.writer_fencing_token,
            writer_fence_sha256=observation.writer_fence_sha256,
        )

    @contextmanager
    def order_observation_guard(self, proof, *, claim, tracked_order):
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


@pytest.fixture
def risk(tmp_path):
    scope = AccountScope("fixture", "identity-account", "sandbox")
    policy = RiskPolicy(
        "trade-identity-test",
        Decimal("100000"),
        max_increase_count=20,
        permit_ttl_seconds=10_000,
        require_strategy_allocation=True,
        notional_unit="USD",
        exposure_accounting_mode=ExposureAccountingMode.LIVE_GROSS,
        max_gross_occupancy_notional=Decimal("100000"),
        max_gross_occupancy_intent_count=20,
        max_exposure_facts_age_seconds=3600,
    )
    authority = _LocalAuthority()
    database = tmp_path / "identity-risk.sqlite3"
    gate = DurableRiskGate(
        database,
        policy,
        clock=_Clock(),
        execution_journal_authority=authority,
        gross_exposure_authority=authority,
    )
    gate.set_strategy_allocation(
        scope,
        "strategy-a",
        "allocation-v1",
        max_notional=Decimal("100000"),
        notional_unit="USD",
        max_gross_occupancy_notional=Decimal("100000"),
        max_gross_occupancy_intent_count=20,
    )
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
    return gate, scope, database


def _intent(scope: AccountScope, intent_id: str, *, instrument: str) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal("500"),
        payload_fingerprint=_sha("request:" + intent_id),
        strategy_id="strategy-a",
        allocation_version="allocation-v1",
        instrument=instrument,
        quantity=Decimal("5"),
        quantity_unit="contract",
        notional_unit="USD",
        exposure_profile_fingerprint="a" * 64,
        instrument_facts_observed_at_ns=_NOW_NS,
        instrument_facts_valid_until_ns=_NOW_NS + 3_600_000_000_000,
    )


def _claimed_permit(gate, scope, intent_id: str, *, instrument: str = "venue/contract-a"):
    intent = _intent(scope, intent_id, instrument=instrument)
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)
    claim = gate.dispatch_claim_binding(permit.permit_id)
    gate.settle(permit.permit_id)
    return intent, claim


def _acked_tracked(gate, scope, intent_id: str, *, instrument: str = "venue/contract-a"):
    """Reserve, claim, settle, and resolve the dispatch latch through the ACK."""

    intent = _intent(scope, intent_id, instrument=instrument)
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
        journal_record_sha256=_sha("tracked-record-" + intent.intent_id),
        reconciliation_evidence_sha256=_sha("reconcile-" + intent.intent_id),
        writer_fence_sha256=_sha("fence"),
        provider_order_id="provider-order-" + intent.intent_id,
        accepted_request_sha256=_sha("accepted-request-" + intent.intent_id),
        exposure_reservation_id="risk-ref-" + intent.intent_id,
        exposure_reservation_sha256=_sha("risk-ref-digest-" + intent.intent_id),
        filled_quantity=0,
        trade_count=0,
    )
    gate.resolve_dispatch_freeze(tracked)
    return intent, tracked


def _fill(
    trade_id: str,
    quantity: str = "5",
    *,
    price: str = "20",
    revision: int = 3,
    fee: str = "0.01",
) -> OrderFillFact:
    return OrderFillFact(
        trade_id=trade_id,
        quantity=Decimal(quantity),
        price=Decimal(price),
        side="BUY",
        position_effect="OPEN",
        fee_amount=Decimal(fee),
        fee_currency="USD",
        source_record_sha256=_sha(f"fill-source:{trade_id}:{quantity}:{price}"),
        source_revision=revision,
    )


def _terminal_observation(
    claim,
    *,
    journal_revision: int,
    fills: tuple[OrderFillFact, ...],
    provider_order_id: str | None = None,
    instrument_id: str = "venue/contract-a",
    instrument_multiplier: Decimal = Decimal("1"),
    domain_ref: str | None = None,
    trade_id_scope: str | None = None,
    state: OrderExposureState = OrderExposureState.FILLED,
    requested_quantity: str = "5",
) -> OrderExposureObservationProof:
    requested = Decimal(requested_quantity)
    cumulative = sum((item.quantity for item in fills), Decimal(0))
    leaves = requested - cumulative
    if state is not OrderExposureState.FILLED:
        raise AssertionError("this helper only builds FILLED terminal observations")
    filled_gross = sum(
        (item.quantity * item.price for item in fills), Decimal(0)
    ) * instrument_multiplier
    return OrderExposureObservationProof(
        scope=claim.scope,
        permit_id=claim.permit_id,
        intent_id=claim.intent_id,
        intent_hash=claim.intent_hash,
        dispatch_claim_digest=claim.claim_digest,
        dispatch_proof_sha256=None,
        provider_order_id=(
            "provider-order-" + claim.intent_id
            if provider_order_id is None
            else provider_order_id
        ),
        accepted_request_sha256=_sha("accepted-request:" + claim.intent_id),
        exposure_reservation_id="risk-exposure:" + claim.intent_id,
        exposure_reservation_sha256=_sha("risk-exposure-digest:" + claim.intent_id),
        order_revision=2,
        journal_revision=journal_revision,
        journal_record_sha256=_sha(f"terminal-record:{claim.intent_id}:{journal_revision}"),
        observation_sha256=_sha(f"observation:{claim.intent_id}:{journal_revision}"),
        fill_history_sha256=_sha(f"fill-history:{claim.intent_id}:{journal_revision}"),
        source_alias_map_sha256=_sha("explicit-source-aliases"),
        state=state,
        requested_quantity=requested,
        cumulative_filled_quantity=cumulative,
        leaves_quantity=leaves,
        filled_gross_notional=filled_gross,
        leaves_gross_notional=Decimal(0),
        leaves_valuation_price=None,
        notional_unit="USD",
        complete_order_snapshot=True,
        complete_fill_history=True,
        fill_watermark_revision=max([2, *(item.source_revision for item in fills)]),
        source_contract_ref="synthetic/contract-a",
        source_contract_version="contract-v1",
        provider_profile_version="profile-v1",
        normalizer_schema_version="normalizer-v1",
        order_side="BUY",
        position_effect="OPEN",
        fills=fills,
        fill_trade_count=len(fills),
        fill_ids_sha256=fill_ids_sha256(fills),
        instrument_id=instrument_id,
        instrument_version="metadata-v1",
        instrument_multiplier=instrument_multiplier,
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
        trade_id_domain_ref=domain_ref,
        trade_id_scope=trade_id_scope,
    )


def _terminal_proof(claim, observation) -> DispatchExposureResolutionProof:
    return DispatchExposureResolutionProof(
        claim=claim,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        dispatch_attempt_count=1,
        reconciliation_evidence_sha256=_sha("terminal-reconciliation:" + claim.intent_id),
        observation=observation,
    )


def _incremental_observation(
    scope: AccountScope,
    tracked: DispatchTrackedOrderProof,
    *,
    state: OrderExposureState,
    journal_revision: int,
    fills: tuple[OrderFillFact, ...],
    cumulative: str,
    leaves: str,
    domain_ref: str | None = None,
    trade_id_scope: str | None = None,
    order_revision: int = 2,
) -> OrderExposureObservationProof:
    requested = Decimal("5")
    cumulative_filled = Decimal(cumulative)
    leaves_quantity = Decimal(leaves)
    filled_gross = sum((item.quantity * item.price for item in fills), Decimal(0))
    leaves_price = (
        None
        if leaves_quantity == 0
        else (Decimal(60) / leaves_quantity)
    )
    return OrderExposureObservationProof(
        scope=scope,
        permit_id=tracked.permit_id,
        intent_id=tracked.intent_id,
        intent_hash=tracked.intent_hash,
        dispatch_claim_digest=tracked.claim_digest,
        dispatch_proof_sha256=tracked.fingerprint,
        provider_order_id=tracked.provider_order_id,
        accepted_request_sha256=tracked.accepted_request_sha256,
        exposure_reservation_id=tracked.exposure_reservation_id,
        exposure_reservation_sha256=tracked.exposure_reservation_sha256,
        order_revision=order_revision,
        journal_revision=journal_revision,
        journal_record_sha256=_sha(f"order-record:{tracked.intent_id}:{journal_revision}"),
        observation_sha256=_sha(f"observation:{tracked.intent_id}:{journal_revision}"),
        fill_history_sha256=_sha(f"fill-history:{tracked.intent_id}:{journal_revision}"),
        source_alias_map_sha256=_sha("explicit-provider-alias-map"),
        state=state,
        requested_quantity=requested,
        cumulative_filled_quantity=cumulative_filled,
        leaves_quantity=leaves_quantity,
        filled_gross_notional=filled_gross,
        leaves_gross_notional=leaves_quantity * leaves_price if leaves_price else Decimal(0),
        leaves_valuation_price=leaves_price,
        notional_unit="USD",
        complete_order_snapshot=True,
        complete_fill_history=True,
        fill_watermark_revision=max([2, *(item.source_revision for item in fills)]),
        source_contract_ref="synthetic/contract-a",
        source_contract_version="contract-v1",
        provider_profile_version="profile-v1",
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
        trade_id_domain_ref=domain_ref,
        trade_id_scope=trade_id_scope,
    )


def _claims(database) -> list[dict[str, object]]:
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        return [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM risk_trade_identity_claims "
                "ORDER BY trade_id_domain_ref, identity_scope, trade_id"
            ).fetchall()
        ]


def _bound_domains(database) -> list[dict[str, object]]:
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        return [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM risk_trade_identity_domains ORDER BY trade_id_domain_ref"
            ).fetchall()
        ]


def _fill_rows(database) -> list[dict[str, object]]:
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        return [
            dict(row)
            for row in connection.execute(
                "SELECT permit_id, trade_id, fact_sha256 FROM risk_order_exposure_fills "
                "ORDER BY trade_id, permit_id"
            ).fetchall()
        ]


def test_same_bare_trade_id_is_credited_in_each_distinct_domain(risk):
    gate, scope, database = risk
    _, claim_a = _claimed_permit(gate, scope, "identity-domain-a")
    first = _terminal_observation(
        claim_a,
        journal_revision=10,
        fills=(_fill("trade-1", "5"),),
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    receipt_a = gate.resolve_dispatch_exposure(_terminal_proof(claim_a, first))
    assert receipt_a.dispatch_latch_active is False

    _, claim_b = _claimed_permit(gate, scope, "identity-domain-b")
    second = _terminal_observation(
        claim_b,
        journal_revision=11,
        fills=(_fill("trade-1", "5", price="21"),),
        domain_ref=_DOMAIN_B,
        trade_id_scope="INSTRUMENT",
    )
    receipt_b = gate.resolve_dispatch_exposure(_terminal_proof(claim_b, second))
    assert receipt_b.dispatch_latch_active is False

    orders = gate.gross_exposure_snapshot(scope)["orders"]
    assert len(orders) == 2
    assert {order.cumulative_filled_quantity for order in orders} == {Decimal("5")}
    assert {order.state for order in orders} == {OrderExposureState.FILLED}
    claims = _claims(database)
    assert {(item["trade_id_domain_ref"], item["permit_id"]) for item in claims} == {
        (_DOMAIN_A, claim_a.permit_id),
        (_DOMAIN_B, claim_b.permit_id),
    }
    assert len(_fill_rows(database)) == 2
    gate.close()


def test_same_domain_cross_permit_trade_reuse_denies_without_credit(risk):
    gate, scope, database = risk
    _, claim_a = _claimed_permit(gate, scope, "identity-occupied")

    first = _terminal_observation(
        claim_a,
        journal_revision=10,
        fills=(_fill("trade-1", "5"),),
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    gate.resolve_dispatch_exposure(_terminal_proof(claim_a, first))

    _, claim_b = _claimed_permit(gate, scope, "identity-collision")
    collision = _terminal_observation(
        claim_b,
        journal_revision=11,
        fills=(_fill("trade-1", "5", price="21"),),
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    with pytest.raises(RiskDeniedError) as denied:
        gate.resolve_dispatch_exposure(_terminal_proof(claim_b, collision))
    assert denied.value.code == "ORDER_EXPOSURE_TRADE_IDENTITY_CONFLICT"

    receipt = gate.dispatch_exposure_resolution_receipt(claim_b.permit_id)
    assert receipt.status is DispatchExposureResolutionReceiptStatus.UNRESOLVED_ACTIVE
    assert receipt.dispatch_latch_active is True
    assert receipt.exposure_proof_sha256 is None

    orders = gate.gross_exposure_snapshot(scope)["orders"]
    assert len(orders) == 1
    assert orders[0].permit_id == claim_a.permit_id
    assert orders[0].cumulative_filled_quantity == Decimal("5")
    assert orders[0].filled_gross_notional == Decimal("500")
    assert [item["permit_id"] for item in _fill_rows(database)] == [claim_a.permit_id]
    assert [item["permit_id"] for item in _claims(database)] == [claim_a.permit_id]
    gate.close()


def test_instrument_scope_keeps_equal_bare_ids_on_distinct_instruments(risk):
    gate, scope, database = risk
    _, claim_a = _claimed_permit(gate, scope, "identity-btc", instrument="venue/BTC-USD")
    first = _terminal_observation(
        claim_a,
        journal_revision=10,
        fills=(_fill("trade-1", "5"),),
        instrument_id="venue/BTC-USD",
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    assert (
        gate.resolve_dispatch_exposure(_terminal_proof(claim_a, first)).dispatch_latch_active
        is False
    )

    _, claim_b = _claimed_permit(gate, scope, "identity-eth", instrument="venue/ETH-USD")
    second = _terminal_observation(
        claim_b,
        journal_revision=11,
        fills=(_fill("trade-1", "5"),),
        instrument_id="venue/ETH-USD",
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    assert (
        gate.resolve_dispatch_exposure(_terminal_proof(claim_b, second)).dispatch_latch_active
        is False
    )
    scopes = {item["identity_scope"] for item in _claims(database)}
    assert scopes == {"venue/BTC-USD", "venue/ETH-USD"}
    assert len(gate.gross_exposure_snapshot(scope)["orders"]) == 2
    gate.close()


def test_declared_scope_mode_is_fixed_on_first_use_and_denies_mismatch(risk):
    gate, scope, database = risk
    _, claim_a = _claimed_permit(gate, scope, "identity-mode-first")

    first = _terminal_observation(
        claim_a,
        journal_revision=10,
        fills=(_fill("trade-1", "5"),),
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    gate.resolve_dispatch_exposure(_terminal_proof(claim_a, first))

    _, claim_b = _claimed_permit(gate, scope, "identity-mode-mismatch")
    mismatch = _terminal_observation(
        claim_b,
        journal_revision=11,
        fills=(_fill("trade-2", "5"),),
        domain_ref=_DOMAIN_A,
        trade_id_scope="ACCOUNT",
    )
    with pytest.raises(RiskDeniedError) as denied:
        gate.resolve_dispatch_exposure(_terminal_proof(claim_b, mismatch))
    assert denied.value.code == "ORDER_EXPOSURE_TRADE_IDENTITY_MODE_MISMATCH"
    assert gate.dispatch_exposure_resolution_receipt(
        claim_b.permit_id
    ).status is DispatchExposureResolutionReceiptStatus.UNRESOLVED_ACTIVE

    domains = _bound_domains(database)
    assert [(item["trade_id_domain_ref"], item["trade_id_scope"]) for item in domains] == [
        (_DOMAIN_A, "INSTRUMENT")
    ]
    assert len(gate.gross_exposure_snapshot(scope)["orders"]) == 1
    gate.close()


def test_legacy_fill_without_domain_mapping_blocks_declared_claim(risk):
    gate, scope, database = risk
    _, claim_legacy = _claimed_permit(gate, scope, "identity-legacy")

    legacy = _terminal_observation(
        claim_legacy,
        journal_revision=10,
        fills=(_fill("trade-1", "5"),),
    )
    gate.resolve_dispatch_exposure(_terminal_proof(claim_legacy, legacy))
    assert _claims(database) == []

    _, claim_declared = _claimed_permit(gate, scope, "identity-declared")
    declared = _terminal_observation(
        claim_declared,
        journal_revision=11,
        fills=(_fill("trade-1", "5", price="21"),),
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    with pytest.raises(RiskDeniedError) as denied:
        gate.resolve_dispatch_exposure(_terminal_proof(claim_declared, declared))
    assert denied.value.code == "ORDER_EXPOSURE_TRADE_IDENTITY_UNMAPPED"
    receipt = gate.dispatch_exposure_resolution_receipt(claim_declared.permit_id)
    assert receipt.status is DispatchExposureResolutionReceiptStatus.UNRESOLVED_ACTIVE
    assert receipt.dispatch_latch_active is True

    # The explicit rejection is bound to the unmapped identity only: the same
    # permit may still resolve a different, previously unseen trade ID.
    followup = _terminal_observation(
        claim_declared,
        journal_revision=12,
        fills=(_fill("trade-2", "5"),),
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    resolved = gate.resolve_dispatch_exposure(_terminal_proof(claim_declared, followup))
    assert resolved.dispatch_latch_active is False
    assert [item["trade_id"] for item in _claims(database)] == ["trade-2"]
    assert len(gate.gross_exposure_snapshot(scope)["orders"]) == 2
    gate.close()


def test_undeclared_proofs_keep_legacy_semantics_without_occupancy(risk):
    gate, scope, database = risk
    _, claim_a = _claimed_permit(gate, scope, "identity-legacy-a")
    first = _terminal_observation(
        claim_a,
        journal_revision=10,
        fills=(_fill("trade-1", "5"),),
    )
    assert (
        gate.resolve_dispatch_exposure(_terminal_proof(claim_a, first)).dispatch_latch_active
        is False
    )

    _, claim_b = _claimed_permit(gate, scope, "identity-legacy-b")
    second = _terminal_observation(
        claim_b,
        journal_revision=11,
        fills=(_fill("trade-1", "5", price="21"),),
    )
    # DIM01 leaves durable journal-proof consumption untouched: the exact
    # terminal proof already consumed above stays denied for its own permit.
    with pytest.raises(PermitInvalidError) as replay:
        gate.resolve_dispatch_exposure(_terminal_proof(claim_a, first))
    assert replay.value.code == "DISPATCH_PROOF_REPLAYED"
    assert (
        gate.resolve_dispatch_exposure(_terminal_proof(claim_b, second)).dispatch_latch_active
        is False
    )
    assert _claims(database) == []
    assert _bound_domains(database) == []
    assert len(_fill_rows(database)) == 2
    gate.close()


def test_incremental_replay_requires_same_permit_and_same_content(risk):
    gate, scope, database = risk
    _, tracked = _acked_tracked(gate, scope, "identity-incremental")

    partial = _incremental_observation(
        scope,
        tracked,
        state=OrderExposureState.PARTIALLY_FILLED,
        journal_revision=10,
        fills=(_fill("trade-1", "2", revision=3),),
        cumulative="2",
        leaves="3",
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    gate.apply_order_exposure_observation(partial)
    claims = _claims(database)
    assert [(item["trade_id"], item["permit_id"]) for item in claims] == [
        ("trade-1", tracked.permit_id)
    ]

    # The dominant fill set replays the identical trade-1 fact and extends the
    # order with one newly observed trade ID under a newer provider revision;
    # both occupations stay bound to the same permit without a second credit.
    complete = _incremental_observation(
        scope,
        tracked,
        state=OrderExposureState.FILLED,
        journal_revision=11,
        fills=(_fill("trade-1", "2", revision=3), _fill("trade-2", "3", revision=4)),
        cumulative="5",
        leaves="0",
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
        order_revision=3,
    )
    gate.apply_order_exposure_observation(complete)
    claims = _claims(database)
    assert {(item["trade_id"], item["permit_id"]) for item in claims} == {
        ("trade-1", tracked.permit_id),
        ("trade-2", tracked.permit_id),
    }
    orders = gate.gross_exposure_snapshot(scope)["orders"]
    assert len(orders) == 1
    assert orders[0].cumulative_filled_quantity == Decimal("5")
    assert orders[0].filled_gross_notional == Decimal("500")

    # Claim rows are immutable by construction.
    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE risk_trade_identity_claims SET fact_sha256 = ? WHERE trade_id = ?",
                (_sha("tampered"), "trade-1"),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM risk_trade_identity_claims WHERE trade_id = ?", ("trade-1",)
            )
    gate.close()


def test_incremental_cross_permit_conflict_rolls_back_and_keeps_latch(risk):
    gate, scope, database = risk
    _, tracked_a = _acked_tracked(gate, scope, "identity-incremental-a")

    first = _incremental_observation(
        scope,
        tracked_a,
        state=OrderExposureState.PARTIALLY_FILLED,
        journal_revision=10,
        fills=(_fill("trade-1", "2", revision=3),),
        cumulative="2",
        leaves="3",
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    gate.apply_order_exposure_observation(first)
    assert [item["permit_id"] for item in _claims(database)] == [tracked_a.permit_id]

    # The account admits the next increase only because A's tracked order was
    # already converted into a fill observation.
    _, tracked_b = _acked_tracked(gate, scope, "identity-incremental-b")

    collision = _incremental_observation(
        scope,
        tracked_b,
        state=OrderExposureState.PARTIALLY_FILLED,
        journal_revision=11,
        fills=(_fill("trade-1", "2", price="21", revision=3),),
        cumulative="2",
        leaves="3",
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    with pytest.raises(RiskDeniedError) as denied:
        gate.apply_order_exposure_observation(collision)
    assert denied.value.code == "ORDER_EXPOSURE_TRADE_IDENTITY_CONFLICT"

    orders = gate.gross_exposure_snapshot(scope)["orders"]
    assert [order.permit_id for order in orders] == [tracked_a.permit_id]
    assert orders[0].cumulative_filled_quantity == Decimal("2")
    assert orders[0].filled_gross_notional == Decimal("200")
    assert [item["permit_id"] for item in _fill_rows(database)] == [tracked_a.permit_id]
    assert [item["permit_id"] for item in _claims(database)] == [tracked_a.permit_id]

    # The rejected permit stays an unconverted ACKED tracked order: the whole
    # observation rolled back, the account remains gated on its reconciliation,
    # and the failed attempt added no durable freeze of its own.
    with pytest.raises(RiskDeniedError) as gated:
        gate.reserve(_intent(scope, "identity-incremental-c", instrument="venue/contract-a"))
    assert gated.value.code == "ORDER_EXPOSURE_RECONCILIATION_REQUIRED"
    assert "dispatch-inflight:" + tracked_b.intent_id not in gate.active_freeze_reasons(scope)
    gate.close()


def test_identity_declaration_validation_and_fingerprint_separation(risk):
    _, scope, _ = risk
    _, claim = _claimed_permit(gate=risk[0], scope=scope, intent_id="identity-validation")

    with pytest.raises(ValueError):
        _terminal_observation(
            claim,
            journal_revision=10,
            fills=(_fill("trade-1", "5"),),
            domain_ref=_DOMAIN_A,
        )
    with pytest.raises(ValueError):
        _terminal_observation(
            claim,
            journal_revision=10,
            fills=(_fill("trade-1", "5"),),
            trade_id_scope="INSTRUMENT",
        )
    with pytest.raises(ValueError):
        _terminal_observation(
            claim,
            journal_revision=10,
            fills=(_fill("trade-1", "5"),),
            domain_ref="bad domain!",
            trade_id_scope="INSTRUMENT",
        )
    with pytest.raises(ValueError):
        _terminal_observation(
            claim,
            journal_revision=10,
            fills=(_fill("trade-1", "5"),),
            domain_ref=_DOMAIN_A,
            trade_id_scope="EXECUTION",
        )

    undeclared = _terminal_observation(
        claim, journal_revision=10, fills=(_fill("trade-1", "5"),)
    )
    declared = _terminal_observation(
        claim,
        journal_revision=10,
        fills=(_fill("trade-1", "5"),),
        domain_ref=_DOMAIN_A,
        trade_id_scope="INSTRUMENT",
    )
    assert undeclared.fingerprint != declared.fingerprint
    risk[0].close()
