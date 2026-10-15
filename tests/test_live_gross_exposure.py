from __future__ import annotations

import hashlib
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
from threading import Event, Thread

import pytest

from bt_api_risk import (
    AccountScope,
    DispatchEvidenceClass,
    DispatchTrackedOrderProof,
    DurableRiskGate,
    ExposureAccountingMode,
    GrossExposureBaselineProof,
    IntentAction,
    OrderExposureObservationProof,
    OrderExposureState,
    OrderFillFact,
    RiskDeniedError,
    RiskIntent,
    RiskPolicy,
    VerifiedDispatchResolution,
    VerifiedGrossExposureBaseline,
    VerifiedOrderExposureObservation,
    fill_ids_sha256,
)

_NOW = 1_700_000_000.0
_NOW_NS = int(_NOW * 1_000_000_000)
_OWNER = "synthetic-writer"
_FENCE_TOKEN = 1


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class SyntheticJournalAuthority:
    """Synthetic source authority for local Risk storage/projection tests only."""

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


class AdvancingJournalAuthority(SyntheticJournalAuthority):
    """Models waiting for the account fence until the proof has expired."""

    def __init__(self, clock, advance_seconds):
        self.clock = clock
        self.advance_seconds = advance_seconds

    @contextmanager
    def baseline_guard(self, proof):
        with super().baseline_guard(proof) as receipt:
            self.clock.value += self.advance_seconds
            yield receipt

    @contextmanager
    def order_observation_guard(self, proof, *, claim, tracked_order):
        with super().order_observation_guard(
            proof, claim=claim, tracked_order=tracked_order
        ) as receipt:
            self.clock.value += self.advance_seconds
            yield receipt


@pytest.fixture
def live_risk(tmp_path):
    scope = AccountScope("fixture", "account-a", "sandbox")
    policy = RiskPolicy(
        "live-gross-test",
        Decimal("1000"),
        max_increase_count=20,
        permit_ttl_seconds=10,
        require_strategy_allocation=True,
        notional_unit="USD",
        exposure_accounting_mode=ExposureAccountingMode.LIVE_GROSS,
        max_gross_occupancy_notional=Decimal("150"),
        max_gross_occupancy_intent_count=3,
        max_exposure_facts_age_seconds=3600,
    )
    authority = SyntheticJournalAuthority()
    database = tmp_path / "live-gross.sqlite3"

    def open_gate():
        return DurableRiskGate(
            database,
            policy,
            clock=lambda: _NOW,
            execution_journal_authority=authority,
            gross_exposure_authority=authority,
        )

    gate = open_gate()
    gate.set_strategy_allocation(
        scope,
        "strategy-a",
        "allocation-v1",
        max_notional=Decimal("1000"),
        notional_unit="USD",
        max_gross_occupancy_notional=Decimal("150"),
        max_gross_occupancy_intent_count=3,
    )
    baseline = GrossExposureBaselineProof(
        scope=scope,
        account_revision=1,
        notional_unit="USD",
        account_gross_notional=Decimal("0"),
        account_active_increase_intent_count=0,
        strategy_baselines=(),
        unmanaged_open_order_count=0,
        complete_positions=True,
        complete_open_orders=True,
        source_snapshot_sha256=_sha("baseline"),
        positions_sha256=_sha("positions"),
        open_orders_sha256=_sha("open-orders"),
        valuation_facts_sha256=_sha("baseline-valuation"),
        source_schema_version="fixture-baseline-v1",
        observed_at_ns=_NOW_NS,
        valid_until_ns=_NOW_NS + 3_600_000_000_000,
        writer_owner_id=_OWNER,
        writer_fencing_token=_FENCE_TOKEN,
        writer_fence_sha256=_sha("fence"),
    )
    gate.install_gross_exposure_baseline(baseline)
    return gate, open_gate, scope, policy, authority


def _intent(
    scope: AccountScope,
    intent_id: str,
    notional: str,
    quantity: str = "5",
    allocation_version: str = "allocation-v1",
) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal(notional),
        payload_fingerprint="synthetic-request-" + intent_id,
        strategy_id="strategy-a",
        allocation_version=allocation_version,
        instrument="BTC-USDT",
        quantity=Decimal(quantity),
        quantity_unit="BTC",
        notional_unit="USD",
    )


def _tracked_order(gate: DurableRiskGate, scope: AccountScope, intent: RiskIntent):
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
    return permit, tracked


def _observation(
    scope: AccountScope,
    tracked: DispatchTrackedOrderProof,
    *,
    state: OrderExposureState,
    order_revision: int,
    journal_revision: int,
    cumulative_filled_quantity: str,
    leaves_quantity: str,
    filled_gross_notional: str,
    leaves_gross_notional: str,
    leaves_valuation_price=None,
    requested_quantity: str = "5",
    fills: tuple[OrderFillFact, ...] = (),
    complete: bool = True,
    observed_at_ns: int = _NOW_NS,
    valid_until_ns: int = _NOW_NS + 3_600_000_000_000,
    instrument_multiplier: Decimal = Decimal("1"),
    quote_currency: str = "USD",
    valuation_unit: str = "USD",
    fx_rate=None,
) -> OrderExposureObservationProof:
    if leaves_valuation_price is None and Decimal(leaves_quantity) > 0:
        conversion = Decimal(1) if fx_rate is None else Decimal(fx_rate)
        claimed_leaves = Decimal(leaves_gross_notional)
        leaves_valuation_price = (
            claimed_leaves / (Decimal(leaves_quantity) * instrument_multiplier * conversion)
            if claimed_leaves > 0
            else Decimal("20")
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
        journal_record_sha256=_sha(f"order-record-{tracked.intent_id}-{journal_revision}"),
        observation_sha256=_sha(f"observation-{tracked.intent_id}-{journal_revision}"),
        fill_history_sha256=_sha(f"fill-history-{tracked.intent_id}-{journal_revision}"),
        source_alias_map_sha256=_sha("explicit-provider-alias-map"),
        state=state,
        requested_quantity=Decimal(requested_quantity),
        cumulative_filled_quantity=Decimal(cumulative_filled_quantity),
        leaves_quantity=Decimal(leaves_quantity),
        filled_gross_notional=Decimal(filled_gross_notional),
        leaves_gross_notional=Decimal(leaves_gross_notional),
        leaves_valuation_price=leaves_valuation_price,
        notional_unit="USD",
        complete_order_snapshot=complete,
        complete_fill_history=complete,
        fill_watermark_revision=(
            max([order_revision, *(item.source_revision for item in fills)]) if complete else 0
        ),
        source_contract_ref="fixture-contract/BTC-USDT",
        source_contract_version="contract-v1",
        provider_profile_version="profile-v1",
        normalizer_schema_version="normalizer-v1",
        order_side="BUY",
        position_effect="OPEN",
        fills=fills,
        fill_trade_count=len(fills),
        fill_ids_sha256=fill_ids_sha256(fills),
        instrument_id="BTC-USDT",
        instrument_version="metadata-v1",
        instrument_multiplier=instrument_multiplier,
        quote_currency=quote_currency,
        valuation_unit=valuation_unit,
        instrument_metadata_sha256=_sha("trusted-instrument-metadata"),
        instrument_metadata_observed_at_ns=observed_at_ns,
        instrument_metadata_valid_until_ns=valid_until_ns,
        valuation_facts_sha256=_sha("trusted-valuation-facts"),
        valuation_observed_at_ns=observed_at_ns,
        valuation_valid_until_ns=valid_until_ns,
        fx_pair=None if fx_rate is None else quote_currency + "/" + valuation_unit,
        fx_rate=fx_rate,
        fx_observed_at_ns=None if fx_rate is None else observed_at_ns,
        fx_valid_until_ns=None if fx_rate is None else valid_until_ns,
        observed_at_ns=observed_at_ns,
        valid_until_ns=valid_until_ns,
        writer_owner_id=_OWNER,
        writer_fencing_token=_FENCE_TOKEN,
        writer_fence_sha256=_sha("fence"),
    )


def _fill(trade_id: str, quantity: str, *, price: str = "20", revision: int = 3) -> OrderFillFact:
    return OrderFillFact(
        trade_id=trade_id,
        quantity=Decimal(quantity),
        price=Decimal(price),
        side="BUY",
        position_effect="OPEN",
        fee_amount=Decimal("0.02"),
        fee_currency="USD",
        source_record_sha256=_sha("fill-source-" + trade_id),
        source_revision=revision,
    )


def test_live_gross_ack_partial_fill_restart_and_confirmed_cancel(tmp_path, live_risk):
    gate, open_gate, scope, _, _ = live_risk
    intent = _intent(scope, "order-lifecycle", "100")
    _, tracked = _tracked_order(gate, scope, intent)

    ack = _observation(
        scope,
        tracked,
        state=OrderExposureState.ACKED,
        order_revision=1,
        journal_revision=3,
        cumulative_filled_quantity="0",
        leaves_quantity="5",
        filled_gross_notional="0",
        leaves_gross_notional="100",
    )
    first = gate.apply_order_exposure_observation(ack)
    assert first.total_gross_notional == Decimal("100")
    assert first.open_gross_notional == Decimal("100")
    with pytest.raises(RiskDeniedError) as over_account:
        gate.reserve(_intent(scope, "before-partial", "60"))
    assert over_account.value.code == "GROSS_EXPOSURE_ACCOUNT_LIMIT_EXHAUSTED"

    fill = _fill("trade-1", "2")
    partial = _observation(
        scope,
        tracked,
        state=OrderExposureState.PARTIALLY_FILLED,
        order_revision=2,
        journal_revision=4,
        cumulative_filled_quantity="2",
        leaves_quantity="3",
        filled_gross_notional="40",
        leaves_gross_notional="60",
        fills=(fill,),
    )
    partial_snapshot = gate.apply_order_exposure_observation(partial)
    assert partial_snapshot.filled_gross_notional == Decimal("40")
    assert partial_snapshot.open_gross_notional == Decimal("60")
    assert partial_snapshot.total_gross_notional == Decimal("100")
    with pytest.raises(RiskDeniedError) as over_partial:
        gate.reserve(_intent(scope, "while-partial", "60"))
    assert over_partial.value.code == "GROSS_EXPOSURE_ACCOUNT_LIMIT_EXHAUSTED"

    # A fresh gate object over the same SQLite file models process restart.
    restarted = open_gate()
    replay = restarted.apply_order_exposure_observation(partial)
    assert replay == partial_snapshot
    with restarted._connection() as connection:
        persisted_fills = connection.execute(
            "SELECT trade_id, fact_sha256 FROM risk_order_exposure_fills WHERE permit_id = ?",
            (tracked.permit_id,),
        ).fetchall()
    assert [(row["trade_id"], row["fact_sha256"]) for row in persisted_fills] == [
        ("trade-1", fill.fingerprint)
    ]

    cancelled = _observation(
        scope,
        tracked,
        state=OrderExposureState.CANCELLED,
        order_revision=3,
        journal_revision=5,
        cumulative_filled_quantity="2",
        leaves_quantity="0",
        filled_gross_notional="40",
        leaves_gross_notional="0",
        fills=(fill,),
    )
    cancelled_snapshot = restarted.apply_order_exposure_observation(cancelled)
    assert cancelled_snapshot.state is OrderExposureState.CANCELLED
    assert cancelled_snapshot.cumulative_filled_quantity == Decimal("2")
    assert cancelled_snapshot.open_gross_notional == 0
    assert cancelled_snapshot.filled_gross_notional == Decimal("40")
    assert cancelled_snapshot.total_gross_notional == Decimal("40")

    admitted_after_confirmed_cancel = restarted.reserve(_intent(scope, "after-cancel", "100"))
    assert admitted_after_confirmed_cancel.notional == Decimal("100")
    with restarted._connection() as connection:
        reservation = connection.execute(
            "SELECT status FROM risk_reservations WHERE permit_id = ?", (tracked.permit_id,)
        ).fetchone()
        fill_count = connection.execute(
            "SELECT COUNT(*) FROM risk_order_exposure_fills WHERE permit_id = ?",
            (tracked.permit_id,),
        ).fetchone()[0]
    assert reservation["status"] == DurableRiskGate._SETTLED
    assert fill_count == 1


def test_fill_and_leaves_gross_are_derived_from_price_multiplier_and_fx(live_risk):
    gate, _, scope, _, _ = live_risk
    intent = _intent(scope, "gross-derivation", "100")
    _, tracked = _tracked_order(gate, scope, intent)
    fill = _fill("high-price-trade", "2", price="100")
    observation = _observation(
        scope,
        tracked,
        state=OrderExposureState.PARTIALLY_FILLED,
        order_revision=1,
        journal_revision=3,
        cumulative_filled_quantity="2",
        leaves_quantity="3",
        filled_gross_notional="40",  # Deliberately understated source projection.
        leaves_gross_notional="60",  # Deliberately understated source projection.
        leaves_valuation_price=Decimal("20"),
        fills=(fill,),
        instrument_multiplier=Decimal("2"),
        quote_currency="EUR",
        valuation_unit="USD",
        fx_rate=Decimal("1.5"),
    )

    snapshot = gate.apply_order_exposure_observation(observation)

    assert snapshot.filled_gross_notional == Decimal("600")
    assert snapshot.open_gross_notional == Decimal("180")
    assert snapshot.total_gross_notional == Decimal("780")
    assert "gross_exposure_limit_exceeded" in gate.active_freeze_reasons(scope)
    with pytest.raises(RiskDeniedError) as blocked:
        gate.reserve(_intent(scope, "must-not-slip-under-cap", "1"))
    assert blocked.value.code == "FROZEN"


def test_new_journal_revision_refreshes_valuation_without_order_revision_or_release(live_risk):
    gate, _, scope, _, _ = live_risk
    intent = _intent(scope, "same-order-revision-refresh", "100")
    _, tracked = _tracked_order(gate, scope, intent)
    first = _observation(
        scope,
        tracked,
        state=OrderExposureState.ACKED,
        order_revision=1,
        journal_revision=3,
        cumulative_filled_quantity="0",
        leaves_quantity="5",
        filled_gross_notional="0",
        leaves_gross_notional="100",
        leaves_valuation_price=Decimal("20"),
    )
    gate.apply_order_exposure_observation(first)
    refreshed = _observation(
        scope,
        tracked,
        state=OrderExposureState.ACKED,
        order_revision=1,
        journal_revision=4,
        cumulative_filled_quantity="0",
        leaves_quantity="5",
        filled_gross_notional="0",
        leaves_gross_notional="125",
        leaves_valuation_price=Decimal("25"),
    )

    snapshot = gate.apply_order_exposure_observation(refreshed)

    assert snapshot.order_revision == 1
    assert snapshot.journal_revision == 4
    assert snapshot.leaves_valuation_price == Decimal("25")
    assert snapshot.open_gross_notional == Decimal("125")
    assert snapshot.total_gross_notional == Decimal("125")


def test_expired_baseline_allows_order_reconciliation_only_until_clean_refresh(live_risk):
    gate, _, scope, _, _ = live_risk
    intent = _intent(scope, "expired-baseline-cancel", "100")
    _, tracked = _tracked_order(gate, scope, intent)
    ack = _observation(
        scope,
        tracked,
        state=OrderExposureState.ACKED,
        order_revision=1,
        journal_revision=3,
        cumulative_filled_quantity="0",
        leaves_quantity="5",
        filled_gross_notional="0",
        leaves_gross_notional="100",
    )
    gate.apply_order_exposure_observation(ack)

    clock = type("MutableClock", (), {"value": _NOW + 3601.0})()
    gate._clock = lambda: clock.value
    observed_at_ns = int(clock.value * 1_000_000_000)
    cancel = _observation(
        scope,
        tracked,
        state=OrderExposureState.CANCELLED,
        order_revision=2,
        journal_revision=4,
        cumulative_filled_quantity="0",
        leaves_quantity="0",
        filled_gross_notional="0",
        leaves_gross_notional="0",
        observed_at_ns=observed_at_ns,
        valid_until_ns=observed_at_ns + 3_600_000_000_000,
    )

    snapshot = gate.apply_order_exposure_observation(cancel)
    assert snapshot.open_gross_notional == 0
    assert "gross_exposure_baseline_stale" in gate.active_freeze_reasons(scope)
    with pytest.raises(RiskDeniedError) as stale_admission:
        gate.reserve(_intent(scope, "still-read-only", "10"))
    assert stale_admission.value.code == "FROZEN"

    refreshed_baseline = GrossExposureBaselineProof(
        scope=scope,
        account_revision=5,
        notional_unit="USD",
        account_gross_notional=Decimal("0"),
        account_active_increase_intent_count=0,
        strategy_baselines=(),
        unmanaged_open_order_count=0,
        complete_positions=True,
        complete_open_orders=True,
        source_snapshot_sha256=_sha("refreshed-baseline"),
        positions_sha256=_sha("refreshed-positions"),
        open_orders_sha256=_sha("refreshed-open-orders"),
        valuation_facts_sha256=_sha("refreshed-baseline-valuation"),
        source_schema_version="fixture-baseline-v1",
        observed_at_ns=observed_at_ns,
        valid_until_ns=observed_at_ns + 3_600_000_000_000,
        writer_owner_id=_OWNER,
        writer_fencing_token=_FENCE_TOKEN,
        writer_fence_sha256=_sha("fence"),
    )
    gate.install_gross_exposure_baseline(refreshed_baseline)

    assert "gross_exposure_baseline_stale" not in gate.active_freeze_reasons(scope)
    assert gate.reserve(_intent(scope, "after-clean-baseline-refresh", "10")).notional == 10


@pytest.mark.parametrize("stale_fact", ("metadata", "valuation", "fx"))
def test_admission_rechecks_each_persisted_valuation_fact_age(live_risk, stale_fact):
    gate, _, scope, _, _ = live_risk
    intent = _intent(scope, "stale-" + stale_fact, "100")
    _, tracked = _tracked_order(gate, scope, intent)
    valid_until_ns = _NOW_NS + 7_200_000_000_000
    observation = _observation(
        scope,
        tracked,
        state=OrderExposureState.ACKED,
        order_revision=1,
        journal_revision=3,
        cumulative_filled_quantity="0",
        leaves_quantity="5",
        filled_gross_notional="0",
        leaves_gross_notional="100",
        quote_currency="EUR" if stale_fact == "fx" else "USD",
        valuation_unit="USD",
        fx_rate=Decimal("1.2") if stale_fact == "fx" else None,
        valid_until_ns=valid_until_ns,
    )
    stale_observed_at_ns = _NOW_NS - 3_500_000_000_000
    if stale_fact == "metadata":
        observation = replace(
            observation,
            instrument_metadata_observed_at_ns=stale_observed_at_ns,
        )
    elif stale_fact == "valuation":
        observation = replace(observation, valuation_observed_at_ns=stale_observed_at_ns)
    else:
        observation = replace(observation, fx_observed_at_ns=stale_observed_at_ns)
    gate.apply_order_exposure_observation(observation)

    gate._clock = lambda: _NOW + 200.0
    with pytest.raises(RiskDeniedError) as stale_admission:
        gate.reserve(_intent(scope, "denied-by-stale-" + stale_fact, "1"))

    assert stale_admission.value.code == "ORDER_EXPOSURE_RECONCILIATION_REQUIRED"


def test_baseline_expiring_while_waiting_for_authority_fence_is_not_installed(tmp_path):
    scope = AccountScope("fixture", "fence-wait-baseline", "sandbox")
    clock = type("MutableClock", (), {"value": _NOW})()
    policy = RiskPolicy(
        "fence-wait-baseline",
        Decimal("1000"),
        max_increase_count=10,
        require_strategy_allocation=True,
        notional_unit="USD",
        exposure_accounting_mode=ExposureAccountingMode.LIVE_GROSS,
        max_gross_occupancy_notional=Decimal("500"),
        max_gross_occupancy_intent_count=10,
        max_exposure_facts_age_seconds=3600,
    )
    authority = AdvancingJournalAuthority(clock, 2.0)
    gate = DurableRiskGate(
        tmp_path / "baseline-fence-wait.sqlite3",
        policy,
        clock=lambda: clock.value,
        gross_exposure_authority=authority,
    )
    baseline = GrossExposureBaselineProof(
        scope=scope,
        account_revision=1,
        notional_unit="USD",
        account_gross_notional=Decimal("0"),
        account_active_increase_intent_count=0,
        strategy_baselines=(),
        unmanaged_open_order_count=0,
        complete_positions=True,
        complete_open_orders=True,
        source_snapshot_sha256=_sha("fence-wait-baseline"),
        positions_sha256=_sha("fence-wait-positions"),
        open_orders_sha256=_sha("fence-wait-orders"),
        valuation_facts_sha256=_sha("fence-wait-valuation"),
        source_schema_version="fixture-baseline-v1",
        observed_at_ns=_NOW_NS,
        valid_until_ns=_NOW_NS + 1_000_000_000,
        writer_owner_id=_OWNER,
        writer_fencing_token=_FENCE_TOKEN,
        writer_fence_sha256=_sha("fence"),
    )

    with pytest.raises(RiskDeniedError) as expired:
        gate.install_gross_exposure_baseline(baseline)

    assert expired.value.code == "GROSS_EXPOSURE_BASELINE_STALE"
    assert gate.gross_exposure_snapshot(scope)["account_baseline_notional"] is None


def test_order_observation_expiring_while_waiting_for_fence_is_not_committed(live_risk):
    gate, _, scope, _, _ = live_risk
    intent = _intent(scope, "order-fence-wait", "100")
    _, tracked = _tracked_order(gate, scope, intent)
    clock = type("MutableClock", (), {"value": _NOW})()
    gate._clock = lambda: clock.value
    gate._gross_exposure_authority = AdvancingJournalAuthority(clock, 2.0)
    proof = _observation(
        scope,
        tracked,
        state=OrderExposureState.ACKED,
        order_revision=1,
        journal_revision=3,
        cumulative_filled_quantity="0",
        leaves_quantity="5",
        filled_gross_notional="0",
        leaves_gross_notional="100",
        valid_until_ns=_NOW_NS + 1_000_000_000,
    )

    with pytest.raises(RiskDeniedError) as expired:
        gate.apply_order_exposure_observation(proof)

    assert expired.value.code == "ORDER_EXPOSURE_OBSERVATION_STALE"
    assert gate.gross_exposure_snapshot(scope)["orders"] == []


def test_unknown_or_incomplete_observation_retains_occupancy_and_freezes_after_restart(
    live_risk,
):
    gate, open_gate, scope, policy, authority = live_risk
    intent = _intent(scope, "unknown-order", "100")
    _, tracked = _tracked_order(gate, scope, intent)
    unknown = _observation(
        scope,
        tracked,
        state=OrderExposureState.UNKNOWN,
        order_revision=1,
        journal_revision=3,
        cumulative_filled_quantity="0",
        leaves_quantity="5",
        filled_gross_notional="0",
        leaves_gross_notional="0",
        complete=False,
        observed_at_ns=_NOW_NS - 7_200_000_000_000,
        valid_until_ns=_NOW_NS - 3_600_000_000_000,
    )
    retained = gate.apply_order_exposure_observation(unknown)
    assert retained.state is OrderExposureState.UNKNOWN
    assert retained.filled_gross_notional == 0
    assert retained.open_gross_notional == Decimal("100")
    assert "order_exposure_unknown" in gate.active_freeze_reasons(scope)

    reopened = open_gate()
    with pytest.raises(RiskDeniedError) as blocked:
        reopened.reserve(_intent(scope, "must-stay-blocked", "10"))
    assert blocked.value.code == "FROZEN"
    with reopened._connection() as connection:
        rows = connection.execute(
            "SELECT status FROM risk_reservations WHERE intent_id IN (?, ?)",
            (intent.intent_id, "must-stay-blocked"),
        ).fetchall()
    assert [row["status"] for row in rows] == [DurableRiskGate._SETTLED]

    # Completeness can improve at the same provider order revision when the
    # account journal has advanced; the earlier UNKNOWN row stays conservative
    # until this exact current-fence observation is committed.
    recovered_ack = _observation(
        scope,
        tracked,
        state=OrderExposureState.ACKED,
        order_revision=1,
        journal_revision=4,
        cumulative_filled_quantity="0",
        leaves_quantity="5",
        filled_gross_notional="0",
        leaves_gross_notional="100",
    )
    recovered = reopened.apply_order_exposure_observation(recovered_ack)
    assert recovered.state is OrderExposureState.ACKED
    assert recovered.total_gross_notional == Decimal("100")
    assert "order_exposure_unknown" not in reopened.active_freeze_reasons(scope)


def test_complete_fill_set_is_reconciled_and_immutable(tmp_path, live_risk):
    gate, _, scope, _, _ = live_risk
    intent = _intent(scope, "fill-identity", "100")
    _, tracked = _tracked_order(gate, scope, intent)
    ack = _observation(
        scope,
        tracked,
        state=OrderExposureState.ACKED,
        order_revision=1,
        journal_revision=3,
        cumulative_filled_quantity="0",
        leaves_quantity="5",
        filled_gross_notional="0",
        leaves_gross_notional="100",
    )
    gate.apply_order_exposure_observation(ack)
    first_fill = _fill("trade-1", "2")
    partial = _observation(
        scope,
        tracked,
        state=OrderExposureState.PARTIALLY_FILLED,
        order_revision=2,
        journal_revision=4,
        cumulative_filled_quantity="2",
        leaves_quantity="3",
        filled_gross_notional="40",
        leaves_gross_notional="60",
        fills=(first_fill,),
    )
    gate.apply_order_exposure_observation(partial)

    conflicting_fill = OrderFillFact(
        trade_id="trade-other",
        quantity=Decimal("2"),
        price=Decimal("20"),
        side="BUY",
        position_effect="OPEN",
        fee_amount=Decimal("0.02"),
        fee_currency="USD",
        source_record_sha256=_sha("fill-source-other"),
        source_revision=3,
    )
    conflicting = _observation(
        scope,
        tracked,
        state=OrderExposureState.PARTIALLY_FILLED,
        order_revision=3,
        journal_revision=5,
        cumulative_filled_quantity="2",
        leaves_quantity="3",
        filled_gross_notional="40",
        leaves_gross_notional="60",
        fills=(conflicting_fill,),
    )
    with pytest.raises(RiskDeniedError) as rejected:
        gate.apply_order_exposure_observation(conflicting)
    assert rejected.value.code == "ORDER_EXPOSURE_FILL_IDENTITY_CONFLICT"
    with gate._connection() as connection:
        row = connection.execute(
            "SELECT order_revision, proof_sha256 FROM risk_order_exposures WHERE permit_id = ?",
            (tracked.permit_id,),
        ).fetchone()
        fills = connection.execute(
            "SELECT trade_id FROM risk_order_exposure_fills WHERE permit_id = ?",
            (tracked.permit_id,),
        ).fetchall()
    assert row["order_revision"] == 2
    assert row["proof_sha256"] == partial.fingerprint
    assert [item["trade_id"] for item in fills] == ["trade-1"]


def test_cancelled_proof_accepts_partial_fill_only_with_zero_leaves_and_complete_history(
    live_risk,
):
    gate, _, scope, _, _ = live_risk
    intent = _intent(scope, "cancel-quantity-shape", "100")
    _, tracked = _tracked_order(gate, scope, intent)
    fill = _fill("trade-1", "2")
    cancelled = _observation(
        scope,
        tracked,
        state=OrderExposureState.CANCELLED,
        order_revision=1,
        journal_revision=3,
        cumulative_filled_quantity="2",
        leaves_quantity="0",
        filled_gross_notional="40",
        leaves_gross_notional="0",
        fills=(fill,),
    )
    result = gate.apply_order_exposure_observation(cancelled)
    assert result.cumulative_filled_quantity == Decimal("2")
    assert result.open_gross_notional == 0

    with pytest.raises(ValueError, match="zero open leaves"):
        _observation(
            scope,
            tracked,
            state=OrderExposureState.CANCELLED,
            order_revision=2,
            journal_revision=4,
            cumulative_filled_quantity="2",
            leaves_quantity="1",
            filled_gross_notional="40",
            leaves_gross_notional="20",
            fills=(fill,),
        )


def test_fractional_quantity_transfer_rounds_only_toward_more_occupancy(live_risk):
    gate, _, scope, _, _ = live_risk
    intent = _intent(scope, "fractional-transfer", "100", quantity="3")
    _, tracked = _tracked_order(gate, scope, intent)
    ack = _observation(
        scope,
        tracked,
        state=OrderExposureState.ACKED,
        order_revision=1,
        journal_revision=3,
        cumulative_filled_quantity="0",
        leaves_quantity="3",
        filled_gross_notional="0",
        leaves_gross_notional="100",
        requested_quantity="3",
    )
    gate.apply_order_exposure_observation(ack)

    first_fill = _fill("fractional-trade-1", "1")
    partial = _observation(
        scope,
        tracked,
        state=OrderExposureState.PARTIALLY_FILLED,
        order_revision=2,
        journal_revision=4,
        cumulative_filled_quantity="1",
        leaves_quantity="2",
        filled_gross_notional="0",
        leaves_gross_notional="0",
        requested_quantity="3",
        fills=(first_fill,),
    )
    partial_snapshot = gate.apply_order_exposure_observation(partial)
    assert partial_snapshot.total_gross_notional >= Decimal("100")

    second_fill = _fill("fractional-trade-2", "2", revision=4)
    filled = _observation(
        scope,
        tracked,
        state=OrderExposureState.FILLED,
        order_revision=3,
        journal_revision=5,
        cumulative_filled_quantity="3",
        leaves_quantity="0",
        filled_gross_notional="100",
        leaves_gross_notional="0",
        requested_quantity="3",
        fills=(first_fill, second_fill),
    )
    filled_snapshot = gate.apply_order_exposure_observation(filled)
    assert filled_snapshot.open_gross_notional == 0
    assert filled_snapshot.filled_gross_notional >= Decimal("100")
    assert filled_snapshot.total_gross_notional >= partial_snapshot.total_gross_notional


def test_account_gross_intent_count_cap_is_independent_of_notional_cap(live_risk):
    gate, _, scope, _, _ = live_risk
    gate.set_strategy_allocation(
        scope,
        "strategy-a",
        "allocation-v2",
        max_notional=Decimal("1000"),
        notional_unit="USD",
        max_gross_occupancy_notional=Decimal("1000"),
        max_gross_occupancy_intent_count=10,
    )
    for index in range(3):
        intent = _intent(
            scope,
            f"account-count-{index}",
            "1",
            quantity="1",
            allocation_version="allocation-v2",
        )
        _, tracked = _tracked_order(gate, scope, intent)
        observation = _observation(
            scope,
            tracked,
            state=OrderExposureState.ACKED,
            order_revision=1,
            journal_revision=3 + index,
            cumulative_filled_quantity="0",
            leaves_quantity="1",
            requested_quantity="1",
            filled_gross_notional="0",
            leaves_gross_notional="1",
        )
        gate.apply_order_exposure_observation(observation)

    with pytest.raises(RiskDeniedError) as denied:
        gate.reserve(
            _intent(
                scope,
                "account-count-over",
                "1",
                quantity="1",
                allocation_version="allocation-v2",
            )
        )
    assert denied.value.code == "GROSS_EXPOSURE_ACCOUNT_COUNT_EXHAUSTED"


def test_strategy_gross_intent_count_cap_is_independent_of_account_cap(live_risk):
    gate, _, scope, _, _ = live_risk
    gate.set_strategy_allocation(
        scope,
        "strategy-a",
        "allocation-v2",
        max_notional=Decimal("1000"),
        notional_unit="USD",
        max_gross_occupancy_notional=Decimal("1000"),
        max_gross_occupancy_intent_count=2,
    )
    for index in range(2):
        intent = _intent(
            scope,
            f"strategy-count-{index}",
            "1",
            quantity="1",
            allocation_version="allocation-v2",
        )
        _, tracked = _tracked_order(gate, scope, intent)
        observation = _observation(
            scope,
            tracked,
            state=OrderExposureState.ACKED,
            order_revision=1,
            journal_revision=3 + index,
            cumulative_filled_quantity="0",
            leaves_quantity="1",
            requested_quantity="1",
            filled_gross_notional="0",
            leaves_gross_notional="1",
        )
        gate.apply_order_exposure_observation(observation)

    with pytest.raises(RiskDeniedError) as denied:
        gate.reserve(
            _intent(
                scope,
                "strategy-count-over",
                "1",
                quantity="1",
                allocation_version="allocation-v2",
            )
        )
    assert denied.value.code == "GROSS_EXPOSURE_STRATEGY_COUNT_EXHAUSTED"


def test_pending_permits_count_toward_account_gross_cap(live_risk):
    gate, _, scope, _, _ = live_risk
    gate.reserve(_intent(scope, "pending-account-first", "100"))

    with pytest.raises(RiskDeniedError) as denied:
        gate.reserve(_intent(scope, "pending-account-second", "60"))

    assert denied.value.code == "GROSS_EXPOSURE_ACCOUNT_LIMIT_EXHAUSTED"


def test_pending_permits_count_toward_strategy_gross_cap(live_risk):
    gate, _, scope, _, _ = live_risk
    gate.set_strategy_allocation(
        scope,
        "strategy-a",
        "allocation-v2",
        max_notional=Decimal("1000"),
        notional_unit="USD",
        max_gross_occupancy_notional=Decimal("50"),
        max_gross_occupancy_intent_count=5,
    )
    gate.reserve(_intent(scope, "pending-strategy-first", "40", allocation_version="allocation-v2"))

    with pytest.raises(RiskDeniedError) as denied:
        gate.reserve(
            _intent(scope, "pending-strategy-second", "20", allocation_version="allocation-v2")
        )

    assert denied.value.code == "GROSS_EXPOSURE_STRATEGY_LIMIT_EXHAUSTED"


class _MutableObservedClock:
    def __init__(self, value):
        self.value = value
        self.first_read = Event()

    def __call__(self):
        self.first_read.set()
        return self.value


def _call_after_sqlite_writer_wait(gate, operation, *, advance_seconds):
    writer_locked = Event()
    release_writer = Event()
    writer_errors = []

    def hold_writer_lock():
        try:
            with gate._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                writer_locked.set()
                if not release_writer.wait(5):
                    raise TimeoutError("test did not release its SQLite writer lock")
                connection.execute("ROLLBACK")
        except BaseException as exc:  # surfaced in the test thread after join
            writer_errors.append(exc)

    writer_thread = Thread(target=hold_writer_lock, daemon=True)
    writer_thread.start()
    assert writer_locked.wait(2), "synthetic SQLite writer did not acquire its lock"

    clock = _MutableObservedClock(_NOW)
    gate._clock = clock
    outcome = {}

    def invoke_operation():
        try:
            outcome["value"] = operation()
        except BaseException as exc:  # surfaced in the test thread after join
            outcome["error"] = exc

    operation_thread = Thread(target=invoke_operation, daemon=True)
    operation_thread.start()
    try:
        assert clock.first_read.wait(2), "admission did not sample its clock"
        # The initial sample has happened, and the other connection still owns
        # BEGIN IMMEDIATE.  Advancing now models expiry during lock acquisition.
        clock.value += advance_seconds
    finally:
        release_writer.set()
    operation_thread.join(5)
    writer_thread.join(5)
    assert not operation_thread.is_alive(), "admission stayed blocked after lock release"
    assert not writer_thread.is_alive(), "synthetic SQLite writer did not stop"
    assert writer_errors == []
    assert "error" in outcome, f"admission unexpectedly succeeded: {outcome.get('value')!r}"
    return outcome["error"]


def test_reserve_rechecks_baseline_after_waiting_for_sqlite_writer(live_risk):
    gate, _, scope, _, _ = live_risk

    denied = _call_after_sqlite_writer_wait(
        gate,
        lambda: gate.reserve(_intent(scope, "baseline-expired-during-wait", "10")),
        advance_seconds=3601,
    )

    assert isinstance(denied, RiskDeniedError)
    assert denied.code == "GROSS_EXPOSURE_BASELINE_STALE"


def test_validate_rechecks_permit_expiry_after_waiting_for_sqlite_writer(live_risk):
    gate, _, scope, _, _ = live_risk
    intent = _intent(scope, "validate-expired-during-wait", "10")
    permit = gate.reserve(intent)

    denied = _call_after_sqlite_writer_wait(
        gate,
        lambda: gate.validate_permit(permit.permit_id, intent),
        advance_seconds=11,
    )

    assert denied.code == "PERMIT_NOT_ACTIVE"


def test_claim_rechecks_permit_expiry_after_waiting_for_sqlite_writer(live_risk):
    gate, _, scope, _, _ = live_risk
    intent = _intent(scope, "claim-expired-during-wait", "10")
    permit = gate.reserve(intent)

    denied = _call_after_sqlite_writer_wait(
        gate,
        lambda: gate.claim_for_dispatch(permit.permit_id, intent),
        advance_seconds=11,
    )

    assert denied.code == "PERMIT_NOT_ACTIVE"
    with gate._connection() as connection:
        claim = connection.execute(
            "SELECT 1 FROM risk_dispatch_claims WHERE permit_id = ?", (permit.permit_id,)
        ).fetchone()
    assert claim is None


def test_legacy_policy_fingerprint_is_unchanged_by_reservations_only_default():
    legacy = RiskPolicy("legacy", Decimal("100"), 4, 30.0)
    explicit = RiskPolicy(
        "legacy",
        Decimal("100"),
        4,
        30.0,
        exposure_accounting_mode=ExposureAccountingMode.RESERVATIONS_ONLY,
    )
    assert legacy.fingerprint == explicit.fingerprint
    assert legacy.exposure_accounting_mode is ExposureAccountingMode.RESERVATIONS_ONLY
