"""Focused source-bound admission checks for recovery REDUCE allocations."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
from hashlib import sha256
from pathlib import Path

import pytest

from bt_api_risk import (
    AccountScope,
    DispatchEvidenceClass,
    DispatchExposureResolutionProof,
    DispatchTerminalProof,
    DispatchTerminalResolutionReceiptStatus,
    DispatchTerminalState,
    DispatchTrackedOrderProof,
    DurableRiskGate,
    IntentAction,
    OrderExposureObservationProof,
    OrderExposureState,
    OrderFillFact,
    PermitInvalidError,
    RecoveryCloseSourceProof,
    RiskDeniedError,
    RiskIntent,
    RiskPolicy,
    VerifiedDispatchExposureResolution,
    VerifiedDispatchResolution,
    VerifiedRecoveryCloseSource,
    fill_ids_sha256,
)

_NOW_NS = 100_000_000_000
_INSTRUMENT = "venue/contract-a"
_STRATEGY = "strategy-a"
_ALLOCATION = "allocation-v1"


def _sha(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


class _Clock:
    def __init__(self):
        self.now_ns = _NOW_NS

    def __call__(self) -> float:
        return self.now_ns / 1_000_000_000

    def ns(self) -> int:
        return self.now_ns


class _JournalAuthority:
    """Synthetic trusted journal guard for local Risk ledger tests."""

    def __init__(self, *, tamper_source=False):
        self.tamper_source = tamper_source

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
    def recovery_close_source_guard(self, proof, *, parent_permit, recovery_intent):
        source_proof_sha256 = (
            _sha("altered-source-proof") if self.tamper_source else proof.fingerprint
        )
        yield VerifiedRecoveryCloseSource(
            scope=proof.scope,
            book_id=proof.book_id,
            parent_permit_id=proof.parent_permit_id,
            parent_intent_id=proof.parent_intent_id,
            parent_intent_hash=proof.parent_intent_hash,
            recovery_intent_id=proof.recovery_intent_id,
            recovery_intent_hash=proof.recovery_intent_hash,
            source_proof_sha256=source_proof_sha256,
            source_evidence_sha256=proof.source_evidence_sha256,
            source_revision=proof.source_revision,
            parent_filled_quantity=proof.parent_filled_quantity,
            attributable_position_quantity=proof.attributable_position_quantity,
            instrument=proof.instrument,
            strategy_id=proof.strategy_id,
            allocation_version=proof.allocation_version,
            quantity_unit=proof.quantity_unit,
            parent_order_side=proof.parent_order_side,
            recovery_order_side=proof.recovery_order_side,
            parent_position_side=proof.parent_position_side,
            parent_position_bucket=proof.parent_position_bucket,
            position_side=proof.position_side,
            position_bucket=proof.position_bucket,
            observed_at_ns=proof.observed_at_ns,
            valid_until_ns=proof.valid_until_ns,
            writer_fence_sha256=_sha("source-writer-fence"),
            attribution_complete=True,
        )


def _gate(path: Path, authority=None, recovery_authority=None, *, clock=None) -> DurableRiskGate:
    clock = _Clock() if clock is None else clock
    return DurableRiskGate(
        path,
        RiskPolicy(
            policy_id="recovery-reduction-test",
            max_increase_notional=Decimal("500"),
            max_increase_count=8,
            require_strategy_allocation=True,
            notional_unit="USD",
        ),
        clock=clock,
        clock_ns=clock.ns,
        execution_journal_authority=authority,
        recovery_close_source_authority=recovery_authority,
    )


def _parent(gate: DurableRiskGate, scope: AccountScope, *, position_side="LONG"):
    gate.set_strategy_allocation(
        scope,
        _STRATEGY,
        _ALLOCATION,
        max_notional=Decimal("5000"),
        notional_unit="USD",
    )
    intent = RiskIntent(
        intent_id="open-original",
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal("100"),
        payload_fingerprint=_sha("open-original-payload"),
        strategy_id=_STRATEGY,
        allocation_version=_ALLOCATION,
        instrument=_INSTRUMENT,
        quantity=Decimal("10"),
        quantity_unit="contract",
        notional_unit="USD",
        exposure_profile_fingerprint=_sha("open-profile"),
        instrument_facts_observed_at_ns=_NOW_NS - 1_000,
        instrument_facts_valid_until_ns=_NOW_NS + 1_000_000_000,
        position_side=position_side,
    )
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)
    claim = gate.dispatch_claim_binding(permit.permit_id)
    gate.settle(permit.permit_id)
    proof = DispatchTrackedOrderProof(
        scope=scope,
        permit_id=permit.permit_id,
        intent_id=intent.intent_id,
        intent_hash=claim.intent_hash,
        cause_id=claim.cause_id,
        claim_digest=claim.claim_digest,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        dispatch_attempt_count=1,
        journal_revision=7,
        journal_record_sha256=_sha("parent-tracked-row"),
        reconciliation_evidence_sha256=_sha("parent-reconcile-row"),
        writer_fence_sha256=_sha("parent-writer-fence"),
        provider_order_id="paper-parent-order",
        accepted_request_sha256=_sha("parent-request"),
        exposure_reservation_id="paper-parent-exposure",
        exposure_reservation_sha256=_sha("parent-exposure-row"),
    )
    gate.resolve_dispatch_freeze(proof)
    return intent, permit


def _recovery_intent(
    scope: AccountScope,
    intent_id: str,
    quantity: str,
    *,
    position_side="LONG",
    position_bucket="ALL",
) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.REDUCE,
        notional=Decimal("0"),
        payload_fingerprint=_sha("recovery:" + intent_id + ":" + quantity),
        strategy_id=_STRATEGY,
        allocation_version=_ALLOCATION,
        instrument=_INSTRUMENT,
        quantity=Decimal(quantity),
        quantity_unit="contract",
        notional_unit="USD",
        position_side=position_side,
        position_bucket=position_bucket,
    )


def _source_proof(parent_intent, parent_permit, recovery_intent, *, revision=1, available="8"):
    return RecoveryCloseSourceProof(
        scope=parent_permit.scope,
        book_id=parent_permit.scope.key,
        parent_permit_id=parent_permit.permit_id,
        parent_intent_id=parent_intent.intent_id,
        parent_intent_hash=parent_intent.fingerprint,
        recovery_intent_id=recovery_intent.intent_id,
        recovery_intent_hash=recovery_intent.fingerprint,
        source_evidence_sha256=_sha("book-window:" + str(revision)),
        source_revision=revision,
        parent_filled_quantity=Decimal("10"),
        attributable_position_quantity=Decimal(available),
        instrument=_INSTRUMENT,
        strategy_id=_STRATEGY,
        allocation_version=_ALLOCATION,
        quantity_unit="contract",
        parent_order_side="BUY",
        recovery_order_side="SELL",
        parent_position_side=parent_permit.position_side,
        parent_position_bucket=parent_permit.position_bucket,
        position_side=recovery_intent.position_side,
        position_bucket=recovery_intent.position_bucket,
        observed_at_ns=_NOW_NS - 1_000,
        valid_until_ns=_NOW_NS + 1_000_000_000,
    )


def _allocate(gate, parent_intent, parent_permit, *, intent_id, quantity, revision=1, available="8"):
    intent = _recovery_intent(parent_permit.scope, intent_id, quantity)
    proof = _source_proof(
        parent_intent,
        parent_permit,
        intent,
        revision=revision,
        available=available,
    )
    allocation = gate.reserve_recovery_reduction(
        intent,
        parent_permit_id=parent_permit.permit_id,
        source_proof=proof,
    )
    return intent, proof, allocation


def _terminal_no_fill(gate, intent, allocation):
    gate.claim_for_dispatch(allocation.permit_id, intent)
    claim = gate.dispatch_claim_binding(allocation.permit_id)
    gate.settle(allocation.permit_id)
    proof = DispatchTerminalProof(
        scope=claim.scope,
        permit_id=claim.permit_id,
        intent_id=claim.intent_id,
        intent_hash=claim.intent_hash,
        cause_id=claim.cause_id,
        claim_digest=claim.claim_digest,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        terminal_state=DispatchTerminalState.REJECTED_NO_FILL,
        dispatch_attempt_count=1,
        journal_revision=8,
        journal_record_sha256=_sha("child-no-fill:" + intent.intent_id),
        reconciliation_evidence_sha256=_sha("child-no-fill-reconcile:" + intent.intent_id),
        writer_fence_sha256=_sha("child-no-fill-fence"),
        fee_record_count=0,
        fee_history_complete=True,
        filled_quantity=0,
        trade_count=0,
    )
    return gate.resolve_dispatch_freeze(proof)


def _terminal_close_proof(gate, intent, allocation):
    gate.claim_for_dispatch(allocation.permit_id, intent)
    claim = gate.dispatch_claim_binding(allocation.permit_id)
    gate.settle(allocation.permit_id)
    quantity = intent.quantity
    fill = OrderFillFact(
        trade_id="trade-" + intent.intent_id,
        quantity=quantity,
        price=Decimal("100"),
        side="SELL",
        position_effect="CLOSE",
        fee_amount=Decimal("0"),
        fee_currency="USD",
        source_record_sha256=_sha("fill:" + intent.intent_id),
        source_revision=4,
    )
    observation = OrderExposureObservationProof(
        scope=intent.scope,
        permit_id=allocation.permit_id,
        intent_id=intent.intent_id,
        intent_hash=claim.intent_hash,
        dispatch_claim_digest=claim.claim_digest,
        dispatch_proof_sha256=None,
        provider_order_id="paper-close-order-" + intent.intent_id,
        accepted_request_sha256=_sha("request:" + intent.intent_id),
        exposure_reservation_id="paper-close-ref-" + intent.intent_id,
        exposure_reservation_sha256=_sha("close-ref-row:" + intent.intent_id),
        order_revision=2,
        journal_revision=10,
        journal_record_sha256=_sha("close-journal:" + intent.intent_id),
        observation_sha256=_sha("close-observation:" + intent.intent_id),
        fill_history_sha256=_sha("close-fill-history:" + intent.intent_id),
        source_alias_map_sha256=_sha("source-aliases"),
        state=OrderExposureState.FILLED,
        requested_quantity=quantity,
        cumulative_filled_quantity=quantity,
        leaves_quantity=Decimal("0"),
        filled_gross_notional=quantity * Decimal("100"),
        leaves_gross_notional=Decimal("0"),
        leaves_valuation_price=None,
        notional_unit="USD",
        complete_order_snapshot=True,
        complete_fill_history=True,
        fill_watermark_revision=9,
        source_contract_ref="paper/contract-a",
        source_contract_version="contract-v1",
        provider_profile_version="paper-provider-v1",
        normalizer_schema_version="paper-normalizer-v1",
        order_side="SELL",
        position_effect="CLOSE",
        position_side="LONG",
        position_bucket="ALL",
        fills=(fill,),
        fill_trade_count=1,
        fill_ids_sha256=fill_ids_sha256((fill,)),
        instrument_id=_INSTRUMENT,
        instrument_version="instrument-v1",
        instrument_multiplier=Decimal("1"),
        quote_currency="USD",
        valuation_unit="USD",
        instrument_metadata_sha256=_sha("instrument-metadata"),
        instrument_metadata_observed_at_ns=_NOW_NS - 1_000,
        instrument_metadata_valid_until_ns=_NOW_NS + 1_000_000_000,
        valuation_facts_sha256=_sha("valuation-facts"),
        valuation_observed_at_ns=_NOW_NS - 1_000,
        valuation_valid_until_ns=_NOW_NS + 1_000_000_000,
        fx_pair=None,
        fx_rate=None,
        fx_observed_at_ns=None,
        fx_valid_until_ns=None,
        observed_at_ns=_NOW_NS - 1_000,
        valid_until_ns=_NOW_NS + 1_000_000_000,
        writer_owner_id="synthetic-writer",
        writer_fencing_token=2,
        writer_fence_sha256=_sha("close-writer-fence"),
    )
    return DispatchExposureResolutionProof(
        claim=claim,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        dispatch_attempt_count=1,
        reconciliation_evidence_sha256=_sha("close-reconcile:" + intent.intent_id),
        observation=observation,
    )


def test_source_proved_recovery_allocation_keeps_original_increase_and_is_verifiable(tmp_path):
    scope = AccountScope("paper", "risk-account", "sandbox")
    authority = _JournalAuthority()
    gate = _gate(tmp_path / "risk.sqlite", authority, _JournalAuthority())
    parent_intent, parent_permit = _parent(gate, scope)
    intent, proof, allocation = _allocate(
        gate, parent_intent, parent_permit, intent_id="recovery-1", quantity="3"
    )

    assert allocation.permit.action is IntentAction.REDUCE
    assert allocation.quantity == Decimal("3")
    assert allocation.source_proof_sha256 == proof.fingerprint
    assert gate.verify_recovery_reduction_allocation(allocation, intent=intent) == allocation
    claimed = gate.claim_for_dispatch(allocation.permit_id, intent)
    assert claimed == allocation.permit
    claim = gate.dispatch_claim_binding(allocation.permit_id)
    assert claim.scope == intent.scope
    assert claim.intent_id == intent.intent_id
    assert claim.intent_hash == intent.fingerprint
    assert gate._execution_journal_authority is authority
    with pytest.raises(PermitInvalidError) as ordinary_replay:
        gate.reserve(intent)
    assert ordinary_replay.value.code == "RECOVERY_REDUCTION_AUTHORITY_REQUIRED"
    with gate._connection() as connection:
        parent = connection.execute(
            "SELECT action, status, notional, quantity FROM risk_reservations WHERE permit_id = ?",
            (parent_permit.permit_id,),
        ).fetchone()
        resolution = connection.execute(
            "SELECT proof_kind FROM risk_dispatch_resolutions WHERE permit_id = ?",
            (parent_permit.permit_id,),
        ).fetchone()
    assert tuple(parent) == ("increase", "settled", "100", "10")
    assert resolution["proof_kind"] == "ACKED_TRACKED"


def test_recovery_guard_rejects_stale_wrong_scope_and_changed_authority_proof(tmp_path):
    scope = AccountScope("paper", "risk-account", "sandbox")
    gate = _gate(tmp_path / "stale.sqlite", _JournalAuthority())
    parent_intent, parent_permit = _parent(gate, scope)
    stale_intent = _recovery_intent(scope, "stale-child", "1")
    stale = replace(
        _source_proof(parent_intent, parent_permit, stale_intent),
        observed_at_ns=_NOW_NS - 10_000,
        valid_until_ns=_NOW_NS - 1,
    )
    with pytest.raises(RiskDeniedError) as expired:
        gate.reserve_recovery_reduction(
            stale_intent, parent_permit_id=parent_permit.permit_id, source_proof=stale
        )
    assert expired.value.code == "RECOVERY_SOURCE_STALE"

    wrong_scope_intent = _recovery_intent(scope, "wrong-scope-child", "1")
    wrong_scope = replace(
        _source_proof(parent_intent, parent_permit, wrong_scope_intent),
        scope=AccountScope("paper", "other-account", "sandbox"),
    )
    with pytest.raises(RiskDeniedError) as scope_error:
        gate.reserve_recovery_reduction(
            wrong_scope_intent,
            parent_permit_id=parent_permit.permit_id,
            source_proof=wrong_scope,
        )
    assert scope_error.value.code == "RECOVERY_SOURCE_SCOPE_MISMATCH"

    tainted_gate = _gate(tmp_path / "tainted.sqlite", _JournalAuthority(tamper_source=True))
    tainted_parent_intent, tainted_parent = _parent(tainted_gate, scope)
    tainted_intent = _recovery_intent(scope, "tainted-child", "1")
    tainted = _source_proof(tainted_parent_intent, tainted_parent, tainted_intent)
    with pytest.raises(PermitInvalidError) as authority_error:
        tainted_gate.reserve_recovery_reduction(
            tainted_intent,
            parent_permit_id=tainted_parent.permit_id,
            source_proof=tainted,
        )
    assert authority_error.value.code == "RECOVERY_SOURCE_PROOF_REJECTED"


def test_source_revisions_do_not_reset_allocation_and_replay_is_exact(tmp_path):
    scope = AccountScope("paper", "risk-account", "sandbox")
    gate = _gate(tmp_path / "revision.sqlite", _JournalAuthority())
    parent_intent, parent_permit = _parent(gate, scope)
    intent, proof, allocation = _allocate(
        gate, parent_intent, parent_permit, intent_id="revision-child-a", quantity="6", available="8"
    )
    assert gate.reserve_recovery_reduction(
        intent, parent_permit_id=parent_permit.permit_id, source_proof=proof
    ) == allocation
    changed_proof = replace(
        proof,
        source_revision=2,
        source_evidence_sha256=_sha("book-window:2"),
        observed_at_ns=_NOW_NS - 500,
    )
    with pytest.raises(PermitInvalidError) as changed_replay:
        gate.reserve_recovery_reduction(
            intent, parent_permit_id=parent_permit.permit_id, source_proof=changed_proof
        )
    assert changed_replay.value.code == "RECOVERY_REDUCTION_REPLAY_CONFLICT"

    second, second_proof = _recovery_intent(scope, "revision-child-b", "5"), None
    second_proof = _source_proof(
        parent_intent, parent_permit, second, revision=3, available="10"
    )
    with pytest.raises(RiskDeniedError) as exhausted:
        gate.reserve_recovery_reduction(
            second,
            parent_permit_id=parent_permit.permit_id,
            source_proof=second_proof,
        )
    assert exhausted.value.code == "RECOVERY_PARENT_QUANTITY_EXHAUSTED"


def test_parallel_allocations_share_one_parent_position_cap(tmp_path):
    scope = AccountScope("paper", "risk-account", "sandbox")
    gate = _gate(tmp_path / "concurrent.sqlite", _JournalAuthority())
    parent_intent, parent_permit = _parent(gate, scope)

    def attempt(index):
        intent = _recovery_intent(scope, "concurrent-child-" + str(index), "2")
        proof = _source_proof(parent_intent, parent_permit, intent, available="3")
        try:
            return gate.reserve_recovery_reduction(
                intent, parent_permit_id=parent_permit.permit_id, source_proof=proof
            )
        except RiskDeniedError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, (1, 2)))
    assert sum(type(result) is not str for result in results) == 1
    assert results.count("RECOVERY_POSITION_QUANTITY_EXHAUSTED") == 1
    with gate._connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM risk_recovery_reduction_allocations WHERE parent_permit_id = ?",
            (parent_permit.permit_id,),
        ).fetchone()[0] == 1


def test_only_resolved_zero_fee_no_fill_returns_quota_but_filled_close_is_permanent(tmp_path):
    scope = AccountScope("paper", "risk-account", "sandbox")
    gate = _gate(tmp_path / "quota.sqlite", _JournalAuthority())
    parent_intent, parent_permit = _parent(gate, scope)
    nofill_intent, _, nofill_allocation = _allocate(
        gate, parent_intent, parent_permit, intent_id="no-fill-child", quantity="8"
    )
    receipt = _terminal_no_fill(gate, nofill_intent, nofill_allocation)
    assert receipt.proof is not None
    assert receipt.proof.filled_quantity == 0
    assert receipt.proof.trade_count == 0
    assert receipt.fee_record_count == 0
    assert receipt.fee_history_complete is True

    close_intent, _, close_allocation = _allocate(
        gate,
        parent_intent,
        parent_permit,
        intent_id="filled-close-child",
        quantity="6",
        revision=2,
        available="10",
    )
    close_receipt = gate.resolve_dispatch_close(
        _terminal_close_proof(gate, close_intent, close_allocation)
    )
    assert close_receipt.filled_quantity == Decimal("6")

    remaining = _recovery_intent(scope, "after-filled-child", "5")
    remaining_proof = _source_proof(
        parent_intent, parent_permit, remaining, revision=3, available="5"
    )
    with pytest.raises(RiskDeniedError) as cumulative:
        gate.reserve_recovery_reduction(
            remaining,
            parent_permit_id=parent_permit.permit_id,
            source_proof=remaining_proof,
        )
    assert cumulative.value.code == "RECOVERY_PARENT_QUANTITY_EXHAUSTED"


def test_regular_reduce_keeps_existing_zero_fill_dispatch_resolution(tmp_path):
    scope = AccountScope("paper", "ordinary-close-account", "sandbox")
    gate = _gate(tmp_path / "ordinary-close.sqlite", _JournalAuthority())
    gate.set_strategy_allocation(
        scope,
        _STRATEGY,
        _ALLOCATION,
        max_notional=Decimal("5000"),
        notional_unit="USD",
    )
    gate.set_closable_position(
        scope,
        _INSTRUMENT,
        _STRATEGY,
        "close-snapshot-v1",
        closable_quantity=Decimal("5"),
        quantity_unit="contract",
        position_side="LONG",
    )
    intent = _recovery_intent(scope, "ordinary-reduce-no-fill", "2")

    permit = gate.reserve(intent)
    assert permit.action is IntentAction.REDUCE
    assert permit.position_side == "LONG"
    gate.claim_for_dispatch(permit.permit_id, intent)
    claim = gate.dispatch_claim_binding(permit.permit_id)
    gate.settle(permit.permit_id)
    proof = DispatchTerminalProof(
        scope=claim.scope,
        permit_id=claim.permit_id,
        intent_id=claim.intent_id,
        intent_hash=claim.intent_hash,
        cause_id=claim.cause_id,
        claim_digest=claim.claim_digest,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        terminal_state=DispatchTerminalState.REJECTED_NO_FILL,
        dispatch_attempt_count=1,
        journal_revision=3,
        journal_record_sha256=_sha("ordinary-reduce-no-fill-row"),
        reconciliation_evidence_sha256=_sha("ordinary-reduce-no-fill-reconciliation"),
        writer_fence_sha256=_sha("ordinary-reduce-no-fill-fence"),
        fee_record_count=0,
        fee_history_complete=True,
        filled_quantity=0,
        trade_count=0,
    )

    receipt = gate.resolve_dispatch_freeze(proof)

    assert receipt is not None
    assert receipt.status is DispatchTerminalResolutionReceiptStatus.NO_FILL_TERMINAL_RESOLVED
    assert receipt.proof == proof
    with gate._connection() as connection:
        status = connection.execute(
            "SELECT status FROM risk_reservations WHERE permit_id = ?",
            (permit.permit_id,),
        ).fetchone()[0]
    assert status == "no_fill_terminal"


def test_parent_allocation_allows_source_proved_dated_child_slice_only(tmp_path):
    scope = AccountScope("paper", "dated-close-account", "sandbox")
    gate = _gate(tmp_path / "dated-close.sqlite", _JournalAuthority())
    parent_intent, parent_permit = _parent(gate, scope)
    dated_intent = _recovery_intent(
        scope,
        "dated-today-child",
        "2",
        position_bucket="TODAY",
    )
    dated_proof = _source_proof(parent_intent, parent_permit, dated_intent, available="3")

    allocation = gate.reserve_recovery_reduction(
        dated_intent,
        parent_permit_id=parent_permit.permit_id,
        source_proof=dated_proof,
    )

    assert allocation.parent_position_bucket == "ALL"
    assert allocation.position_bucket == "TODAY"
    assert allocation.close_position_version.startswith("recovery-1-")
    assert allocation.close_position_version != _ALLOCATION
    assert gate.verify_recovery_reduction_allocation(allocation, intent=dated_intent) == allocation

    wrong_bucket_intent = _recovery_intent(
        scope,
        "wrong-dated-slice-child",
        "1",
        position_bucket="TODAY",
    )
    wrong_bucket_proof = replace(
        _source_proof(parent_intent, parent_permit, wrong_bucket_intent),
        position_bucket="YESTERDAY",
    )
    with pytest.raises(RiskDeniedError) as wrong_slice:
        gate.reserve_recovery_reduction(
            wrong_bucket_intent,
            parent_permit_id=parent_permit.permit_id,
            source_proof=wrong_bucket_proof,
        )
    assert wrong_slice.value.code == "RECOVERY_SOURCE_SCOPE_MISMATCH"

    wrong_side_intent = _recovery_intent(
        scope,
        "wrong-position-side-child",
        "1",
        position_side="SHORT",
    )
    wrong_side_proof = _source_proof(parent_intent, parent_permit, wrong_side_intent)
    with pytest.raises(RiskDeniedError) as wrong_side:
        gate.reserve_recovery_reduction(
            wrong_side_intent,
            parent_permit_id=parent_permit.permit_id,
            source_proof=wrong_side_proof,
        )
    assert wrong_side.value.code == "RECOVERY_SOURCE_SCOPE_MISMATCH"


def test_net_parent_source_side_follows_parent_order_direction(tmp_path):
    scope = AccountScope("paper", "net-parent-account", "sandbox")
    gate = _gate(tmp_path / "net-parent.sqlite", _JournalAuthority())
    parent_intent, parent_permit = _parent(gate, scope, position_side="NET")
    long_child = _recovery_intent(
        scope,
        "net-buy-long-child",
        "1",
        position_side="LONG",
        position_bucket="TODAY",
    )
    long_proof = _source_proof(parent_intent, parent_permit, long_child)

    allocation = gate.reserve_recovery_reduction(
        long_child,
        parent_permit_id=parent_permit.permit_id,
        source_proof=long_proof,
    )
    assert allocation.parent_position_side == "NET"
    assert allocation.position_side == "LONG"

    short_child = _recovery_intent(
        scope,
        "net-buy-short-child",
        "1",
        position_side="SHORT",
    )
    short_proof = _source_proof(parent_intent, parent_permit, short_child)
    with pytest.raises(RiskDeniedError) as wrong_direction:
        gate.reserve_recovery_reduction(
            short_child,
            parent_permit_id=parent_permit.permit_id,
            source_proof=short_proof,
        )
    assert wrong_direction.value.code == "RECOVERY_SOURCE_SCOPE_MISMATCH"


def test_recovery_pending_quantity_is_capped_per_dated_source_slice(tmp_path):
    scope = AccountScope("paper", "dated-slice-cap-account", "sandbox")
    gate = _gate(tmp_path / "dated-slice-cap.sqlite", _JournalAuthority())
    parent_intent, parent_permit = _parent(gate, scope)
    today = _recovery_intent(
        scope, "today-child-a", "2", position_bucket="TODAY"
    )
    today_proof = _source_proof(parent_intent, parent_permit, today, revision=1, available="3")
    today_allocation = gate.reserve_recovery_reduction(
        today, parent_permit_id=parent_permit.permit_id, source_proof=today_proof
    )
    assert today_allocation.quantity == Decimal("2")

    yesterday = _recovery_intent(
        scope, "yesterday-child-a", "2", position_bucket="YESTERDAY"
    )
    yesterday_proof = _source_proof(
        parent_intent, parent_permit, yesterday, revision=2, available="3"
    )
    yesterday_allocation = gate.reserve_recovery_reduction(
        yesterday,
        parent_permit_id=parent_permit.permit_id,
        source_proof=yesterday_proof,
    )
    assert yesterday_allocation.quantity == Decimal("2")

    today_again = _recovery_intent(
        scope, "today-child-b", "2", position_bucket="TODAY"
    )
    today_again_proof = _source_proof(
        parent_intent, parent_permit, today_again, revision=3, available="3"
    )
    with pytest.raises(RiskDeniedError) as slice_exhausted:
        gate.reserve_recovery_reduction(
            today_again,
            parent_permit_id=parent_permit.permit_id,
            source_proof=today_again_proof,
        )
    assert slice_exhausted.value.code == "RECOVERY_POSITION_QUANTITY_EXHAUSTED"

    over_parent = _recovery_intent(
        scope, "cross-slice-parent-cap", "7", position_bucket="YESTERDAY"
    )
    over_parent_proof = _source_proof(
        parent_intent, parent_permit, over_parent, revision=4, available="10"
    )
    with pytest.raises(RiskDeniedError) as parent_exhausted:
        gate.reserve_recovery_reduction(
            over_parent,
            parent_permit_id=parent_permit.permit_id,
            source_proof=over_parent_proof,
        )
    assert parent_exhausted.value.code == "RECOVERY_PARENT_QUANTITY_EXHAUSTED"


def test_recovery_claim_rechecks_source_expiry_after_receipt_verification(tmp_path):
    scope = AccountScope("paper", "expiring-source-account", "sandbox")
    clock = _Clock()
    gate = _gate(tmp_path / "expiring-source.sqlite", _JournalAuthority(), clock=clock)
    parent_intent, parent_permit = _parent(gate, scope)
    intent, proof, allocation = _allocate(
        gate, parent_intent, parent_permit, intent_id="expiring-child", quantity="1"
    )

    assert gate.verify_recovery_reduction_allocation(allocation, intent=intent) == allocation
    with gate._connection() as connection:
        permit_expires_at = connection.execute(
            "SELECT expires_at FROM risk_reservations WHERE permit_id = ?",
            (allocation.permit_id,),
        ).fetchone()[0]
    assert permit_expires_at > proof.valid_until_ns / 1_000_000_000
    clock.now_ns = proof.valid_until_ns

    with pytest.raises(PermitInvalidError) as expired:
        gate.claim_for_dispatch(allocation.permit_id, intent)
    assert expired.value.code == "RECOVERY_SOURCE_STALE"
    with gate._connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM risk_dispatch_claims WHERE permit_id = ?",
            (allocation.permit_id,),
        ).fetchone()[0] == 0


def test_recovery_claim_rechecks_permit_expiry_while_source_remains_fresh(tmp_path):
    scope = AccountScope("paper", "expiring-permit-account", "sandbox")
    clock = _Clock()
    gate = _gate(tmp_path / "expiring-permit.sqlite", _JournalAuthority(), clock=clock)
    parent_intent, parent_permit = _parent(gate, scope)
    intent = _recovery_intent(scope, "expiring-permit-child", "1")
    proof = replace(
        _source_proof(parent_intent, parent_permit, intent),
        valid_until_ns=_NOW_NS + 600_000_000_000,
    )
    allocation = gate.reserve_recovery_reduction(
        intent,
        parent_permit_id=parent_permit.permit_id,
        source_proof=proof,
    )
    assert gate.verify_recovery_reduction_allocation(allocation, intent=intent) == allocation
    assert allocation.valid_until_ns / 1_000_000_000 > allocation.permit.expires_at

    original_check = gate._assert_recovery_allocation_fresh_for_claim_in_transaction
    checks = 0

    def expire_between_checks(connection, *, permit, intent):
        nonlocal checks
        checks += 1
        if checks == 2:
            clock.now_ns = int(permit.expires_at * 1_000_000_000) + 1
        return original_check(connection, permit=permit, intent=intent)

    gate._assert_recovery_allocation_fresh_for_claim_in_transaction = expire_between_checks
    with pytest.raises(PermitInvalidError) as expired:
        gate.claim_for_dispatch(allocation.permit_id, intent)
    assert expired.value.code == "PERMIT_NOT_ACTIVE"
    assert checks == 2
    assert clock.now_ns < proof.valid_until_ns
    with gate._connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM risk_dispatch_claims WHERE permit_id = ?",
            (allocation.permit_id,),
        ).fetchone()[0] == 0
