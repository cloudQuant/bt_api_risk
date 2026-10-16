"""Focused local-SQLite tests for execution-book CLOSE absorption."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from decimal import Decimal
from typing import Optional

import pytest

from bt_api_risk import (
    AccountScope,
    ClosablePositionCloseReceiptV1,
    ClosablePositionRebaseV1,
    DispatchEvidenceClass,
    DispatchExposureResolutionProof,
    DispatchExposureResolutionReceiptStatus,
    DurableRiskGate,
    IntentAction,
    OrderExposureObservationProof,
    OrderExposureState,
    OrderFillFact,
    PermitInvalidError,
    RiskDeniedError,
    RiskIntent,
    RiskPolicy,
    VerifiedDispatchExposureResolution,
    fill_ids_sha256,
)

_NOW_NS = 100_000_000_000
_WRITER = "synthetic-risk-writer"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class _Clock:
    def __call__(self) -> float:
        return 100.0


class _Authority:
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


def _gate(tmp_path):
    scope = AccountScope("fixture", "paper-account", "sandbox")
    gate = DurableRiskGate(
        tmp_path / "risk-rebase.sqlite3",
        RiskPolicy(
            "paper-close-rebase",
            Decimal("5000"),
            8,
            require_strategy_allocation=True,
            notional_unit="USD",
        ),
        clock=_Clock(),
        execution_journal_authority=_Authority(),
    )
    gate.set_strategy_allocation(
        scope,
        "strategy-a",
        "allocation-v1",
        max_notional=Decimal("5000"),
        notional_unit="USD",
    )
    gate.set_closable_position(
        scope,
        "venue/contract-a",
        "strategy-a",
        "owner-declaration-v1",
        closable_quantity=Decimal("5"),
        quantity_unit="contract",
    )
    return gate, scope


def _close_intent(scope: AccountScope, intent_id: str, quantity: str) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.REDUCE,
        notional=Decimal("0"),
        payload_fingerprint=_sha("intent:" + intent_id),
        strategy_id="strategy-a",
        allocation_version="allocation-v1",
        instrument="venue/contract-a",
        quantity=Decimal(quantity),
        quantity_unit="contract",
        notional_unit="USD",
        exposure_profile_fingerprint=_sha("profile:" + intent_id),
        instrument_facts_observed_at_ns=_NOW_NS,
        instrument_facts_valid_until_ns=_NOW_NS + 3_600_000_000_000,
    )


def _make_close(gate: DurableRiskGate, scope: AccountScope, *, intent_id: str, quantity: str):
    intent = _close_intent(scope, intent_id, quantity)
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)
    claim = gate.dispatch_claim_binding(permit.permit_id)
    gate.settle(permit.permit_id)
    fill = OrderFillFact(
        trade_id="trade-" + intent_id,
        quantity=Decimal(quantity),
        price=Decimal("100"),
        side="SELL",
        position_effect="CLOSE",
        fee_amount=Decimal("0"),
        fee_currency="USD",
        source_record_sha256=_sha("fill:" + intent_id),
        source_revision=3,
    )
    observation = OrderExposureObservationProof(
        scope=scope,
        permit_id=permit.permit_id,
        intent_id=intent.intent_id,
        intent_hash=claim.intent_hash,
        dispatch_claim_digest=claim.claim_digest,
        dispatch_proof_sha256=None,
        provider_order_id="paper-order-" + intent_id,
        accepted_request_sha256=_sha("request:" + intent_id),
        exposure_reservation_id="paper-close-ref-" + intent_id,
        exposure_reservation_sha256=_sha("paper-close-ref-digest:" + intent_id),
        order_revision=2,
        journal_revision=6,
        journal_record_sha256=_sha("journal-record:" + intent_id),
        observation_sha256=_sha("observation:" + intent_id),
        fill_history_sha256=_sha("fill-history:" + intent_id),
        source_alias_map_sha256=_sha("source-aliases"),
        state=OrderExposureState.FILLED,
        requested_quantity=Decimal(quantity),
        cumulative_filled_quantity=Decimal(quantity),
        leaves_quantity=Decimal("0"),
        filled_gross_notional=Decimal(quantity) * Decimal("100"),
        leaves_gross_notional=Decimal("0"),
        leaves_valuation_price=None,
        notional_unit="USD",
        complete_order_snapshot=True,
        complete_fill_history=True,
        fill_watermark_revision=5,
        source_contract_ref="paper/contract-a",
        source_contract_version="contract-v1",
        provider_profile_version="paper-provider-v1",
        normalizer_schema_version="paper-normalizer-v1",
        order_side="SELL",
        position_effect="CLOSE",
        fills=(fill,),
        fill_trade_count=1,
        fill_ids_sha256=fill_ids_sha256((fill,)),
        instrument_id="venue/contract-a",
        instrument_version="instrument-v1",
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
        writer_owner_id=_WRITER,
        writer_fencing_token=2,
        writer_fence_sha256=_sha("writer-fence"),
    )
    proof = DispatchExposureResolutionProof(
        claim=claim,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        dispatch_attempt_count=1,
        reconciliation_evidence_sha256=_sha("reconciliation:" + intent_id),
        observation=observation,
    )
    receipt = gate.resolve_dispatch_close(proof)
    assert receipt.status is DispatchExposureResolutionReceiptStatus.TERMINAL_CLOSE_RESOLVED
    return permit.permit_id, intent_id


def _rebase(
    scope: AccountScope,
    refs,
    *,
    cursor: int,
    quantity: str,
    digest: Optional[str] = None,  # noqa: UP045 -- Python 3.9 is supported.
):
    return ClosablePositionRebaseV1(
        scope=scope,
        instrument="venue/contract-a",
        strategy_id="strategy-a",
        closable_quantity=Decimal(quantity),
        quantity_unit="contract",
        execution_generation="a" * 32,
        execution_cursor=cursor,
        snapshot_sha256=digest or _sha(f"snapshot:{cursor}:{quantity}"),
        absorbed_close_receipts=tuple(refs),
    )


def test_full_book_rebase_absorbs_each_verified_close_once_and_keeps_new_closes_bounded(
    tmp_path,
):
    gate, scope = _gate(tmp_path)
    permit_id, intent_id = _make_close(
        gate, scope, intent_id="paper-close-1", quantity="2"
    )

    before = gate.get_closable_position(scope, "venue/contract-a", "strategy-a")
    assert before.declared_quantity == Decimal("5")
    assert before.used_quantity == Decimal("2")
    assert before.available_quantity == Decimal("3")

    refs = gate.get_unabsorbed_settled_close_receipts(
        scope, "venue/contract-a", "strategy-a"
    )
    assert refs == (
        ClosablePositionCloseReceiptV1(
            permit_id=permit_id,
            intent_id=intent_id,
            close_receipt_sha256=refs[0].close_receipt_sha256,
        ),
    )
    result = gate.rebase_closable_position(_rebase(scope, refs, cursor=9, quantity="3"))

    assert result.declared_quantity == Decimal("3")
    assert result.used_quantity == Decimal("0")
    assert result.available_quantity == Decimal("3")
    assert gate.get_unabsorbed_settled_close_receipts(
        scope, "venue/contract-a", "strategy-a"
    ) == ()

    # Same cut is idempotent and the already absorbed close is not subtracted twice.
    replay = gate.rebase_closable_position(_rebase(scope, refs, cursor=9, quantity="3"))
    assert replay.declared_quantity == Decimal("3")
    assert replay.used_quantity == Decimal("0")

    # A later close is a new receipt; the already absorbed first close does
    # not reappear in the unabsorbed set.
    second_permit_id, second_intent_id = _make_close(
        gate, scope, intent_id="paper-close-2", quantity="1"
    )
    second_refs = gate.get_unabsorbed_settled_close_receipts(
        scope, "venue/contract-a", "strategy-a"
    )
    assert len(second_refs) == 1
    assert second_refs[0].permit_id == second_permit_id
    assert second_refs[0].intent_id == second_intent_id
    second_cut = gate.rebase_closable_position(
        _rebase(scope, second_refs, cursor=10, quantity="2")
    )
    assert second_cut.declared_quantity == Decimal("2")
    assert second_cut.used_quantity == Decimal("0")
    assert second_cut.available_quantity == Decimal("2")

    # New closes remain bounded against the latest full execution book.
    new_permit = gate.reserve(_close_intent(scope, "paper-close-3", "2"))
    assert new_permit.quantity == Decimal("2")
    with pytest.raises(RiskDeniedError) as denied:
        gate.reserve(_close_intent(scope, "paper-close-4", "1"))
    assert denied.value.code == "CLOSE_QUANTITY_EXHAUSTED"


def test_rebase_rejects_missing_extra_active_and_unresolved_close_proofs(tmp_path):
    gate, scope = _gate(tmp_path)
    permit_id, intent_id = _make_close(
        gate, scope, intent_id="paper-close-1", quantity="2"
    )
    refs = gate.get_unabsorbed_settled_close_receipts(
        scope, "venue/contract-a", "strategy-a"
    )
    assert refs[0].permit_id == permit_id
    proof = _rebase(scope, (), cursor=4, quantity="3")
    with pytest.raises(RiskDeniedError) as missing:
        gate.rebase_closable_position(proof)
    assert missing.value.code == "CLOSE_REBASE_RECEIPT_SET_MISMATCH"

    active_dir = tmp_path / "active"
    active_dir.mkdir()
    active_gate, active_scope = _gate(active_dir)
    active_gate.reserve(_close_intent(active_scope, "active-close", "1"))
    with pytest.raises(RiskDeniedError) as active:
        active_gate.get_unabsorbed_settled_close_receipts(
            active_scope, "venue/contract-a", "strategy-a"
        )
    assert active.value.code == "CLOSE_REBASE_ACTIVE_CLOSE"

    unresolved_dir = tmp_path / "unresolved"
    unresolved_dir.mkdir()
    unresolved_gate, unresolved_scope = _gate(unresolved_dir)
    unresolved_intent = _close_intent(unresolved_scope, "unresolved-close", "1")
    unresolved_permit = unresolved_gate.reserve(unresolved_intent)
    unresolved_gate.claim_for_dispatch(unresolved_permit.permit_id, unresolved_intent)
    unresolved_gate.settle(unresolved_permit.permit_id)
    with pytest.raises(RiskDeniedError) as unresolved:
        unresolved_gate.get_unabsorbed_settled_close_receipts(
            unresolved_scope, "venue/contract-a", "strategy-a"
        )
    assert unresolved.value.code == "CLOSE_REBASE_UNKNOWN_CLOSE"


def test_rebase_rejects_stale_or_conflicting_cut_and_manual_overwrite(tmp_path):
    gate, scope = _gate(tmp_path)
    permit_id, intent_id = _make_close(
        gate, scope, intent_id="paper-close-1", quantity="2"
    )
    refs = gate.get_unabsorbed_settled_close_receipts(
        scope, "venue/contract-a", "strategy-a"
    )
    assert refs[0].permit_id == permit_id and refs[0].intent_id == intent_id
    gate.rebase_closable_position(_rebase(scope, refs, cursor=9, quantity="3"))

    with pytest.raises(RiskDeniedError) as old:
        gate.rebase_closable_position(_rebase(scope, refs, cursor=8, quantity="4"))
    assert old.value.code == "CLOSE_REBASE_CURSOR_OLD"

    with pytest.raises(RiskDeniedError) as conflict:
        gate.rebase_closable_position(
            _rebase(scope, refs, cursor=9, quantity="4", digest=_sha("different-cut"))
        )
    assert conflict.value.code == "CLOSE_REBASE_CUT_CONFLICT"

    with pytest.raises(RiskDeniedError) as manual:
        gate.set_closable_position(
            scope,
            "venue/contract-a",
            "strategy-a",
            "manual-overwrite-v2",
            closable_quantity=Decimal("100"),
            quantity_unit="contract",
        )
    assert manual.value.code == "CLOSE_POSITION_REBASE_OWNS_SLICE"


def test_rebase_rejects_generation_change_and_wrong_receipt_digest(tmp_path):
    gate, scope = _gate(tmp_path)
    permit_id, intent_id = _make_close(
        gate, scope, intent_id="paper-close-1", quantity="2"
    )
    refs = gate.get_unabsorbed_settled_close_receipts(
        scope, "venue/contract-a", "strategy-a"
    )
    receipt = refs[0]
    wrong_ref = ClosablePositionCloseReceiptV1(
        permit_id=receipt.permit_id,
        intent_id=receipt.intent_id,
        close_receipt_sha256=_sha("forged-close-receipt"),
    )
    with pytest.raises(RiskDeniedError) as mismatch:
        gate.rebase_closable_position(_rebase(scope, (wrong_ref,), cursor=9, quantity="3"))
    assert mismatch.value.code == "CLOSE_REBASE_RECEIPT_SET_MISMATCH"

    gate.rebase_closable_position(_rebase(scope, refs, cursor=9, quantity="3"))
    changed_generation = ClosablePositionRebaseV1(
        scope=scope,
        instrument="venue/contract-a",
        strategy_id="strategy-a",
        closable_quantity=Decimal("3"),
        quantity_unit="contract",
        execution_generation="b" * 32,
        execution_cursor=10,
        snapshot_sha256=_sha("new-generation"),
        absorbed_close_receipts=(),
    )
    with pytest.raises(RiskDeniedError) as generation:
        gate.rebase_closable_position(changed_generation)
    assert generation.value.code == "CLOSE_REBASE_GENERATION_CHANGED"


def test_same_cut_replay_revalidates_absorbed_risk_receipt(tmp_path):
    gate, scope = _gate(tmp_path)
    permit_id, _ = _make_close(gate, scope, intent_id="paper-close-1", quantity="2")
    refs = gate.get_unabsorbed_settled_close_receipts(
        scope, "venue/contract-a", "strategy-a"
    )
    proof = _rebase(scope, refs, cursor=9, quantity="3")
    gate.rebase_closable_position(proof)

    # The production schema makes terminal receipts immutable. Simulate a
    # damaged/edited database to ensure the idempotent fast path still verifies
    # the exact terminal Risk receipt instead of trusting an old absorption row.
    connection = sqlite3.connect(tmp_path / "risk-rebase.sqlite3")
    try:
        connection.execute("DROP TRIGGER risk_close_order_resolution_immutable_update")
        connection.execute(
            """UPDATE risk_close_order_resolutions SET close_reference_id = ?
               WHERE permit_id = ?""",
            ("edited-receipt", permit_id),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(PermitInvalidError) as replay:
        gate.rebase_closable_position(proof)
    assert replay.value.code == "DISPATCH_CLOSE_STATE_CONFLICT"


def test_close_rebase_rejects_unpublished_non_net_position_slices(tmp_path):
    gate, scope = _gate(tmp_path)
    invalid_slices = (
        ("NET", "TODAY"),
        ("NET", "YESTERDAY"),
        ("LONG", "ALL"),
        ("LONG", "TODAY"),
        ("LONG", "YESTERDAY"),
        ("SHORT", "ALL"),
        ("SHORT", "TODAY"),
        ("SHORT", "YESTERDAY"),
    )
    for index, (position_side, position_bucket) in enumerate(invalid_slices):
        with pytest.raises(ValueError, match="NET/ALL only"):
            ClosablePositionRebaseV1(
                scope=scope,
                instrument="venue/contract-a",
                strategy_id="strategy-a",
                closable_quantity=Decimal("2"),
                quantity_unit="contract",
                execution_generation="a" * 32,
                execution_cursor=index,
                snapshot_sha256=_sha(f"non-net-slice:{position_side}:{position_bucket}"),
                absorbed_close_receipts=(),
                position_side=position_side,
                position_bucket=position_bucket,
            )
        with pytest.raises(ValueError, match="NET/ALL only"):
            gate.get_unabsorbed_settled_close_receipts(
                scope,
                "venue/contract-a",
                "strategy-a",
                position_side=position_side,
                position_bucket=position_bucket,
            )
