"""Local-SQLite checks for source-bound terminal net-CLOSE Risk receipts."""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal

import pytest

from bt_api_risk import (
    AccountScope,
    DispatchEvidenceClass,
    DispatchExposureResolutionProof,
    DispatchExposureResolutionReceiptStatus,
    DurableRiskGate,
    IntentAction,
    OrderExposureObservationProof,
    OrderExposureState,
    OrderFillFact,
    PermitInvalidError,
    RiskIntent,
    RiskPolicy,
    VerifiedDispatchExposureResolution,
    fill_ids_sha256,
)

_NOW_NS = 100_000_000_000


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


def _close_proof(gate: DurableRiskGate, scope: AccountScope):
    intent = RiskIntent(
        intent_id="close-1",
        scope=scope,
        action=IntentAction.REDUCE,
        notional=Decimal("0"),
        payload_fingerprint=_sha("intent:close-1"),
        strategy_id="strategy-a",
        allocation_version="allocation-v1",
        instrument="venue/contract-a",
        quantity=Decimal("2"),
        quantity_unit="contract",
        notional_unit="USD",
        exposure_profile_fingerprint=_sha("profile:close-1"),
        instrument_facts_observed_at_ns=_NOW_NS,
        instrument_facts_valid_until_ns=_NOW_NS + 3_600_000_000_000,
    )
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)
    claim = gate.dispatch_claim_binding(permit.permit_id)
    gate.settle(permit.permit_id)
    fill = OrderFillFact(
        trade_id="trade-close-1",
        quantity=Decimal("2"),
        price=Decimal("100"),
        side="SELL",
        position_effect="CLOSE",
        fee_amount=Decimal("0"),
        fee_currency="USD",
        source_record_sha256=_sha("fill:close-1"),
        source_revision=3,
    )
    observation = OrderExposureObservationProof(
        scope=scope,
        permit_id=permit.permit_id,
        intent_id=intent.intent_id,
        intent_hash=claim.intent_hash,
        dispatch_claim_digest=claim.claim_digest,
        dispatch_proof_sha256=None,
        provider_order_id="paper-order-close-1",
        accepted_request_sha256=_sha("request:close-1"),
        exposure_reservation_id="paper-close-ref-1",
        exposure_reservation_sha256=_sha("paper-close-ref-digest:1"),
        order_revision=2,
        journal_revision=6,
        journal_record_sha256=_sha("journal-record:close-1"),
        observation_sha256=_sha("observation:close-1"),
        fill_history_sha256=_sha("fill-history:close-1"),
        source_alias_map_sha256=_sha("source-aliases"),
        state=OrderExposureState.FILLED,
        requested_quantity=Decimal("2"),
        cumulative_filled_quantity=Decimal("2"),
        leaves_quantity=Decimal("0"),
        filled_gross_notional=Decimal("200"),
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
        writer_owner_id="synthetic-risk-writer",
        writer_fencing_token=2,
        writer_fence_sha256=_sha("writer-fence"),
    )
    return DispatchExposureResolutionProof(
        claim=claim,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        dispatch_attempt_count=1,
        reconciliation_evidence_sha256=_sha("reconciliation:close-1"),
        observation=observation,
    )


def test_terminal_close_receipt_is_immutable_and_exact_replay_is_idempotent(tmp_path):
    scope = AccountScope("fixture", "paper-account", "sandbox")
    database = tmp_path / "risk-close.sqlite3"
    policy = RiskPolicy(
        "paper-close-policy",
        Decimal("5000"),
        8,
        require_strategy_allocation=True,
        notional_unit="USD",
    )
    gate = DurableRiskGate(
        database, policy, clock=_Clock(), execution_journal_authority=_Authority()
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
    proof = _close_proof(gate, scope)

    receipt = gate.resolve_dispatch_close(proof)
    assert receipt.status is DispatchExposureResolutionReceiptStatus.TERMINAL_CLOSE_RESOLVED
    assert receipt.position_effect == "CLOSE"
    assert receipt.dispatch_latch_active is False
    assert gate.dispatch_close_resolution_receipt(proof.permit_id) == receipt

    reopened = DurableRiskGate(
        database, policy, clock=_Clock(), execution_journal_authority=_Authority()
    )
    assert reopened.dispatch_close_resolution_receipt(proof.permit_id) == receipt
    assert reopened.resolve_dispatch_close(proof) == receipt

    conflicting = replace(
        proof, reconciliation_evidence_sha256=_sha("different-reconciliation")
    )
    with pytest.raises(PermitInvalidError) as replay:
        reopened.resolve_dispatch_close(conflicting)
    assert replay.value.code == "DISPATCH_PROOF_REPLAYED"

    with reopened._connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM risk_close_order_resolutions WHERE permit_id = ?",
            (proof.permit_id,),
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM risk_order_exposures WHERE permit_id = ?",
            (proof.permit_id,),
        ).fetchone()[0] == 0
