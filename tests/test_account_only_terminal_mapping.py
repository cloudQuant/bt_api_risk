"""Account-only OPEN mapping must retain trusted size for terminal proof checks."""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from decimal import Decimal
from types import SimpleNamespace

import pytest

from bt_api_risk import (
    INSTRUMENT_METADATA_DIGEST_TAG,
    AccountScope,
    DispatchEvidenceClass,
    DispatchExposureResolutionProof,
    DispatchExposureResolutionReceiptStatus,
    DurableRiskGate,
    InstrumentRiskAdmissionMapper,
    InstrumentRiskMetadata,
    InstrumentRiskRegistry,
    OrderExposureObservationProof,
    OrderExposureState,
    OrderFillFact,
    RiskDeniedError,
    RiskPolicy,
    VerifiedDispatchExposureResolution,
    fill_ids_sha256,
)

_NOW_NS = 1_500
_OWNER = "synthetic-risk-writer"
_FENCE_TOKEN = 2


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _metadata(*, quantity_unit: str | None = "BTC") -> InstrumentRiskMetadata:
    return InstrumentRiskMetadata(
        instrument="fixture/BTC-USD",
        metadata_version="instrument-v1",
        as_of_ns=1_000,
        expires_at_ns=5_000,
        tick_size=Decimal("0.01"),
        quantity_step=Decimal("0.001"),
        contract_multiplier=Decimal("1"),
        max_gross_notional=Decimal("1_000"),
        min_quantity=Decimal("0.001"),
        max_quantity=Decimal("10"),
        taker_fee_bps=Decimal("0"),
        fixed_fee=Decimal("0"),
        max_slippage_bps=Decimal("0"),
        quantity_unit=quantity_unit,
        valuation_unit="USD",
    )


def _execution_intent(metadata: InstrumentRiskMetadata, **overrides: object) -> object:
    values: dict[str, object] = {
        "intent_id": "account-only-open-1",
        "instrument": metadata.instrument,
        "quantity": Decimal("1"),
        "price": Decimal("20"),
        "metadata_version": metadata.metadata_version,
        "tags": {INSTRUMENT_METADATA_DIGEST_TAG: metadata.digest},
        "position_effect": SimpleNamespace(value="OPEN"),
        "fingerprint": _sha("immutable-execution-intent"),
        "scope": SimpleNamespace(
            provider="fixture",
            account_ref="wire-account-1",
            environment="sandbox",
        ),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class _SyntheticJournalAuthority:
    """Typed local source authority for this SQLite contract test only."""

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


def _observation(claim, metadata: InstrumentRiskMetadata) -> OrderExposureObservationProof:
    fill = OrderFillFact(
        trade_id="synthetic-trade-1",
        quantity=Decimal("1"),
        price=Decimal("20"),
        side="BUY",
        position_effect="OPEN",
        fee_amount=Decimal("0"),
        fee_currency="USD",
        source_record_sha256=_sha("synthetic-fill-row"),
        source_revision=1,
    )
    fills = (fill,)
    return OrderExposureObservationProof(
        scope=claim.scope,
        permit_id=claim.permit_id,
        intent_id=claim.intent_id,
        intent_hash=claim.intent_hash,
        dispatch_claim_digest=claim.claim_digest,
        dispatch_proof_sha256=None,
        provider_order_id="synthetic-provider-order-1",
        accepted_request_sha256=_sha("accepted-request"),
        exposure_reservation_id="risk-exposure-1",
        exposure_reservation_sha256=_sha("risk-exposure-record"),
        order_revision=1,
        journal_revision=2,
        journal_record_sha256=_sha("terminal-order-event"),
        observation_sha256=_sha("complete-order-snapshot"),
        fill_history_sha256=_sha("complete-fill-history"),
        source_alias_map_sha256=_sha("source-alias-map"),
        state=OrderExposureState.FILLED,
        requested_quantity=Decimal("1"),
        cumulative_filled_quantity=Decimal("1"),
        leaves_quantity=Decimal("0"),
        filled_gross_notional=Decimal("20"),
        leaves_gross_notional=Decimal("0"),
        leaves_valuation_price=None,
        notional_unit="USD",
        complete_order_snapshot=True,
        complete_fill_history=True,
        fill_watermark_revision=1,
        source_contract_ref="synthetic/source-contract",
        source_contract_version="contract-v1",
        provider_profile_version="profile-v1",
        normalizer_schema_version="normalizer-v1",
        order_side="BUY",
        position_effect="OPEN",
        fills=fills,
        fill_trade_count=1,
        fill_ids_sha256=fill_ids_sha256(fills),
        instrument_id=metadata.instrument,
        instrument_version=metadata.metadata_version,
        instrument_multiplier=metadata.contract_multiplier,
        quote_currency="USD",
        valuation_unit="USD",
        instrument_metadata_sha256=metadata.digest,
        instrument_metadata_observed_at_ns=metadata.as_of_ns,
        instrument_metadata_valid_until_ns=metadata.expires_at_ns,
        valuation_facts_sha256=_sha("valuation-facts"),
        valuation_observed_at_ns=_NOW_NS,
        valuation_valid_until_ns=4_000,
        fx_pair=None,
        fx_rate=None,
        fx_observed_at_ns=None,
        fx_valid_until_ns=None,
        observed_at_ns=_NOW_NS,
        valid_until_ns=4_000,
        writer_owner_id=_OWNER,
        writer_fencing_token=_FENCE_TOKEN,
        writer_fence_sha256=_sha("writer-fence"),
    )


def _resolve_terminal(gate, risk_intent, metadata):
    permit = gate.reserve(risk_intent)
    gate.claim_for_dispatch(permit.permit_id, risk_intent)
    claim = gate.dispatch_claim_binding(permit.permit_id)
    gate.settle(permit.permit_id)
    observation = _observation(claim, metadata)
    proof = DispatchExposureResolutionProof(
        claim=claim,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        dispatch_attempt_count=1,
        reconciliation_evidence_sha256=_sha("complete-terminal-reconciliation"),
        observation=observation,
    )
    return permit, proof


def _gate(tmp_path) -> DurableRiskGate:
    return DurableRiskGate(
        tmp_path / "risk.sqlite3",
        RiskPolicy(
            "account-only-terminal-policy",
            Decimal("1_000"),
            max_increase_count=3,
            permit_ttl_seconds=30,
            notional_unit="USD",
        ),
        clock=lambda: 100.0,
        clock_ns=lambda: _NOW_NS,
        execution_journal_authority=_SyntheticJournalAuthority(),
    )


def test_account_only_open_carries_trusted_size_through_terminal_resolution(tmp_path) -> None:
    metadata = _metadata()
    scope = AccountScope("fixture", "risk-account-1", "sandbox")
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: _NOW_NS,
        wire_account_ref="wire-account-1",
    )
    raw_intent = _execution_intent(metadata)
    mapped = mapper(raw_intent)

    assert mapped.strategy_id is None
    assert mapped.instrument == metadata.instrument
    assert mapped.quantity == Decimal("1")
    assert mapped.quantity_unit == "BTC"
    assert mapped.notional == Decimal("20")
    assert mapped.notional_unit == "USD"

    gate = _gate(tmp_path)
    try:
        _permit, proof = _resolve_terminal(gate, mapped, metadata)
        receipt = gate.resolve_dispatch_exposure(proof)

        assert receipt.status is DispatchExposureResolutionReceiptStatus.TERMINAL_EXPOSURE_RESOLVED
        assert receipt.claim.intent_hash == mapped.fingerprint
        assert receipt.requested_quantity == Decimal("1")
        assert receipt.filled_quantity == Decimal("1")
        assert receipt.trade_count == 1
        assert receipt.dispatch_latch_active is False
        assert gate.dispatch_exposure_resolution_receipt(receipt.permit_id) == receipt
    finally:
        gate.close()


def test_missing_quantity_unit_does_not_create_terminally_claimable_size(tmp_path) -> None:
    metadata = _metadata(quantity_unit=None)
    scope = AccountScope("fixture", "risk-account-1", "sandbox")
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: _NOW_NS,
        wire_account_ref="wire-account-1",
    )
    mapped = mapper(_execution_intent(metadata))

    assert mapped.instrument is None
    assert mapped.quantity is None
    assert mapped.quantity_unit is None
    assert mapped.notional == Decimal("20")

    gate = _gate(tmp_path)
    try:
        permit, proof = _resolve_terminal(gate, mapped, metadata)
        with pytest.raises(RiskDeniedError) as rejected:
            gate.resolve_dispatch_exposure(proof)
        assert rejected.value.code == "ORDER_EXPOSURE_REQUEST_MISMATCH"
        unresolved = gate.dispatch_exposure_resolution_receipt(permit.permit_id)
        assert unresolved.status is DispatchExposureResolutionReceiptStatus.UNRESOLVED_ACTIVE
        assert unresolved.dispatch_latch_active is True
    finally:
        gate.close()


@pytest.mark.parametrize(
    ("intent_overrides", "expected_code"),
    (
        ({"tags": {}}, "INSTRUMENT_METADATA_DIGEST_REQUIRED"),
        (
            {
                "scope": SimpleNamespace(
                    provider="fixture",
                    account_ref="another-account",
                    environment="sandbox",
                )
            },
            "ACCOUNT_SCOPE_MISMATCH",
        ),
    ),
)
def test_mapper_rejects_missing_metadata_digest_and_wrong_account_scope(
    intent_overrides: dict[str, object], expected_code: str
) -> None:
    metadata = _metadata()
    scope = AccountScope("fixture", "risk-account-1", "sandbox")
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: _NOW_NS,
        wire_account_ref="wire-account-1",
    )
    with pytest.raises(RiskDeniedError) as rejected:
        mapper(_execution_intent(metadata, **intent_overrides))
    assert rejected.value.code == expected_code
