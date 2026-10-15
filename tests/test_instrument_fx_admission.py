"""Source-bound FX conversion at the instrument risk admission boundary."""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from decimal import Decimal
from types import SimpleNamespace
from typing import Optional

import pytest

from bt_api_risk import (
    INSTRUMENT_METADATA_DIGEST_TAG,
    AccountScope,
    DurableRiskAdmissionAdapter,
    DurableRiskGate,
    ExposureAccountingMode,
    GrossExposureBaselineProof,
    InstrumentRiskAdmissionMapper,
    InstrumentRiskFxRate,
    InstrumentRiskMetadata,
    InstrumentRiskOrder,
    InstrumentRiskRegistry,
    PermitInvalidError,
    RiskAdmissionDeniedError,
    RiskDeniedError,
    RiskPolicy,
    StrategyAllocationSnapshot,
    VerifiedGrossExposureBaseline,
)


_INSTRUMENT = "fixture/eur-contract"
_FX_SOURCE = "fixture-fx-eur-usd"


def _metadata(**overrides: object) -> InstrumentRiskMetadata:
    values: dict[str, object] = {
        "instrument": _INSTRUMENT,
        "metadata_version": "instrument-v1",
        "as_of_ns": 1_000,
        "expires_at_ns": 2_000,
        "tick_size": Decimal("0.1"),
        "quantity_step": Decimal("0.25"),
        "contract_multiplier": Decimal("3"),
        "max_gross_notional": Decimal("1000"),
        "min_quantity": Decimal("0.5"),
        "max_quantity": Decimal("10"),
        "taker_fee_bps": Decimal("10"),
        "fixed_fee": Decimal("3"),
        "max_slippage_bps": Decimal("50"),
        "quantity_unit": "contract",
        "quote_currency": "EUR",
        "valuation_unit": "USD",
        "fx_source_ref": _FX_SOURCE,
        "fixed_fee_unit": "USD",
    }
    values.update(overrides)
    return InstrumentRiskMetadata(**values)  # type: ignore[arg-type]


def _fx_rate(**overrides: object) -> InstrumentRiskFxRate:
    values: dict[str, object] = {
        "instrument": _INSTRUMENT,
        "quote_currency": "EUR",
        "valuation_unit": "USD",
        "rate": Decimal("0.8"),
        "observed_at_ns": 1_200,
        "valid_until_ns": 1_800,
        "source_ref": _FX_SOURCE,
        "source_revision": "fx-r1",
        "source_record_sha256": hashlib.sha256(b"synthetic EUR/USD observation").hexdigest(),
    }
    values.update(overrides)
    return InstrumentRiskFxRate(**values)  # type: ignore[arg-type]


def _order(
    metadata: InstrumentRiskMetadata,
    fx_rate: Optional[InstrumentRiskFxRate],
    **overrides: object,
) -> InstrumentRiskOrder:
    values: dict[str, object] = {
        "instrument": metadata.instrument,
        "quantity": Decimal("2"),
        "limit_price": Decimal("100"),
        "metadata_version": metadata.metadata_version,
        "metadata_digest": metadata.digest,
        "fx_rate": fx_rate,
    }
    values.update(overrides)
    return InstrumentRiskOrder(**values)  # type: ignore[arg-type]


def _execution_shape(
    metadata: InstrumentRiskMetadata,
    fx_rate: Optional[InstrumentRiskFxRate],
    *,
    intent_id: str = "fx-intent-1",
) -> SimpleNamespace:
    return SimpleNamespace(
        intent_id=intent_id,
        scope=SimpleNamespace(
            provider="fixture",
            environment="sandbox",
            account_ref="risk-account",
            strategy_id="strategy-a",
        ),
        instrument=metadata.instrument,
        quantity=Decimal("2"),
        price=Decimal("100"),
        metadata_version=metadata.metadata_version,
        tags={INSTRUMENT_METADATA_DIGEST_TAG: metadata.digest},
        position_effect=SimpleNamespace(value="OPEN"),
        fingerprint="b" * 64,
        fx_rate=fx_rate,
    )


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class _SyntheticBaselineAuthority:
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


def _strategy_allocation(scope: AccountScope) -> StrategyAllocationSnapshot:
    return StrategyAllocationSnapshot(
        scope=scope,
        strategy_id="strategy-a",
        revision="allocation-v1",
        allocated_notional=Decimal("1000"),
        used_notional=Decimal("0"),
        reserved_notional=Decimal("0"),
        available_notional=Decimal("1000"),
        notional_unit="USD",
        max_position=None,
        position_instrument=None,
        position_unit=None,
        as_of=1_700_000_000.0,
        max_gross_occupancy_notional=Decimal("1000"),
        max_gross_occupancy_intent_count=3,
    )


@pytest.mark.parametrize(
    ("fixed_fee", "fixed_fee_unit", "expected_fee", "expected_gross"),
    [
        ("3", "USD", "3.4824", "485.8824"),
        ("30", "EUR", "24.4824", "506.8824"),
    ],
)
def test_cross_currency_assessment_keeps_quote_price_and_converts_all_costs(
    fixed_fee: str,
    fixed_fee_unit: str,
    expected_fee: str,
    expected_gross: str,
) -> None:
    metadata = _metadata(
        fixed_fee=Decimal(fixed_fee),
        fixed_fee_unit=fixed_fee_unit,
    )
    fx_rate = _fx_rate()
    original_order = _order(metadata, fx_rate)

    assessment = InstrumentRiskRegistry((metadata,)).assess(original_order, now_ns=1_500)

    assert original_order.limit_price == Decimal("100")
    assert assessment.order.limit_price == Decimal("100")
    assert assessment.quoted_notional == Decimal("600")
    assert assessment.worst_case_price == Decimal("100.5")
    assert assessment.worst_case_notional == Decimal("603.0")
    assert assessment.worst_case_fee == Decimal(expected_fee)
    assert assessment.gross_notional == Decimal(expected_gross)
    assert assessment.fx_rate is fx_rate


def test_fx_facts_are_immutable_and_bind_all_source_fields() -> None:
    fx_rate = _fx_rate()
    changed_revision = _fx_rate(source_revision="fx-r2")
    changed_record = _fx_rate(
        source_record_sha256=hashlib.sha256(b"revised EUR/USD observation").hexdigest()
    )

    assert fx_rate.fx_pair == "EUR/USD"
    assert fx_rate.digest != changed_revision.digest
    assert fx_rate.digest != changed_record.digest
    with pytest.raises(FrozenInstanceError):
        fx_rate.rate = Decimal("1")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"rate": Decimal("0")}, "rate"),
        ({"rate": 0.8}, "rate"),
        ({"rate": Decimal("NaN")}, "rate"),
        ({"observed_at_ns": True}, "observed_at_ns"),
        ({"valid_until_ns": 1_200}, "valid_until_ns"),
        ({"source_revision": " bad"}, "source_revision"),
        ({"source_record_sha256": "A" * 64}, "source_record_sha256"),
        ({"quote_currency": "USD"}, "cross-currency"),
    ],
)
def test_fx_fact_rejects_malformed_values(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _fx_rate(**overrides)


def test_cross_currency_nonzero_fixed_fee_requires_a_declared_unit() -> None:
    with pytest.raises(ValueError, match="fixed_fee_unit"):
        _metadata(fixed_fee=Decimal("1"), fixed_fee_unit=None)


def test_cross_currency_gross_limit_is_checked_in_valuation_unit() -> None:
    metadata = _metadata(max_gross_notional=Decimal("485.8823"))

    with pytest.raises(RiskDeniedError) as rejected:
        InstrumentRiskRegistry((metadata,)).assess(
            _order(metadata, _fx_rate()), now_ns=1_500
        )

    assert rejected.value.code == "INSTRUMENT_GROSS_NOTIONAL_LIMIT"


@pytest.mark.parametrize(
    ("fx_rate", "now_ns", "code"),
    [
        (None, 1_500, "INSTRUMENT_FX_REQUIRED"),
        (_fx_rate(quote_currency="GBP"), 1_500, "INSTRUMENT_FX_PAIR_MISMATCH"),
        (_fx_rate(source_ref="another-fx-source"), 1_500, "INSTRUMENT_FX_SOURCE_MISMATCH"),
        (_fx_rate(observed_at_ns=1_600), 1_500, "INSTRUMENT_FX_STALE"),
        (_fx_rate(valid_until_ns=1_500), 1_500, "INSTRUMENT_FX_STALE"),
    ],
)
def test_registry_rejects_missing_mismatched_or_stale_fx(
    fx_rate: Optional[InstrumentRiskFxRate],
    now_ns: int,
    code: str,
) -> None:
    metadata = _metadata()
    with pytest.raises(RiskDeniedError) as rejected:
        InstrumentRiskRegistry((metadata,)).assess(_order(metadata, fx_rate), now_ns)
    assert rejected.value.code == code


def test_mapper_requires_exact_trusted_fx_object_and_binds_fact_to_risk_intent() -> None:
    metadata = _metadata()
    trusted_rate = _fx_rate()
    scope = AccountScope("fixture", "risk-account", "sandbox")
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: 1_500,
        fx_rates_by_instrument=(trusted_rate,),
    )

    mapped = mapper(_execution_shape(metadata, trusted_rate))
    changed_rate = _fx_rate(
        rate=Decimal("0.81"),
        source_revision="fx-r2",
        source_record_sha256=hashlib.sha256(b"revised EUR/USD observation").hexdigest(),
    )
    changed_mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: 1_500,
        fx_rates_by_instrument=(changed_rate,),
    )
    changed = changed_mapper(_execution_shape(metadata, changed_rate))

    assert mapped.notional == Decimal("485.8824")
    assert mapped.notional_unit == "USD"
    assert mapped.payload_fingerprint != changed.payload_fingerprint
    with pytest.raises(RiskDeniedError) as unbound:
        mapper(_execution_shape(metadata, _fx_rate()))
    assert unbound.value.code == "INSTRUMENT_FX_SOURCE_UNBOUND"


def test_claim_rechecks_fx_freshness_before_creating_a_dispatch_claim(tmp_path) -> None:
    metadata = _metadata()
    fx_rate = _fx_rate()
    scope = AccountScope("fixture", "risk-account", "sandbox")
    clock_values = iter((1_500, 1_800))
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: next(clock_values),
        fx_rates_by_instrument=(fx_rate,),
    )
    gate = DurableRiskGate(
        tmp_path / "fx-freshness.sqlite3",
        RiskPolicy("fx-freshness-policy", Decimal("1000"), 3, notional_unit="USD"),
        clock=lambda: 1_700_000_000.0,
        clock_ns=lambda: 1_500,
    )
    adapter = DurableRiskAdmissionAdapter(gate, mapper)
    intent = _execution_shape(metadata, fx_rate)
    try:
        permit = adapter.reserve(intent)

        with pytest.raises(RiskAdmissionDeniedError) as stale:
            adapter.claim_for_dispatch(permit.permit_id, intent)

        assert stale.value.code == "INSTRUMENT_FX_STALE"
        with pytest.raises(PermitInvalidError) as no_claim:
            gate.dispatch_claim_binding(permit.permit_id)
        assert no_claim.value.code == "PERMIT_NOT_DISPATCH_CLAIMED"
        gate.release(permit.permit_id, "FX expired before dispatch claim")
    finally:
        gate.close()


def test_reserve_rechecks_fx_at_the_risk_transaction_cut(tmp_path) -> None:
    metadata = _metadata()
    fx_rate = _fx_rate()
    scope = AccountScope("fixture", "risk-account", "sandbox")
    now_ns = [1_799]
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: now_ns[0],
        fx_rates_by_instrument=(fx_rate,),
    )
    gate = DurableRiskGate(
        tmp_path / "fx-reserve-cut.sqlite3",
        RiskPolicy("fx-reserve-cut-policy", Decimal("1000"), 3, notional_unit="USD"),
        clock=lambda: 1_700_000_000.0,
        clock_ns=lambda: now_ns[0],
    )
    intent = mapper(_execution_shape(metadata, fx_rate))
    assert intent.instrument_facts_observed_at_ns == 1_200
    assert intent.instrument_facts_valid_until_ns == 1_800
    now_ns[0] = 1_800

    try:
        with pytest.raises(RiskDeniedError) as stale:
            gate.reserve(intent)
        assert stale.value.code == "INSTRUMENT_FACTS_STALE"
        assert gate.snapshot(scope)["increase_count"] == 0
    finally:
        gate.close()


def test_dispatch_claim_rechecks_fx_at_the_final_gate_cut(tmp_path) -> None:
    metadata = _metadata()
    fx_rate = _fx_rate()
    scope = AccountScope("fixture", "risk-account", "sandbox")
    mapper_now_ns = [1_500]
    gate_clock = SimpleNamespace(phase="reserve", reads=0)

    def gate_now_ns() -> int:
        if gate_clock.phase == "reserve":
            return 1_500
        gate_clock.reads += 1
        return 1_799 if gate_clock.reads == 1 else 1_800

    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: mapper_now_ns[0],
        fx_rates_by_instrument=(fx_rate,),
    )
    gate = DurableRiskGate(
        tmp_path / "fx-claim-cut.sqlite3",
        RiskPolicy("fx-claim-cut-policy", Decimal("1000"), 3, notional_unit="USD"),
        clock=lambda: 1_700_000_000.0,
        clock_ns=gate_now_ns,
    )
    try:
        permit = gate.reserve(mapper(_execution_shape(metadata, fx_rate)))
        gate_clock.phase = "claim"
        mapper_now_ns[0] = 1_799
        claim_intent = mapper(_execution_shape(metadata, fx_rate))

        with pytest.raises(PermitInvalidError) as stale:
            gate.claim_for_dispatch(permit.permit_id, claim_intent)

        assert stale.value.code == "INSTRUMENT_FACTS_STALE"
        assert gate_clock.reads == 3
        with pytest.raises(PermitInvalidError) as no_claim:
            gate.dispatch_claim_binding(permit.permit_id)
        assert no_claim.value.code == "PERMIT_NOT_DISPATCH_CLAIMED"
        gate.release(permit.permit_id, "FX expired at dispatch claim transaction cut")
    finally:
        gate.close()


def test_expiry_after_dispatch_claim_and_freeze_writes_rolls_back_them(tmp_path) -> None:
    metadata = _metadata()
    fx_rate = _fx_rate()
    scope = AccountScope("fixture", "risk-account", "sandbox")
    mapper_now_ns = [1_500]
    gate_clock = SimpleNamespace(
        phase="reserve",
        claim_reads=0,
        writes_observed=False,
        post_write_samples=[],
    )

    def gate_now_ns() -> int:
        if gate_clock.phase == "reserve":
            return 1_500
        gate_clock.claim_reads += 1
        sample = 1_800 if gate_clock.writes_observed else 1_799
        if gate_clock.writes_observed:
            gate_clock.post_write_samples.append(sample)
        return sample

    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: mapper_now_ns[0],
        fx_rates_by_instrument=(fx_rate,),
    )
    gate = DurableRiskGate(
        tmp_path / "fx-claim-rollback.sqlite3",
        RiskPolicy("fx-claim-rollback-policy", Decimal("1000"), 3, notional_unit="USD"),
        clock=lambda: 1_700_000_000.0,
        clock_ns=gate_now_ns,
    )
    try:
        permit = gate.reserve(mapper(_execution_shape(metadata, fx_rate)))
        gate_clock.phase = "claim"
        mapper_now_ns[0] = 1_799
        claim_intent = mapper(_execution_shape(metadata, fx_rate))
        original_freeze = gate._freeze_in_transaction

        def observe_claim_and_freeze_writes(
            connection,
            freeze_scope,
            cause_id,
            reason,
            updated_at,
        ) -> None:
            original_freeze(connection, freeze_scope, cause_id, reason, updated_at)
            assert connection.in_transaction
            claim = connection.execute(
                "SELECT intent_id, intent_hash, scope_key, cause_id "
                "FROM risk_dispatch_claims WHERE permit_id = ?",
                (permit.permit_id,),
            ).fetchone()
            assert claim is not None
            assert claim["intent_id"] == claim_intent.intent_id
            assert claim["intent_hash"] == claim_intent.fingerprint
            assert claim["scope_key"] == scope.key
            assert claim["cause_id"] == cause_id
            freeze = connection.execute(
                "SELECT active, reason FROM risk_freezes "
                "WHERE scope_key = ? AND cause_id = ?",
                (scope.key, cause_id),
            ).fetchone()
            assert freeze is not None
            assert freeze["active"] == 1
            assert freeze["reason"] == reason
            gate_clock.writes_observed = True

        gate._freeze_in_transaction = observe_claim_and_freeze_writes

        with pytest.raises(PermitInvalidError) as stale:
            gate.claim_for_dispatch(permit.permit_id, claim_intent)

        assert stale.value.code == "INSTRUMENT_FACTS_STALE"
        assert gate_clock.writes_observed is True
        assert gate_clock.claim_reads >= 4
        assert gate_clock.post_write_samples == [1_800]
        with gate._connection() as connection:
            claim_count = connection.execute(
                "SELECT COUNT(*) FROM risk_dispatch_claims WHERE permit_id = ?",
                (permit.permit_id,),
            ).fetchone()[0]
            freeze_count = connection.execute(
                "SELECT COUNT(*) FROM risk_freezes "
                "WHERE scope_key = ? AND cause_id = ?",
                (scope.key, gate._dispatch_freeze_cause(claim_intent.intent_id)),
            ).fetchone()[0]
        assert claim_count == 0
        assert freeze_count == 0
        assert gate.active_freeze_reasons(scope) == []
        with pytest.raises(PermitInvalidError) as no_claim:
            gate.dispatch_claim_binding(permit.permit_id)
        assert no_claim.value.code == "PERMIT_NOT_DISPATCH_CLAIMED"
        gate.release(permit.permit_id, "FX expired after claim and freeze writes")
    finally:
        gate.close()


def test_live_gross_claim_rechecks_fx_after_final_exposure_scan(tmp_path) -> None:
    metadata = _metadata()
    fx_rate = _fx_rate()
    scope = AccountScope("fixture", "risk-account", "sandbox")
    clock = SimpleNamespace(phase="reserve", now_ns=1_500)
    policy = RiskPolicy(
        "fx-live-gross-cut-policy",
        Decimal("1000"),
        max_increase_count=10,
        require_strategy_allocation=True,
        notional_unit="USD",
        exposure_accounting_mode=ExposureAccountingMode.LIVE_GROSS,
        max_gross_occupancy_notional=Decimal("1000"),
        max_gross_occupancy_intent_count=3,
        max_exposure_facts_age_seconds=3600,
    )
    gate = DurableRiskGate(
        tmp_path / "fx-live-gross-cut.sqlite3",
        policy,
        clock=lambda: 1_700_000_000.0,
        clock_ns=lambda: clock.now_ns,
        gross_exposure_authority=_SyntheticBaselineAuthority(),
    )
    gate.set_strategy_allocation(
        scope,
        "strategy-a",
        "allocation-v1",
        max_notional=Decimal("1000"),
        notional_unit="USD",
        max_gross_occupancy_notional=Decimal("1000"),
        max_gross_occupancy_intent_count=3,
    )
    gate.install_gross_exposure_baseline(
        GrossExposureBaselineProof(
            scope=scope,
            account_revision=1,
            notional_unit="USD",
            account_gross_notional=Decimal("0"),
            account_active_increase_intent_count=0,
            strategy_baselines=(),
            unmanaged_open_order_count=0,
            complete_positions=True,
            complete_open_orders=True,
            source_snapshot_sha256=_sha("fx-cut-baseline"),
            positions_sha256=_sha("fx-cut-positions"),
            open_orders_sha256=_sha("fx-cut-open-orders"),
            valuation_facts_sha256=_sha("fx-cut-valuation"),
            source_schema_version="fx-cut-baseline-v1",
            observed_at_ns=1_000,
            valid_until_ns=3_000,
            writer_owner_id="fx-cut-synthetic-writer",
            writer_fencing_token=1,
            writer_fence_sha256=_sha("fx-cut-fence"),
        )
    )
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: clock.now_ns,
        allocation_reader=lambda _execution_scope: _strategy_allocation(scope),
        fx_rates_by_instrument=(fx_rate,),
    )
    original_live_gross_scan = gate._assert_live_gross_limits
    scan_state = SimpleNamespace(phase="reserve", calls=0)

    def advancing_live_gross_scan(
        connection,
        intent,
        *,
        include_intent=True,
        now_ns=None,
    ) -> None:
        scan_state.calls += 1
        original_live_gross_scan(
            connection,
            intent,
            include_intent=include_intent,
            now_ns=now_ns,
        )
        if scan_state.phase == "claim" and scan_state.calls == 5:
            assert clock.now_ns == 1_799
            clock.now_ns = 1_800

    gate._assert_live_gross_limits = advancing_live_gross_scan
    try:
        permit = gate.reserve(mapper(_execution_shape(metadata, fx_rate)))
        assert scan_state.calls == 2

        scan_state.phase = "claim"
        clock.phase = "claim"
        clock.now_ns = 1_799
        claim_intent = mapper(_execution_shape(metadata, fx_rate))
        assert claim_intent.instrument_facts_valid_until_ns == 1_800
        with pytest.raises(PermitInvalidError) as stale:
            gate.claim_for_dispatch(permit.permit_id, claim_intent)

        assert stale.value.code == "INSTRUMENT_FACTS_STALE"
        assert scan_state.calls == 5
        assert clock.now_ns == 1_800
        assert gate.active_freeze_reasons(scope) == []
        with pytest.raises(PermitInvalidError) as no_claim:
            gate.dispatch_claim_binding(permit.permit_id)
        assert no_claim.value.code == "PERMIT_NOT_DISPATCH_CLAIMED"
        gate.release(permit.permit_id, "FX expired during LIVE_GROSS claim scan")
    finally:
        gate.close()


def test_legacy_same_currency_metadata_and_admission_fingerprint_are_unchanged() -> None:
    metadata = InstrumentRiskMetadata(
        instrument="fixture/legacy-contract",
        metadata_version="legacy-v1",
        as_of_ns=1_000,
        expires_at_ns=2_000,
        tick_size=Decimal("0.1"),
        quantity_step=Decimal("0.25"),
        contract_multiplier=Decimal("3"),
        max_gross_notional=Decimal("1000"),
        min_quantity=Decimal("0.5"),
        max_quantity=Decimal("10"),
        taker_fee_bps=Decimal("10"),
        fixed_fee=Decimal("0.2"),
        max_slippage_bps=Decimal("50"),
    )
    order = _order(metadata, None)
    assessment = InstrumentRiskRegistry((metadata,)).assess(order, now_ns=1_500)

    old_metadata_payload = {
        "as_of_ns": 1_000,
        "contract_multiplier": "3",
        "expires_at_ns": 2_000,
        "fixed_fee": "0.2",
        "instrument": "fixture/legacy-contract",
        "max_gross_notional": "1000",
        "max_quantity": "10",
        "max_slippage_bps": "50",
        "metadata_version": "legacy-v1",
        "min_quantity": "0.5",
        "quantity_step": "0.25",
        "schema": "bt_api_risk.instrument-admission.v1",
        "taker_fee_bps": "10",
        "tick_size": "0.1",
    }
    old_metadata_digest = hashlib.sha256(
        json.dumps(old_metadata_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    # Pin the text emitted by the existing public HEAD implementation. Decimal
    # equality alone ignores the trailing-zero distinction used by the digest.
    old_admission_payload = {
        "gross_notional": "603.803",
        "intent_fingerprint": "b" * 64,
        "metadata_digest": old_metadata_digest,
        "quoted_notional": "600",
        "schema": "bt_api_risk.instrument-admission.v1",
        "worst_case_fee": "0.803",
        "worst_case_notional": "603.0",
        "worst_case_price": "100.5",
    }

    assert metadata.to_payload() == old_metadata_payload
    assert metadata.digest == old_metadata_digest
    assert assessment.worst_case_fee == Decimal("0.803")
    assert assessment.gross_notional == Decimal("603.803")
    assert assessment.bound_payload_fingerprint("b" * 64) == hashlib.sha256(
        json.dumps(old_admission_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

