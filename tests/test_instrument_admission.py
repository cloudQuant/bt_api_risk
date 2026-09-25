"""Unit tests for the provider-independent instrument risk admission policy."""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import pytest

# isort: split -- root and subpackage configs classify bt_api_risk differently.
from bt_api_risk import (
    INSTRUMENT_METADATA_DIGEST_TAG,
    AccountScope,
    DurableRiskGate,
    InstrumentRiskAdmissionMapper,
    InstrumentRiskMetadata,
    InstrumentRiskOrder,
    InstrumentRiskRegistry,
    IntentAction,
    PermitInvalidError,
    RiskDeniedError,
    RiskPolicy,
)


def _metadata(**overrides: object) -> InstrumentRiskMetadata:
    values: dict[str, object] = {
        "instrument": "fixture/contract",
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
        "fixed_fee": Decimal("0.2"),
        "max_slippage_bps": Decimal("50"),
    }
    values.update(overrides)
    return InstrumentRiskMetadata(**values)  # type: ignore[arg-type]


def _order(metadata: InstrumentRiskMetadata, **overrides: object) -> InstrumentRiskOrder:
    values: dict[str, object] = {
        "instrument": metadata.instrument,
        "quantity": Decimal("2"),
        "limit_price": Decimal("100"),
        "metadata_version": metadata.metadata_version,
        "metadata_digest": metadata.digest,
    }
    values.update(overrides)
    return InstrumentRiskOrder(**values)  # type: ignore[arg-type]


def _execution_shape(metadata: InstrumentRiskMetadata, **overrides: object) -> object:
    values: dict[str, object] = {
        "intent_id": "intent.instrument",
        "instrument": metadata.instrument,
        "quantity": Decimal("2"),
        "price": Decimal("100"),
        "metadata_version": metadata.metadata_version,
        "tags": {INSTRUMENT_METADATA_DIGEST_TAG: metadata.digest},
        "position_effect": SimpleNamespace(value="OPEN"),
        "fingerprint": "a" * 64,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_assessment_enforces_lattices_multiplier_slippage_and_fee() -> None:
    metadata = _metadata()

    assessment = InstrumentRiskRegistry((metadata,)).assess(_order(metadata), now_ns=1_500)

    assert assessment.quoted_notional == Decimal("600")
    assert assessment.worst_case_price == Decimal("100.5")
    assert assessment.worst_case_notional == Decimal("603.0")
    assert assessment.worst_case_fee == Decimal("0.8030")
    assert assessment.gross_notional == Decimal("603.8030")


@pytest.mark.parametrize(
    ("overrides", "code"),
    (
        ({"quantity": Decimal("2.1")}, "INSTRUMENT_QUANTITY_LATTICE"),
        ({"limit_price": Decimal("100.05")}, "INSTRUMENT_PRICE_LATTICE"),
        ({"quantity": Decimal("0.25")}, "INSTRUMENT_MIN_QUANTITY"),
        ({"quantity": Decimal("10.25")}, "INSTRUMENT_MAX_QUANTITY"),
        ({"limit_price": None}, "INSTRUMENT_PRICE_UNPROVEN"),
    ),
)
def test_assessment_rejects_unprovable_quantity_or_price(
    overrides: dict[str, object], code: str
) -> None:
    metadata = _metadata()
    with pytest.raises(RiskDeniedError) as caught:
        InstrumentRiskRegistry((metadata,)).assess(_order(metadata, **overrides), now_ns=1_500)
    assert caught.value.code == code


@pytest.mark.parametrize(
    ("order_overrides", "now_ns", "code"),
    (
        ({"metadata_version": "instrument-v2"}, 1_500, "INSTRUMENT_METADATA_VERSION_MISMATCH"),
        ({"metadata_digest": "b" * 64}, 1_500, "INSTRUMENT_METADATA_DIGEST_MISMATCH"),
        ({}, 999, "INSTRUMENT_METADATA_NOT_ACTIVE"),
        ({}, 2_000, "INSTRUMENT_METADATA_STALE"),
    ),
)
def test_assessment_requires_exact_fresh_trusted_metadata(
    order_overrides: dict[str, object], now_ns: int, code: str
) -> None:
    metadata = _metadata()
    with pytest.raises(RiskDeniedError) as caught:
        InstrumentRiskRegistry((metadata,)).assess(
            _order(metadata, **order_overrides), now_ns=now_ns
        )
    assert caught.value.code == code


def test_gross_notional_limit_includes_adverse_price_and_fees() -> None:
    metadata = _metadata(max_gross_notional=Decimal("603.8"))
    with pytest.raises(RiskDeniedError) as caught:
        InstrumentRiskRegistry((metadata,)).assess(_order(metadata), now_ns=1_500)
    assert caught.value.code == "INSTRUMENT_GROSS_NOTIONAL_LIMIT"


def test_metadata_digest_changes_when_any_execution_fact_changes() -> None:
    metadata = _metadata()
    changed_multiplier = _metadata(contract_multiplier=Decimal("4"))
    changed_fee = _metadata(taker_fee_bps=Decimal("11"))

    assert metadata.digest != changed_multiplier.digest
    assert metadata.digest != changed_fee.digest


def test_instrument_admission_public_exports_are_declared() -> None:
    import bt_api_risk

    expected = {
        "INSTRUMENT_METADATA_DIGEST_TAG",
        "InstrumentRiskAdmissionMapper",
        "InstrumentRiskAssessment",
        "InstrumentRiskMetadata",
        "InstrumentRiskOrder",
        "InstrumentRiskRegistry",
    }

    assert expected.issubset(set(bt_api_risk.__all__))
    assert all(hasattr(bt_api_risk, name) for name in expected)


def test_mapper_binds_metadata_and_risk_envelope_into_permit_identity(tmp_path) -> None:
    metadata = _metadata()
    scope = AccountScope("fixture", "account", "sandbox")
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: 1_500,
    )
    intent = _execution_shape(metadata)
    mapped = mapper(intent)
    gate = DurableRiskGate(
        tmp_path / "risk.sqlite3",
        RiskPolicy("instrument-policy", Decimal("2_000"), 2),
    )
    permit = gate.reserve(mapped)

    assert mapped.action is IntentAction.INCREASE
    assert mapped.notional == Decimal("603.8030")

    changed_metadata = _metadata(taker_fee_bps=Decimal("20"))
    changed_mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((changed_metadata,)),
        clock_ns=lambda: 1_500,
    )
    changed_intent = _execution_shape(
        changed_metadata,
        intent_id=intent.intent_id,
        fingerprint=intent.fingerprint,
    )
    with pytest.raises(PermitInvalidError) as caught:
        gate.claim_for_dispatch(permit.permit_id, changed_mapper(changed_intent))
    assert caught.value.code == "PERMIT_INTENT_MISMATCH"


def test_mapper_requires_digest_and_proven_position_effect() -> None:
    metadata = _metadata()
    scope = AccountScope("fixture", "account", "sandbox")
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: 1_500,
    )
    with pytest.raises(RiskDeniedError) as missing_digest:
        mapper(_execution_shape(metadata, tags={}))
    assert missing_digest.value.code == "INSTRUMENT_METADATA_DIGEST_REQUIRED"

    with pytest.raises(RiskDeniedError) as unknown_effect:
        mapper(_execution_shape(metadata, position_effect=SimpleNamespace(value="UNKNOWN")))
    assert unknown_effect.value.code == "INSTRUMENT_POSITION_EFFECT_UNPROVEN"


def test_mapper_keeps_a_proven_reduce_available_when_entry_metadata_is_stale() -> None:
    metadata = _metadata()
    scope = AccountScope("fixture", "account", "sandbox")
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: 2_001,
    )
    close = _execution_shape(
        metadata,
        price=None,
        position_effect=SimpleNamespace(value="CLOSE"),
    )

    mapped = mapper(close)

    assert mapped.action is IntentAction.REDUCE
    assert mapped.notional == Decimal("0")


def test_mapper_still_rejects_a_close_with_an_invalid_quantity_lattice() -> None:
    metadata = _metadata()
    scope = AccountScope("fixture", "account", "sandbox")
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: 2_001,
    )
    close = _execution_shape(
        metadata,
        quantity=Decimal("2.1"),
        position_effect=SimpleNamespace(value="CLOSE"),
    )

    with pytest.raises(RiskDeniedError) as caught:
        mapper(close)
    assert caught.value.code == "INSTRUMENT_QUANTITY_LATTICE"


@pytest.mark.parametrize(
    "overrides",
    (
        {"tick_size": Decimal("NaN")},
        {"quantity_step": Decimal("0")},
        {"contract_multiplier": Decimal("0")},
        {"max_gross_notional": Decimal("0")},
        {"taker_fee_bps": Decimal("-0.1")},
        {"fixed_fee": Decimal("-0.01")},
        {"max_slippage_bps": Decimal("-1")},
        {"min_quantity": Decimal("0.3")},
        {"max_quantity": Decimal("0.3")},
        {"expires_at_ns": 1_000},
    ),
)
def test_metadata_rejects_nonfinite_or_non_lattice_static_facts(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        _metadata(**overrides)
