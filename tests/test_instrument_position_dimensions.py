"""Focused source tests for mapper-side position side and bucket binding."""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import pytest

from bt_api_risk import (
    INSTRUMENT_METADATA_DIGEST_TAG,
    AccountScope,
    InstrumentRiskAdmissionMapper,
    InstrumentRiskMetadata,
    InstrumentRiskRegistry,
    IntentAction,
    RiskDeniedError,
    StrategyAllocationSnapshot,
)


def _metadata() -> InstrumentRiskMetadata:
    return InstrumentRiskMetadata(
        instrument="fixture/contract",
        metadata_version="instrument-v1",
        as_of_ns=1_000,
        expires_at_ns=2_000,
        tick_size=Decimal("0.1"),
        quantity_step=Decimal("0.25"),
        contract_multiplier=Decimal("1"),
        max_gross_notional=Decimal("10000"),
        min_quantity=Decimal("0.25"),
        max_quantity=Decimal("100"),
        taker_fee_bps=Decimal("0"),
        fixed_fee=Decimal("0"),
        max_slippage_bps=Decimal("0"),
        valuation_unit="USD",
        quantity_unit="contract",
    )


def _allocation(scope: AccountScope) -> StrategyAllocationSnapshot:
    return StrategyAllocationSnapshot(
        scope=scope,
        strategy_id="strategy-1",
        revision="allocation-v1",
        allocated_notional=Decimal("10000"),
        used_notional=Decimal("0"),
        reserved_notional=Decimal("0"),
        available_notional=Decimal("10000"),
        notional_unit="USD",
        max_position=Decimal("100"),
        position_instrument="fixture/contract",
        position_unit="contract",
        as_of=1.5,
    )


def _intent(metadata: InstrumentRiskMetadata, *, effect: str, side: str, **overrides: object):
    values: dict[str, object] = {
        "intent_id": "intent.position-dimensions",
        "scope": SimpleNamespace(
            provider="fixture",
            environment="sandbox",
            account_ref="account",
            strategy_id="strategy-1",
            trading_day="2026-10-17",
        ),
        "instrument": metadata.instrument,
        "quantity": Decimal("2"),
        "price": Decimal("100"),
        "metadata_version": metadata.metadata_version,
        "tags": {INSTRUMENT_METADATA_DIGEST_TAG: metadata.digest},
        "position_effect": SimpleNamespace(value=effect),
        "side": SimpleNamespace(value=side),
        "position_side": "NET",
        "position_bucket": "ALL",
        "fingerprint": "a" * 64,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    ("position_side", "position_bucket", "effect", "side"),
    (
        ("LONG", "ALL", "CLOSE", "SELL"),
        ("LONG", "TODAY", "CLOSE_TODAY", "SELL"),
        ("LONG", "YESTERDAY", "CLOSE_YESTERDAY", "SELL"),
        ("SHORT", "ALL", "CLOSE", "BUY"),
        ("SHORT", "TODAY", "CLOSE_TODAY", "BUY"),
        ("SHORT", "YESTERDAY", "CLOSE_YESTERDAY", "BUY"),
    ),
)
def test_mapper_binds_close_side_and_bucket_into_risk_intent(
    position_side: str,
    position_bucket: str,
    effect: str,
    side: str,
) -> None:
    metadata = _metadata()
    scope = AccountScope("fixture", "account", "sandbox")
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: 1_500,
        allocation_reader=lambda _scope: _allocation(scope),
    )

    mapped = mapper(
        _intent(
            metadata,
            effect=effect,
            side=side,
            position_side=position_side,
            position_bucket=position_bucket,
        )
    )

    assert mapped.action is IntentAction.REDUCE
    assert mapped.position_side == position_side
    assert mapped.position_bucket == position_bucket
    assert mapped.instrument == metadata.instrument
    assert mapped.quantity == Decimal("2")
    assert mapped.quantity_unit == "contract"


@pytest.mark.parametrize(
    ("effect", "side", "position_side", "position_bucket", "code"),
    (
        ("CLOSE", "BUY", "LONG", "ALL", "INSTRUMENT_POSITION_SIDE_MISMATCH"),
        ("CLOSE", "SELL", "SHORT", "TODAY", "INSTRUMENT_POSITION_SIDE_MISMATCH"),
        ("CLOSE_TODAY", "SELL", "NET", "ALL", "INSTRUMENT_POSITION_BUCKET_UNPROVEN"),
        ("CLOSE_YESTERDAY", "BUY", "LONG", "TODAY", "INSTRUMENT_POSITION_BUCKET_MISMATCH"),
        ("OPEN", "BUY", "SHORT", "ALL", "INSTRUMENT_POSITION_SIDE_MISMATCH"),
        ("OPEN", "SELL", "LONG", "TODAY", "INSTRUMENT_POSITION_BUCKET_INVALID_FOR_OPEN"),
    ),
)
def test_mapper_rejects_cross_bucket_or_direction_mismatch(
    effect: str,
    side: str,
    position_side: str,
    position_bucket: str,
    code: str,
) -> None:
    metadata = _metadata()
    scope = AccountScope("fixture", "account", "sandbox")
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: 1_500,
        allocation_reader=lambda _scope: _allocation(scope),
    )

    with pytest.raises(RiskDeniedError) as rejected:
        mapper(
            _intent(
                metadata,
                effect=effect,
                side=side,
                position_side=position_side,
                position_bucket=position_bucket,
            )
        )

    assert rejected.value.code == code


def test_mapper_defaults_legacy_net_close_to_net_all() -> None:
    metadata = _metadata()
    scope = AccountScope("fixture", "account", "sandbox")
    mapper = InstrumentRiskAdmissionMapper(
        scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: 1_500,
        allocation_reader=lambda _scope: _allocation(scope),
    )

    mapped = mapper(_intent(metadata, effect="CLOSE", side="SELL"))

    assert mapped.action is IntentAction.REDUCE
    assert mapped.position_side == "NET"
    assert mapped.position_bucket == "ALL"
