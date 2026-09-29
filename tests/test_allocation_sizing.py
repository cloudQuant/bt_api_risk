from dataclasses import replace
from decimal import Decimal, localcontext

import pytest

from bt_api_risk.allocation_sizing import size_for_strategy_allocation
from bt_api_risk.core.admission import (
    AccountScope,
    RiskDeniedError,
    StrategyAllocationSnapshot,
)
from bt_api_risk.core.instrument import InstrumentRiskMetadata, InstrumentRiskRegistry


def fixture(
    *, budget="600", step="1", minimum=None, maximum=None, fee="0", slippage="0"
):
    allocation = StrategyAllocationSnapshot(
        AccountScope("fixture", "account-a", "simulation"),
        "strategy-a",
        "revision-1",
        Decimal(budget),
        Decimal(0),
        Decimal(0),
        Decimal(budget),
        "CNY",
        None,
        None,
        None,
        1.0,
    )
    metadata = InstrumentRiskMetadata(
        "FUTURE",
        "v1",
        1,
        100,
        Decimal("1"),
        Decimal(step),
        Decimal("1"),
        Decimal("100000"),
        min_quantity=None if minimum is None else Decimal(minimum),
        max_quantity=None if maximum is None else Decimal(maximum),
        fixed_fee=Decimal(fee),
        max_slippage_bps=Decimal(slippage),
        valuation_unit="CNY",
    )
    return allocation, InstrumentRiskRegistry([metadata])


def size(allocation, registry, *, now_ns=2):
    return size_for_strategy_allocation(
        allocation,
        registry,
        instrument="FUTURE",
        limit_price=Decimal("100"),
        now_ns=now_ns,
    )


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({}, "6"),
        ({"budget": "699"}, "6"),
        ({"budget": "99"}, "0"),
        ({"fee": "1"}, "5"),
        ({"slippage": "100"}, "5"),
        ({"maximum": "3"}, "3"),
        ({"minimum": "7"}, "0"),
        ({"step": "0.1", "budget": "39"}, "0.3"),
    ],
)
def test_exact_lattice_budget_fee_and_adverse_price(kwargs, expected):
    assert size(*fixture(**kwargs)) == Decimal(expected)


def test_fixed_fee_is_charged_once_and_ambient_decimal_precision_does_not_round_up():
    allocation, registry = fixture(budget="611", fee="11")
    with localcontext() as context:
        context.prec = 2
        assert size(allocation, registry) == Decimal("6")


@pytest.mark.parametrize(
    "value", [None, True, Decimal("NaN"), Decimal("Infinity"), Decimal("-1")]
)
def test_invalid_budget_rejects(value):
    allocation, registry = fixture()
    with pytest.raises(ValueError):
        size(replace(allocation, available_notional=value), registry)


def test_missing_or_cross_unit_facts_and_unknown_position_budget_reject():
    allocation, registry = fixture()
    for changes in (
        {"completeness": "LOCAL_LEDGER_INCOMPLETE"},
        {"notional_unit": "USD"},
        {"max_position": Decimal("10")},
    ):
        with pytest.raises(RiskDeniedError):
            size(replace(allocation, **changes), registry)


def test_expired_metadata_rejects_instead_of_sizing_from_stale_value():
    with pytest.raises(RiskDeniedError):
        size(*fixture(), now_ns=101)


def test_existing_occupancy_is_not_ignored():
    allocation, registry = fixture()
    with pytest.raises(ValueError, match="occupancy"):
        size(replace(allocation, used_notional=Decimal("1")), registry)


def test_large_exponent_gap_does_not_drop_a_small_fixed_fee():
    allocation, registry = fixture(budget="1e102", fee="1e-100")
    metadata = replace(registry.get("FUTURE"), max_gross_notional=Decimal("1e103"))
    quantity = size_for_strategy_allocation(
        allocation,
        InstrumentRiskRegistry([metadata]),
        instrument="FUTURE",
        limit_price=Decimal("1e100"),
        now_ns=2,
    )
    assert quantity == Decimal("99")


def test_unknown_instrument_rejects():
    allocation, registry = fixture()
    with pytest.raises(RiskDeniedError, match="instrument"):
        size_for_strategy_allocation(
            allocation,
            registry,
            instrument="OTHER",
            limit_price=Decimal("100"),
            now_ns=2,
        )


@pytest.mark.parametrize(
    "price", [None, True, 100.0, "100", Decimal("NaN"), Decimal("0")]
)
def test_advisory_price_requires_explicit_positive_decimal(price):
    allocation, registry = fixture()
    with pytest.raises(ValueError, match="limit price"):
        size_for_strategy_allocation(
            allocation, registry, instrument="FUTURE", limit_price=price, now_ns=2
        )


def test_unsupported_arithmetic_scale_rejects_before_advice():
    allocation, registry = fixture()
    with pytest.raises(ValueError, match="arithmetic bound"):
        size_for_strategy_allocation(
            allocation,
            registry,
            instrument="FUTURE",
            limit_price=Decimal("1e10001"),
            now_ns=2,
        )


def test_oversized_allocation_scale_rejects_before_fraction_allocation():
    allocation, registry = fixture(budget="1e10001")
    with pytest.raises(ValueError, match="arithmetic bound"):
        size(allocation, registry)
