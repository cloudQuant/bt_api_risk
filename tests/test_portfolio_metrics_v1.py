from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from bt_api_risk.portfolio_metrics_v1 import (
    DRAWDOWN_METHOD_V1,
    FX_UNIT_V1,
    HISTORICAL_VAR_ES_METHOD_V1,
    LOSS_UNIT_V1,
    PRICE_UNIT_V1,
    SHOCK_UNIT_V1,
    SPOT_EXPOSURE_METHOD_V1,
    SPOT_SCENARIO_METHOD_V1,
    HistoricalLossObservationV1,
    NavObservationV1,
    PortfolioMetricsError,
    SpotPositionMetricInputV1,
    SpotPriceFxShockV1,
    calculate_historical_var_es_v1,
    calculate_max_drawdown_v1,
    calculate_spot_exposure_v1,
    calculate_spot_scenario_pnl_v1,
)

_UTC = timezone.utc
_USD = "USD"
_T0 = datetime(2026, 1, 1, tzinfo=_UTC)


def _time(day: int) -> datetime:
    return _T0 + timedelta(days=day)


def _spot(
    ref: str,
    *,
    base: str,
    quote: str,
    quantity: str,
    price: str,
    fx: str,
    cut: datetime = _T0,
) -> SpotPositionMetricInputV1:
    return SpotPositionMetricInputV1(
        position_ref=ref,
        as_of_utc=cut,
        base_currency=base,
        quote_currency=quote,
        quantity=Decimal(quantity),
        quantity_unit=base,
        unit_price=Decimal(price),
        price_unit=PRICE_UNIT_V1,
        reporting_per_quote=Decimal(fx),
        fx_unit=FX_UNIT_V1,
    )


def _loss(day: int, amount: str, currency: str = _USD) -> HistoricalLossObservationV1:
    return HistoricalLossObservationV1(
        as_of_utc=_time(day),
        loss=Decimal(amount),
        currency=currency,
        loss_unit=LOSS_UNIT_V1,
    )


def test_spot_net_and_gross_reconcile_signed_rows_and_explicit_fx() -> None:
    report = calculate_spot_exposure_v1(
        (
            _spot("btc-long", base="BTC", quote="USD", quantity="2", price="20000", fx="1"),
            _spot("btc-short", base="BTC", quote="USD", quantity="-0.5", price="20000", fx="1"),
            _spot("eth-long", base="ETH", quote="EUR", quantity="3", price="2000", fx="1.1"),
        ),
        reporting_currency="USD",
    )

    assert report.method_ref == SPOT_EXPOSURE_METHOD_V1
    assert report.reporting_currency == "USD"
    assert report.net_reporting_notional == Decimal("36600.000000000000000000")
    assert report.gross_reporting_notional == Decimal("56600.000000000000000000")
    assert sum((row.signed_reporting_notional for row in report.contributions), Decimal("0")) == (
        report.net_reporting_notional
    )
    assert sum((row.gross_reporting_notional for row in report.contributions), Decimal("0")) == (
        report.gross_reporting_notional
    )


def test_spot_exposure_rejects_inconsistent_or_mixed_valuation_cuts() -> None:
    first = _spot("first", base="BTC", quote="USD", quantity="1", price="10", fx="1")
    second = _spot(
        "second", base="ETH", quote="USD", quantity="1", price="10", fx="1", cut=_time(1)
    )
    with pytest.raises(PortfolioMetricsError, match="POSITION_CUT_MISMATCH"):
        calculate_spot_exposure_v1((first, second), reporting_currency="USD")

    same_currency_bad_fx = _spot(
        "same-currency", base="BTC", quote="USD", quantity="1", price="10", fx="1.01"
    )
    with pytest.raises(PortfolioMetricsError, match="INCONSISTENT_SAME_CURRENCY_FX"):
        calculate_spot_exposure_v1((same_currency_bad_fx,), reporting_currency="USD")


def test_max_drawdown_returns_hand_calculated_peak_to_trough_ratio() -> None:
    report = calculate_max_drawdown_v1(
        tuple(
            NavObservationV1(_time(day), Decimal(nav), "USD")
            for day, nav in enumerate(("100", "120", "90", "96", "84", "132"))
        )
    )

    assert report.method_ref == DRAWDOWN_METHOD_V1
    assert report.max_drawdown_ratio == Decimal("-0.300000000000000000")
    assert report.peak_nav == Decimal("120")
    assert report.trough_nav == Decimal("84")
    assert report.peak_as_of_utc == _time(1)
    assert report.trough_as_of_utc == _time(4)


def test_max_drawdown_preserves_zero_when_nav_only_makes_new_highs() -> None:
    report = calculate_max_drawdown_v1(
        (NavObservationV1(_time(0), Decimal("10"), "USD"),
         NavObservationV1(_time(1), Decimal("11"), "USD"))
    )
    assert report.max_drawdown_ratio == Decimal("0E-18")
    assert report.peak_as_of_utc == _time(0)
    assert report.trough_as_of_utc == _time(0)


def test_historical_var_nearest_rank_and_fractional_tail_es_are_hand_checkable() -> None:
    report = calculate_historical_var_es_v1(
        (_loss(0, "-4"), _loss(1, "1"), _loss(2, "2"), _loss(3, "3"), _loss(4, "10")),
        reporting_currency="USD",
        horizon_ref="daily-close-to-close-v1",
        confidence=Decimal("0.7"),
    )

    # ceil(5 * 0.7) selects loss 3; the 1.5-sample tail is 10 + 0.5*3.
    assert report.method_ref == HISTORICAL_VAR_ES_METHOD_V1
    assert report.var_loss == Decimal("3")
    assert report.expected_shortfall_loss == Decimal("7.666666666666666667")
    assert report.tail_observation_mass == Decimal("1.5")
    assert report.observation_count == 5
    assert report.horizon_ref == "daily-close-to-close-v1"


def test_spot_stress_uses_compounded_price_and_fx_factors_and_reconciles() -> None:
    report = calculate_spot_scenario_pnl_v1(
        (
            _spot("eur-spot", base="BTC", quote="EUR", quantity="10", price="100", fx="1.2"),
            _spot("gbp-short", base="ETH", quote="GBP", quantity="-2", price="50", fx="1.5"),
        ),
        (
            SpotPriceFxShockV1("eur-spot", Decimal("-0.2"), Decimal("0.1"), SHOCK_UNIT_V1),
            SpotPriceFxShockV1("gbp-short", Decimal("0.5"), Decimal("-0.2"), SHOCK_UNIT_V1),
        ),
        reporting_currency="USD",
        scenario_ref="euro-risk-off",
        scenario_version="euro-risk-off-v1",
    )

    # Base 1,200 USD; stressed value is 10*100*0.8*1.2*1.1 = 1,056 USD.
    assert report.method_ref == SPOT_SCENARIO_METHOD_V1
    assert report.scenario_ref == "euro-risk-off"
    assert report.as_of_utc == _T0
    assert report.pnl_reporting_amount == Decimal("-174.000000000000000000")
    eur_row, gbp_short = report.contributions
    assert eur_row.position_ref == "eur-spot"
    assert eur_row.base_reporting_notional == Decimal("1200.000000000000000000")
    assert eur_row.stressed_reporting_notional == Decimal("1056.000000000000000000")
    assert eur_row.pnl_reporting_amount == Decimal("-144.000000000000000000")
    assert gbp_short.position_ref == "gbp-short"
    assert gbp_short.base_reporting_notional == Decimal("-150.000000000000000000")
    assert gbp_short.stressed_reporting_notional == Decimal("-180.000000000000000000")
    assert gbp_short.pnl_reporting_amount == Decimal("-30.000000000000000000")
    assert sum((row.base_reporting_notional for row in report.contributions), Decimal("0")) == (
        Decimal("1050.000000000000000000")
    )
    assert sum((row.stressed_reporting_notional for row in report.contributions), Decimal("0")) == (
        Decimal("876.000000000000000000")
    )
    assert sum((row.pnl_reporting_amount for row in report.contributions), Decimal("0")) == (
        report.pnl_reporting_amount
    )


@pytest.mark.parametrize("bad", [1.25, True, Decimal("NaN"), Decimal("Infinity")])
def test_metric_inputs_reject_non_decimal_or_non_finite_values(bad: object) -> None:
    with pytest.raises(PortfolioMetricsError):
        SpotPositionMetricInputV1(
            position_ref="bad-number",
            as_of_utc=_T0,
            base_currency="BTC",
            quote_currency="USD",
            quantity=bad,  # type: ignore[arg-type]
            quantity_unit="BTC",
            unit_price=Decimal("10"),
            price_unit=PRICE_UNIT_V1,
            reporting_per_quote=Decimal("1"),
            fx_unit=FX_UNIT_V1,
        )


def test_metric_inputs_reject_unsupported_units_and_out_of_range_decimals() -> None:
    with pytest.raises(PortfolioMetricsError, match="INVALID_QUANTITY_UNIT"):
        SpotPositionMetricInputV1(
            position_ref="wrong-unit",
            as_of_utc=_T0,
            base_currency="BTC",
            quote_currency="USD",
            quantity=Decimal("1"),
            quantity_unit="CONTRACTS",
            unit_price=Decimal("10"),
            price_unit=PRICE_UNIT_V1,
            reporting_per_quote=Decimal("1"),
            fx_unit=FX_UNIT_V1,
        )
    with pytest.raises(PortfolioMetricsError, match="DECIMAL_OUT_OF_RANGE"):
        _spot(
            "too-large",
            base="BTC",
            quote="USD",
            quantity="1000000000000000000000000",
            price="10",
            fx="1",
        )


def test_spot_metric_rejects_non_spot_fact_rows() -> None:
    with pytest.raises(PortfolioMetricsError, match="UNSUPPORTED_ROW_TYPE"):
        calculate_spot_exposure_v1(
            (NavObservationV1(_time(0), Decimal("10"), "USD"),),  # type: ignore[arg-type]
            reporting_currency="USD",
        )


def test_drawdown_and_historical_loss_require_ordered_utc_cuts() -> None:
    with pytest.raises(PortfolioMetricsError, match="INVALID_UTC_TIMESTAMP"):
        NavObservationV1(datetime(2026, 1, 1), Decimal("10"), "USD")
    with pytest.raises(PortfolioMetricsError, match="NAV_CUTS_NOT_STRICTLY_INCREASING"):
        calculate_max_drawdown_v1(
            (
                NavObservationV1(_time(1), Decimal("10"), "USD"),
                NavObservationV1(_time(0), Decimal("9"), "USD"),
            )
        )
    with pytest.raises(PortfolioMetricsError, match="LOSS_CUTS_NOT_STRICTLY_INCREASING"):
        calculate_historical_var_es_v1(
            (_loss(1, "1"), _loss(0, "2")),
            reporting_currency="USD",
            horizon_ref="one-step-v1",
            confidence=Decimal("0.5"),
        )


def test_historical_var_es_rejects_invalid_confidence_currency_and_horizon() -> None:
    observations = (_loss(0, "1"), _loss(1, "2"))
    with pytest.raises(PortfolioMetricsError, match="INVALID_CONFIDENCE"):
        calculate_historical_var_es_v1(
            observations,
            reporting_currency="USD",
            horizon_ref="one-step-v1",
            confidence=Decimal("1"),
        )
    with pytest.raises(PortfolioMetricsError, match="MIXED_LOSS_CURRENCY"):
        calculate_historical_var_es_v1(
            (_loss(0, "1", "USD"), _loss(1, "2", "EUR")),
            reporting_currency="USD",
            horizon_ref="one-step-v1",
            confidence=Decimal("0.5"),
        )
    with pytest.raises(PortfolioMetricsError, match="INVALID_REFERENCE"):
        calculate_historical_var_es_v1(
            observations,
            reporting_currency="USD",
            horizon_ref="one-step",
            confidence=Decimal("0.5"),
        )


def test_stress_requires_complete_mapping() -> None:
    positions = (
        _spot("one", base="BTC", quote="USD", quantity="1", price="10", fx="1"),
        _spot("two", base="ETH", quote="USD", quantity="1", price="20", fx="1"),
    )
    with pytest.raises(PortfolioMetricsError, match="INCOMPLETE_SHOCK_COVERAGE"):
        calculate_spot_scenario_pnl_v1(
            positions,
            (SpotPriceFxShockV1("one", Decimal("0"), Decimal("0"), SHOCK_UNIT_V1),),
            reporting_currency="USD",
            scenario_ref="all-spot-down",
            scenario_version="all-spot-down-v1",
        )


def test_total_price_loss_is_zero_valued_and_below_minus_one_is_rejected() -> None:
    zero_price_shock = SpotPriceFxShockV1(
        "zeroed", Decimal("-1"), Decimal("0"), SHOCK_UNIT_V1
    )
    report = calculate_spot_scenario_pnl_v1(
        (_spot("zeroed", base="BTC", quote="USD", quantity="2", price="10", fx="1"),),
        (zero_price_shock,),
        reporting_currency="USD",
        scenario_ref="total-price-loss",
        scenario_version="total-price-loss-v1",
    )
    assert report.contributions[0].base_reporting_notional == Decimal(
        "20.000000000000000000"
    )
    assert report.contributions[0].stressed_reporting_notional == Decimal("0E-18")
    assert report.contributions[0].pnl_reporting_amount == Decimal(
        "-20.000000000000000000"
    )
    assert report.pnl_reporting_amount == Decimal("-20.000000000000000000")
    with pytest.raises(PortfolioMetricsError, match="INVALID_PRICE_SHOCK_FACTOR"):
        SpotPriceFxShockV1("below-zero", Decimal("-1.0001"), Decimal("0"), SHOCK_UNIT_V1)
    with pytest.raises(PortfolioMetricsError, match="INVALID_FX_SHOCK_FACTOR"):
        SpotPriceFxShockV1("zero-fx", Decimal("0"), Decimal("-1"), SHOCK_UNIT_V1)
