"""Bounded, offline portfolio metrics over caller-supplied typed facts.

This module is a numeric component only. It does not establish that inputs are
complete, current, authenticated, or from a particular account, and it grants
no account or order authority. Callers must bind facts to their own trusted
source and preserve the returned method and unit metadata.

V1 conventions:

* Spot notional is quantity times quote-per-base price times an explicit
  reporting-per-quote FX rate. Net is the signed sum; gross is the sum of
  absolute notionals, over only the supplied spot rows.
* Drawdown is NAV divided by the running prior-or-current peak, minus one;
  maximum drawdown is the most negative observed ratio.
* Historical loss VaR uses the inverse empirical CDF with nearest-rank index
  ceil(n*q). ES is the equal-weight empirical upper-tail integral, including a
  fractional boundary observation when n*(1-q) is not an integer. Losses are
  signed reporting-currency amounts over the caller-defined one-step horizon.
* A spot scenario reprices each supplied row as quantity * shocked price * FX
  and reports the difference from its base value. Price and FX shocks are
  fractional returns, applied multiplicatively.

The VaR and ES terminology follows Basel Framework MAR 10.17-10.18. Those
definitions do not prescribe this module's finite-sample quantile convention;
the method identifier above makes that convention explicit and is not a claim
of Basel regulatory-model compliance. The drawdown ratio is the peak-to-trough
formula recommended by CFA Institute in its comment on SEC Form PF; the SEC
adopting release did not prescribe one methodology. Stress scenarios require
documented, internally consistent assumptions and limitations as described by
the BCBS Stress Testing Principles; the spot repricing formula here is a
versioned package convention, not a universal stress model.

All sequences are capped at 10,000 rows. Inputs allow at most 24 decimal
coefficient digits and an absolute exponent of 18. Derived amounts and ratios
use 18 fractional digits with ROUND_HALF_EVEN; the selected empirical VaR loss
is returned exactly as supplied.

References:
* https://www.bis.org/committees/bcbs/basel-framework/standard/mar
* https://www.sec.gov/comments/s7-22-22/s72222-20145430-310651.pdf
* https://www.sec.gov/file/ia-6546
* https://www.bis.org/publications/201810-guidelines-stress-testing-principles
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import (
    ROUND_CEILING,
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DecimalException,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from typing import Final, TypeVar, cast

from .portfolio_analytics import (
    PortfolioAnalyticsError,
    _require_currency,
    _require_decimal,
    _require_text,
)

PORTFOLIO_METRICS_SCHEMA_V1: Final[str] = "portfolio_metrics_v1"
SPOT_EXPOSURE_METHOD_V1: Final[str] = "spot_notional_net_gross_v1"
DRAWDOWN_METHOD_V1: Final[str] = "nav_running_peak_ratio_v1"
HISTORICAL_VAR_ES_METHOD_V1: Final[str] = (
    "historical_loss_nearest_rank_fractional_tail_es_v1"
)
SPOT_SCENARIO_METHOD_V1: Final[str] = "spot_multiplicative_price_fx_revaluation_v1"
SPOT_SCOPE_V1: Final[str] = "SUPPLIED_SPOT_ROWS_ONLY"
PRICE_UNIT_V1: Final[str] = "QUOTE_PER_BASE"
FX_UNIT_V1: Final[str] = "REPORTING_PER_QUOTE"
LOSS_UNIT_V1: Final[str] = "REPORTING_CURRENCY_AMOUNT"
SHOCK_UNIT_V1: Final[str] = "FRACTIONAL_RETURN"

_OUTPUT_QUANTUM: Final[Decimal] = Decimal("1e-18")
_DECIMAL_PRECISION: Final[int] = 256
_MAX_DECIMAL_DIGITS: Final[int] = 24
_MAX_DECIMAL_EXPONENT: Final[int] = 18
_MAX_ROWS: Final[int] = 10_000
_Row = TypeVar("_Row")


class PortfolioMetricsError(ValueError):
    """Finite validation or calculation failure without echoed input values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _require_ref(value: object, *, versioned: bool = False) -> str:
    try:
        return _require_text(value, versioned=versioned)
    except PortfolioAnalyticsError as exc:
        raise PortfolioMetricsError("INVALID_REFERENCE") from exc


def _require_currency_code(value: object) -> str:
    try:
        return _require_currency(value)
    except PortfolioAnalyticsError as exc:
        raise PortfolioMetricsError("INVALID_CURRENCY") from exc


def _require_metric_decimal(value: object) -> Decimal:
    try:
        result = _require_decimal(value)
    except PortfolioAnalyticsError as exc:
        raise PortfolioMetricsError(exc.code) from exc
    parts = result.as_tuple()
    if len(parts.digits) > _MAX_DECIMAL_DIGITS or abs(parts.exponent) > _MAX_DECIMAL_EXPONENT:
        raise PortfolioMetricsError("DECIMAL_OUT_OF_RANGE")
    return result


def _require_utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise PortfolioMetricsError("INVALID_UTC_TIMESTAMP")
    try:
        offset = value.utcoffset()
    except (OverflowError, ValueError) as exc:
        raise PortfolioMetricsError("INVALID_UTC_TIMESTAMP") from exc
    if offset != timedelta(0):
        raise PortfolioMetricsError("INVALID_UTC_TIMESTAMP")
    return value


def _require_rows(
    value: object, row_type: type[_Row], *, minimum: int = 1
) -> tuple[_Row, ...]:
    if type(value) not in (tuple, list):
        raise PortfolioMetricsError("INVALID_ROWS")
    rows = cast(Sequence[object], value)
    if not minimum <= len(rows) <= _MAX_ROWS:
        raise PortfolioMetricsError("INVALID_ROW_COUNT")
    if any(type(row) is not row_type for row in rows):
        raise PortfolioMetricsError("UNSUPPORTED_ROW_TYPE")
    return tuple(rows)


def _decimal_context() -> Context:
    return Context(
        prec=_DECIMAL_PRECISION,
        rounding=ROUND_HALF_EVEN,
        Emin=-999_999,
        Emax=999_999,
        flags=[],
        traps=[InvalidOperation, DivisionByZero, Overflow],
    )


def _quantize(value: Decimal) -> Decimal:
    try:
        result = value.quantize(_OUTPUT_QUANTUM, rounding=ROUND_HALF_EVEN)
        return abs(result) if result.is_zero() else result
    except (DecimalException, OverflowError) as exc:
        raise PortfolioMetricsError("CALCULATION_OUT_OF_RANGE") from exc


def _calculation_error(exc: Exception) -> PortfolioMetricsError:
    del exc
    return PortfolioMetricsError("CALCULATION_OUT_OF_RANGE")


@dataclass(frozen=True, slots=True)
class SpotPositionMetricInputV1:
    """One already-marked spot row with explicit quantity, price, FX, and cut units."""

    position_ref: str
    as_of_utc: datetime
    base_currency: str
    quote_currency: str
    quantity: Decimal
    quantity_unit: str
    unit_price: Decimal
    price_unit: str
    reporting_per_quote: Decimal
    fx_unit: str

    def __post_init__(self) -> None:
        _require_ref(self.position_ref)
        _require_utc(self.as_of_utc)
        _require_currency_code(self.base_currency)
        _require_currency_code(self.quote_currency)
        _require_metric_decimal(self.quantity)
        if type(self.quantity_unit) is not str or self.quantity_unit != self.base_currency:
            raise PortfolioMetricsError("INVALID_QUANTITY_UNIT")
        if type(self.price_unit) is not str or self.price_unit != PRICE_UNIT_V1:
            raise PortfolioMetricsError("INVALID_PRICE_UNIT")
        if _require_metric_decimal(self.unit_price) <= 0:
            raise PortfolioMetricsError("INVALID_UNIT_PRICE")
        if _require_metric_decimal(self.reporting_per_quote) <= 0:
            raise PortfolioMetricsError("INVALID_FX_RATE")
        if type(self.fx_unit) is not str or self.fx_unit != FX_UNIT_V1:
            raise PortfolioMetricsError("INVALID_FX_UNIT")


@dataclass(frozen=True, slots=True)
class SpotExposureContributionV1:
    position_ref: str
    signed_reporting_notional: Decimal
    gross_reporting_notional: Decimal


@dataclass(frozen=True, slots=True)
class SpotExposureReportV1:
    schema_version: str
    method_ref: str
    scope: str
    as_of_utc: datetime
    reporting_currency: str
    net_reporting_notional: Decimal
    gross_reporting_notional: Decimal
    contributions: tuple[SpotExposureContributionV1, ...]


@dataclass(frozen=True, slots=True)
class NavObservationV1:
    as_of_utc: datetime
    nav: Decimal
    currency: str

    def __post_init__(self) -> None:
        _require_utc(self.as_of_utc)
        _require_metric_decimal(self.nav)
        _require_currency_code(self.currency)


@dataclass(frozen=True, slots=True)
class DrawdownReportV1:
    schema_version: str
    method_ref: str
    reporting_currency: str
    max_drawdown_ratio: Decimal
    peak_nav: Decimal
    trough_nav: Decimal
    peak_as_of_utc: datetime
    trough_as_of_utc: datetime
    observation_count: int


@dataclass(frozen=True, slots=True)
class HistoricalLossObservationV1:
    as_of_utc: datetime
    loss: Decimal
    currency: str
    loss_unit: str

    def __post_init__(self) -> None:
        _require_utc(self.as_of_utc)
        _require_metric_decimal(self.loss)
        _require_currency_code(self.currency)
        if type(self.loss_unit) is not str or self.loss_unit != LOSS_UNIT_V1:
            raise PortfolioMetricsError("INVALID_LOSS_UNIT")


@dataclass(frozen=True, slots=True)
class HistoricalVarEsReportV1:
    schema_version: str
    method_ref: str
    reporting_currency: str
    horizon_ref: str
    confidence: Decimal
    var_loss: Decimal
    expected_shortfall_loss: Decimal
    tail_observation_mass: Decimal
    observation_count: int
    first_as_of_utc: datetime
    last_as_of_utc: datetime


@dataclass(frozen=True, slots=True)
class SpotPriceFxShockV1:
    position_ref: str
    price_return: Decimal
    fx_return: Decimal
    shock_unit: str

    def __post_init__(self) -> None:
        _require_ref(self.position_ref)
        _require_metric_decimal(self.price_return)
        _require_metric_decimal(self.fx_return)
        if type(self.shock_unit) is not str or self.shock_unit != SHOCK_UNIT_V1:
            raise PortfolioMetricsError("INVALID_SHOCK_UNIT")
        if self.price_return < Decimal("-1"):
            raise PortfolioMetricsError("INVALID_PRICE_SHOCK_FACTOR")
        if self.fx_return <= Decimal("-1"):
            raise PortfolioMetricsError("INVALID_FX_SHOCK_FACTOR")


@dataclass(frozen=True, slots=True)
class SpotStressContributionV1:
    position_ref: str
    base_reporting_notional: Decimal
    stressed_reporting_notional: Decimal
    pnl_reporting_amount: Decimal


@dataclass(frozen=True, slots=True)
class SpotStressReportV1:
    schema_version: str
    method_ref: str
    scope: str
    scenario_ref: str
    scenario_version: str
    as_of_utc: datetime
    reporting_currency: str
    pnl_reporting_amount: Decimal
    contributions: tuple[SpotStressContributionV1, ...]


def calculate_spot_exposure_v1(
    positions: Sequence[SpotPositionMetricInputV1], *, reporting_currency: str
) -> SpotExposureReportV1:
    """Calculate signed net and absolute gross notional for supplied spot rows."""

    rows = _require_rows(positions, SpotPositionMetricInputV1)
    reporting = _require_currency_code(reporting_currency)
    refs = tuple(row.position_ref for row in rows)
    if len(refs) != len(set(refs)):
        raise PortfolioMetricsError("DUPLICATE_POSITION_REF")
    cut = rows[0].as_of_utc
    if any(row.as_of_utc != cut for row in rows):
        raise PortfolioMetricsError("POSITION_CUT_MISMATCH")
    for row in rows:
        if row.quote_currency == reporting and row.reporting_per_quote != Decimal("1"):
            raise PortfolioMetricsError("INCONSISTENT_SAME_CURRENCY_FX")

    try:
        with localcontext(_decimal_context()):
            contributions = tuple(
                SpotExposureContributionV1(
                    position_ref=row.position_ref,
                    signed_reporting_notional=_quantize(
                        row.quantity * row.unit_price * row.reporting_per_quote
                    ),
                    gross_reporting_notional=_quantize(
                        abs(row.quantity * row.unit_price * row.reporting_per_quote)
                    ),
                )
                for row in rows
            )
            net = sum(
                (row.signed_reporting_notional for row in contributions), Decimal("0")
            )
            gross = sum(
                (row.gross_reporting_notional for row in contributions), Decimal("0")
            )
    except (DecimalException, OverflowError, ZeroDivisionError) as exc:
        raise _calculation_error(exc) from exc
    return SpotExposureReportV1(
        schema_version=PORTFOLIO_METRICS_SCHEMA_V1,
        method_ref=SPOT_EXPOSURE_METHOD_V1,
        scope=SPOT_SCOPE_V1,
        as_of_utc=cut,
        reporting_currency=reporting,
        net_reporting_notional=net,
        gross_reporting_notional=gross,
        contributions=contributions,
    )


def calculate_max_drawdown_v1(
    observations: Sequence[NavObservationV1],
) -> DrawdownReportV1:
    """Return the most negative NAV/running-peak ratio over ordered UTC cuts."""

    rows = _require_rows(observations, NavObservationV1, minimum=2)
    currency = rows[0].currency
    if any(row.currency != currency for row in rows):
        raise PortfolioMetricsError("MIXED_NAV_CURRENCY")
    if any(left.as_of_utc >= right.as_of_utc for left, right in zip(rows, rows[1:])):
        raise PortfolioMetricsError("NAV_CUTS_NOT_STRICTLY_INCREASING")
    if rows[0].nav <= 0:
        raise PortfolioMetricsError("INITIAL_NAV_NOT_POSITIVE")

    try:
        with localcontext(_decimal_context()):
            peak = rows[0]
            max_drawdown = Decimal("0")
            max_peak = rows[0]
            max_trough = rows[0]
            for row in rows[1:]:
                drawdown = row.nav / peak.nav - Decimal("1")
                if drawdown < max_drawdown:
                    max_drawdown = drawdown
                    max_peak = peak
                    max_trough = row
                if row.nav > peak.nav:
                    peak = row
            return DrawdownReportV1(
                schema_version=PORTFOLIO_METRICS_SCHEMA_V1,
                method_ref=DRAWDOWN_METHOD_V1,
                reporting_currency=currency,
                max_drawdown_ratio=_quantize(max_drawdown),
                peak_nav=max_peak.nav,
                trough_nav=max_trough.nav,
                peak_as_of_utc=max_peak.as_of_utc,
                trough_as_of_utc=max_trough.as_of_utc,
                observation_count=len(rows),
            )
    except (DecimalException, OverflowError, ZeroDivisionError) as exc:
        raise _calculation_error(exc) from exc


def calculate_historical_var_es_v1(
    observations: Sequence[HistoricalLossObservationV1],
    *,
    reporting_currency: str,
    horizon_ref: str,
    confidence: Decimal,
) -> HistoricalVarEsReportV1:
    """Calculate nearest-rank empirical VaR and fractionally weighted upper-tail ES.

    The caller supplies one consistently defined loss observation horizon;
    this numerical component validates timestamps and units but cannot prove
    the economic comparability or source completeness of those observations.
    """

    rows = _require_rows(observations, HistoricalLossObservationV1, minimum=2)
    reporting = _require_currency_code(reporting_currency)
    horizon = _require_ref(horizon_ref, versioned=True)
    q = _require_metric_decimal(confidence)
    if not Decimal("0") < q < Decimal("1"):
        raise PortfolioMetricsError("INVALID_CONFIDENCE")
    if any(row.currency != reporting for row in rows):
        raise PortfolioMetricsError("MIXED_LOSS_CURRENCY")
    if any(left.as_of_utc >= right.as_of_utc for left, right in zip(rows, rows[1:])):
        raise PortfolioMetricsError("LOSS_CUTS_NOT_STRICTLY_INCREASING")

    try:
        with localcontext(_decimal_context()):
            ordered_losses = sorted(row.loss for row in rows)
            n = len(ordered_losses)
            rank = int((Decimal(n) * q).to_integral_value(rounding=ROUND_CEILING))
            var_loss = ordered_losses[rank - 1]
            tail_mass = Decimal(n) * (Decimal("1") - q)
            whole_tail_rows = int(tail_mass)
            fractional_tail_row = tail_mass - Decimal(whole_tail_rows)
            tail_sum = sum(
                ordered_losses[n - whole_tail_rows :], Decimal("0")
            ) if whole_tail_rows else Decimal("0")
            if fractional_tail_row:
                tail_sum += ordered_losses[n - whole_tail_rows - 1] * fractional_tail_row
            expected_shortfall = _quantize(tail_sum / tail_mass)
    except (DecimalException, OverflowError, ZeroDivisionError) as exc:
        raise _calculation_error(exc) from exc
    return HistoricalVarEsReportV1(
        schema_version=PORTFOLIO_METRICS_SCHEMA_V1,
        method_ref=HISTORICAL_VAR_ES_METHOD_V1,
        reporting_currency=reporting,
        horizon_ref=horizon,
        confidence=q,
        var_loss=var_loss,
        expected_shortfall_loss=expected_shortfall,
        tail_observation_mass=tail_mass,
        observation_count=len(rows),
        first_as_of_utc=rows[0].as_of_utc,
        last_as_of_utc=rows[-1].as_of_utc,
    )


def calculate_spot_scenario_pnl_v1(
    positions: Sequence[SpotPositionMetricInputV1],
    shocks: Sequence[SpotPriceFxShockV1],
    *,
    reporting_currency: str,
    scenario_ref: str,
    scenario_version: str,
) -> SpotStressReportV1:
    """Reprice every supplied spot row under a complete explicit price/FX shock set."""

    rows = _require_rows(positions, SpotPositionMetricInputV1)
    shock_rows = _require_rows(shocks, SpotPriceFxShockV1)
    reporting = _require_currency_code(reporting_currency)
    scenario = _require_ref(scenario_ref)
    version = _require_ref(scenario_version, versioned=True)
    position_refs = tuple(row.position_ref for row in rows)
    shock_refs = tuple(row.position_ref for row in shock_rows)
    if len(position_refs) != len(set(position_refs)):
        raise PortfolioMetricsError("DUPLICATE_POSITION_REF")
    if len(shock_refs) != len(set(shock_refs)):
        raise PortfolioMetricsError("DUPLICATE_SHOCK_REF")
    if set(position_refs) != set(shock_refs):
        raise PortfolioMetricsError("INCOMPLETE_SHOCK_COVERAGE")
    cut = rows[0].as_of_utc
    if any(row.as_of_utc != cut for row in rows):
        raise PortfolioMetricsError("POSITION_CUT_MISMATCH")
    for row in rows:
        if row.quote_currency == reporting and row.reporting_per_quote != Decimal("1"):
            raise PortfolioMetricsError("INCONSISTENT_SAME_CURRENCY_FX")

    shock_by_ref = {row.position_ref: row for row in shock_rows}
    try:
        with localcontext(_decimal_context()):
            built_contributions: list[SpotStressContributionV1] = []
            for row in rows:
                shock = shock_by_ref[row.position_ref]
                base_notional = _quantize(
                    row.quantity * row.unit_price * row.reporting_per_quote
                )
                stressed_notional = _quantize(
                    row.quantity
                    * row.unit_price
                    * (Decimal("1") + shock.price_return)
                    * row.reporting_per_quote
                    * (Decimal("1") + shock.fx_return)
                )
                built_contributions.append(
                    SpotStressContributionV1(
                        position_ref=row.position_ref,
                        base_reporting_notional=base_notional,
                        stressed_reporting_notional=stressed_notional,
                        pnl_reporting_amount=stressed_notional - base_notional,
                    )
                )
            contributions = tuple(built_contributions)
            total_pnl = sum(
                (row.pnl_reporting_amount for row in contributions), Decimal("0")
            )
    except (DecimalException, OverflowError, ZeroDivisionError) as exc:
        raise _calculation_error(exc) from exc
    return SpotStressReportV1(
        schema_version=PORTFOLIO_METRICS_SCHEMA_V1,
        method_ref=SPOT_SCENARIO_METHOD_V1,
        scope=SPOT_SCOPE_V1,
        scenario_ref=scenario,
        scenario_version=version,
        as_of_utc=cut,
        reporting_currency=reporting,
        pnl_reporting_amount=total_pnl,
        contributions=contributions,
    )
