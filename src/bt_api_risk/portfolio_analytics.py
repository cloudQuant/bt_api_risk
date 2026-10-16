"""Deterministic, offline spot-portfolio valuation and return calculation.

This is a Risk-package calculation entry, not the ``analysis.submit`` task
worker or SDK service adapter. A deployment must inject a trusted facts source
that binds the authenticated principal to the requested portfolio and returns
complete, versioned facts. The request itself contains selectors only; it can
never provide balances, membership, prices, FX, or coverage claims.

The supported economic model is deliberately narrow: positive spot inventory
plus non-negative cash, marked in a reporting currency at exact UTC calendar
day-end cuts. External contributions and withdrawals are adjusted using the
Modified Dietz estimate with UTC calendar-day, end-of-day flow weights (each
flow is treated as occurring at the end of its UTC calendar date). Dividends,
interest, trade settlement, fees, and other internal cash movements must
already be reflected in both valuation points and must not be supplied as
external capital flows.

The calculation uses a fixed Decimal context and fixed output scale. It does
not load account credentials, contact a provider, import the admission gate,
or grant order permission. Modified Dietz is an estimate, not a claim of GIPS
compliance; the GIPS Asset Owners Handbook explains the formula and its
limitations at:
https://www.gipsstandards.org/standards/gips-standards-for-asset-owners/gips-standards-handbook-for-asset-owners/
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DecimalException,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from typing import Protocol

_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_VERSIONED_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*-v[1-9][0-9]*$")
_CURRENCY_RE = re.compile(r"^[A-Z][A-Z0-9]{1,11}$")
_SUPPORTED_SOURCE_MODES = frozenset({"research", "imported", "paper"})
_SUPPORTED_ASSET_CLASSES = frozenset({"cash", "spot"})
_SUPPORTED_VALUATION_BASIS = "cash_spot_after_booked_internal_flows_v1"
_CALCULATION_REF = "spot_nav_modified_dietz_v1"
_RETURN_METHOD = "MODIFIED_DIETZ_ESTIMATE_V1"
_FLOW_WEIGHT_POLICY = "UTC_CALENDAR_DAY_END_V1"
_VALUATION_CUT_POLICY = "UTC_CALENDAR_DAY_END_V1"
_SPOT_PRICE_UNIT = "QUOTE_PER_BASE"
_FX_RATE_UNIT = "QUOTE_PER_BASE"
_OUTPUT_SCALE = 18
_OUTPUT_QUANTUM = Decimal("1e-18")
_DECIMAL_PRECISION = 50
_DECIMAL_EMIN = -999_999
_DECIMAL_EMAX = 999_999
_DECIMAL_POLICY = (
    "PRECISION_50_EMIN_NEG999999_EMAX_999999_HALF_EVEN_TRAPS_INVALID_DIVISION_OVERFLOW_"
    "QUANTIZE_18_CANONICAL_STRING_V1"
)
_MAX_DECIMAL_DIGITS = 64
_MAX_DECIMAL_EXPONENT = 36
_MAX_FACT_ROWS = 10_000
_NANOSECONDS_PER_SECOND = 1_000_000_000
_NANOSECONDS_PER_DAY = 86_400 * _NANOSECONDS_PER_SECOND
_EPOCH_DATE = date(1970, 1, 1)


class PortfolioAnalyticsError(ValueError):
    """Finite request/source-contract error that never echoes supplied data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PortfolioAnalyticsSourceUnavailableError(Exception):
    """A source may use this typed signal when no complete fact cut is available."""


def _require_text(value: object, *, versioned: bool = False) -> str:
    if type(value) is not str or value != value.strip():
        raise PortfolioAnalyticsError("INVALID_REFERENCE")
    pattern = _VERSIONED_REF_RE if versioned else _REF_RE
    if pattern.fullmatch(value) is None:
        raise PortfolioAnalyticsError("INVALID_REFERENCE")
    return value


def _require_currency(value: object) -> str:
    if type(value) is not str or _CURRENCY_RE.fullmatch(value) is None:
        raise PortfolioAnalyticsError("INVALID_CURRENCY")
    return value


def _require_date(value: object) -> date:
    if type(value) is not date:
        raise PortfolioAnalyticsError("INVALID_PERIOD_DATE")
    return value


def _require_timestamp(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise PortfolioAnalyticsError("INVALID_TIMESTAMP")
    return value


def _require_decimal(value: object) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise PortfolioAnalyticsError("INVALID_DECIMAL")
    parts = value.as_tuple()
    if len(parts.digits) > _MAX_DECIMAL_DIGITS or abs(parts.exponent) > _MAX_DECIMAL_EXPONENT:
        raise PortfolioAnalyticsError("DECIMAL_OUT_OF_RANGE")
    return value


def _require_positive_int(value: object, code: str = "INVALID_VERSION") -> int:
    if type(value) is not int or value <= 0:
        raise PortfolioAnalyticsError(code)
    return value


def _tuple_of(value: object, item_type: type, code: str) -> tuple[object, ...]:
    if type(value) not in (tuple, list):
        raise PortfolioAnalyticsError(code)
    result = tuple(value)
    if any(type(item) is not item_type for item in result):
        raise PortfolioAnalyticsError(code)
    return result


def _canonical_decimal(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if text in {"", "-0"}:
        return "0"
    return text


def _quantized_decimal(value: Decimal) -> Decimal:
    try:
        return value.quantize(_OUTPUT_QUANTUM, rounding=ROUND_HALF_EVEN)
    except InvalidOperation as exc:
        raise PortfolioAnalyticsError("CALCULATION_OUT_OF_RANGE") from exc


def _utc_date_for_ns(value: int) -> date:
    day_offset = value // _NANOSECONDS_PER_DAY
    try:
        return date.fromordinal(_EPOCH_DATE.toordinal() + day_offset)
    except (OverflowError, ValueError) as exc:
        raise PortfolioAnalyticsError("INVALID_TIMESTAMP") from exc


def _normalized_refs(value: object, code: str) -> tuple[str, ...]:
    if type(value) not in (tuple, list):
        raise PortfolioAnalyticsError(code)
    if len(value) > _MAX_FACT_ROWS:
        raise PortfolioAnalyticsError("INPUT_LIMIT_EXCEEDED")
    copied = tuple(_require_text(item) for item in value)
    if len(set(copied)) != len(copied):
        raise PortfolioAnalyticsError(code)
    return tuple(sorted(copied))


@dataclass(frozen=True, slots=True)
class PortfolioAnalyticsRequestV1:
    """Selectors only; this object cannot carry portfolio financial facts."""

    portfolio_ref: str
    membership_version: int
    period_start_date_utc: date
    period_end_date_utc: date
    reporting_currency: str

    def __post_init__(self) -> None:
        _require_text(self.portfolio_ref)
        _require_positive_int(self.membership_version)
        _require_date(self.period_start_date_utc)
        _require_date(self.period_end_date_utc)
        _require_currency(self.reporting_currency)
        if self.period_end_date_utc <= self.period_start_date_utc:
            raise PortfolioAnalyticsError("INVALID_PERIOD")


@dataclass(frozen=True, slots=True)
class PortfolioAnalyticsModelProfileV1:
    """Immutable calculation/freshness settings supplied by trusted code."""

    model_profile_ref: str
    max_mark_age_ns: int
    max_fx_age_ns: int
    max_input_bytes: int = 1_048_576
    max_period_days: int = 3_660

    def __post_init__(self) -> None:
        _require_text(self.model_profile_ref, versioned=True)
        for value, lower, upper in (
            (self.max_mark_age_ns, 0, 31_536_000 * _NANOSECONDS_PER_SECOND),
            (self.max_fx_age_ns, 0, 31_536_000 * _NANOSECONDS_PER_SECOND),
            (self.max_input_bytes, 1, 67_108_864),
            (self.max_period_days, 1, 36_600),
        ):
            if type(value) is not int or not lower < value <= upper:
                raise PortfolioAnalyticsError("INVALID_MODEL_PROFILE")


@dataclass(frozen=True, slots=True)
class PortfolioMembershipV1:
    """Immutable membership version effective for the entire requested period."""

    portfolio_ref: str
    membership_version: int
    member_refs: tuple[str, ...]
    effective_start_date_utc: date
    effective_end_date_utc_exclusive: date | None
    source_ref: str
    source_version: str
    content_sha256: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.portfolio_ref)
        _require_positive_int(self.membership_version)
        members = _normalized_refs(self.member_refs, "INVALID_MEMBERSHIP")
        if not members:
            raise PortfolioAnalyticsError("EMPTY_MEMBERSHIP")
        object.__setattr__(self, "member_refs", members)
        _require_date(self.effective_start_date_utc)
        if self.effective_end_date_utc_exclusive is not None:
            _require_date(self.effective_end_date_utc_exclusive)
            if self.effective_end_date_utc_exclusive <= self.effective_start_date_utc:
                raise PortfolioAnalyticsError("INVALID_MEMBERSHIP_INTERVAL")
        _require_text(self.source_ref)
        _require_text(self.source_version, versioned=True)
        expected = _membership_digest_fields(
            self.portfolio_ref,
            self.membership_version,
            self.member_refs,
            self.effective_start_date_utc,
            self.effective_end_date_utc_exclusive,
            self.source_ref,
            self.source_version,
        )
        if self.content_sha256 is None:
            object.__setattr__(self, "content_sha256", expected)
        elif type(self.content_sha256) is not str or self.content_sha256 != expected:
            raise PortfolioAnalyticsError("MEMBERSHIP_DIGEST_MISMATCH")


def _membership_digest_fields(
    portfolio_ref: str,
    membership_version: int,
    member_refs: tuple[str, ...],
    effective_start_date_utc: date,
    effective_end_date_utc_exclusive: date | None,
    source_ref: str,
    source_version: str,
) -> str:
    payload = {
        "effective_end_date_utc_exclusive": (
            effective_end_date_utc_exclusive.isoformat()
            if effective_end_date_utc_exclusive is not None
            else None
        ),
        "effective_start_date_utc": effective_start_date_utc.isoformat(),
        "member_refs": list(member_refs),
        "membership_version": membership_version,
        "portfolio_ref": portfolio_ref,
        "source_ref": source_ref,
        "source_version": source_version,
        "version": 1,
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class CashBalanceV1:
    balance_ref: str
    member_ref: str
    currency: str
    amount: Decimal

    def __post_init__(self) -> None:
        _require_text(self.balance_ref)
        _require_text(self.member_ref)
        _require_currency(self.currency)
        _require_decimal(self.amount)


@dataclass(frozen=True, slots=True)
class SpotPositionV1:
    """A spot row; price is quote currency per one base-currency unit."""

    position_ref: str
    member_ref: str
    instrument_ref: str
    product_kind: str
    base_currency: str
    quote_currency: str
    price_unit: str
    quantity: Decimal
    unit_price: Decimal
    price_as_of_ns: int
    price_valid_until_ns: int
    price_source_ref: str
    price_source_version: str
    price_source_generation: str
    price_source_cursor: str
    price_observation_ref: str
    instrument_metadata_ref: str
    instrument_metadata_version: str

    def __post_init__(self) -> None:
        for value in (
            self.position_ref,
            self.member_ref,
            self.instrument_ref,
            self.price_source_ref,
            self.price_source_cursor,
            self.price_observation_ref,
            self.instrument_metadata_ref,
        ):
            _require_text(value)
        _require_text(self.product_kind)
        _require_currency(self.base_currency)
        _require_currency(self.quote_currency)
        if self.price_unit != _SPOT_PRICE_UNIT:
            raise PortfolioAnalyticsError("UNSUPPORTED_SPOT_PRICE_UNIT")
        _require_decimal(self.quantity)
        _require_decimal(self.unit_price)
        _require_timestamp(self.price_as_of_ns)
        _require_timestamp(self.price_valid_until_ns)
        if self.price_valid_until_ns < self.price_as_of_ns:
            raise PortfolioAnalyticsError("INVALID_MARK_VALIDITY")
        _require_text(self.price_source_version, versioned=True)
        _require_text(self.price_source_generation)
        _require_text(self.instrument_metadata_version, versioned=True)
        if self.unit_price <= 0:
            raise PortfolioAnalyticsError("INVALID_MARK_PRICE")


@dataclass(frozen=True, slots=True)
class FxObservationV1:
    """A positive BASE_TO_QUOTE rate: one base unit equals ``rate`` quote units."""

    observation_ref: str
    base_currency: str
    quote_currency: str
    direction: str
    rate_unit: str
    rate: Decimal
    as_of_ns: int
    valid_until_ns: int
    source_ref: str
    source_version: str
    source_generation: str
    source_cursor: str

    def __post_init__(self) -> None:
        for value in (self.observation_ref, self.source_ref, self.source_cursor):
            _require_text(value)
        _require_currency(self.base_currency)
        _require_currency(self.quote_currency)
        if (
            self.base_currency == self.quote_currency
            or type(self.direction) is not str
            or self.direction != "BASE_TO_QUOTE"
        ):
            raise PortfolioAnalyticsError("INVALID_FX_DIRECTION")
        if self.rate_unit != _FX_RATE_UNIT:
            raise PortfolioAnalyticsError("INVALID_FX_RATE_UNIT")
        _require_decimal(self.rate)
        if self.rate <= 0:
            raise PortfolioAnalyticsError("INVALID_FX_RATE")
        _require_timestamp(self.as_of_ns)
        _require_timestamp(self.valid_until_ns)
        if self.valid_until_ns < self.as_of_ns:
            raise PortfolioAnalyticsError("INVALID_FX_VALIDITY")
        _require_text(self.source_version, versioned=True)
        _require_text(self.source_generation)


@dataclass(frozen=True, slots=True)
class ExternalCapitalFlowV1:
    """Only external capital flows; contribution is positive, withdrawal negative."""

    flow_ref: str
    direction: str
    amount: Decimal
    currency: str
    effective_at_ns: int
    source_ref: str
    source_version: str
    source_generation: str
    source_cursor: str

    def __post_init__(self) -> None:
        for value in (self.flow_ref, self.source_ref, self.source_cursor, self.source_generation):
            _require_text(value)
        if type(self.direction) is not str or self.direction not in {
            "CONTRIBUTION",
            "WITHDRAWAL",
        }:
            raise PortfolioAnalyticsError("INVALID_EXTERNAL_FLOW_DIRECTION")
        _require_decimal(self.amount)
        if self.amount <= 0:
            raise PortfolioAnalyticsError("INVALID_EXTERNAL_FLOW_AMOUNT")
        _require_currency(self.currency)
        _require_timestamp(self.effective_at_ns)
        _require_text(self.source_version, versioned=True)

    @property
    def signed_amount(self) -> Decimal:
        return self.amount if self.direction == "CONTRIBUTION" else -self.amount


@dataclass(frozen=True, slots=True)
class PortfolioValuationPointV1:
    """One complete cash+spot valuation at the specified UTC calendar close."""

    valuation_date_utc: date
    as_of_ns: int
    snapshot_ref: str
    source_generation: str
    source_cursor: str
    valuation_cut_policy: str
    coverage_complete: bool
    covered_member_refs: tuple[str, ...]
    covered_asset_classes: tuple[str, ...]
    cash_balances: tuple[CashBalanceV1, ...]
    spot_positions: tuple[SpotPositionV1, ...]

    def __post_init__(self) -> None:
        _require_date(self.valuation_date_utc)
        _require_timestamp(self.as_of_ns)
        if _utc_date_for_ns(self.as_of_ns) != self.valuation_date_utc:
            raise PortfolioAnalyticsError("VALUATION_DATE_MISMATCH")
        _require_text(self.snapshot_ref)
        _require_text(self.source_generation)
        _require_text(self.source_cursor)
        if self.valuation_cut_policy != _VALUATION_CUT_POLICY:
            raise PortfolioAnalyticsError("UNSUPPORTED_VALUATION_CUT_POLICY")
        if self.as_of_ns % _NANOSECONDS_PER_DAY != _NANOSECONDS_PER_DAY - 1:
            raise PortfolioAnalyticsError("VALUATION_NOT_AT_UTC_DAY_END")
        if type(self.coverage_complete) is not bool:
            raise PortfolioAnalyticsError("INVALID_COVERAGE_FLAG")
        members = _normalized_refs(self.covered_member_refs, "INVALID_MEMBER_COVERAGE")
        object.__setattr__(self, "covered_member_refs", members)
        if type(self.covered_asset_classes) not in (tuple, list):
            raise PortfolioAnalyticsError("INVALID_ASSET_COVERAGE")
        if any(type(item) is not str or not item for item in self.covered_asset_classes):
            raise PortfolioAnalyticsError("INVALID_ASSET_COVERAGE")
        classes = tuple(sorted(self.covered_asset_classes))
        if len(set(classes)) != len(classes):
            raise PortfolioAnalyticsError("INVALID_ASSET_COVERAGE")
        object.__setattr__(self, "covered_asset_classes", classes)
        object.__setattr__(
            self,
            "cash_balances",
            _tuple_of(self.cash_balances, CashBalanceV1, "INVALID_CASH_FACTS"),
        )
        object.__setattr__(
            self,
            "spot_positions",
            _tuple_of(self.spot_positions, SpotPositionV1, "INVALID_POSITION_FACTS"),
        )


@dataclass(frozen=True, slots=True)
class ExternalFlowCoverageV1:
    """Proof that the source enumerated all external capital flows in the period."""

    source_ref: str
    source_version: str
    source_generation: str
    start_as_of_ns: int
    end_as_of_ns: int
    start_cursor: str
    end_cursor: str
    complete: bool

    def __post_init__(self) -> None:
        for value in (self.source_ref, self.source_generation, self.start_cursor, self.end_cursor):
            _require_text(value)
        _require_text(self.source_version, versioned=True)
        _require_timestamp(self.start_as_of_ns)
        _require_timestamp(self.end_as_of_ns)
        if self.end_as_of_ns <= self.start_as_of_ns or type(self.complete) is not bool:
            raise PortfolioAnalyticsError("INVALID_FLOW_COVERAGE")


@dataclass(frozen=True, slots=True)
class PortfolioAnalyticsFactsV1:
    """Trusted-source response containing one internally consistent fact cut."""

    portfolio_ref: str
    source_mode: str
    source_ref: str
    source_version: str
    source_generation: str
    snapshot_ref: str
    valuation_basis_ref: str
    membership: PortfolioMembershipV1
    beginning: PortfolioValuationPointV1
    ending: PortfolioValuationPointV1
    external_flows: tuple[ExternalCapitalFlowV1, ...]
    flow_coverage: ExternalFlowCoverageV1
    fx_observations: tuple[FxObservationV1, ...]

    def __post_init__(self) -> None:
        _require_text(self.portfolio_ref)
        _require_text(self.source_ref)
        _require_text(self.source_version, versioned=True)
        _require_text(self.source_generation)
        _require_text(self.snapshot_ref)
        _require_text(self.valuation_basis_ref)
        if type(self.source_mode) is not str or self.source_mode not in {
            "research",
            "imported",
            "paper",
            "live",
        }:
            raise PortfolioAnalyticsError("INVALID_SOURCE_MODE")
        if type(self.membership) is not PortfolioMembershipV1:
            raise PortfolioAnalyticsError("INVALID_MEMBERSHIP")
        if type(self.beginning) is not PortfolioValuationPointV1 or type(
            self.ending
        ) is not PortfolioValuationPointV1:
            raise PortfolioAnalyticsError("INVALID_VALUATION_POINTS")
        if type(self.flow_coverage) is not ExternalFlowCoverageV1:
            raise PortfolioAnalyticsError("INVALID_FLOW_COVERAGE")
        object.__setattr__(
            self,
            "external_flows",
            _tuple_of(self.external_flows, ExternalCapitalFlowV1, "INVALID_EXTERNAL_FLOWS"),
        )
        object.__setattr__(
            self,
            "fx_observations",
            _tuple_of(self.fx_observations, FxObservationV1, "INVALID_FX_FACTS"),
        )


class PortfolioAnalyticsFactsSourceV1(Protocol):
    """A trusted source adapter; it must enforce principal-to-portfolio access."""

    def read_portfolio_facts(
        self, principal_ref: str, request: PortfolioAnalyticsRequestV1
    ) -> PortfolioAnalyticsFactsV1: ...


@dataclass(frozen=True, slots=True)
class PortfolioAnalyticsReportV1:
    """Stable, JSON-safe projection. Unavailable metrics are ``None``, never zero."""

    status: str
    reason_codes: tuple[str, ...]
    model_profile_ref: str
    calculation_ref: str
    return_method: str
    flow_weight_policy: str
    reporting_currency: str
    portfolio_ref: str
    membership_version: int
    membership_sha256: str | None
    source_mode: str | None
    source_ref: str | None
    source_version: str | None
    source_generation: str | None
    facts_snapshot_ref: str | None
    beginning_date_utc: str
    beginning_as_of_ns: int | None
    beginning_snapshot_ref: str | None
    beginning_source_cursor: str | None
    ending_date_utc: str
    ending_as_of_ns: int | None
    ending_snapshot_ref: str | None
    ending_source_cursor: str | None
    flow_source_ref: str | None
    flow_source_version: str | None
    flow_start_cursor: str | None
    flow_end_cursor: str | None
    input_sha256: str | None
    beginning_nav: Decimal | None
    ending_nav: Decimal | None
    external_cashflow_net: Decimal | None
    modified_dietz_return: Decimal | None
    beginning_native_values: tuple[tuple[str, Decimal], ...]
    ending_native_values: tuple[tuple[str, Decimal], ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "beginning": {
                "as_of_ns": self.beginning_as_of_ns,
                "date_utc": self.beginning_date_utc,
                "nav": _payload_decimal(self.beginning_nav),
                "native_values": _native_values_payload(self.beginning_native_values),
                "snapshot_ref": self.beginning_snapshot_ref,
                "source_cursor": self.beginning_source_cursor,
            },
            "calculation_ref": self.calculation_ref,
            "ending": {
                "as_of_ns": self.ending_as_of_ns,
                "date_utc": self.ending_date_utc,
                "nav": _payload_decimal(self.ending_nav),
                "native_values": _native_values_payload(self.ending_native_values),
                "snapshot_ref": self.ending_snapshot_ref,
                "source_cursor": self.ending_source_cursor,
            },
            "external_cashflow_net": _payload_decimal(self.external_cashflow_net),
            "facts_snapshot_ref": self.facts_snapshot_ref,
            "flow_source": {
                "end_cursor": self.flow_end_cursor,
                "source_ref": self.flow_source_ref,
                "source_version": self.flow_source_version,
                "start_cursor": self.flow_start_cursor,
            },
            "flow_weight_policy": self.flow_weight_policy,
            "fx_policy": "IDENTITY_OR_DIRECT_BASE_TO_REPORTING_V1",
            "decimal_policy": _DECIMAL_POLICY,
            "input_sha256": self.input_sha256,
            "membership": {
                "content_sha256": self.membership_sha256,
                "version": self.membership_version,
            },
            "model_profile_ref": self.model_profile_ref,
            "portfolio_ref": self.portfolio_ref,
            "reason_codes": list(self.reason_codes),
            "reporting_currency": self.reporting_currency,
            "return_method": self.return_method,
            "return_ratio": _payload_decimal(self.modified_dietz_return),
            "source": {
                "generation": self.source_generation,
                "mode": self.source_mode,
                "source_ref": self.source_ref,
                "source_version": self.source_version,
            },
            "status": self.status,
            "version": 1,
        }


def _payload_decimal(value: Decimal | None) -> str | None:
    return None if value is None else _canonical_decimal(value)


def _native_values_payload(values: tuple[tuple[str, Decimal], ...]) -> list[dict[str, str]]:
    return [{"currency": currency, "value": _canonical_decimal(value)} for currency, value in values]


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _decimal_payload(value: Decimal) -> str:
    return _canonical_decimal(value)


def _request_payload(request: PortfolioAnalyticsRequestV1) -> dict[str, object]:
    return {
        "membership_version": request.membership_version,
        "period_end_date_utc": request.period_end_date_utc.isoformat(),
        "period_start_date_utc": request.period_start_date_utc.isoformat(),
        "portfolio_ref": request.portfolio_ref,
        "reporting_currency": request.reporting_currency,
        "version": 1,
    }


def _facts_payload(facts: PortfolioAnalyticsFactsV1) -> dict[str, object]:
    membership = facts.membership

    def point_payload(point: PortfolioValuationPointV1) -> dict[str, object]:
        return {
            "as_of_ns": point.as_of_ns,
            "cash_balances": [
                {
                    "amount": _decimal_payload(row.amount),
                    "balance_ref": row.balance_ref,
                    "currency": row.currency,
                    "member_ref": row.member_ref,
                }
                for row in sorted(point.cash_balances, key=lambda item: item.balance_ref)
            ],
            "covered_asset_classes": list(point.covered_asset_classes),
            "covered_member_refs": list(point.covered_member_refs),
            "coverage_complete": point.coverage_complete,
            "snapshot_ref": point.snapshot_ref,
            "source_cursor": point.source_cursor,
            "source_generation": point.source_generation,
            "valuation_cut_policy": point.valuation_cut_policy,
            "spot_positions": [
                {
                    "base_currency": row.base_currency,
                    "instrument_metadata_ref": row.instrument_metadata_ref,
                    "instrument_metadata_version": row.instrument_metadata_version,
                    "instrument_ref": row.instrument_ref,
                    "member_ref": row.member_ref,
                    "position_ref": row.position_ref,
                    "price_as_of_ns": row.price_as_of_ns,
                    "price_observation_ref": row.price_observation_ref,
                    "price_source_generation": row.price_source_generation,
                    "price_source_cursor": row.price_source_cursor,
                    "price_source_ref": row.price_source_ref,
                    "price_source_version": row.price_source_version,
                    "price_unit": row.price_unit,
                    "price_valid_until_ns": row.price_valid_until_ns,
                    "product_kind": row.product_kind,
                    "quantity": _decimal_payload(row.quantity),
                    "quote_currency": row.quote_currency,
                    "unit_price": _decimal_payload(row.unit_price),
                }
                for row in sorted(point.spot_positions, key=lambda item: item.position_ref)
            ],
            "valuation_date_utc": point.valuation_date_utc.isoformat(),
        }

    return {
        "beginning": point_payload(facts.beginning),
        "ending": point_payload(facts.ending),
        "external_flows": [
            {
                "amount": _decimal_payload(flow.amount),
                "currency": flow.currency,
                "direction": flow.direction,
                "effective_at_ns": flow.effective_at_ns,
                "flow_ref": flow.flow_ref,
                "source_cursor": flow.source_cursor,
                "source_ref": flow.source_ref,
                "source_version": flow.source_version,
                "source_generation": flow.source_generation,
            }
            for flow in sorted(facts.external_flows, key=lambda item: item.flow_ref)
        ],
        "facts_snapshot_ref": facts.snapshot_ref,
        "flow_coverage": {
            "complete": facts.flow_coverage.complete,
            "end_as_of_ns": facts.flow_coverage.end_as_of_ns,
            "end_cursor": facts.flow_coverage.end_cursor,
            "source_generation": facts.flow_coverage.source_generation,
            "source_ref": facts.flow_coverage.source_ref,
            "source_version": facts.flow_coverage.source_version,
            "start_as_of_ns": facts.flow_coverage.start_as_of_ns,
            "start_cursor": facts.flow_coverage.start_cursor,
        },
        "fx_observations": [
            {
                "as_of_ns": row.as_of_ns,
                "base_currency": row.base_currency,
                "direction": row.direction,
                "observation_ref": row.observation_ref,
                "quote_currency": row.quote_currency,
                "rate_unit": row.rate_unit,
                "rate": _decimal_payload(row.rate),
                "valid_until_ns": row.valid_until_ns,
                "source_cursor": row.source_cursor,
                "source_ref": row.source_ref,
                "source_version": row.source_version,
                "source_generation": row.source_generation,
            }
            for row in sorted(facts.fx_observations, key=lambda item: item.observation_ref)
        ],
        "membership": {
            "content_sha256": membership.content_sha256,
            "effective_end_date_utc_exclusive": (
                membership.effective_end_date_utc_exclusive.isoformat()
                if membership.effective_end_date_utc_exclusive is not None
                else None
            ),
            "effective_start_date_utc": membership.effective_start_date_utc.isoformat(),
            "member_refs": list(membership.member_refs),
            "membership_version": membership.membership_version,
            "portfolio_ref": membership.portfolio_ref,
            "source_ref": membership.source_ref,
            "source_version": membership.source_version,
        },
        "portfolio_ref": facts.portfolio_ref,
        "source_generation": facts.source_generation,
        "source_mode": facts.source_mode,
        "source_ref": facts.source_ref,
        "source_version": facts.source_version,
        "valuation_basis_ref": facts.valuation_basis_ref,
        "version": 1,
    }


class PortfolioAnalyticsService:
    """Call the deterministic cash+spot valuation and return entry directly.

    This package-local method is not an SDK RPC or asynchronous task API. The
    trusted source is responsible for enforcing the principal's current
    portfolio grant before returning any facts.
    """

    def __init__(
        self,
        source: PortfolioAnalyticsFactsSourceV1,
        model_profile: PortfolioAnalyticsModelProfileV1,
        *,
        allowed_source_modes: Sequence[str],
    ) -> None:
        if not callable(getattr(source, "read_portfolio_facts", None)):
            raise PortfolioAnalyticsError("INVALID_FACTS_SOURCE")
        if type(model_profile) is not PortfolioAnalyticsModelProfileV1:
            raise PortfolioAnalyticsError("INVALID_MODEL_PROFILE")
        if type(allowed_source_modes) not in (tuple, list) or not allowed_source_modes:
            raise PortfolioAnalyticsError("INVALID_SOURCE_MODES")
        modes = tuple(allowed_source_modes)
        if any(type(mode) is not str or mode not in _SUPPORTED_SOURCE_MODES for mode in modes):
            raise PortfolioAnalyticsError("INVALID_SOURCE_MODES")
        if len(set(modes)) != len(modes):
            raise PortfolioAnalyticsError("DUPLICATE_SOURCE_MODE")
        self._source = source
        self._model_profile = model_profile
        self._allowed_source_modes = frozenset(modes)

    def analyze_snapshot_v1(
        self, request: PortfolioAnalyticsRequestV1, *, principal_ref: str
    ) -> PortfolioAnalyticsReportV1:
        """Read one trusted complete fact cut and return valuation/return metrics."""

        if type(request) is not PortfolioAnalyticsRequestV1:
            raise PortfolioAnalyticsError("INVALID_REQUEST")
        _require_text(principal_ref)
        period_days = (request.period_end_date_utc - request.period_start_date_utc).days
        if period_days > self._model_profile.max_period_days:
            return self._unavailable(request, ("PERIOD_TOO_LONG",))
        try:
            facts = self._source.read_portfolio_facts(principal_ref, request)
        except PortfolioAnalyticsSourceUnavailableError:
            return self._unavailable(request, ("SOURCE_FACTS_UNAVAILABLE",))
        if type(facts) is not PortfolioAnalyticsFactsV1:
            raise PortfolioAnalyticsError("INVALID_SOURCE_RESPONSE")

        if _fact_row_count(facts) > _MAX_FACT_ROWS:
            return self._unavailable(request, ("INPUT_LIMIT_EXCEEDED",), facts)

        try:
            facts_bytes = _canonical_json(
                {
                    "facts": _facts_payload(facts),
                    "model_profile": self._profile_payload(),
                    "principal_ref": principal_ref,
                    "request": _request_payload(request),
                }
            )
        except (TypeError, ValueError, OverflowError) as exc:
            raise PortfolioAnalyticsError("INVALID_SOURCE_RESPONSE") from exc
        if len(facts_bytes) > self._model_profile.max_input_bytes:
            digest = hashlib.sha256(facts_bytes).hexdigest()
            return self._unavailable(request, ("INPUT_LIMIT_EXCEEDED",), facts, digest)
        input_sha256 = hashlib.sha256(facts_bytes).hexdigest()

        reasons = self._validate_facts(request, facts)
        if reasons:
            return self._unavailable(request, reasons, facts, input_sha256)

        try:
            with localcontext(
                Context(
                    prec=_DECIMAL_PRECISION,
                    rounding=ROUND_HALF_EVEN,
                    Emin=_DECIMAL_EMIN,
                    Emax=_DECIMAL_EMAX,
                    capitals=1,
                    clamp=0,
                    flags=[],
                    traps=[InvalidOperation, DivisionByZero, Overflow],
                )
            ):
                beginning_native, beginning_nav = self._value_point(
                    facts.beginning, request.reporting_currency, facts.fx_observations
                )
                ending_native, ending_nav = self._value_point(
                    facts.ending, request.reporting_currency, facts.fx_observations
                )
                flows = self._flow_values(
                    request, facts.external_flows, facts.fx_observations
                )
                external_total = sum((flow[0] for flow in flows), Decimal(0))
                weighted_total = sum((flow[0] * flow[1] for flow in flows), Decimal(0))
                denominator = beginning_nav + weighted_total
                if denominator <= 0:
                    raise _UnavailableError("NON_POSITIVE_RETURN_DENOMINATOR")
                return_value = (ending_nav - beginning_nav - external_total) / denominator
                return PortfolioAnalyticsReportV1(
                    status="AVAILABLE",
                    reason_codes=(),
                    model_profile_ref=self._model_profile.model_profile_ref,
                    calculation_ref=_CALCULATION_REF,
                    return_method=_RETURN_METHOD,
                    flow_weight_policy=_FLOW_WEIGHT_POLICY,
                    reporting_currency=request.reporting_currency,
                    portfolio_ref=request.portfolio_ref,
                    membership_version=request.membership_version,
                    membership_sha256=facts.membership.content_sha256,
                    source_mode=facts.source_mode,
                    source_ref=facts.source_ref,
                    source_version=facts.source_version,
                    source_generation=facts.source_generation,
                    facts_snapshot_ref=facts.snapshot_ref,
                    beginning_date_utc=request.period_start_date_utc.isoformat(),
                    beginning_as_of_ns=facts.beginning.as_of_ns,
                    beginning_snapshot_ref=facts.beginning.snapshot_ref,
                    beginning_source_cursor=facts.beginning.source_cursor,
                    ending_date_utc=request.period_end_date_utc.isoformat(),
                    ending_as_of_ns=facts.ending.as_of_ns,
                    ending_snapshot_ref=facts.ending.snapshot_ref,
                    ending_source_cursor=facts.ending.source_cursor,
                    flow_source_ref=facts.flow_coverage.source_ref,
                    flow_source_version=facts.flow_coverage.source_version,
                    flow_start_cursor=facts.flow_coverage.start_cursor,
                    flow_end_cursor=facts.flow_coverage.end_cursor,
                    input_sha256=input_sha256,
                    beginning_nav=_quantized_decimal(beginning_nav),
                    ending_nav=_quantized_decimal(ending_nav),
                    external_cashflow_net=_quantized_decimal(external_total),
                    modified_dietz_return=_quantized_decimal(return_value),
                    beginning_native_values=tuple(
                        (currency, _quantized_decimal(value))
                        for currency, value in sorted(beginning_native.items())
                    ),
                    ending_native_values=tuple(
                        (currency, _quantized_decimal(value))
                        for currency, value in sorted(ending_native.items())
                    ),
                )
        except _UnavailableError as exc:
            return self._unavailable(request, (exc.code,), facts, input_sha256)
        except (DecimalException, OverflowError, ZeroDivisionError) as exc:
            raise PortfolioAnalyticsError("CALCULATION_OUT_OF_RANGE") from exc

    def _profile_payload(self) -> dict[str, object]:
        return {
            "max_fx_age_ns": self._model_profile.max_fx_age_ns,
            "max_input_bytes": self._model_profile.max_input_bytes,
            "max_mark_age_ns": self._model_profile.max_mark_age_ns,
            "max_period_days": self._model_profile.max_period_days,
            "model_profile_ref": self._model_profile.model_profile_ref,
            "calculation_ref": _CALCULATION_REF,
            "return_method": _RETURN_METHOD,
            "flow_weight_policy": _FLOW_WEIGHT_POLICY,
            "valuation_cut_policy": _VALUATION_CUT_POLICY,
            "valuation_basis_ref": _SUPPORTED_VALUATION_BASIS,
            "spot_price_unit": _SPOT_PRICE_UNIT,
            "fx_rate_unit": _FX_RATE_UNIT,
            "fx_pair_policy": "DIRECT_SOURCE_TO_REPORTING_ONLY_V1",
            "input_digest_policy": "SORTED_COMPACT_ASCII_JSON_CANONICAL_DECIMAL_V1",
            "decimal_policy": _DECIMAL_POLICY,
            "output_precision": _DECIMAL_PRECISION,
            "output_rounding": "ROUND_HALF_EVEN",
            "output_scale": _OUTPUT_SCALE,
            "max_fact_rows": _MAX_FACT_ROWS,
            "max_decimal_digits": _MAX_DECIMAL_DIGITS,
            "max_decimal_exponent": _MAX_DECIMAL_EXPONENT,
            "source_modes": sorted(self._allowed_source_modes),
            "version": 1,
        }

    def _validate_facts(
        self, request: PortfolioAnalyticsRequestV1, facts: PortfolioAnalyticsFactsV1
    ) -> tuple[str, ...]:
        reasons: set[str] = set()
        membership = facts.membership
        expected_members = membership.member_refs
        for value, expected in (
            (facts.portfolio_ref, request.portfolio_ref),
            (membership.portfolio_ref, request.portfolio_ref),
        ):
            if value != expected:
                reasons.add("PORTFOLIO_REF_MISMATCH")
        if membership.membership_version != request.membership_version:
            reasons.add("MEMBERSHIP_VERSION_MISMATCH")
        if request.period_start_date_utc < membership.effective_start_date_utc:
            reasons.add("MEMBERSHIP_NOT_VALID_FOR_PERIOD")
        if (
            membership.effective_end_date_utc_exclusive is not None
            and request.period_end_date_utc >= membership.effective_end_date_utc_exclusive
        ):
            reasons.add("MEMBERSHIP_NOT_VALID_FOR_PERIOD")
        if facts.source_mode not in self._allowed_source_modes:
            reasons.add("SOURCE_MODE_NOT_ALLOWED")
        if facts.source_mode == "live":
            reasons.add("LIVE_SOURCE_UNSUPPORTED_IN_V1")
        if facts.valuation_basis_ref != _SUPPORTED_VALUATION_BASIS:
            reasons.add("UNSUPPORTED_VALUATION_BASIS")

        for point, expected_date in (
            (facts.beginning, request.period_start_date_utc),
            (facts.ending, request.period_end_date_utc),
        ):
            if point.valuation_date_utc != expected_date:
                reasons.add("VALUATION_DATE_MISMATCH")
            if point.source_generation != facts.source_generation:
                reasons.add("SOURCE_GENERATION_MISMATCH")
            if not point.coverage_complete:
                reasons.add("VALUATION_COVERAGE_INCOMPLETE")
            if point.covered_member_refs != expected_members:
                reasons.add("MEMBERSHIP_COVERAGE_MISMATCH")
            if set(point.covered_asset_classes) != _SUPPORTED_ASSET_CLASSES:
                reasons.add("UNSUPPORTED_OR_INCOMPLETE_ASSET_COVERAGE")
            member_set = set(expected_members)
            for row in point.cash_balances:
                if row.member_ref not in member_set:
                    reasons.add("UNKNOWN_MEMBER_FACT")
                if row.amount < 0:
                    reasons.add("NEGATIVE_CASH_UNSUPPORTED")
            for row in point.spot_positions:
                if row.member_ref not in member_set:
                    reasons.add("UNKNOWN_MEMBER_FACT")
                if row.product_kind != "SPOT":
                    reasons.add("UNSUPPORTED_PRODUCT")
                if row.quantity <= 0:
                    reasons.add(
                        "SHORT_SPOT_UNSUPPORTED" if row.quantity < 0 else "NON_POSITIVE_SPOT_QUANTITY"
                    )
                if row.price_as_of_ns > point.as_of_ns:
                    reasons.add("FUTURE_MARK")
                else:
                    if point.as_of_ns > row.price_valid_until_ns:
                        reasons.add("MARK_EXPIRED_AT_CUT")
                    if point.as_of_ns - row.price_as_of_ns > self._model_profile.max_mark_age_ns:
                        reasons.add("STALE_MARK")
        if facts.beginning.as_of_ns >= facts.ending.as_of_ns:
            reasons.add("INVALID_VALUATION_INTERVAL")

        flow_coverage = facts.flow_coverage
        if not flow_coverage.complete:
            reasons.add("EXTERNAL_FLOW_COVERAGE_INCOMPLETE")
        if (
            flow_coverage.start_as_of_ns != facts.beginning.as_of_ns
            or flow_coverage.end_as_of_ns != facts.ending.as_of_ns
            or flow_coverage.source_generation != facts.source_generation
        ):
            reasons.add("EXTERNAL_FLOW_CUT_MISMATCH")
        if len({flow.flow_ref for flow in facts.external_flows}) != len(facts.external_flows):
            reasons.add("DUPLICATE_EXTERNAL_FLOW")
        for flow in facts.external_flows:
            if (
                flow.source_ref != flow_coverage.source_ref
                or flow.source_version != flow_coverage.source_version
                or flow.source_generation != flow_coverage.source_generation
            ):
                reasons.add("EXTERNAL_FLOW_SOURCE_MISMATCH")
            if not facts.beginning.as_of_ns < flow.effective_at_ns <= facts.ending.as_of_ns:
                reasons.add("EXTERNAL_FLOW_OUTSIDE_PERIOD")
            flow_date = _utc_date_for_ns(flow.effective_at_ns)
            if not request.period_start_date_utc < flow_date <= request.period_end_date_utc:
                reasons.add("EXTERNAL_FLOW_DATE_OUTSIDE_PERIOD")

        for point in (facts.beginning, facts.ending):
            balance_refs = [row.balance_ref for row in point.cash_balances]
            position_refs = [row.position_ref for row in point.spot_positions]
            position_assets = [
                (row.member_ref, row.instrument_ref)
                for row in point.spot_positions
            ]
            if len(set(balance_refs)) != len(balance_refs):
                reasons.add("DUPLICATE_CASH_FACT_ID")
            if len(set(position_refs)) != len(position_refs):
                reasons.add("DUPLICATE_POSITION_FACT_ID")
            if len(set(position_assets)) != len(position_assets):
                reasons.add("DUPLICATE_SPOT_ASSET_FACT")
        fx_ids = [row.observation_ref for row in facts.fx_observations]
        if len(set(fx_ids)) != len(fx_ids):
            reasons.add("DUPLICATE_FX_OBSERVATION")
        return tuple(sorted(reasons))

    def _value_point(
        self,
        point: PortfolioValuationPointV1,
        reporting_currency: str,
        fx_observations: tuple[FxObservationV1, ...],
    ) -> tuple[dict[str, Decimal], Decimal]:
        native: dict[str, Decimal] = {}
        for row in point.cash_balances:
            native[row.currency] = native.get(row.currency, Decimal(0)) + row.amount
        for row in point.spot_positions:
            if row.product_kind != "SPOT":
                raise _UnavailableError("UNSUPPORTED_PRODUCT")
            if row.quantity <= 0:
                raise _UnavailableError(
                    "SHORT_SPOT_UNSUPPORTED" if row.quantity < 0 else "NON_POSITIVE_SPOT_QUANTITY"
                )
            native[row.quote_currency] = native.get(row.quote_currency, Decimal(0)) + (
                row.quantity * row.unit_price
            )
        nav = Decimal(0)
        for currency, amount in native.items():
            if amount == 0:
                continue
            rate = self._fx_rate(
                currency, reporting_currency, point.as_of_ns, fx_observations
            )
            nav += amount * rate
        return native, nav

    def _flow_values(
        self,
        request: PortfolioAnalyticsRequestV1,
        flows: tuple[ExternalCapitalFlowV1, ...],
        fx_observations: tuple[FxObservationV1, ...],
    ) -> tuple[tuple[Decimal, Decimal], ...]:
        total_days = (request.period_end_date_utc - request.period_start_date_utc).days
        if total_days <= 0:
            raise _UnavailableError("INVALID_PERIOD")
        values: list[tuple[Decimal, Decimal]] = []
        for flow in flows:
            rate = self._fx_rate(
                flow.currency, request.reporting_currency, flow.effective_at_ns, fx_observations
            )
            flow_date = _utc_date_for_ns(flow.effective_at_ns)
            elapsed_days = (flow_date - request.period_start_date_utc).days
            weight = Decimal(total_days - elapsed_days) / Decimal(total_days)
            values.append((flow.signed_amount * rate, weight))
        return tuple(values)

    def _fx_rate(
        self,
        source_currency: str,
        reporting_currency: str,
        as_of_ns: int,
        observations: tuple[FxObservationV1, ...],
    ) -> Decimal:
        if source_currency == reporting_currency:
            return Decimal(1)
        eligible: list[FxObservationV1] = []
        saw_direct = False
        saw_inverse = False
        for row in observations:
            direct = row.base_currency == source_currency and row.quote_currency == reporting_currency
            inverse = row.base_currency == reporting_currency and row.quote_currency == source_currency
            if direct:
                saw_direct = True
                if row.as_of_ns <= as_of_ns:
                    eligible.append(row)
            elif inverse:
                saw_inverse = True
        if not eligible:
            if saw_direct:
                raise _UnavailableError("FX_RATE_AFTER_CUT")
            if saw_inverse:
                raise _UnavailableError("FX_PAIR_DIRECTION_UNSUPPORTED")
            raise _UnavailableError("FX_RATE_MISSING")
        newest_ns = max(row.as_of_ns for row in eligible)
        newest = [row for row in eligible if row.as_of_ns == newest_ns]
        if len(newest) != 1:
            raise _UnavailableError("FX_RATE_AMBIGUOUS")
        row = newest[0]
        if as_of_ns - row.as_of_ns > self._model_profile.max_fx_age_ns:
            raise _UnavailableError("FX_RATE_STALE")
        if as_of_ns > row.valid_until_ns:
            raise _UnavailableError("FX_RATE_EXPIRED_AT_CUT")
        return row.rate

    def _unavailable(
        self,
        request: PortfolioAnalyticsRequestV1,
        reason_codes: Sequence[str],
        facts: PortfolioAnalyticsFactsV1 | None = None,
        input_sha256: str | None = None,
    ) -> PortfolioAnalyticsReportV1:
        membership_sha = facts.membership.content_sha256 if facts is not None else None
        return PortfolioAnalyticsReportV1(
            status="UNAVAILABLE",
            reason_codes=tuple(sorted(set(reason_codes))),
            model_profile_ref=self._model_profile.model_profile_ref,
            calculation_ref=_CALCULATION_REF,
            return_method=_RETURN_METHOD,
            flow_weight_policy=_FLOW_WEIGHT_POLICY,
            reporting_currency=request.reporting_currency,
            portfolio_ref=request.portfolio_ref,
            membership_version=request.membership_version,
            membership_sha256=membership_sha,
            source_mode=facts.source_mode if facts is not None else None,
            source_ref=facts.source_ref if facts is not None else None,
            source_version=facts.source_version if facts is not None else None,
            source_generation=facts.source_generation if facts is not None else None,
            facts_snapshot_ref=facts.snapshot_ref if facts is not None else None,
            beginning_date_utc=request.period_start_date_utc.isoformat(),
            beginning_as_of_ns=facts.beginning.as_of_ns if facts is not None else None,
            beginning_snapshot_ref=facts.beginning.snapshot_ref if facts is not None else None,
            beginning_source_cursor=facts.beginning.source_cursor if facts is not None else None,
            ending_date_utc=request.period_end_date_utc.isoformat(),
            ending_as_of_ns=facts.ending.as_of_ns if facts is not None else None,
            ending_snapshot_ref=facts.ending.snapshot_ref if facts is not None else None,
            ending_source_cursor=facts.ending.source_cursor if facts is not None else None,
            flow_source_ref=facts.flow_coverage.source_ref if facts is not None else None,
            flow_source_version=facts.flow_coverage.source_version if facts is not None else None,
            flow_start_cursor=facts.flow_coverage.start_cursor if facts is not None else None,
            flow_end_cursor=facts.flow_coverage.end_cursor if facts is not None else None,
            input_sha256=input_sha256,
            beginning_nav=None,
            ending_nav=None,
            external_cashflow_net=None,
            modified_dietz_return=None,
            beginning_native_values=(),
            ending_native_values=(),
        )


class _UnavailableError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fact_row_count(facts: PortfolioAnalyticsFactsV1) -> int:
    return (
        len(facts.membership.member_refs)
        + len(facts.beginning.covered_member_refs)
        + len(facts.ending.covered_member_refs)
        + len(facts.beginning.cash_balances)
        + len(facts.beginning.spot_positions)
        + len(facts.ending.cash_balances)
        + len(facts.ending.spot_positions)
        + len(facts.external_flows)
        + len(facts.fx_observations)
    )
