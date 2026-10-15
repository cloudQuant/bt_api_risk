"""Immutable instrument-level admission facts for managed execution.

The durable account gate in :mod:`bt_api_risk.core.admission` owns account
capacity and dispatch latches.  It deliberately does not know an exchange's
quantity lattice, contract multiplier, price tick, fees, or a bounded price
envelope.  This module supplies that missing deterministic calculation without
importing an exchange, an execution package, or a provider client.

Only a reviewed composition root may create :class:`InstrumentRiskMetadata`.
An order must repeat the exact digest of that trusted metadata.  The resulting
gross worst-case exposure is then folded into ``RiskIntent.payload_fingerprint``
so a permit cannot be claimed after its instrument facts have changed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation, localcontext
from fractions import Fraction
from typing import Any, Optional

from .admission import (
    AccountScope,
    IntentAction,
    RiskDeniedError,
    RiskIntent,
    StrategyAllocationSnapshot,
)

INSTRUMENT_METADATA_DIGEST_TAG = "instrument_metadata_digest"
"""The immutable ``OrderIntent.tags`` key carrying the reviewed metadata digest."""

_SCHEMA = "bt_api_risk.instrument-admission.v1"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_INSTRUMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NOTIONAL_UNIT = re.compile(r"^[A-Z][A-Z0-9]{2,11}$")
_BPS_DENOMINATOR = Decimal("10000")


def _identifier(value: object, name: str, *, instrument: bool = False) -> str:
    pattern = _INSTRUMENT if instrument else _IDENTIFIER
    if not isinstance(value, str) or value != value.strip() or not pattern.fullmatch(value):
        raise ValueError("invalid " + name)
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("invalid " + name)
    return value


def _decimal(
    value: object,
    name: str,
    *,
    positive: bool = False,
    nonnegative: bool = False,
) -> Decimal:
    if isinstance(value, (bool, float)):
        raise ValueError("invalid " + name)
    try:
        decimal_value = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as error:
        raise ValueError("invalid " + name) from error
    if (
        not decimal_value.is_finite()
        or (positive and decimal_value <= 0)
        or (nonnegative and decimal_value < 0)
    ):
        raise ValueError("invalid " + name)
    _precision(decimal_value)
    return decimal_value


def _decimal_text(value: Decimal) -> str:
    return format(value, "f")


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _coefficient_and_exponent(value: Decimal) -> tuple[int, int]:
    """Return an exact positive Decimal as integer coefficient and base-10 exponent."""

    sign, digits, exponent = value.as_tuple()
    coefficient = 0
    for digit in digits:
        coefficient = coefficient * 10 + digit
    if sign:
        coefficient = -coefficient
    return coefficient, exponent


def _is_on_lattice(value: Decimal, step: Decimal) -> bool:
    """Check ``value / step`` exactly without Decimal context rounding."""

    _precision(value, step)
    value_coefficient, value_exponent = _coefficient_and_exponent(value)
    step_coefficient, step_exponent = _coefficient_and_exponent(step)
    exponent = min(value_exponent, step_exponent)
    value_integer = value_coefficient * 10 ** (value_exponent - exponent)
    step_integer = step_coefficient * 10 ** (step_exponent - exponent)
    return value_integer % step_integer == 0


def _precision(*values: Decimal) -> int:
    """Include exponent gaps so adding a small fee cannot silently lose it."""

    precision = max(
        50,
        sum(len(value.as_tuple().digits) + abs(value.as_tuple().exponent) for value in values) + 32,
    )
    if precision > 10000:
        raise ValueError("instrument decimal scale exceeds the supported arithmetic bound")
    return precision


def _ceil_to_lattice(value: Decimal, step: Decimal) -> Decimal:
    """Round a positive value up to the next exact permitted price tick."""

    precision = _precision(value, step)
    value_coefficient, value_exponent = _coefficient_and_exponent(value)
    step_coefficient, step_exponent = _coefficient_and_exponent(step)
    exponent = min(value_exponent, step_exponent)
    value_integer = value_coefficient * 10 ** (value_exponent - exponent)
    step_integer = step_coefficient * 10 ** (step_exponent - exponent)
    quotient = (value_integer + step_integer - 1) // step_integer
    with localcontext() as context:
        context.prec = max(
            precision,
            len(str(quotient)) + len(step.as_tuple().digits) + 8,
        )
        return Decimal(quotient) * step


@dataclass(frozen=True)
class InstrumentRiskMetadata:
    """Reviewed, time-bounded instrument facts used before a provider write.

    ``max_gross_notional`` is intentionally fee-inclusive and is denominated
    in ``valuation_unit`` when one is supplied.  It limits the calculation
    returned by :class:`InstrumentRiskAssessment`, which includes a
    conservative adverse price envelope and estimated taker/fixed fees.
    ``fixed_fee_unit`` names the denomination of ``fixed_fee``.  Historical
    same-currency records may omit it; cross-currency records with a nonzero
    fixed fee must state either the quote or valuation unit explicitly.
    The class is provider-neutral; a deployment must obtain and review these
    values through its own trusted metadata path before it can construct one.
    """

    instrument: str
    metadata_version: str
    as_of_ns: int
    expires_at_ns: int
    tick_size: Decimal
    quantity_step: Decimal
    contract_multiplier: Decimal
    max_gross_notional: Decimal
    min_quantity: Optional[  # noqa: UP045 -- package supports Python 3.9.
        Decimal
    ] = None
    max_quantity: Optional[  # noqa: UP045 -- package supports Python 3.9.
        Decimal
    ] = None
    taker_fee_bps: Decimal = Decimal("0")
    fixed_fee: Decimal = Decimal("0")
    max_slippage_bps: Decimal = Decimal("0")
    quantity_unit: Optional[str] = None  # noqa: UP045 -- package supports Python 3.9.
    valuation_unit: Optional[str] = None  # noqa: UP045 -- package supports Python 3.9.
    quote_currency: Optional[str] = None  # noqa: UP045 -- package supports Python 3.9.
    fx_source_ref: Optional[str] = None  # noqa: UP045 -- package supports Python 3.9.
    fixed_fee_unit: Optional[str] = None  # noqa: UP045 -- package supports Python 3.9.

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "instrument",
            _identifier(self.instrument, "instrument", instrument=True),
        )
        object.__setattr__(
            self,
            "metadata_version",
            _identifier(self.metadata_version, "metadata_version"),
        )
        if type(self.as_of_ns) is not int or self.as_of_ns <= 0:
            raise ValueError("invalid as_of_ns")
        if type(self.expires_at_ns) is not int or self.expires_at_ns <= self.as_of_ns:
            raise ValueError("invalid expires_at_ns")
        object.__setattr__(self, "tick_size", _decimal(self.tick_size, "tick_size", positive=True))
        object.__setattr__(
            self,
            "quantity_step",
            _decimal(self.quantity_step, "quantity_step", positive=True),
        )
        object.__setattr__(
            self,
            "contract_multiplier",
            _decimal(self.contract_multiplier, "contract_multiplier", positive=True),
        )
        object.__setattr__(
            self,
            "max_gross_notional",
            _decimal(self.max_gross_notional, "max_gross_notional", positive=True),
        )
        for name in ("taker_fee_bps", "fixed_fee", "max_slippage_bps"):
            object.__setattr__(
                self,
                name,
                _decimal(getattr(self, name), name, nonnegative=True),
            )
        for name in ("min_quantity", "max_quantity"):
            value = getattr(self, name)
            if value is not None:
                normalized = _decimal(value, name, positive=True)
                if not _is_on_lattice(normalized, self.quantity_step):
                    raise ValueError(name + " must be on quantity_step lattice")
                object.__setattr__(self, name, normalized)
        if self.quantity_unit is not None:
            object.__setattr__(
                self, "quantity_unit", _identifier(self.quantity_unit, "quantity_unit")
            )
        if self.valuation_unit is not None and (
            not isinstance(self.valuation_unit, str)
            or not _NOTIONAL_UNIT.fullmatch(self.valuation_unit)
        ):
            raise ValueError("valuation_unit must be a canonical uppercase unit code")
        if self.quote_currency is not None and (
            not isinstance(self.quote_currency, str)
            or not _NOTIONAL_UNIT.fullmatch(self.quote_currency)
        ):
            raise ValueError("quote_currency must be a canonical uppercase unit code")
        if self.quote_currency is not None and self.valuation_unit is None:
            raise ValueError("quote_currency requires a valuation_unit")
        cross_currency = (
            self.quote_currency is not None
            and self.valuation_unit is not None
            and self.quote_currency != self.valuation_unit
        )
        if self.fx_source_ref is not None:
            object.__setattr__(
                self,
                "fx_source_ref",
                _identifier(self.fx_source_ref, "fx_source_ref"),
            )
        if cross_currency != (self.fx_source_ref is not None):
            raise ValueError("cross-currency metadata requires exactly one fx_source_ref")
        if self.fixed_fee_unit is not None:
            if (
                not isinstance(self.fixed_fee_unit, str)
                or not _NOTIONAL_UNIT.fullmatch(self.fixed_fee_unit)
            ):
                raise ValueError("fixed_fee_unit must be a canonical uppercase unit code")
            allowed_fee_units = {self.valuation_unit}
            if self.quote_currency is not None:
                allowed_fee_units.add(self.quote_currency)
            if self.fixed_fee_unit not in allowed_fee_units:
                raise ValueError("fixed_fee_unit must match the quote or valuation unit")
        if cross_currency and self.fixed_fee > 0 and self.fixed_fee_unit is None:
            raise ValueError("cross-currency fixed_fee requires an explicit fixed_fee_unit")
        if (
            self.min_quantity is not None
            and self.max_quantity is not None
            and self.min_quantity > self.max_quantity
        ):
            raise ValueError("min_quantity cannot exceed max_quantity")

    def to_payload(self) -> dict[str, object]:
        """Return the full non-secret canonical content that the digest binds."""

        payload: dict[str, object] = {
            "as_of_ns": self.as_of_ns,
            "contract_multiplier": _decimal_text(self.contract_multiplier),
            "expires_at_ns": self.expires_at_ns,
            "fixed_fee": _decimal_text(self.fixed_fee),
            "instrument": self.instrument,
            "max_gross_notional": _decimal_text(self.max_gross_notional),
            "max_quantity": None if self.max_quantity is None else _decimal_text(self.max_quantity),
            "max_slippage_bps": _decimal_text(self.max_slippage_bps),
            "metadata_version": self.metadata_version,
            "min_quantity": None if self.min_quantity is None else _decimal_text(self.min_quantity),
            "quantity_step": _decimal_text(self.quantity_step),
            "schema": _SCHEMA,
            "taker_fee_bps": _decimal_text(self.taker_fee_bps),
            "tick_size": _decimal_text(self.tick_size),
        }
        if self.quantity_unit is not None:
            payload["quantity_unit"] = self.quantity_unit
        if self.valuation_unit is not None:
            payload["valuation_unit"] = self.valuation_unit
        if self.quote_currency is not None:
            payload["quote_currency"] = self.quote_currency
        if self.fx_source_ref is not None:
            payload["fx_source_ref"] = self.fx_source_ref
        if self.fixed_fee_unit is not None:
            payload["fixed_fee_unit"] = self.fixed_fee_unit
        return payload

    @property
    def digest(self) -> str:
        """Return the exact trusted-metadata digest required in each intent."""

        return _sha256(_canonical_json(self.to_payload()))


@dataclass(frozen=True)
class InstrumentRiskFxRate:
    """One immutable, source-bound quote-to-valuation conversion fact.

    ``rate`` is the amount of ``valuation_unit`` represented by one unit of
    ``quote_currency``.  Source provenance is part of the canonical payload so
    changing the provider record or revision changes the admission identity.
    """

    instrument: str
    quote_currency: str
    valuation_unit: str
    rate: Decimal
    observed_at_ns: int
    valid_until_ns: int
    source_ref: str
    source_revision: str
    source_record_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "instrument",
            _identifier(self.instrument, "instrument", instrument=True),
        )
        for name in ("quote_currency", "valuation_unit"):
            value = getattr(self, name)
            if type(value) is not str or not _NOTIONAL_UNIT.fullmatch(value):
                raise ValueError("invalid " + name)
        if self.quote_currency == self.valuation_unit:
            raise ValueError("FX facts are only valid for cross-currency pairs")
        object.__setattr__(self, "rate", _decimal(self.rate, "rate", positive=True))
        if type(self.observed_at_ns) is not int or self.observed_at_ns <= 0:
            raise ValueError("invalid observed_at_ns")
        if type(self.valid_until_ns) is not int or self.valid_until_ns <= self.observed_at_ns:
            raise ValueError("invalid valid_until_ns")
        object.__setattr__(self, "source_ref", _identifier(self.source_ref, "source_ref"))
        object.__setattr__(
            self,
            "source_revision",
            _identifier(self.source_revision, "source_revision"),
        )
        _digest(self.source_record_sha256, "source_record_sha256")

    @property
    def fx_pair(self) -> str:
        """Return the canonical ``QUOTE/VALUATION`` pair."""

        return self.quote_currency + "/" + self.valuation_unit

    def to_payload(self) -> dict[str, object]:
        """Return all immutable FX facts in their canonical wire form."""

        return {
            "fx_pair": self.fx_pair,
            "instrument": self.instrument,
            "observed_at_ns": self.observed_at_ns,
            "quote_currency": self.quote_currency,
            "rate": _decimal_text(self.rate),
            "schema": "bt_api_risk.instrument-fx-rate.v1",
            "source_record_sha256": self.source_record_sha256,
            "source_ref": self.source_ref,
            "source_revision": self.source_revision,
            "valid_until_ns": self.valid_until_ns,
            "valuation_unit": self.valuation_unit,
        }

    @property
    def digest(self) -> str:
        """Return the stable digest of the exact source-bound FX fact."""

        return _sha256(_canonical_json(self.to_payload()))


@dataclass(frozen=True)
class InstrumentRiskOrder:
    """The instrument-relevant subset of one immutable execution request."""

    instrument: str
    quantity: Decimal
    limit_price: Optional[Decimal]  # noqa: UP045 -- package supports Python 3.9.
    metadata_version: str
    metadata_digest: str
    fx_rate: Optional[InstrumentRiskFxRate] = None  # noqa: UP045 -- package supports Python 3.9.

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "instrument",
            _identifier(self.instrument, "instrument", instrument=True),
        )
        object.__setattr__(self, "quantity", _decimal(self.quantity, "quantity", positive=True))
        if self.limit_price is not None:
            object.__setattr__(
                self,
                "limit_price",
                _decimal(self.limit_price, "limit_price", positive=True),
            )
        object.__setattr__(
            self,
            "metadata_version",
            _identifier(self.metadata_version, "metadata_version"),
        )
        object.__setattr__(
            self, "metadata_digest", _digest(self.metadata_digest, "metadata_digest")
        )
        if self.fx_rate is not None and (
            type(self.fx_rate) is not InstrumentRiskFxRate
            or self.fx_rate.instrument != self.instrument
        ):
            raise ValueError("FX facts must be an exact typed fact for the order instrument")


@dataclass(frozen=True)
class InstrumentRiskAssessment:
    """One deterministic, fee-inclusive bound accepted by a trusted profile.

    For cross-currency assessments, ``quoted_notional`` and
    ``worst_case_notional`` remain in the quote currency so price and tick
    checks stay in the execution denomination. ``worst_case_fee`` and
    ``gross_notional`` are in the valuation unit after applying the bound FX
    fact. Same-currency assessments retain the historical unit and arithmetic.
    """

    metadata: InstrumentRiskMetadata
    order: InstrumentRiskOrder
    worst_case_price: Decimal
    quoted_notional: Decimal
    worst_case_notional: Decimal
    worst_case_fee: Decimal
    gross_notional: Decimal
    fx_rate: Optional[InstrumentRiskFxRate] = None  # noqa: UP045 -- package supports Python 3.9.

    def __post_init__(self) -> None:
        if self.order.instrument != self.metadata.instrument:
            raise ValueError("assessment instrument does not match metadata")
        for name in (
            "worst_case_price",
            "quoted_notional",
            "worst_case_notional",
            "gross_notional",
        ):
            object.__setattr__(self, name, _decimal(getattr(self, name), name, positive=True))
        object.__setattr__(
            self,
            "worst_case_fee",
            _decimal(self.worst_case_fee, "worst_case_fee", nonnegative=True),
        )
        quote_currency = self.metadata.quote_currency or self.metadata.valuation_unit
        cross_currency = (
            quote_currency is not None
            and self.metadata.valuation_unit is not None
            and quote_currency != self.metadata.valuation_unit
        )
        if cross_currency:
            if type(self.fx_rate) is not InstrumentRiskFxRate:
                raise ValueError("cross-currency assessment requires typed FX facts")
            _validate_fx_binding(self.metadata, self.order, self.fx_rate)
        elif self.fx_rate is not None:
            raise ValueError("same-currency assessment cannot carry FX facts")
        conversion_rate = Decimal("1") if self.fx_rate is None else self.fx_rate.rate
        if Fraction(self.gross_notional) != (
            Fraction(self.worst_case_notional) * Fraction(conversion_rate)
            + Fraction(self.worst_case_fee)
        ):
            raise ValueError("gross_notional must equal worst_case_notional plus worst_case_fee")

    def bound_payload_fingerprint(self, intent_fingerprint: str) -> str:
        """Bind trusted metadata and all risk amounts to an execution intent hash."""

        intent_fingerprint = _digest(intent_fingerprint, "intent_fingerprint")
        payload: dict[str, object] = {
            "gross_notional": _decimal_text(self.gross_notional),
            "intent_fingerprint": intent_fingerprint,
            "metadata_digest": self.metadata.digest,
            "quoted_notional": _decimal_text(self.quoted_notional),
            "schema": _SCHEMA,
            "worst_case_fee": _decimal_text(self.worst_case_fee),
            "worst_case_notional": _decimal_text(self.worst_case_notional),
            "worst_case_price": _decimal_text(self.worst_case_price),
        }
        # Omitting this key entirely preserves legacy same-currency fingerprints.
        if self.fx_rate is not None:
            payload["fx_rate"] = self.fx_rate.to_payload()
            payload["fx_rate_sha256"] = self.fx_rate.digest
        return _sha256(_canonical_json(payload))

    @property
    def fixed_fee_in_valuation_unit(self) -> Decimal:
        """Return the assessed fixed fee converted to the account unit."""

        fixed_fee = self.metadata.fixed_fee
        if (
            fixed_fee > 0
            and self.fx_rate is not None
            and self.metadata.fixed_fee_unit == self.fx_rate.quote_currency
        ):
            with localcontext() as context:
                context.prec = _precision(fixed_fee, self.fx_rate.rate)
                return fixed_fee * self.fx_rate.rate
        return fixed_fee


def _fx_binding_error(
    metadata: InstrumentRiskMetadata,
    order: InstrumentRiskOrder,
    fx_rate: object,
) -> Optional[str]:
    """Return a stable denial code when a rate does not match trusted facts."""

    if type(fx_rate) is not InstrumentRiskFxRate:
        return "INSTRUMENT_FX_REQUIRED"
    if order.instrument != metadata.instrument or fx_rate.instrument != metadata.instrument:
        return "INSTRUMENT_FX_INSTRUMENT_MISMATCH"
    if order.fx_rate is not fx_rate:
        return "INSTRUMENT_FX_ORDER_MISMATCH"
    if (
        metadata.quote_currency is None
        or metadata.valuation_unit is None
        or fx_rate.quote_currency != metadata.quote_currency
        or fx_rate.valuation_unit != metadata.valuation_unit
        or fx_rate.fx_pair != metadata.quote_currency + "/" + metadata.valuation_unit
    ):
        return "INSTRUMENT_FX_PAIR_MISMATCH"
    if fx_rate.source_ref != metadata.fx_source_ref:
        return "INSTRUMENT_FX_SOURCE_MISMATCH"
    return None


def _validate_fx_binding(
    metadata: InstrumentRiskMetadata,
    order: InstrumentRiskOrder,
    fx_rate: InstrumentRiskFxRate,
) -> None:
    code = _fx_binding_error(metadata, order, fx_rate)
    if code is not None:
        raise ValueError("FX fact does not match trusted metadata: " + code)


class InstrumentRiskRegistry:
    """Immutable exact-instrument metadata registry with fail-closed lookups."""

    def __init__(self, metadata: Iterable[InstrumentRiskMetadata]) -> None:
        records: dict[str, InstrumentRiskMetadata] = {}
        for item in metadata:
            if not isinstance(item, InstrumentRiskMetadata):
                raise ValueError("instrument metadata entries are required")
            if item.instrument in records:
                raise ValueError("duplicate instrument metadata")
            records[item.instrument] = item
        if not records:
            raise ValueError("at least one instrument metadata entry is required")
        self._records = records

    def get(self, instrument: str) -> Optional[InstrumentRiskMetadata]:  # noqa: UP045 -- Python 3.9.
        """Return a registered profile without making an admission decision."""

        return self._records.get(instrument)

    def assess(self, order: InstrumentRiskOrder, now_ns: int) -> InstrumentRiskAssessment:
        """Validate metadata/lattices and calculate the worst-case local bound."""

        metadata = self._metadata_for(order, now_ns, require_fresh=True)
        quote_currency = metadata.quote_currency or metadata.valuation_unit
        cross_currency = (
            quote_currency is not None
            and metadata.valuation_unit is not None
            and quote_currency != metadata.valuation_unit
        )
        fx_rate = order.fx_rate
        if cross_currency:
            binding_error = _fx_binding_error(metadata, order, fx_rate)
            if binding_error is not None:
                raise RiskDeniedError(
                    binding_error,
                    "FX facts do not match the trusted instrument, pair, or source",
                )
            assert type(fx_rate) is InstrumentRiskFxRate
            if not fx_rate.observed_at_ns <= now_ns < fx_rate.valid_until_ns:
                raise RiskDeniedError(
                    "INSTRUMENT_FX_STALE",
                    "FX facts are not current at the Risk admission boundary",
                )
            if metadata.fixed_fee > 0 and metadata.fixed_fee_unit is None:
                raise RiskDeniedError(
                    "INSTRUMENT_FIXED_FEE_UNIT_UNPROVEN",
                    "cross-currency fixed fees require an explicit currency unit",
                )
        elif fx_rate is not None:
            raise RiskDeniedError(
                "INSTRUMENT_FX_UNEXPECTED",
                "FX facts are not applicable to this same-currency instrument",
            )
        if order.limit_price is None:
            raise RiskDeniedError(
                "INSTRUMENT_PRICE_UNPROVEN",
                "instrument admission requires a bounded limit price",
            )
        if not _is_on_lattice(order.quantity, metadata.quantity_step):
            raise RiskDeniedError(
                "INSTRUMENT_QUANTITY_LATTICE",
                "order quantity is not on the reviewed quantity lattice",
            )
        if not _is_on_lattice(order.limit_price, metadata.tick_size):
            raise RiskDeniedError(
                "INSTRUMENT_PRICE_LATTICE",
                "order price is not on the reviewed tick lattice",
            )
        if metadata.min_quantity is not None and order.quantity < metadata.min_quantity:
            raise RiskDeniedError(
                "INSTRUMENT_MIN_QUANTITY",
                "order quantity is below the reviewed minimum",
            )
        if metadata.max_quantity is not None and order.quantity > metadata.max_quantity:
            raise RiskDeniedError(
                "INSTRUMENT_MAX_QUANTITY", "order quantity exceeds the reviewed maximum"
            )

        precision_values = (
            order.quantity,
            order.limit_price,
            metadata.contract_multiplier,
            metadata.taker_fee_bps,
            metadata.fixed_fee,
            metadata.max_slippage_bps,
        )
        if fx_rate is not None:
            precision_values += (fx_rate.rate,)
        with localcontext() as context:
            context.prec = _precision(*precision_values)
            adverse_price = order.limit_price * (
                Decimal("1") + metadata.max_slippage_bps / _BPS_DENOMINATOR
            )
            worst_case_price = _ceil_to_lattice(adverse_price, metadata.tick_size)
            quoted_notional = order.quantity * order.limit_price * metadata.contract_multiplier
            worst_case_notional = order.quantity * worst_case_price * metadata.contract_multiplier
            if fx_rate is None:
                # Keep exact legacy arithmetic and fingerprints for same-unit
                # instruments which predate explicit currency metadata.
                worst_case_fee = (
                    worst_case_notional * metadata.taker_fee_bps / _BPS_DENOMINATOR
                    + metadata.fixed_fee
                )
                gross_notional = worst_case_notional + worst_case_fee
            else:
                variable_quote_fee = (
                    worst_case_notional * metadata.taker_fee_bps / _BPS_DENOMINATOR
                )
                if metadata.fixed_fee_unit == fx_rate.quote_currency:
                    fixed_fee_valuation = metadata.fixed_fee * fx_rate.rate
                else:
                    fixed_fee_valuation = metadata.fixed_fee
                worst_case_fee = variable_quote_fee * fx_rate.rate + fixed_fee_valuation
                gross_notional = worst_case_notional * fx_rate.rate + worst_case_fee
        if gross_notional > metadata.max_gross_notional:
            raise RiskDeniedError(
                "INSTRUMENT_GROSS_NOTIONAL_LIMIT",
                "worst-case notional plus fees exceeds the reviewed instrument limit",
            )
        return InstrumentRiskAssessment(
            metadata=metadata,
            order=order,
            worst_case_price=worst_case_price,
            quoted_notional=quoted_notional,
            worst_case_notional=worst_case_notional,
            worst_case_fee=worst_case_fee,
            gross_notional=gross_notional,
            fx_rate=fx_rate,
        )

    def validate_reduction(self, order: InstrumentRiskOrder, now_ns: int) -> InstrumentRiskMetadata:
        """Validate a known risk-reducing request without market-data freshness gating.

        A stale quote must not become an excuse to prevent an independently
        classified close.  The trusted profile/digest and quantity lattice are
        still required, so this is not a route around provider contract facts.
        Entry-only min/max and gross-notional limits are intentionally omitted:
        a position that is already larger than a new-entry limit must remain
        closable.
        """

        metadata = self._metadata_for(order, now_ns, require_fresh=False)
        if not _is_on_lattice(order.quantity, metadata.quantity_step):
            raise RiskDeniedError(
                "INSTRUMENT_QUANTITY_LATTICE",
                "order quantity is not on the reviewed quantity lattice",
            )
        if order.limit_price is not None and not _is_on_lattice(
            order.limit_price, metadata.tick_size
        ):
            raise RiskDeniedError(
                "INSTRUMENT_PRICE_LATTICE",
                "order price is not on the reviewed tick lattice",
            )
        return metadata

    def _metadata_for(
        self,
        order: InstrumentRiskOrder,
        now_ns: int,
        *,
        require_fresh: bool,
    ) -> InstrumentRiskMetadata:
        if not isinstance(order, InstrumentRiskOrder):
            raise ValueError("instrument risk order is required")
        if type(now_ns) is not int or now_ns <= 0:
            raise ValueError("invalid now_ns")
        metadata = self._records.get(order.instrument)
        if metadata is None:
            raise RiskDeniedError(
                "INSTRUMENT_UNREGISTERED", "instrument has no reviewed risk metadata"
            )
        if order.metadata_version != metadata.metadata_version:
            raise RiskDeniedError(
                "INSTRUMENT_METADATA_VERSION_MISMATCH",
                "intent metadata version does not match trusted instrument metadata",
            )
        if order.metadata_digest != metadata.digest:
            raise RiskDeniedError(
                "INSTRUMENT_METADATA_DIGEST_MISMATCH",
                "intent metadata digest does not match trusted instrument metadata",
            )
        if require_fresh and now_ns < metadata.as_of_ns:
            raise RiskDeniedError(
                "INSTRUMENT_METADATA_NOT_ACTIVE",
                "instrument metadata is not active yet",
            )
        if require_fresh and now_ns >= metadata.expires_at_ns:
            raise RiskDeniedError("INSTRUMENT_METADATA_STALE", "instrument metadata is expired")
        return metadata


class InstrumentRiskAdmissionMapper:
    """Map a provider-neutral execution intent through instrument risk facts.

    The mapper uses attribute access instead of importing ``bt_api_execution``.
    This keeps the risk package independent while still letting a composition
    root pass it to ``SharedRiskAdmissionAdapter``.  The caller owns the
    account scope and metadata registry; arbitrary strategy tags cannot select
    another profile because the digest must match that registry exactly. A
    composition root may configure ``wire_account_ref`` when the execution
    order's routed account alias differs from the durable Risk account ID.
    """

    def __init__(
        self,
        scope: AccountScope,
        registry: InstrumentRiskRegistry,
        *,
        clock_ns: Optional[Callable[[], int]] = None,  # noqa: UP045 -- Python 3.9.
        allocation_reader: Optional[  # noqa: UP045 -- Python 3.9 is supported.
            Callable[[Any], Any]
        ] = None,
        wire_account_ref: Optional[str] = None,  # noqa: UP045 -- Python 3.9 is supported.
        fx_rates_by_instrument: Optional[  # noqa: UP045 -- Python 3.9 is supported.
            Iterable[InstrumentRiskFxRate]
        ] = None,
    ) -> None:
        if not isinstance(scope, AccountScope):
            raise ValueError("scope must be an AccountScope")
        if not isinstance(registry, InstrumentRiskRegistry):
            raise ValueError("registry must be an InstrumentRiskRegistry")
        if clock_ns is not None and not callable(clock_ns):
            raise ValueError("clock_ns must be callable")
        if allocation_reader is not None and not callable(allocation_reader):
            raise ValueError("allocation_reader must be callable")
        if wire_account_ref is None:
            wire_account_ref = scope.account_id
        elif (
            type(wire_account_ref) is not str
            or not wire_account_ref.strip()
            or wire_account_ref != wire_account_ref.strip()
        ):
            raise ValueError("wire_account_ref must be a non-empty account alias")
        fx_rates: dict[str, InstrumentRiskFxRate] = {}
        if fx_rates_by_instrument is not None:
            if isinstance(fx_rates_by_instrument, (str, bytes)):
                raise ValueError("fx_rates_by_instrument must contain typed FX facts")
            try:
                for fx_rate in fx_rates_by_instrument:
                    if type(fx_rate) is not InstrumentRiskFxRate:
                        raise ValueError("fx_rates_by_instrument must contain typed FX facts")
                    if fx_rate.instrument in fx_rates:
                        raise ValueError("duplicate instrument FX fact")
                    fx_rates[fx_rate.instrument] = fx_rate
            except TypeError as error:
                raise ValueError("fx_rates_by_instrument must be iterable") from error
        self._scope = scope
        self._registry = registry
        self._clock_ns = clock_ns or _wall_clock_ns
        self._allocation_reader = allocation_reader
        self._wire_account_ref = wire_account_ref
        self._fx_rates_by_instrument = fx_rates

    @property
    def registry(self) -> InstrumentRiskRegistry:
        """Return the immutable registry used by this mapper."""

        return self._registry

    @property
    def wire_account_ref(self) -> str:
        """Return the exact routed account alias accepted for this Risk scope."""

        return self._wire_account_ref

    def _validated_execution_scope(self, intent: Any) -> Any:
        execution_scope = getattr(intent, "scope", None)
        if execution_scope is None:
            if self._allocation_reader is not None:
                raise RiskDeniedError(
                    "STRATEGY_ALLOCATION_SCOPE_MISMATCH",
                    "execution intent has no strategy allocation scope",
                )
            return None
        try:
            provider = execution_scope.provider
            account_ref = execution_scope.account_ref
            environment = execution_scope.environment
        except AttributeError:
            raise RiskDeniedError(
                "ACCOUNT_SCOPE_MISMATCH", "execution intent has no valid routed account scope"
            ) from None
        if (
            provider != self._scope.provider
            or account_ref != self._wire_account_ref
            or environment != self._scope.environment
        ):
            raise RiskDeniedError(
                "ACCOUNT_SCOPE_MISMATCH",
                "execution scope does not match the configured routed account alias",
            )
        return execution_scope

    def assessment_for(self, intent: Any) -> InstrumentRiskAssessment:
        """Assess one execution-shaped object and reject missing trusted facts."""

        order = self._order_from_intent(intent)
        self._verify_fx_source_binding(order)
        now_ns = self._clock_ns()
        return self._registry.assess(order, now_ns)

    def _verify_fx_source_binding(self, order: InstrumentRiskOrder) -> None:
        """Require the order to carry this mapper's exact configured FX fact."""

        if order.fx_rate is None:
            return
        configured = self._fx_rates_by_instrument.get(order.instrument)
        if configured is not order.fx_rate:
            raise RiskDeniedError(
                "INSTRUMENT_FX_SOURCE_UNBOUND",
                "FX fact is not the exact source-bound fact configured for this instrument",
            )

    def _order_from_intent(self, intent: Any) -> InstrumentRiskOrder:
        tags = getattr(intent, "tags", None)
        if not isinstance(tags, Mapping):
            raise RiskDeniedError("INSTRUMENT_METADATA_DIGEST_REQUIRED", "intent tags are required")
        metadata_digest = tags.get(INSTRUMENT_METADATA_DIGEST_TAG)
        if not isinstance(metadata_digest, str) or not _SHA256.fullmatch(metadata_digest):
            raise RiskDeniedError(
                "INSTRUMENT_METADATA_DIGEST_REQUIRED",
                "intent is missing the exact instrument metadata digest",
            )
        try:
            order = InstrumentRiskOrder(
                instrument=intent.instrument,
                quantity=intent.quantity,
                limit_price=intent.price,
                metadata_version=intent.metadata_version,
                metadata_digest=metadata_digest,
                fx_rate=getattr(intent, "fx_rate", None),
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise RiskDeniedError(
                "INSTRUMENT_INTENT_INVALID", "intent lacks valid instrument-risk fields"
            ) from error
        return order

    def __call__(self, intent: Any) -> RiskIntent:
        """Create the account-bound risk intent for one verified execution intent."""

        execution_scope = self._validated_execution_scope(intent)
        order = self._order_from_intent(intent)
        try:
            intent_id = intent.intent_id
            intent_fingerprint = intent.fingerprint
        except AttributeError as error:
            raise RiskDeniedError(
                "INSTRUMENT_INTENT_INVALID", "intent lacks immutable identity"
            ) from error
        position_effect = getattr(getattr(intent, "position_effect", None), "value", None)
        strategy_id = None
        allocation_version = None
        quantity_unit = None
        notional_unit = None
        instrument_facts_observed_at_ns = None
        instrument_facts_valid_until_ns = None
        if position_effect == "OPEN":
            self._verify_fx_source_binding(order)
            assessment = self._registry.assess(order, self._clock_ns())
            action = IntentAction.INCREASE
            notional = assessment.gross_notional
            payload_fingerprint = assessment.bound_payload_fingerprint(intent_fingerprint)
            quantity_unit = assessment.metadata.quantity_unit
            # The valuation unit is a trusted instrument fact, independent of
            # whether this order has a separate strategy allocation.  Carry it
            # into the account reservation so a fixed-unit account policy can
            # enforce its denomination on account-only risk admission too.
            notional_unit = assessment.metadata.valuation_unit
            if assessment.fx_rate is not None:
                instrument_facts_observed_at_ns = max(
                    assessment.metadata.as_of_ns,
                    assessment.fx_rate.observed_at_ns,
                )
                instrument_facts_valid_until_ns = min(
                    assessment.metadata.expires_at_ns,
                    assessment.fx_rate.valid_until_ns,
                )
            if self._allocation_reader is not None:
                try:
                    strategy_id = _identifier(execution_scope.strategy_id, "strategy_id")
                except (AttributeError, TypeError, ValueError) as error:
                    raise RiskDeniedError(
                        "STRATEGY_ALLOCATION_UNAVAILABLE",
                        "authoritative strategy allocation is unavailable or malformed",
                    ) from error
                try:
                    allocation = self._allocation_reader(execution_scope)
                except (AttributeError, TypeError, ValueError) as error:
                    raise RiskDeniedError(
                        "STRATEGY_ALLOCATION_UNAVAILABLE",
                        "authoritative strategy allocation is unavailable or malformed",
                    ) from error
                if type(allocation) is StrategyAllocationSnapshot:
                    # The durable reader is account-scoped, while legacy SDK
                    # allocation DTOs are execution-scope-scoped. Handle the
                    # exact local snapshot as its own contract so similarly
                    # shaped caller objects cannot impersonate its scope.
                    if (
                        type(allocation.scope) is not AccountScope
                        or allocation.scope != self._scope
                        or allocation.strategy_id != strategy_id
                    ):
                        raise RiskDeniedError(
                            "STRATEGY_ALLOCATION_SCOPE_MISMATCH",
                            "risk-ledger snapshot does not match the bound account and strategy",
                        )
                    if (
                        allocation.source != "local_risk_reservation_ledger"
                        or allocation.completeness != "LOCAL_LEDGER_COMPLETE"
                        or allocation.reason is not None
                    ):
                        raise RiskDeniedError(
                            "STRATEGY_ALLOCATION_UNAVAILABLE",
                            "risk-ledger allocation snapshot is incomplete",
                        )
                    try:
                        allocation_notional = _decimal(
                            allocation.allocated_notional,
                            "allocation.allocated_notional",
                            nonnegative=True,
                        )
                        _decimal(
                            allocation.available_notional,
                            "allocation.available_notional",
                            nonnegative=True,
                        )
                        _decimal(
                            allocation.used_notional,
                            "allocation.used_notional",
                            nonnegative=True,
                        )
                        _decimal(
                            allocation.reserved_notional,
                            "allocation.reserved_notional",
                            nonnegative=True,
                        )
                    except ValueError as error:
                        raise RiskDeniedError(
                            "STRATEGY_ALLOCATION_UNAVAILABLE",
                            "risk-ledger allocation snapshot has invalid numeric limits",
                        ) from error
                    allocation_version = allocation.revision
                    allocation_position = allocation.max_position
                    allocation_notional_unit = allocation.notional_unit
                    allocation_position_instrument = allocation.position_instrument
                    allocation_position_unit = allocation.position_unit
                else:
                    # Compatibility path for reviewed execution-owned DTOs.
                    # It retains its exact scope binding and never accepts an
                    # untyped snapshot-like object.
                    try:
                        allocation_scope = allocation.scope
                        allocation_version = allocation.allocation_version
                        allocation_notional = getattr(allocation, "max_notional", None)
                        allocation_position = getattr(allocation, "max_position", None)
                        allocation_notional_unit = getattr(allocation, "notional_unit", None)
                        allocation_position_instrument = getattr(
                            allocation, "position_instrument", None
                        )
                        allocation_position_unit = getattr(allocation, "position_unit", None)
                    except (AttributeError, TypeError, ValueError) as error:
                        raise RiskDeniedError(
                            "STRATEGY_ALLOCATION_UNAVAILABLE",
                            "authoritative strategy allocation is unavailable or malformed",
                        ) from error
                    if allocation_scope != execution_scope:
                        raise RiskDeniedError(
                            "STRATEGY_ALLOCATION_SCOPE_MISMATCH",
                            "strategy allocation does not match the bound account and strategy",
                        )
                try:
                    _identifier(allocation_version, "allocation_version")
                    metadata_notional_unit = assessment.metadata.valuation_unit
                    if (
                        metadata_notional_unit is None
                        or not isinstance(allocation_notional_unit, str)
                        or not _NOTIONAL_UNIT.fullmatch(allocation_notional_unit)
                        or allocation_notional_unit != metadata_notional_unit
                    ):
                        raise RiskDeniedError(
                            "STRATEGY_ALLOCATION_NOTIONAL_UNIT_UNAVAILABLE",
                            "allocation and trusted instrument facts must bind one notional unit",
                        )
                    notional_unit = metadata_notional_unit
                    if allocation_notional is not None:
                        normalized_notional = _decimal(
                            allocation_notional,
                            "allocation.max_notional",
                            nonnegative=True,
                        )
                        if notional > normalized_notional:
                            raise RiskDeniedError(
                                "STRATEGY_ALLOCATION_EXHAUSTED",
                                "intent notional exceeds the strategy allocation",
                            )
                    if allocation_position is not None:
                        normalized_position = _decimal(
                            allocation_position,
                            "allocation.max_position",
                            positive=True,
                        )
                        metadata_unit = assessment.metadata.quantity_unit
                        if (
                            allocation_position_instrument != order.instrument
                            or not isinstance(allocation_position_unit, str)
                            or metadata_unit is None
                            or allocation_position_unit != metadata_unit
                        ):
                            raise RiskDeniedError(
                                "STRATEGY_POSITION_SCOPE_UNAVAILABLE",
                                "max_position requires an exact allocation instrument and quantity unit",
                            )
                        if order.quantity > normalized_position:
                            raise RiskDeniedError(
                                "STRATEGY_ALLOCATION_EXHAUSTED",
                                "intent quantity exceeds the strategy allocation",
                            )
                        quantity_unit = metadata_unit
                except (TypeError, ValueError) as error:
                    raise RiskDeniedError(
                        "STRATEGY_ALLOCATION_UNAVAILABLE",
                        "strategy allocation limits are invalid",
                    ) from error
        elif position_effect in {"CLOSE", "CLOSE_TODAY", "CLOSE_YESTERDAY"}:
            metadata = self._registry.validate_reduction(order, self._clock_ns())
            action = IntentAction.REDUCE
            notional = Decimal("0")
            payload_fingerprint = _reduction_payload_fingerprint(
                intent_fingerprint, order, metadata
            )
        else:
            raise RiskDeniedError(
                "INSTRUMENT_POSITION_EFFECT_UNPROVEN",
                "intent position effect cannot be mapped to a risk action",
            )
        return RiskIntent(
            intent_id=intent_id,
            scope=self._scope,
            action=action,
            notional=notional,
            payload_fingerprint=payload_fingerprint,
            strategy_id=strategy_id,
            allocation_version=allocation_version,
            instrument=(
                order.instrument
                if action is IntentAction.INCREASE and quantity_unit is not None
                else None
            ),
            quantity=(
                order.quantity
                if action is IntentAction.INCREASE and quantity_unit is not None
                else None
            ),
            quantity_unit=(
                quantity_unit
                if action is IntentAction.INCREASE and quantity_unit is not None
                else None
            ),
            notional_unit=notional_unit,
            instrument_facts_observed_at_ns=instrument_facts_observed_at_ns,
            instrument_facts_valid_until_ns=instrument_facts_valid_until_ns,
        )

    def map_group_intent(self, intent: Any) -> RiskIntent:
        """Map an opening group order and bind its mapper-owned economic profile.

        This opt-in entry point leaves normal order mappings and their legacy
        fingerprints byte-compatible.  Quantity, price, and the current
        metadata validity interval are excluded from the profile digest;
        the mapped child still carries a separately recomputed trusted notional
        and is checked against the reserved maxima at claim time.
        """

        mapped = self(intent)
        if (
            mapped.action is not IntentAction.INCREASE
            or mapped.strategy_id is None
            or mapped.allocation_version is None
            or mapped.instrument is None
            or mapped.quantity_unit is None
            or mapped.notional_unit is None
        ):
            raise RiskDeniedError(
                "GROUP_STRATEGY_ALLOCATION_REQUIRED",
                "group legs require a mapped opening intent with strategy allocation",
            )
        order = self._order_from_intent(intent)
        self._verify_fx_source_binding(order)
        observed_at_ns = self._clock_ns()
        assessment = self._registry.assess(order, observed_at_ns)
        metadata = assessment.metadata
        side = getattr(getattr(intent, "side", None), "value", None)
        if side not in {"BUY", "SELL"}:
            raise RiskDeniedError(
                "GROUP_EXPOSURE_SIDE_UNPROVEN",
                "group order side is not a supported canonical value",
            )
        profile_payload: dict[str, object] = {
            "contract_multiplier": _decimal_text(metadata.contract_multiplier),
            "exposure_profile_schema": "bt_api_risk.group-exposure-profile.v1",
            "fixed_fee": _decimal_text(metadata.fixed_fee),
            "instrument": metadata.instrument,
            "max_slippage_bps": _decimal_text(metadata.max_slippage_bps),
            "notional_unit": metadata.valuation_unit,
            "position_effect": "OPEN",
            "quantity_step": _decimal_text(metadata.quantity_step),
            "quantity_unit": metadata.quantity_unit,
            "side": side,
            "taker_fee_bps": _decimal_text(metadata.taker_fee_bps),
            "tick_size": _decimal_text(metadata.tick_size),
        }
        for name in ("quote_currency", "fx_source_ref", "fixed_fee_unit"):
            value = getattr(metadata, name)
            if value is not None:
                profile_payload[name] = value
        profile = _sha256(_canonical_json(profile_payload))
        facts_observed_at_ns = observed_at_ns
        facts_valid_until_ns = metadata.expires_at_ns
        if assessment.fx_rate is not None:
            facts_observed_at_ns = max(
                metadata.as_of_ns,
                assessment.fx_rate.observed_at_ns,
            )
            facts_valid_until_ns = min(
                metadata.expires_at_ns,
                assessment.fx_rate.valid_until_ns,
            )
            if not facts_observed_at_ns <= observed_at_ns < facts_valid_until_ns:
                raise RiskDeniedError(
                    "INSTRUMENT_FX_STALE",
                    "instrument and FX facts are not current for the group reservation",
                )
        return replace(
            mapped,
            exposure_profile_fingerprint=profile,
            instrument_facts_observed_at_ns=facts_observed_at_ns,
            instrument_facts_valid_until_ns=facts_valid_until_ns,
        )


def _reduction_payload_fingerprint(
    intent_fingerprint: str,
    order: InstrumentRiskOrder,
    metadata: InstrumentRiskMetadata,
) -> str:
    """Bind a close to the exact historical instrument facts without an entry valuation."""

    intent_fingerprint = _digest(intent_fingerprint, "intent_fingerprint")
    return _sha256(
        _canonical_json(
            {
                "intent_fingerprint": intent_fingerprint,
                "limit_price": None
                if order.limit_price is None
                else _decimal_text(order.limit_price),
                "metadata_digest": metadata.digest,
                "quantity": _decimal_text(order.quantity),
                "risk_action": "reduce",
                "schema": _SCHEMA,
            }
        )
    )


def _wall_clock_ns() -> int:
    import time

    return time.time_ns()


__all__ = [
    "INSTRUMENT_METADATA_DIGEST_TAG",
    "InstrumentRiskAdmissionMapper",
    "InstrumentRiskAssessment",
    "InstrumentRiskFxRate",
    "InstrumentRiskMetadata",
    "InstrumentRiskOrder",
    "InstrumentRiskRegistry",
]
