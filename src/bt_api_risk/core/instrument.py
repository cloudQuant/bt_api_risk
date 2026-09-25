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
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext
from typing import Any, Optional

from .admission import AccountScope, IntentAction, RiskDeniedError, RiskIntent

INSTRUMENT_METADATA_DIGEST_TAG = "instrument_metadata_digest"
"""The immutable ``OrderIntent.tags`` key carrying the reviewed metadata digest."""

_SCHEMA = "bt_api_risk.instrument-admission.v1"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_INSTRUMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
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

    value_coefficient, value_exponent = _coefficient_and_exponent(value)
    step_coefficient, step_exponent = _coefficient_and_exponent(step)
    exponent = min(value_exponent, step_exponent)
    value_integer = value_coefficient * 10 ** (value_exponent - exponent)
    step_integer = step_coefficient * 10 ** (step_exponent - exponent)
    return value_integer % step_integer == 0


def _precision(*values: Decimal) -> int:
    """Return a sufficient practical Decimal precision for exact local arithmetic."""

    return max(50, sum(len(value.as_tuple().digits) for value in values) + 24)


def _ceil_to_lattice(value: Decimal, step: Decimal) -> Decimal:
    """Round a positive value up to the next exact permitted price tick."""

    value_coefficient, value_exponent = _coefficient_and_exponent(value)
    step_coefficient, step_exponent = _coefficient_and_exponent(step)
    exponent = min(value_exponent, step_exponent)
    value_integer = value_coefficient * 10 ** (value_exponent - exponent)
    step_integer = step_coefficient * 10 ** (step_exponent - exponent)
    quotient = (value_integer + step_integer - 1) // step_integer
    with localcontext() as context:
        context.prec = max(
            _precision(value, step), len(str(quotient)) + len(step.as_tuple().digits) + 8
        )
        return Decimal(quotient) * step


@dataclass(frozen=True)
class InstrumentRiskMetadata:
    """Reviewed, time-bounded instrument facts used before a provider write.

    ``max_gross_notional`` is intentionally fee-inclusive.  It limits the
    calculation returned by :class:`InstrumentRiskAssessment`, which includes
    a conservative adverse price envelope and estimated taker/fixed fees.
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
    min_quantity: Optional[Decimal] = None  # noqa: UP045 -- package supports Python 3.9.
    max_quantity: Optional[Decimal] = None  # noqa: UP045 -- package supports Python 3.9.
    taker_fee_bps: Decimal = Decimal("0")
    fixed_fee: Decimal = Decimal("0")
    max_slippage_bps: Decimal = Decimal("0")

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "instrument", _identifier(self.instrument, "instrument", instrument=True)
        )
        object.__setattr__(
            self, "metadata_version", _identifier(self.metadata_version, "metadata_version")
        )
        if type(self.as_of_ns) is not int or self.as_of_ns <= 0:
            raise ValueError("invalid as_of_ns")
        if type(self.expires_at_ns) is not int or self.expires_at_ns <= self.as_of_ns:
            raise ValueError("invalid expires_at_ns")
        object.__setattr__(self, "tick_size", _decimal(self.tick_size, "tick_size", positive=True))
        object.__setattr__(
            self, "quantity_step", _decimal(self.quantity_step, "quantity_step", positive=True)
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
        if (
            self.min_quantity is not None
            and self.max_quantity is not None
            and self.min_quantity > self.max_quantity
        ):
            raise ValueError("min_quantity cannot exceed max_quantity")

    def to_payload(self) -> dict[str, object]:
        """Return the full non-secret canonical content that the digest binds."""

        return {
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

    @property
    def digest(self) -> str:
        """Return the exact trusted-metadata digest required in each intent."""

        return _sha256(_canonical_json(self.to_payload()))


@dataclass(frozen=True)
class InstrumentRiskOrder:
    """The instrument-relevant subset of one immutable execution request."""

    instrument: str
    quantity: Decimal
    limit_price: Optional[Decimal]  # noqa: UP045 -- package supports Python 3.9.
    metadata_version: str
    metadata_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "instrument", _identifier(self.instrument, "instrument", instrument=True)
        )
        object.__setattr__(self, "quantity", _decimal(self.quantity, "quantity", positive=True))
        if self.limit_price is not None:
            object.__setattr__(
                self, "limit_price", _decimal(self.limit_price, "limit_price", positive=True)
            )
        object.__setattr__(
            self, "metadata_version", _identifier(self.metadata_version, "metadata_version")
        )
        object.__setattr__(
            self, "metadata_digest", _digest(self.metadata_digest, "metadata_digest")
        )


@dataclass(frozen=True)
class InstrumentRiskAssessment:
    """One deterministic, fee-inclusive bound accepted by a trusted profile."""

    metadata: InstrumentRiskMetadata
    order: InstrumentRiskOrder
    worst_case_price: Decimal
    quoted_notional: Decimal
    worst_case_notional: Decimal
    worst_case_fee: Decimal
    gross_notional: Decimal

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
            _decimal(self.worst_case_fee, "worst_case_fee"),
        )

    def bound_payload_fingerprint(self, intent_fingerprint: str) -> str:
        """Bind trusted metadata and all risk amounts to an execution intent hash."""

        intent_fingerprint = _digest(intent_fingerprint, "intent_fingerprint")
        return _sha256(
            _canonical_json(
                {
                    "gross_notional": _decimal_text(self.gross_notional),
                    "intent_fingerprint": intent_fingerprint,
                    "metadata_digest": self.metadata.digest,
                    "quoted_notional": _decimal_text(self.quoted_notional),
                    "schema": _SCHEMA,
                    "worst_case_fee": _decimal_text(self.worst_case_fee),
                    "worst_case_notional": _decimal_text(self.worst_case_notional),
                    "worst_case_price": _decimal_text(self.worst_case_price),
                }
            )
        )


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
        if order.limit_price is None:
            raise RiskDeniedError(
                "INSTRUMENT_PRICE_UNPROVEN", "instrument admission requires a bounded limit price"
            )
        if not _is_on_lattice(order.quantity, metadata.quantity_step):
            raise RiskDeniedError(
                "INSTRUMENT_QUANTITY_LATTICE",
                "order quantity is not on the reviewed quantity lattice",
            )
        if not _is_on_lattice(order.limit_price, metadata.tick_size):
            raise RiskDeniedError(
                "INSTRUMENT_PRICE_LATTICE", "order price is not on the reviewed tick lattice"
            )
        if metadata.min_quantity is not None and order.quantity < metadata.min_quantity:
            raise RiskDeniedError(
                "INSTRUMENT_MIN_QUANTITY", "order quantity is below the reviewed minimum"
            )
        if metadata.max_quantity is not None and order.quantity > metadata.max_quantity:
            raise RiskDeniedError(
                "INSTRUMENT_MAX_QUANTITY", "order quantity exceeds the reviewed maximum"
            )

        with localcontext() as context:
            context.prec = _precision(
                order.quantity,
                order.limit_price,
                metadata.contract_multiplier,
                metadata.taker_fee_bps,
                metadata.fixed_fee,
                metadata.max_slippage_bps,
            )
            adverse_price = order.limit_price * (
                Decimal("1") + metadata.max_slippage_bps / _BPS_DENOMINATOR
            )
            worst_case_price = _ceil_to_lattice(adverse_price, metadata.tick_size)
            quoted_notional = order.quantity * order.limit_price * metadata.contract_multiplier
            worst_case_notional = order.quantity * worst_case_price * metadata.contract_multiplier
            worst_case_fee = (
                worst_case_notional * metadata.taker_fee_bps / _BPS_DENOMINATOR + metadata.fixed_fee
            )
            gross_notional = worst_case_notional + worst_case_fee
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
                "INSTRUMENT_PRICE_LATTICE", "order price is not on the reviewed tick lattice"
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
                "INSTRUMENT_METADATA_NOT_ACTIVE", "instrument metadata is not active yet"
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
    another profile because the digest must match that registry exactly.
    """

    def __init__(
        self,
        scope: AccountScope,
        registry: InstrumentRiskRegistry,
        *,
        clock_ns: Optional[Callable[[], int]] = None,  # noqa: UP045 -- Python 3.9.
    ) -> None:
        if not isinstance(scope, AccountScope):
            raise ValueError("scope must be an AccountScope")
        if not isinstance(registry, InstrumentRiskRegistry):
            raise ValueError("registry must be an InstrumentRiskRegistry")
        if clock_ns is not None and not callable(clock_ns):
            raise ValueError("clock_ns must be callable")
        self._scope = scope
        self._registry = registry
        self._clock_ns = clock_ns or _wall_clock_ns

    @property
    def registry(self) -> InstrumentRiskRegistry:
        """Return the immutable registry used by this mapper."""

        return self._registry

    def assessment_for(self, intent: Any) -> InstrumentRiskAssessment:
        """Assess one execution-shaped object and reject missing trusted facts."""

        order = self._order_from_intent(intent)
        now_ns = self._clock_ns()
        return self._registry.assess(order, now_ns)

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
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise RiskDeniedError(
                "INSTRUMENT_INTENT_INVALID", "intent lacks valid instrument-risk fields"
            ) from error
        return order

    def __call__(self, intent: Any) -> RiskIntent:
        """Create the account-bound risk intent for one verified execution intent."""

        order = self._order_from_intent(intent)
        try:
            intent_id = intent.intent_id
            intent_fingerprint = intent.fingerprint
        except AttributeError as error:
            raise RiskDeniedError(
                "INSTRUMENT_INTENT_INVALID", "intent lacks immutable identity"
            ) from error
        position_effect = getattr(getattr(intent, "position_effect", None), "value", None)
        if position_effect == "OPEN":
            assessment = self._registry.assess(order, self._clock_ns())
            action = IntentAction.INCREASE
            notional = assessment.gross_notional
            payload_fingerprint = assessment.bound_payload_fingerprint(intent_fingerprint)
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
    "InstrumentRiskMetadata",
    "InstrumentRiskOrder",
    "InstrumentRiskRegistry",
]
