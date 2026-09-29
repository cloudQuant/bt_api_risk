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
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not pattern.fullmatch(value)
    ):
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
        sum(
            len(value.as_tuple().digits) + abs(value.as_tuple().exponent)
            for value in values
        )
        + 32,
    )
    if precision > 10000:
        raise ValueError(
            "instrument decimal scale exceeds the supported arithmetic bound"
        )
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
        object.__setattr__(
            self, "tick_size", _decimal(self.tick_size, "tick_size", positive=True)
        )
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
            "max_quantity": None
            if self.max_quantity is None
            else _decimal_text(self.max_quantity),
            "max_slippage_bps": _decimal_text(self.max_slippage_bps),
            "metadata_version": self.metadata_version,
            "min_quantity": None
            if self.min_quantity is None
            else _decimal_text(self.min_quantity),
            "quantity_step": _decimal_text(self.quantity_step),
            "schema": _SCHEMA,
            "taker_fee_bps": _decimal_text(self.taker_fee_bps),
            "tick_size": _decimal_text(self.tick_size),
        }
        if self.quantity_unit is not None:
            payload["quantity_unit"] = self.quantity_unit
        if self.valuation_unit is not None:
            payload["valuation_unit"] = self.valuation_unit
        return payload

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
            self,
            "instrument",
            _identifier(self.instrument, "instrument", instrument=True),
        )
        object.__setattr__(
            self, "quantity", _decimal(self.quantity, "quantity", positive=True)
        )
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
            object.__setattr__(
                self, name, _decimal(getattr(self, name), name, positive=True)
            )
        object.__setattr__(
            self,
            "worst_case_fee",
            _decimal(self.worst_case_fee, "worst_case_fee", nonnegative=True),
        )
        if Fraction(self.gross_notional) != (
            Fraction(self.worst_case_notional) + Fraction(self.worst_case_fee)
        ):
            raise ValueError(
                "gross_notional must equal worst_case_notional plus worst_case_fee"
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

    def get(
        self, instrument: str
    ) -> Optional[InstrumentRiskMetadata]:  # noqa: UP045 -- Python 3.9.
        """Return a registered profile without making an admission decision."""

        return self._records.get(instrument)

    def assess(
        self, order: InstrumentRiskOrder, now_ns: int
    ) -> InstrumentRiskAssessment:
        """Validate metadata/lattices and calculate the worst-case local bound."""

        metadata = self._metadata_for(order, now_ns, require_fresh=True)
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
            quoted_notional = (
                order.quantity * order.limit_price * metadata.contract_multiplier
            )
            worst_case_notional = (
                order.quantity * worst_case_price * metadata.contract_multiplier
            )
            worst_case_fee = (
                worst_case_notional * metadata.taker_fee_bps / _BPS_DENOMINATOR
                + metadata.fixed_fee
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

    def validate_reduction(
        self, order: InstrumentRiskOrder, now_ns: int
    ) -> InstrumentRiskMetadata:
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
            raise RiskDeniedError(
                "INSTRUMENT_METADATA_STALE", "instrument metadata is expired"
            )
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
        allocation_reader: Optional[  # noqa: UP045 -- Python 3.9 is supported.
            Callable[[Any], Any]
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
        self._scope = scope
        self._registry = registry
        self._clock_ns = clock_ns or _wall_clock_ns
        self._allocation_reader = allocation_reader

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
            raise RiskDeniedError(
                "INSTRUMENT_METADATA_DIGEST_REQUIRED", "intent tags are required"
            )
        metadata_digest = tags.get(INSTRUMENT_METADATA_DIGEST_TAG)
        if not isinstance(metadata_digest, str) or not _SHA256.fullmatch(
            metadata_digest
        ):
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
        position_effect = getattr(
            getattr(intent, "position_effect", None), "value", None
        )
        strategy_id = None
        allocation_version = None
        quantity_unit = None
        notional_unit = None
        if position_effect == "OPEN":
            assessment = self._registry.assess(order, self._clock_ns())
            action = IntentAction.INCREASE
            notional = assessment.gross_notional
            payload_fingerprint = assessment.bound_payload_fingerprint(
                intent_fingerprint
            )
            quantity_unit = assessment.metadata.quantity_unit
            if self._allocation_reader is not None:
                execution_scope = getattr(intent, "scope", None)
                if execution_scope is None:
                    raise RiskDeniedError(
                        "STRATEGY_ALLOCATION_SCOPE_MISMATCH",
                        "execution intent has no strategy allocation scope",
                    )
                try:
                    allocation = self._allocation_reader(execution_scope)
                    strategy_id = execution_scope.strategy_id
                except (AttributeError, TypeError, ValueError) as error:
                    raise RiskDeniedError(
                        "STRATEGY_ALLOCATION_UNAVAILABLE",
                        "authoritative strategy allocation is unavailable or malformed",
                    ) from error
                if (
                    getattr(execution_scope, "provider", None) != self._scope.provider
                    or getattr(execution_scope, "account_ref", None)
                    != self._scope.account_id
                    or getattr(execution_scope, "environment", None)
                    != self._scope.environment
                ):
                    raise RiskDeniedError(
                        "STRATEGY_ALLOCATION_SCOPE_MISMATCH",
                        "strategy allocation does not match the bound account and strategy",
                    )
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
                        allocation_notional_unit = getattr(
                            allocation, "notional_unit", None
                        )
                        allocation_position_instrument = getattr(
                            allocation, "position_instrument", None
                        )
                        allocation_position_unit = getattr(
                            allocation, "position_unit", None
                        )
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
                    _identifier(strategy_id, "strategy_id")
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
                if action is IntentAction.INCREASE
                and strategy_id
                and quantity_unit is not None
                else None
            ),
            quantity=(
                order.quantity
                if action is IntentAction.INCREASE
                and strategy_id
                and quantity_unit is not None
                else None
            ),
            quantity_unit=(
                quantity_unit
                if action is IntentAction.INCREASE
                and strategy_id
                and quantity_unit is not None
                else None
            ),
            notional_unit=notional_unit,
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
