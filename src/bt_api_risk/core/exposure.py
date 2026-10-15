"""Typed, provider-neutral proofs for durable gross-exposure accounting.

The values in this module are claims, not authority.  ``DurableRiskGate`` only
consumes them while an injected authority verifies the immutable source row
and holds the current account writer fence across the Risk transaction.
"""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import AbstractContextManager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext
from enum import Enum
from fractions import Fraction
from typing import TYPE_CHECKING, Optional, Protocol

if TYPE_CHECKING:
    from .admission import AccountScope, DispatchClaimBinding, DispatchTrackedOrderProof

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_UNIT = re.compile(r"^[A-Z][A-Z0-9]{2,11}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")


def _digest(value: object, name: str) -> str:
    if type(value) is not str or _SHA256_HEX.fullmatch(value) is None:
        raise ValueError("invalid " + name)
    return value


def _decimal(value: object, name: str, *, positive: bool = False) -> Decimal:
    if isinstance(value, bool):
        raise ValueError("invalid " + name)
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("invalid " + name) from exc
    if not result.is_finite() or result < 0 or (positive and result <= 0):
        raise ValueError("invalid " + name)
    return result


def _signed_decimal(value: object, name: str) -> Decimal:
    if isinstance(value, bool):
        raise ValueError("invalid " + name)
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("invalid " + name) from exc
    if not result.is_finite():
        raise ValueError("invalid " + name)
    return result


def _decimal_text(value: Decimal) -> str:
    if value == 0:
        return "0"
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def _proof_hash(values: dict[str, object]) -> str:
    payload = {
        key: _decimal_text(value) if isinstance(value, Decimal) else value
        for key, value in values.items()
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class ExposureAccountingMode(str, Enum):
    """Meaning of the optional long-lived occupancy controls."""

    RESERVATIONS_ONLY = "RESERVATIONS_ONLY"
    LIVE_GROSS = "LIVE_GROSS"


class OrderExposureState(str, Enum):
    """Normalized lifecycle states accepted by the exposure projection."""

    UNKNOWN = "UNKNOWN"
    ACKED = "ACKED"
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    FILLED = "FILLED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class OrderFillFact:
    """One immutable normalized fill row included in a complete order proof.

    The adapter supplies the normalized quote-currency price, fee, and source-row digest while
    the authority binds the enclosing proof to its source journal.  Risk uses
    the fill identities and quantities to reconcile the complete cumulative
    quantity and stores each fact immutably; it does not infer a reduce from a
    fill or client flag.
    """

    trade_id: str
    quantity: Decimal
    price: Decimal
    side: str
    position_effect: str
    fee_amount: Decimal
    fee_currency: str
    source_record_sha256: str
    source_revision: int

    def __post_init__(self) -> None:
        _require_text(self.trade_id, "trade_id")
        object.__setattr__(
            self, "quantity", _decimal(self.quantity, "fill quantity", positive=True)
        )
        object.__setattr__(self, "price", _decimal(self.price, "fill price", positive=True))
        object.__setattr__(self, "fee_amount", _signed_decimal(self.fee_amount, "fill fee"))
        if self.side not in ("BUY", "SELL"):
            raise ValueError("fill side must be BUY or SELL")
        if self.position_effect != "OPEN":
            raise ValueError("only source-proven opening fills are supported")
        if type(self.fee_currency) is not str or _UNIT.fullmatch(self.fee_currency) is None:
            raise ValueError("invalid fill fee currency")
        _digest(self.source_record_sha256, "fill source record digest")
        if type(self.source_revision) is not int or self.source_revision <= 0:
            raise ValueError("invalid fill source revision")

    @property
    def fingerprint(self) -> str:
        return _proof_hash(
            {
                "trade_id": self.trade_id,
                "quantity": self.quantity,
                "price": self.price,
                "side": self.side,
                "position_effect": self.position_effect,
                "fee_amount": self.fee_amount,
                "fee_currency": self.fee_currency,
                "source_record_sha256": self.source_record_sha256,
                "source_revision": self.source_revision,
            }
        )


def fill_ids_sha256(fills: tuple[OrderFillFact, ...]) -> str:
    """Return the canonical digest used to bind the complete fill-id set."""
    if type(fills) is not tuple or any(type(item) is not OrderFillFact for item in fills):
        raise ValueError("fills must be an immutable OrderFillFact tuple")
    ids = [item.trade_id for item in fills]
    return fill_ids_sha256_from_ids(tuple(ids))


def fill_ids_sha256_from_ids(trade_ids: tuple[str, ...]) -> str:
    if type(trade_ids) is not tuple or any(type(value) is not str for value in trade_ids):
        raise ValueError("trade IDs must be an immutable string tuple")
    ids = list(trade_ids)
    if len(ids) != len(set(ids)):
        raise ValueError("fill trade IDs must be unique")
    return hashlib.sha256(
        json.dumps(sorted(ids), separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class StrategyGrossBaseline:
    """One fully attributed strategy slice in an account baseline."""

    strategy_id: str
    gross_notional: Decimal
    active_increase_intent_count: int

    def __post_init__(self) -> None:
        if type(self.strategy_id) is not str or _IDENTIFIER.fullmatch(self.strategy_id) is None:
            raise ValueError("invalid baseline strategy_id")
        object.__setattr__(self, "gross_notional", _decimal(self.gross_notional, "gross_notional"))
        if (
            type(self.active_increase_intent_count) is not int
            or self.active_increase_intent_count < 0
        ):
            raise ValueError("invalid baseline active increase-intent count")
        if (self.gross_notional > 0) != (self.active_increase_intent_count > 0):
            raise ValueError("baseline gross and occupied-intent count must agree")


@dataclass(frozen=True)
class GrossExposureBaselineProof:
    """Claimed complete account-position baseline for one clean Risk generation.

    Existing positions must be attributed to strategies and all amounts must
    already be converted into the immutable account policy unit.  This first
    implementation intentionally requires zero unmanaged open orders; those
    must be represented as Risk-owned order records before LIVE_GROSS can
    admit increases.
    """

    scope: AccountScope
    account_revision: int
    notional_unit: str
    account_gross_notional: Decimal
    account_active_increase_intent_count: int
    strategy_baselines: tuple[StrategyGrossBaseline, ...]
    unmanaged_open_order_count: int
    complete_positions: bool
    complete_open_orders: bool
    source_snapshot_sha256: str
    positions_sha256: str
    open_orders_sha256: str
    valuation_facts_sha256: str
    source_schema_version: str
    observed_at_ns: int
    valid_until_ns: int
    writer_owner_id: str
    writer_fencing_token: int
    writer_fence_sha256: str

    def __post_init__(self) -> None:
        from .admission import AccountScope

        if type(self.scope) is not AccountScope:
            raise ValueError("invalid baseline scope")
        if type(self.account_revision) is not int or self.account_revision <= 0:
            raise ValueError("invalid account baseline revision")
        if type(self.notional_unit) is not str or _UNIT.fullmatch(self.notional_unit) is None:
            raise ValueError("invalid baseline notional unit")
        object.__setattr__(
            self,
            "account_gross_notional",
            _decimal(self.account_gross_notional, "account_gross_notional"),
        )
        if type(self.strategy_baselines) is not tuple or any(
            type(item) is not StrategyGrossBaseline for item in self.strategy_baselines
        ):
            raise ValueError("strategy_baselines must be an immutable tuple")
        ids = [item.strategy_id for item in self.strategy_baselines]
        if ids != sorted(set(ids)):
            raise ValueError("strategy baseline identities must be unique and sorted")
        total = sum(
            (Fraction(item.gross_notional) for item in self.strategy_baselines), Fraction(0)
        )
        if total != Fraction(self.account_gross_notional):
            raise ValueError("baseline positions must be fully attributed to strategies")
        if (
            type(self.account_active_increase_intent_count) is not int
            or self.account_active_increase_intent_count < 0
            or self.account_active_increase_intent_count
            != sum(item.active_increase_intent_count for item in self.strategy_baselines)
        ):
            raise ValueError("baseline occupied-intent counts must be fully attributed")
        if (self.account_gross_notional > 0) != (self.account_active_increase_intent_count > 0):
            raise ValueError("baseline gross and occupied-intent count must agree")
        if type(self.unmanaged_open_order_count) is not int or self.unmanaged_open_order_count != 0:
            raise ValueError("baseline requires zero unmanaged open orders")
        if self.complete_positions is not True or self.complete_open_orders is not True:
            raise ValueError("baseline must prove complete positions and open orders")
        for name in (
            "source_snapshot_sha256",
            "positions_sha256",
            "open_orders_sha256",
            "valuation_facts_sha256",
            "writer_fence_sha256",
        ):
            _digest(getattr(self, name), name)
        _require_text(self.source_schema_version, "source_schema_version")
        _require_text(self.writer_owner_id, "writer_owner_id")
        if type(self.writer_fencing_token) is not int or self.writer_fencing_token <= 0:
            raise ValueError("invalid baseline writer fencing token")
        _validate_interval(self.observed_at_ns, self.valid_until_ns, "baseline")

    @property
    def fingerprint(self) -> str:
        return _proof_hash(
            {
                "scope_key": self.scope.key,
                "account_revision": self.account_revision,
                "notional_unit": self.notional_unit,
                "account_gross_notional": self.account_gross_notional,
                "account_active_increase_intent_count": self.account_active_increase_intent_count,
                "strategy_baselines": [
                    [
                        item.strategy_id,
                        _decimal_text(item.gross_notional),
                        item.active_increase_intent_count,
                    ]
                    for item in self.strategy_baselines
                ],
                "unmanaged_open_order_count": self.unmanaged_open_order_count,
                "complete_positions": self.complete_positions,
                "complete_open_orders": self.complete_open_orders,
                "source_snapshot_sha256": self.source_snapshot_sha256,
                "positions_sha256": self.positions_sha256,
                "open_orders_sha256": self.open_orders_sha256,
                "valuation_facts_sha256": self.valuation_facts_sha256,
                "source_schema_version": self.source_schema_version,
                "observed_at_ns": self.observed_at_ns,
                "valid_until_ns": self.valid_until_ns,
                "writer_owner_id": self.writer_owner_id,
                "writer_fencing_token": self.writer_fencing_token,
                "writer_fence_sha256": self.writer_fence_sha256,
            }
        )


@dataclass(frozen=True)
class VerifiedGrossExposureBaseline:
    """Authority receipt binding a baseline proof to a live account fence."""

    scope: AccountScope
    proof_sha256: str
    account_revision: int
    writer_owner_id: str
    writer_fencing_token: int
    writer_fence_sha256: str

    def __post_init__(self) -> None:
        _digest(self.proof_sha256, "proof_sha256")
        _digest(self.writer_fence_sha256, "writer_fence_sha256")
        _require_text(self.writer_owner_id, "writer_owner_id")
        if type(self.account_revision) is not int or self.account_revision <= 0:
            raise ValueError("invalid verified baseline revision")
        if type(self.writer_fencing_token) is not int or self.writer_fencing_token <= 0:
            raise ValueError("invalid verified baseline fencing token")


@dataclass(frozen=True)
class OrderExposureObservationProof:
    """One complete or explicitly unknown durable provider-order observation.

    Digests bind normalized facts and their source mapping.  The configured
    authority, not this constructor, proves those facts came from the exact
    account journal row under the current writer fence.
    """

    scope: AccountScope
    permit_id: str
    intent_id: str
    intent_hash: str
    dispatch_claim_digest: str
    dispatch_proof_sha256: str
    provider_order_id: str
    accepted_request_sha256: str
    exposure_reservation_id: str
    exposure_reservation_sha256: str
    order_revision: int
    journal_revision: int
    journal_record_sha256: str
    observation_sha256: str
    fill_history_sha256: str
    source_alias_map_sha256: str
    state: OrderExposureState
    requested_quantity: Decimal
    cumulative_filled_quantity: Decimal
    leaves_quantity: Decimal
    filled_gross_notional: Decimal
    leaves_gross_notional: Decimal
    leaves_valuation_price: Optional[Decimal]  # noqa: UP045 -- Python 3.9 is supported.
    notional_unit: str
    complete_order_snapshot: bool
    complete_fill_history: bool
    fill_watermark_revision: int
    source_contract_ref: str
    source_contract_version: str
    provider_profile_version: str
    normalizer_schema_version: str
    order_side: str
    position_effect: str
    fills: tuple[OrderFillFact, ...]
    fill_trade_count: int
    fill_ids_sha256: str
    instrument_id: str
    instrument_version: str
    instrument_multiplier: Decimal
    quote_currency: str
    valuation_unit: str
    instrument_metadata_sha256: str
    instrument_metadata_observed_at_ns: int
    instrument_metadata_valid_until_ns: int
    valuation_facts_sha256: str
    valuation_observed_at_ns: int
    valuation_valid_until_ns: int
    fx_pair: Optional[str]  # noqa: UP045 -- Python 3.9 is supported.
    fx_rate: Optional[Decimal]  # noqa: UP045 -- Python 3.9 is supported.
    fx_observed_at_ns: Optional[int]  # noqa: UP045 -- Python 3.9 is supported.
    fx_valid_until_ns: Optional[int]  # noqa: UP045 -- Python 3.9 is supported.
    observed_at_ns: int
    valid_until_ns: int
    writer_owner_id: str
    writer_fencing_token: int
    writer_fence_sha256: str

    def __post_init__(self) -> None:
        from .admission import AccountScope

        if type(self.scope) is not AccountScope:
            raise ValueError("invalid order observation scope")
        for name in (
            "permit_id",
            "intent_id",
            "provider_order_id",
            "exposure_reservation_id",
            "source_contract_ref",
            "source_contract_version",
            "provider_profile_version",
            "normalizer_schema_version",
            "instrument_id",
            "instrument_version",
            "writer_owner_id",
        ):
            _require_text(getattr(self, name), name)
        for name in (
            "intent_hash",
            "dispatch_claim_digest",
            "dispatch_proof_sha256",
            "accepted_request_sha256",
            "exposure_reservation_sha256",
            "journal_record_sha256",
            "observation_sha256",
            "fill_history_sha256",
            "fill_ids_sha256",
            "source_alias_map_sha256",
            "instrument_metadata_sha256",
            "valuation_facts_sha256",
            "writer_fence_sha256",
        ):
            _digest(getattr(self, name), name)
        for name in ("order_revision", "journal_revision"):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError("invalid " + name)
        if type(self.fill_watermark_revision) is not int or self.fill_watermark_revision < 0:
            raise ValueError("invalid fill_watermark_revision")
        if type(self.fill_trade_count) is not int or self.fill_trade_count < 0:
            raise ValueError("invalid fill_trade_count")
        if type(self.writer_fencing_token) is not int or self.writer_fencing_token <= 0:
            raise ValueError("invalid writer fencing token")
        if type(self.state) is not OrderExposureState:
            raise ValueError("invalid order exposure state")
        for name in ("requested_quantity", "instrument_multiplier"):
            object.__setattr__(self, name, _decimal(getattr(self, name), name, positive=True))
        for name in (
            "cumulative_filled_quantity",
            "leaves_quantity",
            "filled_gross_notional",
            "leaves_gross_notional",
        ):
            object.__setattr__(self, name, _decimal(getattr(self, name), name))
        if self.leaves_valuation_price is not None:
            object.__setattr__(
                self,
                "leaves_valuation_price",
                _decimal(self.leaves_valuation_price, "leaves_valuation_price", positive=True),
            )
        if self.cumulative_filled_quantity > self.requested_quantity:
            raise ValueError("filled quantity exceeds requested quantity")
        if type(self.fills) is not tuple or any(
            type(item) is not OrderFillFact for item in self.fills
        ):
            raise ValueError("fills must be an immutable OrderFillFact tuple")
        if self.fill_trade_count != len(self.fills):
            raise ValueError("fill trade count must equal the supplied immutable fill facts")
        if fill_ids_sha256(self.fills) != self.fill_ids_sha256:
            raise ValueError("fill ID digest does not match the immutable fill facts")
        if any(
            item.side != self.order_side or item.position_effect != self.position_effect
            for item in self.fills
        ):
            raise ValueError("fill side/effect must match the accepted order")
        fill_quantity = sum((Fraction(item.quantity) for item in self.fills), Fraction(0))
        if self.state is not OrderExposureState.UNKNOWN:
            if fill_quantity != Fraction(self.cumulative_filled_quantity):
                raise ValueError("complete fill quantities must equal cumulative filled quantity")
            if any(item.source_revision > self.fill_watermark_revision for item in self.fills):
                raise ValueError("fill watermark does not cover every supplied fill revision")
        elif fill_quantity > Fraction(self.cumulative_filled_quantity):
            raise ValueError("observed fill facts exceed cumulative filled quantity")
        for name in ("notional_unit", "quote_currency", "valuation_unit"):
            value = getattr(self, name)
            if type(value) is not str or _UNIT.fullmatch(value) is None:
                raise ValueError("invalid " + name)
        if (
            type(self.complete_order_snapshot) is not bool
            or type(self.complete_fill_history) is not bool
        ):
            raise ValueError("observation completeness flags must be boolean")
        if self.order_side not in ("BUY", "SELL"):
            raise ValueError("order_side must be a canonical BUY or SELL")
        if self.position_effect != "OPEN":
            raise ValueError("only source-proven opening exposure is supported")
        fx_values = (self.fx_pair, self.fx_rate, self.fx_observed_at_ns, self.fx_valid_until_ns)
        if any(value is not None for value in fx_values):
            if not all(value is not None for value in fx_values):
                raise ValueError(
                    "FX pair, rate, observed time, and expiry must be supplied together"
                )
            if self.fx_pair != self.quote_currency + "/" + self.valuation_unit:
                raise ValueError("FX pair must match quote and valuation units")
            object.__setattr__(self, "fx_rate", _decimal(self.fx_rate, "fx_rate", positive=True))
            _validate_interval(self.fx_observed_at_ns, self.fx_valid_until_ns, "FX facts")
        elif self.quote_currency != self.valuation_unit:
            raise ValueError("cross-currency valuation requires explicit FX facts")
        _validate_interval(self.observed_at_ns, self.valid_until_ns, "order observation")
        if (
            type(self.instrument_metadata_valid_until_ns) is not int
            or type(self.instrument_metadata_observed_at_ns) is not int
            or self.instrument_metadata_observed_at_ns <= 0
            or self.instrument_metadata_valid_until_ns <= self.instrument_metadata_observed_at_ns
        ):
            raise ValueError("invalid instrument metadata validity interval")
        if (
            type(self.valuation_observed_at_ns) is not int
            or type(self.valuation_valid_until_ns) is not int
            or self.valuation_observed_at_ns <= 0
            or self.valuation_valid_until_ns <= self.valuation_observed_at_ns
            or self.valuation_valid_until_ns > self.instrument_metadata_valid_until_ns
        ):
            raise ValueError("invalid valuation facts validity interval")
        if self.instrument_metadata_sha256 == "0" * 64:
            raise ValueError("instrument metadata digest cannot be a zero sentinel")
        if self.state is OrderExposureState.ACKED and (
            self.cumulative_filled_quantity != 0 or self.leaves_quantity != self.requested_quantity
        ):
            raise ValueError("ACKED requires zero fills and all requested quantity open")
        if self.state is OrderExposureState.PARTIALLY_FILLED and not (
            0 < self.cumulative_filled_quantity < self.requested_quantity
            and self.leaves_quantity == self.requested_quantity - self.cumulative_filled_quantity
        ):
            raise ValueError("PARTIALLY_FILLED quantities must reconcile to requested quantity")
        if self.state is OrderExposureState.FILLED and not (
            self.cumulative_filled_quantity == self.requested_quantity and self.leaves_quantity == 0
        ):
            raise ValueError("FILLED requires all requested quantity and zero leaves")
        if self.state in (OrderExposureState.CANCELLED, OrderExposureState.REJECTED) and (
            self.leaves_quantity != 0
        ):
            raise ValueError("terminal order observation must have zero open leaves")
        if (
            self.state is OrderExposureState.UNKNOWN
            and self.leaves_quantity > self.requested_quantity
        ):
            raise ValueError("unknown order leaves cannot exceed the requested quantity")
        if self.state is not OrderExposureState.UNKNOWN:
            if not self.complete_order_snapshot or not self.complete_fill_history:
                raise ValueError("known order state requires complete order and fill evidence")
            if self.fill_watermark_revision < self.order_revision:
                raise ValueError("fill history watermark does not cover the order revision")
            if self.valuation_observed_at_ns > self.observed_at_ns:
                raise ValueError("valuation facts cannot be newer than their order observation")
            if (
                self.fx_valid_until_ns is not None
                and self.valuation_valid_until_ns > self.fx_valid_until_ns
            ):
                raise ValueError("valuation facts outlive their FX evidence")
            if self.leaves_quantity > 0 and self.leaves_valuation_price is None:
                raise ValueError("open leaves require a source-backed valuation price")

    @property
    def fingerprint(self) -> str:
        values: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if name == "scope":
                values["scope_key"] = value.key
            elif isinstance(value, Decimal):
                values[name] = _decimal_text(value)
            elif isinstance(value, Enum):
                values[name] = value.value
            elif name == "fills":
                values[name] = [item.fingerprint for item in value]
            else:
                values[name] = value
        return _proof_hash(values)


@dataclass(frozen=True)
class VerifiedOrderExposureObservation:
    """Authority receipt for one exact observation and the active fence."""

    scope: AccountScope
    permit_id: str
    intent_id: str
    proof_sha256: str
    dispatch_claim_digest: str
    dispatch_proof_sha256: str
    order_revision: int
    journal_revision: int
    writer_owner_id: str
    writer_fencing_token: int
    writer_fence_sha256: str

    def __post_init__(self) -> None:
        for name in ("permit_id", "intent_id", "writer_owner_id"):
            _require_text(getattr(self, name), name)
        for name in (
            "proof_sha256",
            "dispatch_claim_digest",
            "dispatch_proof_sha256",
            "writer_fence_sha256",
        ):
            _digest(getattr(self, name), name)
        for name in ("order_revision", "journal_revision", "writer_fencing_token"):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError("invalid " + name)


@dataclass(frozen=True)
class OrderExposureSnapshot:
    """Risk-owned durable occupancy projection after a trusted observation."""

    scope: AccountScope
    permit_id: str
    intent_id: str
    order_revision: int
    journal_revision: int
    state: OrderExposureState
    requested_quantity: Decimal
    cumulative_filled_quantity: Decimal
    leaves_quantity: Decimal
    filled_gross_notional: Decimal
    open_gross_notional: Decimal
    notional_unit: str
    proof_sha256: str
    observed_at_ns: int
    valid_until_ns: int
    leaves_valuation_price: Optional[Decimal] = None  # noqa: UP045 -- Python 3.9 is supported.

    @property
    def total_gross_notional(self) -> Decimal:
        values = (self.filled_gross_notional, self.open_gross_notional)
        nonzero = [value for value in values if value]
        if not nonzero:
            return Decimal(0)
        precision = (
            max(value.adjusted() for value in nonzero)
            - min(value.as_tuple().exponent for value in nonzero)
            + 1
        )
        with localcontext() as context:
            context.prec = max(1, precision)
            return sum(values, Decimal(0))


class GrossExposureAuthority(Protocol):
    """Application authority that verifies evidence while holding the account fence."""

    def baseline_guard(
        self, proof: GrossExposureBaselineProof
    ) -> AbstractContextManager[
        Optional[VerifiedGrossExposureBaseline]  # noqa: UP045 -- Python 3.9 is supported.
    ]: ...

    def order_observation_guard(
        self,
        proof: OrderExposureObservationProof,
        *,
        claim: DispatchClaimBinding,
        tracked_order: DispatchTrackedOrderProof,
    ) -> AbstractContextManager[
        Optional[VerifiedOrderExposureObservation]  # noqa: UP045 -- Python 3.9 is supported.
    ]: ...


def verified_baseline_matches(proof: GrossExposureBaselineProof, receipt: object) -> bool:
    return type(receipt) is VerifiedGrossExposureBaseline and all(
        (
            receipt.scope == proof.scope,
            receipt.proof_sha256 == proof.fingerprint,
            receipt.account_revision == proof.account_revision,
            receipt.writer_owner_id == proof.writer_owner_id,
            receipt.writer_fencing_token == proof.writer_fencing_token,
            receipt.writer_fence_sha256 == proof.writer_fence_sha256,
        )
    )


def verified_observation_matches(proof: OrderExposureObservationProof, receipt: object) -> bool:
    return type(receipt) is VerifiedOrderExposureObservation and all(
        (
            receipt.scope == proof.scope,
            receipt.permit_id == proof.permit_id,
            receipt.intent_id == proof.intent_id,
            receipt.proof_sha256 == proof.fingerprint,
            receipt.dispatch_claim_digest == proof.dispatch_claim_digest,
            receipt.dispatch_proof_sha256 == proof.dispatch_proof_sha256,
            receipt.order_revision == proof.order_revision,
            receipt.journal_revision == proof.journal_revision,
            receipt.writer_owner_id == proof.writer_owner_id,
            receipt.writer_fencing_token == proof.writer_fencing_token,
            receipt.writer_fence_sha256 == proof.writer_fence_sha256,
        )
    )


def _require_text(value: object, name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError("invalid " + name)


def _validate_interval(start: object, end: object, name: str) -> None:
    if type(start) is not int or start <= 0 or type(end) is not int or end <= start:
        raise ValueError("invalid " + name + " validity interval")
