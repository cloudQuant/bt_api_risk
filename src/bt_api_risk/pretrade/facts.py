"""Read-only fact values the pre-trade Risk core consumes.

Every value is a claim supplied by the trusted host (the SDK Risk service
host) from Gateway-bound sources. Any field may be None, which always means
"unknown" and never zero. Constructing a value proves nothing about its
source; the host is responsible for source binding and freshness. Numbers are
exact ``Decimal`` values; floats are refused.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType

from bt_api_base.market_protocol import MarketInstrumentKey

POSITION_SIDES = frozenset({"LONG", "SHORT"})
EVENT_KINDS = frozenset({"order", "trade", "order_error", "cancel_error"})
EVENT_STATUSES = frozenset(
    {"submitted", "accepted", "partially_filled", "filled", "cancelled", "rejected", "unknown"}
)
TERMINAL_STATUSES = frozenset({"filled", "cancelled", "rejected"})
_SIDES = frozenset({"BUY", "SELL"})
_OFFSETS = frozenset({"OPEN", "CLOSE", "CLOSE_TODAY", "CLOSE_YESTERDAY"})


class RiskFactError(ValueError):
    """Finite fact validation error; never echoes the offending value."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _ref(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and value.isprintable()
        and len(value) <= 256
    )


def _opt_ref(value: object) -> bool:
    return value is None or _ref(value)


def _opt_decimal(value: object, *, positive: bool) -> bool:
    if value is None:
        return True
    if type(value) is not Decimal or not value.is_finite():
        return False
    return value > 0 if positive else value >= 0


def _opt_ns(value: object) -> bool:
    return value is None or (type(value) is int and value >= 0)


def _opt_day(value: object) -> bool:
    return value is None or (type(value) is str and len(value) == 8 and value.isdigit())


def _opt_bool(value: object) -> bool:
    return value is None or type(value) is bool


def _instrument(value: object) -> bool:
    return type(value) is MarketInstrumentKey


@dataclass(frozen=True)
class PriceFact:
    """Latest trade price for an instrument as obtained by the Risk market principal."""

    instrument: MarketInstrumentKey
    last_price: Decimal | None = None
    source_time_ns: int | None = None
    received_time_ns: int | None = None
    quality_ok: bool | None = None

    def __post_init__(self) -> None:
        if not (
            _instrument(self.instrument)
            and _opt_decimal(self.last_price, positive=True)
            and _opt_ns(self.source_time_ns)
            and _opt_ns(self.received_time_ns)
            and _opt_bool(self.quality_ok)
        ):
            raise RiskFactError("RISK_FACT_INVALID")


@dataclass(frozen=True)
class InstrumentFacts:
    """Provider instrument facts forwarded by the Gateway."""

    instrument: MarketInstrumentKey
    multiplier: Decimal | None = None
    tick_size: Decimal | None = None
    expiry_trading_day: str | None = None

    def __post_init__(self) -> None:
        if not (
            _instrument(self.instrument)
            and _opt_decimal(self.multiplier, positive=True)
            and _opt_decimal(self.tick_size, positive=True)
            and _opt_day(self.expiry_trading_day)
        ):
            raise RiskFactError("RISK_FACT_INVALID")


@dataclass(frozen=True)
class AccountSnapshot:
    """Typed account snapshot (positions and funds) for the bound account.

    ``positions`` maps ``(instrument_id, "LONG"|"SHORT")`` to
    ``(today, yesterday)`` quantities. A missing key in a ``complete``
    snapshot means a zero position; in an incomplete snapshot nothing can be
    concluded. The host sets ``complete`` False when the snapshot is stale or
    partial.
    """

    as_of_ns: int | None = None
    trading_day: str | None = None
    positions: Mapping[tuple[str, str], tuple[Decimal, Decimal]] | None = None
    balance: Decimal | None = None
    available: Decimal | None = None
    margin: Decimal | None = None
    close_profit: Decimal | None = None
    position_profit: Decimal | None = None
    commission: Decimal | None = None
    equity: Decimal | None = None
    currency: str | None = None
    complete: bool = False

    def __post_init__(self) -> None:
        if not (
            _opt_ns(self.as_of_ns)
            and _opt_day(self.trading_day)
            and _opt_ref(self.currency)
            and type(self.complete) is bool
        ):
            raise RiskFactError("RISK_FACT_INVALID")
        for name in ("balance", "available", "margin", "commission", "equity"):
            if not _opt_decimal(getattr(self, name), positive=False):
                raise RiskFactError("RISK_FACT_INVALID")
        for name in ("close_profit", "position_profit"):
            value = getattr(self, name)
            if value is not None and (type(value) is not Decimal or not value.is_finite()):
                raise RiskFactError("RISK_FACT_INVALID")
        if self.positions is not None:
            frozen: dict[tuple[str, str], tuple[Decimal, Decimal]] = {}
            if not isinstance(self.positions, Mapping):
                raise RiskFactError("RISK_FACT_INVALID")
            for key, value in self.positions.items():
                if (
                    type(key) is not tuple
                    or len(key) != 2
                    or not _ref(key[0])
                    or key[1] not in POSITION_SIDES
                    or type(value) is not tuple
                    or len(value) != 2
                    or not all(_opt_decimal(item, positive=False) for item in value)
                    or any(item is None for item in value)
                ):
                    raise RiskFactError("RISK_FACT_INVALID")
                frozen[key] = value
            object.__setattr__(self, "positions", MappingProxyType(frozen))

    def position(self, instrument_id: str, side: str) -> tuple[Decimal, Decimal] | None:
        """Return (today, yesterday) or None when not provable."""
        if not self.complete or self.positions is None:
            return None
        return self.positions.get((instrument_id, side), (Decimal(0), Decimal(0)))


@dataclass(frozen=True)
class StrategyFinancialFact:
    """Gateway strategy financial projection (D63-44 value) for one strategy.

    ``day_start_value`` is optional; when the Gateway provides it, it is the
    strategy value at the start of ``trading_day``. Without it the ledger uses
    the first value it recorded for the trading day.
    """

    strategy_ref: str
    trading_day: str | None = None
    value: Decimal | None = None
    as_of_ns: int | None = None
    complete: bool = False
    day_start_value: Decimal | None = None

    def __post_init__(self) -> None:
        for name in ("value", "day_start_value"):
            value = getattr(self, name)
            if value is not None and (type(value) is not Decimal or not value.is_finite()):
                raise RiskFactError("RISK_FACT_INVALID")
        if not (
            _ref(self.strategy_ref)
            and _opt_day(self.trading_day)
            and _opt_ns(self.as_of_ns)
            and type(self.complete) is bool
        ):
            raise RiskFactError("RISK_FACT_INVALID")


@dataclass(frozen=True)
class MarginRateFact:
    """Provider margin rate row (ratio by money) for one instrument."""

    instrument: MarketInstrumentKey
    long_rate: Decimal | None = None
    short_rate: Decimal | None = None
    as_of_ns: int | None = None
    complete: bool = False

    def __post_init__(self) -> None:
        if not (
            _instrument(self.instrument)
            and _opt_decimal(self.long_rate, positive=True)
            and _opt_decimal(self.short_rate, positive=True)
            and _opt_ns(self.as_of_ns)
            and type(self.complete) is bool
        ):
            raise RiskFactError("RISK_FACT_INVALID")


@dataclass(frozen=True)
class ObservedExecutionEvent:
    """One event of the Gateway account observation stream, already typed by the host.

    ``strategy_ref`` None means external or unattributed. ``origin`` is
    ``self``, ``risk:<principal>``, ``execution:<principal>`` or ``external``.
    Order identity is, in order of preference, the request key (with origin and
    strategy), the Gateway reservation id, or the neutral venue order
    reference ``order_ref``; an order-shaped event needs at least one of them.
    Trades need ``trade_id``.
    """

    epoch: str
    sequence: int
    kind: str
    strategy_ref: str | None
    origin: str
    request_key: str | None
    reservation_id: str | None
    instrument: MarketInstrumentKey
    side: str
    offset: str | None
    status: str
    quantity: Decimal
    filled_quantity: Decimal
    limit_price: Decimal | None = None
    trade_id: str | None = None
    trade_price: Decimal | None = None
    trade_quantity: Decimal | None = None
    trading_day: str | None = None
    order_ref: str | None = None

    def __post_init__(self) -> None:
        ok = (
            _ref(self.epoch)
            and type(self.sequence) is int
            and self.sequence >= 0
            and self.kind in EVENT_KINDS
            and _opt_ref(self.strategy_ref)
            and _origin_ok(self.origin)
            and _opt_ref(self.request_key)
            and _opt_ref(self.reservation_id)
            and _opt_ref(self.order_ref)
            and _instrument(self.instrument)
            and self.side in _SIDES
            and (self.offset is None or self.offset in _OFFSETS)
            and self.status in EVENT_STATUSES
            and _opt_decimal(self.quantity, positive=True)
            and self.quantity is not None
            and _opt_decimal(self.filled_quantity, positive=False)
            and self.filled_quantity is not None
            and self.filled_quantity <= self.quantity
            and _opt_decimal(self.limit_price, positive=True)
            and _opt_ref(self.trade_id)
            and _opt_decimal(self.trade_price, positive=True)
            and _opt_decimal(self.trade_quantity, positive=True)
            and _opt_day(self.trading_day)
        )
        if not ok:
            raise RiskFactError("RISK_OBSERVATION_INVALID")
        if self.request_key is None and self.reservation_id is None and self.order_ref is None:
            raise RiskFactError("RISK_OBSERVATION_IDENTITY_MISSING")
        if self.kind == "trade" and (
            self.trade_id is None or self.trade_quantity is None or self.trade_price is None
        ):
            raise RiskFactError("RISK_OBSERVATION_INVALID")
        if self.kind != "trade" and self.trade_id is not None:
            raise RiskFactError("RISK_OBSERVATION_INVALID")

    @property
    def order_identity(self) -> str:
        """Stable order identity used for deduplication."""
        if self.request_key is not None:
            return "rk:" + self.origin + "|" + (self.strategy_ref or "") + "|" + self.request_key
        if self.reservation_id is not None:
            return "res:" + self.reservation_id
        return "ref:" + str(self.order_ref)


def _origin_ok(value: object) -> bool:
    if value in ("self", "external"):
        return True
    if type(value) is not str:
        return False
    for prefix in ("risk:", "execution:"):
        if value.startswith(prefix):
            return _ref(value[len(prefix) :])
    return False


__all__ = [
    "AccountSnapshot",
    "EVENT_KINDS",
    "EVENT_STATUSES",
    "InstrumentFacts",
    "MarginRateFact",
    "ObservedExecutionEvent",
    "POSITION_SIDES",
    "PriceFact",
    "RiskFactError",
    "StrategyFinancialFact",
    "TERMINAL_STATUSES",
]
