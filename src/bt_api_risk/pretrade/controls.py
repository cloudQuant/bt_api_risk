"""Built-in pre-trade controls (freeze 64.01 section 7) as pure functions.

Inputs are the order shape, the frozen fact snapshot and the exposure the
engine aggregated from the ledger inside its transaction. Every function
returns a finite refusal code or None. Unknown facts never pass a check that
needs them (INV64-05); CLOSE differences follow the freeze table.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal

from .facts import (
    AccountSnapshot,
    InstrumentFacts,
    MarginRateFact,
    PriceFact,
    StrategyFinancialFact,
)
from .policy import RiskPolicy

# Venues whose CLOSE draws on separate today/yesterday buckets (SHFE/INE, D63-49 / U64-1).
DATED_BUCKET_VENUES = frozenset({"SHFE", "INE"})
_NS_PER_MS = 1_000_000
_BPS = Decimal(10000)


def derive_effect(side: str, offset: str, venue: str) -> tuple[str, str, str]:
    """Return (effect, affected position side, close bucket) from an explicit offset."""
    if offset == "OPEN":
        return "INCREASE", ("LONG" if side == "BUY" else "SHORT"), "OPEN"
    position_side = "LONG" if side == "SELL" else "SHORT"
    if venue in DATED_BUCKET_VENUES:
        return "REDUCE", position_side, ("TODAY" if offset == "CLOSE_TODAY" else "YESTERDAY")
    return "REDUCE", position_side, "ALL"


@dataclass(frozen=True)
class OrderShape:
    strategy_ref: str
    instrument_id: str
    venue: str
    side: str
    offset: str
    effect: str
    position_side: str
    bucket: str
    quantity: Decimal
    limit_price: Decimal | None
    parent_ref: str | None = None

    @property
    def is_open(self) -> bool:
        return self.effect == "INCREASE"


@dataclass(frozen=True)
class FactSnapshot:
    now_ns: int
    trading_day: str | None
    reference: PriceFact | None
    instrument: InstrumentFacts | None
    account: AccountSnapshot | None
    strategy: StrategyFinancialFact | None
    margin_rate: MarginRateFact | None

    def usable_account(self) -> AccountSnapshot | None:
        account = self.account
        if (
            account is None
            or not account.complete
            or account.trading_day is None
            or account.trading_day != self.trading_day
            or account.as_of_ns is None
        ):
            return None
        return account


@dataclass(frozen=True)
class Exposure:
    """Worst-case aggregates for one order's instrument and affected position side."""

    continuity_verified: bool
    strategy_positions_verified: bool
    strategy_position: Decimal
    strategy_inflight_open: Decimal
    account_inflight_open: Decimal
    post_snapshot_open: Decimal
    post_snapshot_close: Mapping[str, Decimal] = field(default_factory=dict)
    account_inflight_close: Mapping[str, Decimal] = field(default_factory=dict)
    day_open_volume: Decimal = Decimal(0)
    day_inflight_open: Decimal = Decimal(0)
    uncovered_margin: Decimal | None = Decimal(0)
    envelope_credit: Decimal = Decimal(0)


def usable_reference(fact: PriceFact | None, now_ns: int, max_age_ms: int | None) -> Decimal | None:
    """Latest trade price if present, of good quality and (when an age is set) fresh."""
    if (
        fact is None
        or fact.last_price is None
        or fact.quality_ok is not True
        or fact.source_time_ns is None
        or fact.received_time_ns is None
    ):
        return None
    if max_age_ms is not None:
        oldest = min(fact.source_time_ns, fact.received_time_ns)
        if now_ns - oldest > max_age_ms * _NS_PER_MS:
            return None
    return fact.last_price


def check_quantity_cap(policy: RiskPolicy, order: OrderShape) -> str | None:
    """R-01: mandatory per (strategy, instrument); OPEN and CLOSE (D64-03)."""
    cap = policy.max_quantity.get(order.strategy_ref, {}).get(order.instrument_id)
    if cap is None:
        return "risk_limit_unconfigured"
    if order.quantity > cap:
        return "risk_order_quantity_exceeds_cap"
    return None


def check_notional_cap(policy: RiskPolicy, order: OrderShape, facts: FactSnapshot) -> str | None:
    """R-01b: quantity x price x multiplier; facts missing refuse OPEN only."""
    cap = policy.max_notional.get(order.strategy_ref, {}).get(order.instrument_id)
    if cap is None:
        return None
    multiplier = None if facts.instrument is None else facts.instrument.multiplier
    price = order.limit_price
    if price is None:
        price = usable_reference(facts.reference, facts.now_ns, None)
    if multiplier is None:
        return "risk_instrument_facts_unavailable" if order.is_open else None
    if price is None:
        return "risk_reference_price_unavailable" if order.is_open else None
    if order.quantity * price * multiplier > cap:
        return "risk_order_notional_exceeds_cap"
    return None


def check_price_band(policy: RiskPolicy, order: OrderShape, facts: FactSnapshot) -> str | None:
    """R-02: market orders refused for OPEN and CLOSE when enabled (D64-04)."""
    band = policy.price_band
    if band is None or not band.enabled:
        return None
    if order.limit_price is None:
        return "risk_price_band_market_order"
    if not (order.is_open or band.apply_to_close):
        return None
    ticks = band.ticks.get(order.instrument_id)
    bps = band.bps.get(order.instrument_id)
    if ticks is None and bps is None:
        return "risk_limit_unconfigured"
    reference = usable_reference(facts.reference, facts.now_ns, band.max_reference_age_ms)
    if reference is None:
        return "risk_reference_price_unavailable"
    deviation = abs(order.limit_price - reference)
    if ticks is not None:
        tick = None if facts.instrument is None else facts.instrument.tick_size
        if tick is None:
            return "risk_instrument_facts_unavailable"
        if deviation > ticks * tick:
            return "risk_price_band_exceeded"
        return None
    if deviation * _BPS > bps * reference:  # type: ignore[operator]
        return "risk_price_band_exceeded"
    return None


def _projected_add(order: OrderShape, exposure: Exposure) -> Decimal:
    return order.quantity - exposure.envelope_credit


def account_worst_position(
    order: OrderShape, facts: FactSnapshot, exposure: Exposure
) -> Decimal | None:
    """Filled account position + post-snapshot opens + in-flight opens + this order."""
    account = facts.usable_account()
    if account is None or not exposure.continuity_verified:
        return None
    position = account.position(order.instrument_id, order.position_side)
    if position is None:
        return None
    return (
        position[0]
        + position[1]
        + exposure.post_snapshot_open
        + exposure.account_inflight_open
        + _projected_add(order, exposure)
    )


def check_position(
    policy: RiskPolicy, order: OrderShape, facts: FactSnapshot, exposure: Exposure
) -> str | None:
    """R-03: worst-case position per strategy x instrument and account x instrument (OPEN)."""
    if not order.is_open:
        return None
    strategy_limits = policy.position_strategies.get(order.strategy_ref, {}).get(
        order.instrument_id
    )
    if strategy_limits is not None:
        if not exposure.strategy_positions_verified:
            return "risk_position_facts_unavailable"
        worst = (
            exposure.strategy_position
            + exposure.strategy_inflight_open
            + _projected_add(order, exposure)
        )
        if worst > strategy_limits.get(order.position_side):
            return "risk_position_limit_exceeded"
    account_limits = policy.position_account.get(order.instrument_id)
    if account_limits is not None:
        worst = account_worst_position(order, facts, exposure)
        if worst is None:
            return "risk_position_facts_unavailable"
        if worst > account_limits.get(order.position_side):
            return "risk_position_limit_exceeded"
    return None


def closable_quantity(order: OrderShape, facts: FactSnapshot, exposure: Exposure) -> Decimal | None:
    account = facts.usable_account()
    if account is None or not exposure.continuity_verified:
        return None
    position = account.position(order.instrument_id, order.position_side)
    if position is None:
        return None
    today, yesterday = position
    base = {"TODAY": today, "YESTERDAY": yesterday, "ALL": today + yesterday}[order.bucket]
    return (
        base
        - exposure.post_snapshot_close.get(order.bucket, Decimal(0))
        - exposure.account_inflight_close.get(order.bucket, Decimal(0))
    )


def check_closable(
    policy: RiskPolicy, order: OrderShape, facts: FactSnapshot, exposure: Exposure
) -> str | None:
    """R-03b: this close <= account closable - other in-flight closes (D63-49)."""
    if order.is_open or not policy.closable_check_enabled:
        return None
    available = closable_quantity(order, facts, exposure)
    if available is None:
        return "risk_closable_unverified"
    if _projected_add(order, exposure) > available:
        return "risk_closable_exceeded"
    return None


def margin_per_unit(order: OrderShape, facts: FactSnapshot) -> Decimal | None:
    """price x multiplier x rate for one unit of an OPEN, or None when any fact is missing."""
    if not order.is_open:
        return None
    rate_fact = facts.margin_rate
    if rate_fact is None or not rate_fact.complete:
        return None
    rate = rate_fact.long_rate if order.position_side == "LONG" else rate_fact.short_rate
    multiplier = None if facts.instrument is None else facts.instrument.multiplier
    price = order.limit_price
    if price is None:
        price = usable_reference(facts.reference, facts.now_ns, None)
    if rate is None or multiplier is None or price is None:
        return None
    return price * multiplier * rate


def check_margin(
    policy: RiskPolicy, order: OrderShape, facts: FactSnapshot, exposure: Exposure
) -> str | None:
    """R-08 (warn/deny): estimated margin vs available minus uncovered local occupancy."""
    if policy.margin_mode == "off" or not order.is_open:
        return None
    unit = margin_per_unit(order, facts)
    account = facts.usable_account()
    if (
        unit is None
        or account is None
        or account.available is None
        or exposure.uncovered_margin is None
    ):
        return "risk_margin_facts_unavailable"
    needed = unit * _projected_add(order, exposure)
    if needed + exposure.uncovered_margin > account.available:
        return "risk_margin_insufficient"
    return None


def check_exchange_rules(
    policy: RiskPolicy, order: OrderShape, facts: FactSnapshot, exposure: Exposure
) -> str | None:
    """R-11: trusted single-account rule file (position limit, daily open, no-open day)."""
    rules = policy.exchange_rules
    if rules is None or not order.is_open:
        return None
    rule = rules.instruments.get(order.instrument_id)
    if rule is None:
        return None
    if rule.no_open_from_trading_day is not None:
        if facts.trading_day is None:
            return "risk_exchange_rule_unavailable"
        if facts.trading_day >= rule.no_open_from_trading_day:
            return "risk_exchange_rule_exceeded"
    if rule.position_limit is not None:
        worst = account_worst_position(order, facts, exposure)
        if worst is None:
            return "risk_exchange_rule_unavailable"
        if worst > rule.position_limit.get(order.position_side):
            return "risk_exchange_rule_exceeded"
    if rule.daily_open_limit is not None:
        if not exposure.continuity_verified:
            return "risk_exchange_rule_unavailable"
        total = (
            exposure.day_open_volume + exposure.day_inflight_open + _projected_add(order, exposure)
        )
        if total > rule.daily_open_limit:
            return "risk_exchange_rule_exceeded"
    return None


def crosses(new_side: str, new_price: Decimal | None, resting_price: Decimal | None) -> bool:
    """R-05 price crossing: buy >= opposite sell; a market order crosses anything."""
    if new_price is None or resting_price is None:
        return True
    if new_side == "BUY":
        return new_price >= resting_price
    return new_price <= resting_price


def self_trade(
    new_side: str, new_price: Decimal | None, resting: Iterable[tuple[str, Decimal | None]]
) -> bool:
    """True when any opposite-side working order may match the new order."""
    return any(side != new_side and crosses(new_side, new_price, price) for side, price in resting)


def loss_values(account: AccountSnapshot | None) -> Decimal | None:
    """Account day profit from provider facts: close_profit + position_profit - commission."""
    if (
        account is None
        or account.close_profit is None
        or account.position_profit is None
        or account.commission is None
    ):
        return None
    return account.close_profit + account.position_profit - account.commission


__all__ = [
    "DATED_BUCKET_VENUES",
    "Exposure",
    "FactSnapshot",
    "OrderShape",
    "account_worst_position",
    "check_closable",
    "check_exchange_rules",
    "check_margin",
    "check_notional_cap",
    "check_position",
    "check_price_band",
    "check_quantity_cap",
    "closable_quantity",
    "crosses",
    "derive_effect",
    "loss_values",
    "margin_per_unit",
    "self_trade",
    "usable_reference",
]
