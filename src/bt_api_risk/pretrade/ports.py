"""Ports the SDK Risk service host implements for the pre-trade core.

``bt_api_risk`` never imports the SDK, the Gateway or Execution packages
(INV64-02). The host composes these ports from its Gateway delegate, control,
observation and market clients. Replies are claims from the Gateway; only the
proof rules in :mod:`bt_api_risk.pretrade.engine` turn them into state.
Instrument scope strings for the control port use ``"<venue>:<native_symbol>"``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .facts import (
    AccountSnapshot,
    InstrumentFacts,
    MarginRateFact,
    PriceFact,
    StrategyFinancialFact,
)

CALLER_ROLES = frozenset({"strategy", "execution", "operator"})
GATEWAY_OUTCOMES = frozenset(
    {"OBSERVED", "QUEUED", "REQUEST_DENIED", "TRANSPORT_NOT_STARTED", "UNKNOWN"}
)
GATEWAY_COMMAND_STATES = frozenset(
    {"RESERVED", "DISPATCHING", "SENT", "NOT_SENT", "UNKNOWN", "RELEASED", "EXPIRED"}
)
CONTROL_OUTCOMES = frozenset({"OBSERVED", "REQUEST_DENIED", "TRANSPORT_NOT_STARTED", "UNKNOWN"})
CONTROL_MODES = frozenset({"STOP_NEW", "FREEZE", "DRAIN"})
CONTROL_SCOPE_KINDS = frozenset({"account", "strategy", "instrument"})


class PortValueError(ValueError):
    """Finite port value error; never echoes the offending value."""

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


@dataclass(frozen=True)
class CallerIdentity:
    """Authenticated caller, as installed by the service authority (never self-declared)."""

    principal_ref: str
    actor_ref: str
    role: str
    strategy_refs: frozenset[str]
    run_id: str | None
    operations: frozenset[str]

    def __post_init__(self) -> None:
        if (
            not _ref(self.principal_ref)
            or not _ref(self.actor_ref)
            or self.role not in CALLER_ROLES
            or type(self.strategy_refs) is not frozenset
            or not all(_ref(item) for item in self.strategy_refs)
            or not _opt_ref(self.run_id)
            or type(self.operations) is not frozenset
            or not all(_ref(item) for item in self.operations)
        ):
            raise PortValueError("RISK_CALLER_INVALID")


@dataclass(frozen=True)
class GatewayReply:
    """A Gateway delegate command reply as mapped by the host."""

    outcome: str
    state: str | None = None
    reservation_id: str | None = None
    version: int | None = None
    digest: str | None = None
    owner_generation: str | None = None
    reservation_generation: str | None = None
    code: str | None = None

    def __post_init__(self) -> None:
        if (
            self.outcome not in GATEWAY_OUTCOMES
            or (self.state is not None and self.state not in GATEWAY_COMMAND_STATES)
            or not all(
                _opt_ref(getattr(self, name))
                for name in (
                    "reservation_id",
                    "digest",
                    "owner_generation",
                    "reservation_generation",
                    "code",
                )
            )
            or (self.version is not None and (type(self.version) is not int or self.version < 0))
        ):
            raise PortValueError("RISK_GATEWAY_REPLY_INVALID")


class GatewayOrderPort(Protocol):
    def reserve(
        self,
        *,
        strategy_ref: str,
        run_id: str | None,
        request_key: str,
        canonical_payload: str,
        parent_ref: str | None,
        child_id: str | None,
        ttl_seconds: float,
    ) -> GatewayReply: ...

    def dispatch(
        self,
        *,
        strategy_ref: str,
        run_id: str | None,
        request_key: str,
        market_ref: dict | None,
    ) -> GatewayReply: ...

    def status(
        self, *, strategy_ref: str, run_id: str | None, request_key: str
    ) -> GatewayReply: ...

    def release(
        self, *, strategy_ref: str, run_id: str | None, request_key: str, operation_id: str
    ) -> GatewayReply: ...

    def cancel(
        self, *, strategy_ref: str, run_id: str | None, request_key: str, operation_id: str
    ) -> GatewayReply: ...


@dataclass(frozen=True)
class ControlReply:
    """A Gateway control port reply as mapped by the host."""

    outcome: str
    cause_id: str | None = None
    active: bool | None = None
    version: int | None = None
    code: str | None = None

    def __post_init__(self) -> None:
        if (
            self.outcome not in CONTROL_OUTCOMES
            or not _opt_ref(self.cause_id)
            or not _opt_ref(self.code)
            or (self.active is not None and type(self.active) is not bool)
            or (self.version is not None and (type(self.version) is not int or self.version < 0))
        ):
            raise PortValueError("RISK_CONTROL_REPLY_INVALID")


class GatewayControlPort(Protocol):
    def apply(
        self, *, cause_id: str, mode: str, scope_kind: str, scope_value: str
    ) -> ControlReply: ...

    def status(self, *, cause_id: str) -> ControlReply: ...

    def cancel_scope(
        self, *, operation_id: str, scope_kind: str, scope_value: str
    ) -> ControlReply: ...


class FactsPort(Protocol):
    """In-memory fact caches refreshed by the host; calls must be cheap and do no I/O."""

    def reference_price(self, instrument) -> PriceFact | None: ...

    def market_ref(self, instrument) -> dict | None: ...

    def instrument_facts(self, instrument) -> InstrumentFacts | None: ...

    def account_snapshot(self) -> AccountSnapshot | None: ...

    def strategy_financial(self, strategy_ref: str) -> StrategyFinancialFact | None: ...

    def margin_rate(self, instrument) -> MarginRateFact | None: ...

    def trading_day(self) -> str | None: ...


def instrument_scope_value(instrument) -> str:
    """Gateway control scope string for an instrument: ``<venue>:<native_symbol>``."""
    return instrument.venue + ":" + instrument.native_symbol


__all__ = [
    "CALLER_ROLES",
    "CONTROL_MODES",
    "CONTROL_OUTCOMES",
    "CONTROL_SCOPE_KINDS",
    "CallerIdentity",
    "ControlReply",
    "FactsPort",
    "GATEWAY_COMMAND_STATES",
    "GATEWAY_OUTCOMES",
    "GatewayControlPort",
    "GatewayOrderPort",
    "GatewayReply",
    "PortValueError",
    "instrument_scope_value",
]
