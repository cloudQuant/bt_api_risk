"""Server-side rule extension contract (Q32 / D64-08) and the built-in R-04 rule.

A rule only decides. The Risk host owns transactions, counters, latches,
control commands and audit. Rules are selected only from the trusted service
configuration (built-ins plus an allowlist of ``module:Class`` with an
expected version); a client request can never name a class. Any exception, a
non-``RuleDecision`` result, an unknown code or a version mismatch is a
fail-closed ``DENY risk_rule_failed``. Once a check has denied, later rules are
not evaluated, so no rule can turn an earlier DENY into PASS.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from bt_api_base.risk_service_protocol import (
    RISK_REFUSAL_CODES,
    RiskOrderView,
    RiskParentView,
)

RULE_OUTCOMES = frozenset({"PASS", "WARN", "DENY"})
RULE_PHASES = frozenset({"reserve", "claim"})
EFFECTS = frozenset({"INCREASE", "REDUCE"})
BREACH_ACTIONS = frozenset({"STOP_NEW", "FREEZE"})
BREACH_SCOPES = frozenset({"account", "strategy", "instrument"})
RULE_FAILED = "risk_rule_failed"


class RuleConfigError(ValueError):
    """Finite rule registry error; never echoes configuration values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class BreachRequest:
    """A rule's request that the host latch a scope and ask the Gateway for a control."""

    action: str
    scope_kind: str
    scope_value: str

    def __post_init__(self) -> None:
        if (
            self.action not in BREACH_ACTIONS
            or self.scope_kind not in BREACH_SCOPES
            or type(self.scope_value) is not str
            or (self.scope_kind == "account") != (self.scope_value == "")
        ):
            raise RuleConfigError("RULE_BREACH_INVALID")


@dataclass(frozen=True)
class RuleDecision:
    outcome: str
    code: str | None = None
    breach: BreachRequest | None = None

    def __post_init__(self) -> None:
        if self.outcome not in RULE_OUTCOMES:
            raise RuleConfigError("RULE_DECISION_INVALID")
        if self.outcome == "PASS" and self.code is not None:
            raise RuleConfigError("RULE_DECISION_INVALID")
        if self.outcome != "PASS" and self.code not in RISK_REFUSAL_CODES:
            raise RuleConfigError("RULE_DECISION_INVALID")
        if self.breach is not None and type(self.breach) is not BreachRequest:
            raise RuleConfigError("RULE_DECISION_INVALID")


PASS = RuleDecision("PASS")


@dataclass(frozen=True)
class RuleContext:
    """Read-only input to a rule.

    ``facts`` is the host's frozen fact snapshot, ``counters`` a read-only
    mapping of the counts relevant to this order, ``params`` the deep-frozen
    rule parameters from the policy.
    """

    phase: str
    view: RiskOrderView | None
    parent: RiskParentView | None
    effect: str
    facts: Any
    counters: Mapping[str, Any]
    trading_day: str
    params: Mapping[str, Any]
    policy_version: int


class RiskRule:
    """Base class for server-side rules. Subclasses set ``version`` and implement ``evaluate``."""

    version: int = 0

    def __init__(self, rule_id: str) -> None:
        self.rule_id = rule_id

    def evaluate(self, ctx: RuleContext) -> RuleDecision:  # pragma: no cover - abstract
        raise NotImplementedError


def _valid_decision(decision: object) -> bool:
    if type(decision) is not RuleDecision:
        return False
    # Re-validate: a rule could bypass __post_init__ with object.__new__.
    try:
        RuleDecision(decision.outcome, decision.code, decision.breach)  # type: ignore[attr-defined]
        if decision.breach is not None:  # type: ignore[attr-defined]
            breach = decision.breach  # type: ignore[attr-defined]
            BreachRequest(breach.action, breach.scope_kind, breach.scope_value)
    except (RuleConfigError, AttributeError, TypeError):
        return False
    return True


def run_rule(rule: RiskRule, expected_version: int, ctx: RuleContext) -> RuleDecision:
    """Evaluate one rule fail-closed."""
    if type(rule).version != expected_version:
        return RuleDecision("DENY", RULE_FAILED)
    try:
        decision = rule.evaluate(ctx)
    except Exception:
        return RuleDecision("DENY", RULE_FAILED)
    if not _valid_decision(decision):
        return RuleDecision("DENY", RULE_FAILED)
    return decision


class OrderCountStopNewRule(RiskRule):
    """Built-in R-04 (D64-08): account x instrument x trading-day order/cancel counts.

    Counters supplied by the host (claim phase):
    ``orders`` and ``cancels`` (counts already recorded for the instrument and
    trading day) and ``strategy_recent_orders`` (this strategy's claims inside
    the per-strategy window). The order being claimed is counted after this
    rule passes. When the count reaches ``block`` the rule requests an
    account x instrument STOP_NEW; further ordinary OPEN orders are refused with
    ``risk_order_count_limit``. CLOSE is never refused by this rule.
    """

    version = 1
    CODE = "risk_order_count_limit"

    def evaluate(self, ctx: RuleContext) -> RuleDecision:
        if ctx.phase != "claim" or ctx.view is None:
            return PASS
        params = ctx.params
        orders = params.get("orders")
        cancels = params.get("cancels")
        rate = params.get("per_strategy_rate")
        count = ctx.counters["orders"]
        cancel_count = ctx.counters["cancels"]
        if ctx.effect == "INCREASE":
            if rate is not None and ctx.counters["strategy_recent_orders"] >= rate["max_orders"]:
                return RuleDecision("DENY", self.CODE)
            if orders is not None and count >= orders["block"]:
                return RuleDecision("DENY", self.CODE)
            if cancels is not None and cancel_count >= cancels["block"]:
                return RuleDecision("DENY", self.CODE)
        after = count + 1
        if orders is not None and after >= orders["block"]:
            return RuleDecision(
                "WARN",
                self.CODE,
                BreachRequest("STOP_NEW", "instrument", ctx.view.instrument.instrument_id),
            )
        if orders is not None and after >= orders["warn"]:
            return RuleDecision("WARN", self.CODE)
        return PASS

    @staticmethod
    def cancel_breach(cancel_count_after: int, params: Mapping[str, Any]) -> bool:
        """True when an observed cancellation makes the cancel count reach its block."""
        cancels = params.get("cancels")
        return cancels is not None and cancel_count_after >= cancels["block"]


class RuleRegistry:
    """Trusted rule implementations: built-ins plus an allowlist from service configuration.

    ``allowlist`` maps ``"module:Class"`` to the expected class ``version``.
    ``r04`` may name a trusted subclass of :class:`OrderCountStopNewRule`.
    """

    def __init__(
        self,
        allowlist: Mapping[str, int] | None = None,
        *,
        r04: type[OrderCountStopNewRule] = OrderCountStopNewRule,
    ) -> None:
        if not isinstance(r04, type) or not issubclass(r04, OrderCountStopNewRule):
            raise RuleConfigError("RULE_BUILTIN_INVALID")
        entries = dict(allowlist or {})
        for name, version in entries.items():
            if type(name) is not str or ":" not in name or type(version) is not int or version <= 0:
                raise RuleConfigError("RULE_ALLOWLIST_INVALID")
        self._allowlist = MappingProxyType(entries)
        self._r04 = r04
        self._classes: dict[str, type[RiskRule]] = {}

    @property
    def allowlist(self) -> Mapping[str, int]:
        return self._allowlist

    def builtin_r04(self) -> tuple[RiskRule, int]:
        return self._r04("R-04"), self._r04.version

    def instantiate(self, rule_id: str, implementation: str, version: int) -> tuple[RiskRule, int]:
        """Load an allowlisted class; the expected version is the allowlisted one."""
        expected = self._allowlist.get(implementation)
        if expected is None or expected != version:
            raise RuleConfigError("RULE_NOT_ALLOWED")
        cls = self._classes.get(implementation)
        if cls is None:
            module_name, _, class_name = implementation.partition(":")
            try:
                module = importlib.import_module(module_name)
                cls = getattr(module, class_name)
            except (ImportError, AttributeError):
                raise RuleConfigError("RULE_UNAVAILABLE") from None
            if not isinstance(cls, type) or not issubclass(cls, RiskRule):
                raise RuleConfigError("RULE_NOT_A_RISK_RULE")
            self._classes[implementation] = cls
        return cls(rule_id), expected


__all__ = [
    "BREACH_ACTIONS",
    "BreachRequest",
    "EFFECTS",
    "OrderCountStopNewRule",
    "PASS",
    "RULE_FAILED",
    "RULE_OUTCOMES",
    "RULE_PHASES",
    "RiskRule",
    "RuleConfigError",
    "RuleContext",
    "RuleDecision",
    "RuleRegistry",
    "run_rule",
]
