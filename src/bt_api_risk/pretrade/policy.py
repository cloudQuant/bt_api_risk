"""Policy document ``bt_api_risk.policy.v1`` (freeze 64.01 section 6).

The document is operator configuration, never a strategy request. Parsing is
strict: unknown keys are refused, numbers must be strings or integers that
parse to finite positive ``Decimal`` values (floats are refused), an enabled
control missing a required field is a configuration error (never "off"), and
mandatory limits have no default (INV64-03). Errors carry a finite code and,
at most, a fixed schema location; they never echo document values.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Any

POLICY_SCHEMA = "bt_api_risk.policy.v1"
EXCHANGE_RULES_SCHEMA = "bt_api_risk.exchange_rules.v1"
MARGIN_MODES = ("off", "warn", "deny")
DUPLICATE_ACTIONS = frozenset({"warn", "deny"})
BREACH_REQUESTS = {"stop_new": "STOP_NEW", "freeze": "FREEZE"}
CANCEL_ACTIONS = frozenset({"cancel_only", "stop_new_and_cancel"})
SCOPE_KINDS = frozenset({"account", "strategy", "instrument"})
LOSS_RULES = {
    "loss.account_day": frozenset({"account"}),
    "loss.account_drawdown": frozenset({"account"}),
    "loss.strategy_day": frozenset({"account", "strategy"}),
    "loss.strategy_drawdown": frozenset({"account", "strategy"}),
}
CUSTOM_RULE_SCOPES = frozenset({"account", "strategy", "instrument"})
_MAX_TEXT_BYTES = 1_048_576
_MAX_DEPTH = 12
_MAX_NODES = 100_000
_IMPLEMENTATION = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")


class RiskPolicyError(ValueError):
    """Finite policy validation error.

    ``where`` is a fixed schema location (built only from literal schema key
    names), never a value taken from the document.
    """

    def __init__(self, code: str, where: str | None = None) -> None:
        self.code = code
        self.where = where
        super().__init__(code if where is None else code + "@" + where)


def _fail(code: str, where: str | None = None) -> None:
    raise RiskPolicyError(code, where)


# ---------------------------------------------------------------- loading


def _strict_yaml_loader():
    try:
        import yaml
    except ImportError:  # pragma: no cover - depends on the installation
        _fail("policy_yaml_unavailable")

    class StrictLoader(yaml.SafeLoader):
        """SafeLoader without YAML 1.1 yes/no/on/off booleans or timestamps."""

    resolvers = {}
    for first, entries in yaml.SafeLoader.yaml_implicit_resolvers.items():
        kept = [
            (tag, regexp)
            for tag, regexp in entries
            if tag not in ("tag:yaml.org,2002:bool", "tag:yaml.org,2002:timestamp")
        ]
        if kept:
            resolvers[first] = kept
    StrictLoader.yaml_implicit_resolvers = resolvers
    StrictLoader.add_implicit_resolver(
        "tag:yaml.org,2002:bool",
        re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
        list("tTfF"),
    )

    def construct_mapping(loader, node, deep=False):
        loader.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if type(key) is not str:
                _fail("policy_invalid_key")
            if key in mapping:
                _fail("policy_duplicate_key")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    StrictLoader.add_constructor("tag:yaml.org,2002:map", construct_mapping)
    return yaml, StrictLoader


def _reject_float(_text: str) -> None:
    _fail("policy_float_refused")


def _reject_constant(_text: str) -> None:
    _fail("policy_float_refused")


def _json_pairs(pairs):
    mapping: dict[str, Any] = {}
    for key, value in pairs:
        if key in mapping:
            _fail("policy_duplicate_key")
        mapping[key] = value
    return mapping


def load_document(raw: object) -> Any:
    """Load YAML (strict safe loader) or JSON text, or accept an already parsed mapping."""
    if isinstance(raw, Mapping):
        return raw
    if type(raw) is bytes:
        if len(raw) > _MAX_TEXT_BYTES:
            _fail("policy_too_large")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            _fail("policy_invalid_document")
    if type(raw) is not str:
        _fail("policy_invalid_document")
    if len(raw.encode("utf-8")) > _MAX_TEXT_BYTES:
        _fail("policy_too_large")
    if raw.lstrip().startswith("{"):
        try:
            return json.loads(
                raw,
                object_pairs_hook=_json_pairs,
                parse_float=_reject_float,
                parse_constant=_reject_constant,
            )
        except RiskPolicyError:
            raise
        except (ValueError, RecursionError):
            _fail("policy_invalid_document")
    yaml, loader = _strict_yaml_loader()
    try:
        return yaml.load(raw, Loader=loader)
    except RiskPolicyError:
        raise
    except (yaml.YAMLError, RecursionError, ValueError, TypeError):
        _fail("policy_invalid_document")
    raise AssertionError("unreachable")


def _check_tree(value: object) -> None:
    """Refuse floats and non-plain types anywhere; bound depth and size."""
    stack = [(value, 0)]
    seen = 0
    while stack:
        item, depth = stack.pop()
        seen += 1
        if seen > _MAX_NODES or depth > _MAX_DEPTH:
            _fail("policy_too_large")
        if type(item) is float:
            _fail("policy_float_refused")
        if item is None or type(item) in (bool, int, str):
            continue
        if isinstance(item, Mapping):
            for key, element in item.items():
                if type(key) is not str:
                    _fail("policy_invalid_key")
                stack.append((element, depth + 1))
            continue
        if type(item) in (list, tuple):
            stack.extend((element, depth + 1) for element in item)
            continue
        _fail("policy_invalid_value")


# ---------------------------------------------------------------- scalar parsing


def _ref(value: object, where: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or not value.isprintable()
        or len(value) > 256
    ):
        _fail("policy_invalid_value", where)
    return value  # type: ignore[return-value]


def _mapping(value: object, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("policy_invalid_value", where)
    return value  # type: ignore[return-value]


def _keys(value: Mapping[str, Any], where: str, *, required=(), optional=()) -> None:
    allowed = set(required) | set(optional)
    for key in value:
        if key not in allowed:
            _fail("policy_unknown_key", where)
    for key in required:
        if key not in value:
            _fail("policy_missing_key", where)


def _decimal(value: object, where: str) -> Decimal:
    if type(value) is float:
        _fail("policy_float_refused", where)
    if type(value) is int:
        number = Decimal(value)
    elif type(value) is str and value and value == value.strip():
        try:
            number = Decimal(value)
        except InvalidOperation:
            _fail("policy_invalid_number", where)
    else:
        _fail("policy_invalid_number", where)
    if not number.is_finite() or number <= 0:
        _fail("policy_invalid_number", where)
    return number


def _count(value: object, where: str) -> int:
    number = _decimal(value, where)
    if number != number.to_integral_value():
        _fail("policy_invalid_number", where)
    return int(number)


def _bool(value: object, where: str) -> bool:
    if type(value) is not bool:
        _fail("policy_invalid_value", where)
    return value  # type: ignore[return-value]


def _day(value: object, where: str) -> str:
    if type(value) is not str or len(value) != 8 or not value.isdigit():
        _fail("policy_invalid_value", where)
    return value  # type: ignore[return-value]


def _text(value: Decimal) -> str:
    text = format(value.normalize(), "f")
    return text if text != "-0" else "0"


def _frozen(value: dict) -> Mapping:
    return MappingProxyType(value)


def _freeze_params(value: object) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_params(item) for key, item in value.items()})
    if type(value) in (list, tuple):
        return tuple(_freeze_params(item) for item in value)
    return value


def _plain(value: object) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [_plain(item) for item in value]
    return value


# ---------------------------------------------------------------- policy model


@dataclass(frozen=True)
class SideLimits:
    long: Decimal
    short: Decimal

    def get(self, side: str) -> Decimal:
        return self.long if side == "LONG" else self.short


@dataclass(frozen=True)
class PriceBandPolicy:
    enabled: bool
    ticks: Mapping[str, Decimal]
    bps: Mapping[str, Decimal]
    max_reference_age_ms: int | None
    apply_to_close: bool


@dataclass(frozen=True)
class Thresholds:
    warn: int
    block: int


@dataclass(frozen=True)
class RatePolicy:
    max_orders: int
    window_ms: int


@dataclass(frozen=True)
class CounterPolicy:
    orders: Thresholds | None
    cancels: Thresholds | None
    per_strategy_rate: RatePolicy | None


@dataclass(frozen=True)
class DuplicatePolicy:
    window_ms: int
    action: str


@dataclass(frozen=True)
class LossLimit:
    block: Decimal
    warn: Decimal | None = None


@dataclass(frozen=True)
class StrategyLoss:
    day: LossLimit | None
    drawdown: LossLimit | None


@dataclass(frozen=True)
class LossPolicy:
    account_day: LossLimit | None
    account_drawdown: LossLimit | None
    strategies: Mapping[str, StrategyLoss]


@dataclass(frozen=True)
class ExchangeInstrumentRule:
    position_limit: SideLimits | None
    daily_open_limit: Decimal | None
    no_open_from_trading_day: str | None


@dataclass(frozen=True)
class ExchangeRuleSet:
    rule_set_id: str
    instruments: Mapping[str, ExchangeInstrumentRule]
    digest: str
    canonical: str


@dataclass(frozen=True)
class BreachAction:
    rule: str
    request: str  # STOP_NEW | FREEZE
    scope: str


@dataclass(frozen=True)
class CancelRule:
    rule: str
    action: str  # cancel_only | stop_new_and_cancel
    scope: str


@dataclass(frozen=True)
class CustomRuleSpec:
    rule_id: str
    implementation: str
    version: int
    params: Mapping[str, Any]


@dataclass(frozen=True)
class RiskPolicy:
    """Validated, immutable policy. Identity is ``policy_id`` plus ``digest``."""

    policy_id: str
    route: str
    account_scope: str
    max_quantity: Mapping[str, Mapping[str, Decimal]]
    max_notional: Mapping[str, Mapping[str, Decimal]]
    price_band: PriceBandPolicy | None
    position_account: Mapping[str, SideLimits]
    position_strategies: Mapping[str, Mapping[str, SideLimits]]
    closable_check_enabled: bool
    counters: CounterPolicy | None
    self_trade_enabled: bool
    duplicate: DuplicatePolicy | None
    loss: LossPolicy | None
    margin_mode: str
    exchange_rules_file: str | None
    exchange_rules: ExchangeRuleSet | None
    breach_actions: tuple[BreachAction, ...]
    cancel_rules: tuple[CancelRule, ...]
    rules: tuple[CustomRuleSpec, ...]
    canonical: str = field(repr=False)
    digest: str = ""

    def breach_action_for(self, rule: str, scope: str) -> tuple[BreachAction, ...]:
        return tuple(
            item for item in self.breach_actions if item.rule == rule and item.scope == scope
        )

    def cancel_rules_for(self, rule: str) -> tuple[CancelRule, ...]:
        return tuple(item for item in self.cancel_rules if item.rule == rule)


def _side_limits(value: object, where: str) -> SideLimits:
    mapping = _mapping(value, where)
    _keys(mapping, where, required=("long", "short"))
    return SideLimits(_decimal(mapping["long"], where), _decimal(mapping["short"], where))


def _strategy_instrument_numbers(value: object, where: str) -> Mapping[str, Mapping[str, Decimal]]:
    result: dict[str, Mapping[str, Decimal]] = {}
    for strategy, per_instrument in _mapping(value, where).items():
        _ref(strategy, where)
        inner: dict[str, Decimal] = {}
        for instrument, number in _mapping(per_instrument, where).items():
            _ref(instrument, where)
            inner[instrument] = _decimal(number, where)
        result[strategy] = _frozen(inner)
    return _frozen(result)


def _thresholds(value: object, where: str) -> Thresholds:
    mapping = _mapping(value, where)
    _keys(mapping, where, required=("warn", "block"))
    warn, block = _count(mapping["warn"], where), _count(mapping["block"], where)
    if warn > block:
        _fail("policy_invalid_value", where)
    return Thresholds(warn, block)


def _loss_limit(value: object, where: str) -> LossLimit:
    mapping = _mapping(value, where)
    _keys(mapping, where, required=("block",), optional=("warn",))
    block = _decimal(mapping["block"], where)
    warn = None if "warn" not in mapping else _decimal(mapping["warn"], where)
    if warn is not None and warn > block:
        _fail("policy_invalid_value", where)
    return LossLimit(block=block, warn=warn)


def _parse_price_band(value: object) -> PriceBandPolicy:
    where = "price_band"
    mapping = _mapping(value, where)
    _keys(
        mapping,
        where,
        required=("enabled",),
        optional=(
            "max_deviation_ticks",
            "max_deviation_bps",
            "max_reference_age_ms",
            "apply_to_close",
        ),
    )
    enabled = _bool(mapping["enabled"], where)
    ticks: dict[str, Decimal] = {}
    bps: dict[str, Decimal] = {}
    for key, target in (("max_deviation_ticks", ticks), ("max_deviation_bps", bps)):
        for instrument, number in _mapping(mapping.get(key, {}), where).items():
            target[_ref(instrument, where)] = _decimal(number, where)
    if set(ticks) & set(bps):
        _fail("policy_invalid_value", where)
    age = None
    if "max_reference_age_ms" in mapping:
        age = _count(mapping["max_reference_age_ms"], where)
    apply_to_close = _bool(mapping.get("apply_to_close", False), where)
    if enabled and (age is None or not (ticks or bps)):
        _fail("policy_control_incomplete", where)
    return PriceBandPolicy(enabled, _frozen(ticks), _frozen(bps), age, apply_to_close)


def _parse_position(value: object):
    where = "position"
    mapping = _mapping(value, where)
    _keys(mapping, where, optional=("account", "strategies"))
    if not mapping:
        _fail("policy_control_incomplete", where)
    account: dict[str, SideLimits] = {}
    for instrument, limits in _mapping(mapping.get("account", {}), where).items():
        account[_ref(instrument, where)] = _side_limits(limits, where)
    strategies: dict[str, Mapping[str, SideLimits]] = {}
    for strategy, per_instrument in _mapping(mapping.get("strategies", {}), where).items():
        inner: dict[str, SideLimits] = {}
        for instrument, limits in _mapping(per_instrument, where).items():
            inner[_ref(instrument, where)] = _side_limits(limits, where)
        strategies[_ref(strategy, where)] = _frozen(inner)
    return _frozen(account), _frozen(strategies)


def _parse_counters(value: object) -> CounterPolicy:
    where = "counters"
    mapping = _mapping(value, where)
    _keys(mapping, where, optional=("orders", "cancels", "per_strategy_rate"))
    if not mapping:
        _fail("policy_control_incomplete", where)
    orders = None if "orders" not in mapping else _thresholds(mapping["orders"], "counters.orders")
    cancels = None
    if "cancels" in mapping:
        cancels = _thresholds(mapping["cancels"], "counters.cancels")
    rate = None
    if "per_strategy_rate" in mapping:
        rate_where = "counters.per_strategy_rate"
        raw = _mapping(mapping["per_strategy_rate"], rate_where)
        _keys(raw, rate_where, required=("max_orders", "window_ms"))
        rate = RatePolicy(
            _count(raw["max_orders"], rate_where), _count(raw["window_ms"], rate_where)
        )
    return CounterPolicy(orders, cancels, rate)


def _parse_loss(value: object) -> LossPolicy:
    where = "loss"
    mapping = _mapping(value, where)
    _keys(mapping, where, optional=("account_day", "account_drawdown", "strategies"))
    if not mapping:
        _fail("policy_control_incomplete", where)
    account_day = None
    if "account_day" in mapping:
        account_day = _loss_limit(mapping["account_day"], "loss.account_day")
    account_drawdown = None
    if "account_drawdown" in mapping:
        account_drawdown = _loss_limit(mapping["account_drawdown"], "loss.account_drawdown")
    strategies: dict[str, StrategyLoss] = {}
    for strategy, raw in _mapping(mapping.get("strategies", {}), "loss.strategies").items():
        _ref(strategy, "loss.strategies")
        entry = _mapping(raw, "loss.strategies")
        _keys(entry, "loss.strategies", optional=("day", "drawdown"))
        if not entry:
            _fail("policy_control_incomplete", "loss.strategies")
        strategies[strategy] = StrategyLoss(
            day=None if "day" not in entry else _loss_limit(entry["day"], "loss.strategies"),
            drawdown=None
            if "drawdown" not in entry
            else _loss_limit(entry["drawdown"], "loss.strategies"),
        )
    return LossPolicy(account_day, account_drawdown, _frozen(strategies))


def _parse_rules(value: object, allowlist: Mapping[str, int] | None) -> tuple[CustomRuleSpec, ...]:
    where = "rules"
    if type(value) is not list:
        _fail("policy_invalid_value", where)
    specs: list[CustomRuleSpec] = []
    seen: set[str] = set()
    for raw in value:  # type: ignore[union-attr]
        entry = _mapping(raw, where)
        _keys(entry, where, required=("id", "implementation", "version"), optional=("params",))
        rule_id = _ref(entry["id"], where)
        if rule_id in seen or rule_id in LOSS_RULES or rule_id.startswith(("R-", "loss.")):
            _fail("policy_invalid_value", where)
        seen.add(rule_id)
        implementation = _ref(entry["implementation"], where)
        if _IMPLEMENTATION.match(implementation) is None:
            _fail("policy_invalid_value", where)
        version = _count(entry["version"], where)
        params = _mapping(entry.get("params", {}), where)
        if allowlist is None or allowlist.get(implementation) != version:
            _fail("policy_rule_not_allowed", where)
        specs.append(CustomRuleSpec(rule_id, implementation, version, _freeze_params(params)))
    return tuple(specs)


def _scope(value: object, where: str) -> str:
    if value not in SCOPE_KINDS:
        _fail("policy_invalid_value", where)
    return value  # type: ignore[return-value]


def _rule_scopes(rule: str, custom_ids: set[str], where: str) -> frozenset[str]:
    if rule in LOSS_RULES:
        return LOSS_RULES[rule]
    if rule in custom_ids:
        return CUSTOM_RULE_SCOPES
    _fail("policy_invalid_value", where)
    raise AssertionError("unreachable")


def _parse_breach_actions(value: object, custom_ids: set[str]) -> tuple[BreachAction, ...]:
    where = "breach_actions"
    if type(value) is not list:
        _fail("policy_invalid_value", where)
    result: list[BreachAction] = []
    for raw in value:  # type: ignore[union-attr]
        entry = _mapping(raw, where)
        _keys(entry, where, required=("rule", "request", "scope"))
        rule = _ref(entry["rule"], where)
        request = BREACH_REQUESTS.get(entry["request"]) if type(entry["request"]) is str else None
        if request is None:
            _fail("policy_invalid_value", where)
        scope = _scope(entry["scope"], where)
        if scope not in _rule_scopes(rule, custom_ids, where):
            _fail("policy_invalid_value", where)
        item = BreachAction(rule, request, scope)  # type: ignore[arg-type]
        if item in result:
            _fail("policy_invalid_value", where)
        result.append(item)
    return tuple(result)


def _parse_cancel_rules(value: object, custom_ids: set[str]) -> tuple[CancelRule, ...]:
    where = "cancel_rules"
    if type(value) is not list:
        _fail("policy_invalid_value", where)
    result: list[CancelRule] = []
    for raw in value:  # type: ignore[union-attr]
        entry = _mapping(raw, where)
        _keys(entry, where, required=("rule", "action", "scope"))
        rule = _ref(entry["rule"], where)
        if entry["action"] not in CANCEL_ACTIONS:
            _fail("policy_invalid_value", where)
        scope = _scope(entry["scope"], where)
        if scope not in _rule_scopes(rule, custom_ids, where):
            _fail("policy_invalid_value", where)
        item = CancelRule(rule, entry["action"], scope)
        if any(existing.rule == rule and existing.scope == scope for existing in result):
            _fail("policy_invalid_value", where)
        result.append(item)
    return tuple(result)


def parse_exchange_rules(raw: object) -> ExchangeRuleSet:
    """Parse the trusted exchange rule file ``bt_api_risk.exchange_rules.v1`` (R-11)."""
    document = load_document(raw)
    _check_tree(document)
    where = "exchange_rules"
    mapping = _mapping(document, where)
    _keys(mapping, where, required=("schema", "rule_set_id", "instruments"))
    if mapping["schema"] != EXCHANGE_RULES_SCHEMA:
        _fail("policy_schema_unsupported", where)
    rule_set_id = _ref(mapping["rule_set_id"], where)
    instruments: dict[str, ExchangeInstrumentRule] = {}
    normalized: dict[str, Any] = {}
    for instrument, raw_rule in _mapping(mapping["instruments"], where).items():
        _ref(instrument, where)
        entry = _mapping(raw_rule, where)
        _keys(
            entry,
            where,
            optional=("position_limit", "daily_open_limit", "no_open_from_trading_day"),
        )
        if not entry:
            _fail("policy_control_incomplete", where)
        position = (
            None if "position_limit" not in entry else _side_limits(entry["position_limit"], where)
        )
        daily = (
            None if "daily_open_limit" not in entry else _decimal(entry["daily_open_limit"], where)
        )
        no_open = None
        if "no_open_from_trading_day" in entry:
            no_open = _day(entry["no_open_from_trading_day"], where)
        instruments[instrument] = ExchangeInstrumentRule(position, daily, no_open)
        normalized[instrument] = {
            "position_limit": None
            if position is None
            else {"long": _text(position.long), "short": _text(position.short)},
            "daily_open_limit": None if daily is None else _text(daily),
            "no_open_from_trading_day": no_open,
        }
    canonical = json.dumps(
        {"schema": EXCHANGE_RULES_SCHEMA, "rule_set_id": rule_set_id, "instruments": normalized},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return ExchangeRuleSet(rule_set_id, _frozen(instruments), digest, canonical)


def validate_policy_document(
    raw: object,
    *,
    exchange_rules_text: object = None,
    rule_allowlist: Mapping[str, int] | None = None,
) -> RiskPolicy:
    """Offline validator: parse and normalize a policy or raise ``RiskPolicyError``.

    ``exchange_rules_text`` is the content of the trusted file named by
    ``exchange_rules.file`` (the host resolves and reads it). ``rule_allowlist``
    is the trusted service configuration of custom rule implementations
    (``"module:Class" -> version``); a policy naming any other rule is refused.
    """
    document = load_document(raw)
    _check_tree(document)
    mapping = _mapping(document, "policy")
    _keys(
        mapping,
        "policy",
        required=("schema", "policy_id", "account", "per_order"),
        optional=(
            "price_band",
            "position",
            "closable_check",
            "counters",
            "self_trade",
            "duplicate",
            "loss",
            "margin_precheck",
            "exchange_rules",
            "breach_actions",
            "cancel_rules",
            "rules",
        ),
    )
    if mapping["schema"] != POLICY_SCHEMA:
        _fail("policy_schema_unsupported", "schema")
    policy_id = _ref(mapping["policy_id"], "policy_id")
    account = _mapping(mapping["account"], "account")
    _keys(account, "account", required=("route", "account_scope"))
    route = _ref(account["route"], "account")
    account_scope = _ref(account["account_scope"], "account")

    per_order = _mapping(mapping["per_order"], "per_order")
    _keys(per_order, "per_order", required=("max_quantity",), optional=("max_notional",))
    max_quantity = _strategy_instrument_numbers(per_order["max_quantity"], "per_order.max_quantity")
    max_notional = _strategy_instrument_numbers(
        per_order.get("max_notional", {}), "per_order.max_notional"
    )
    price_band = None if "price_band" not in mapping else _parse_price_band(mapping["price_band"])
    position_account: Mapping[str, SideLimits] = _frozen({})
    position_strategies: Mapping[str, Mapping[str, SideLimits]] = _frozen({})
    if "position" in mapping:
        position_account, position_strategies = _parse_position(mapping["position"])

    closable = True
    if "closable_check" in mapping:
        raw_closable = _mapping(mapping["closable_check"], "closable_check")
        _keys(raw_closable, "closable_check", required=("enabled",))
        closable = _bool(raw_closable["enabled"], "closable_check")

    counters = None if "counters" not in mapping else _parse_counters(mapping["counters"])

    self_trade = True
    if "self_trade" in mapping:
        raw_self = _mapping(mapping["self_trade"], "self_trade")
        _keys(raw_self, "self_trade", required=("enabled",), optional=("on_unverifiable",))
        self_trade = _bool(raw_self["enabled"], "self_trade")
        if raw_self.get("on_unverifiable", "deny") != "deny":
            _fail("policy_invalid_value", "self_trade")

    duplicate = None
    if "duplicate" in mapping:
        raw_dup = _mapping(mapping["duplicate"], "duplicate")
        _keys(raw_dup, "duplicate", required=("window_ms", "action"))
        if raw_dup["action"] not in DUPLICATE_ACTIONS:
            _fail("policy_invalid_value", "duplicate")
        duplicate = DuplicatePolicy(_count(raw_dup["window_ms"], "duplicate"), raw_dup["action"])

    loss = None if "loss" not in mapping else _parse_loss(mapping["loss"])

    margin_mode = "off"
    if "margin_precheck" in mapping:
        raw_margin = _mapping(mapping["margin_precheck"], "margin_precheck")
        _keys(raw_margin, "margin_precheck", required=("mode",))
        if raw_margin["mode"] not in MARGIN_MODES:
            _fail("policy_invalid_value", "margin_precheck")
        margin_mode = raw_margin["mode"]

    exchange_rules_file = None
    exchange_rules = None
    if "exchange_rules" in mapping:
        raw_rules = _mapping(mapping["exchange_rules"], "exchange_rules")
        _keys(raw_rules, "exchange_rules", required=("file",))
        exchange_rules_file = _ref(raw_rules["file"], "exchange_rules")
        if exchange_rules_text is None:
            _fail("policy_exchange_rules_unavailable", "exchange_rules")
        exchange_rules = parse_exchange_rules(exchange_rules_text)
    elif exchange_rules_text is not None:
        _fail("policy_invalid_value", "exchange_rules")

    rules = () if "rules" not in mapping else _parse_rules(mapping["rules"], rule_allowlist)
    custom_ids = {spec.rule_id for spec in rules}
    breach_actions: tuple[BreachAction, ...] = ()
    if "breach_actions" in mapping:
        breach_actions = _parse_breach_actions(mapping["breach_actions"], custom_ids)
    cancel_rules: tuple[CancelRule, ...] = ()
    if "cancel_rules" in mapping:
        cancel_rules = _parse_cancel_rules(mapping["cancel_rules"], custom_ids)

    normalized = {
        "schema": POLICY_SCHEMA,
        "policy_id": policy_id,
        "account": {"route": route, "account_scope": account_scope},
        "per_order": {
            "max_quantity": _numbers_text(max_quantity),
            "max_notional": _numbers_text(max_notional),
        },
        "price_band": None
        if price_band is None
        else {
            "enabled": price_band.enabled,
            "ticks": {key: _text(value) for key, value in price_band.ticks.items()},
            "bps": {key: _text(value) for key, value in price_band.bps.items()},
            "max_reference_age_ms": price_band.max_reference_age_ms,
            "apply_to_close": price_band.apply_to_close,
        },
        "position": {
            "account": {key: _limits_text(value) for key, value in position_account.items()},
            "strategies": {
                strategy: {key: _limits_text(value) for key, value in inner.items()}
                for strategy, inner in position_strategies.items()
            },
        },
        "closable_check": closable,
        "counters": None if counters is None else _counters_plain(counters),
        "self_trade": self_trade,
        "duplicate": None
        if duplicate is None
        else {"window_ms": duplicate.window_ms, "action": duplicate.action},
        "loss": None if loss is None else _loss_plain(loss),
        "margin_precheck": margin_mode,
        "exchange_rules": None
        if exchange_rules is None
        else {"file": exchange_rules_file, "digest": exchange_rules.digest},
        "breach_actions": sorted([item.rule, item.request, item.scope] for item in breach_actions),
        "cancel_rules": sorted([item.rule, item.action, item.scope] for item in cancel_rules),
        "rules": [
            {
                "id": spec.rule_id,
                "implementation": spec.implementation,
                "version": spec.version,
                "params": _plain(spec.params),
            }
            for spec in rules
        ],
    }
    canonical = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return RiskPolicy(
        policy_id=policy_id,
        route=route,
        account_scope=account_scope,
        max_quantity=max_quantity,
        max_notional=max_notional,
        price_band=price_band,
        position_account=position_account,
        position_strategies=position_strategies,
        closable_check_enabled=closable,
        counters=counters,
        self_trade_enabled=self_trade,
        duplicate=duplicate,
        loss=loss,
        margin_mode=margin_mode,
        exchange_rules_file=exchange_rules_file,
        exchange_rules=exchange_rules,
        breach_actions=breach_actions,
        cancel_rules=cancel_rules,
        rules=rules,
        canonical=canonical,
        digest=digest,
    )


def _numbers_text(value: Mapping[str, Mapping[str, Decimal]]) -> dict:
    return {
        strategy: {instrument: _text(number) for instrument, number in inner.items()}
        for strategy, inner in value.items()
    }


def _limits_text(value: SideLimits) -> dict:
    return {"long": _text(value.long), "short": _text(value.short)}


def _counters_plain(value: CounterPolicy) -> dict:
    return {
        "orders": None
        if value.orders is None
        else {"warn": value.orders.warn, "block": value.orders.block},
        "cancels": None
        if value.cancels is None
        else {"warn": value.cancels.warn, "block": value.cancels.block},
        "per_strategy_rate": None
        if value.per_strategy_rate is None
        else {
            "max_orders": value.per_strategy_rate.max_orders,
            "window_ms": value.per_strategy_rate.window_ms,
        },
    }


def _loss_limit_plain(value: LossLimit | None) -> dict | None:
    if value is None:
        return None
    return {"block": _text(value.block), "warn": None if value.warn is None else _text(value.warn)}


def _loss_plain(value: LossPolicy) -> dict:
    return {
        "account_day": _loss_limit_plain(value.account_day),
        "account_drawdown": _loss_limit_plain(value.account_drawdown),
        "strategies": {
            strategy: {
                "day": _loss_limit_plain(entry.day),
                "drawdown": _loss_limit_plain(entry.drawdown),
            }
            for strategy, entry in value.strategies.items()
        },
    }


# ---------------------------------------------------------------- hot update classification

# Item kinds: "cap" (higher is looser; absent means no limit), "required" (higher is
# looser; absent refuses everything), "protect" (presence/True is protective),
# "floor" (higher is tighter; absent means no protection), "mode" (off<warn<deny),
# "day_floor" (earlier date is tighter; absent means no protection), "opaque" (any
# change is classified as loosening because its direction cannot be proven).
_ABSENT = object()


def _items(policy: RiskPolicy) -> dict[str, tuple[str, Any]]:
    items: dict[str, tuple[str, Any]] = {}
    for strategy, inner in policy.max_quantity.items():
        for instrument, number in inner.items():
            items["per_order.max_quantity:" + strategy + ":" + instrument] = ("required", number)
    for strategy, inner in policy.max_notional.items():
        for instrument, number in inner.items():
            items["per_order.max_notional:" + strategy + ":" + instrument] = ("cap", number)
    band = policy.price_band
    items["price_band.enabled"] = ("protect", bool(band and band.enabled))
    if band is not None:
        for instrument, number in band.ticks.items():
            items["price_band.ticks:" + instrument] = ("required", number)
        for instrument, number in band.bps.items():
            items["price_band.bps:" + instrument] = ("required", number)
        if band.max_reference_age_ms is not None:
            items["price_band.max_reference_age_ms"] = ("cap", Decimal(band.max_reference_age_ms))
        items["price_band.apply_to_close"] = ("protect", band.apply_to_close)
    for instrument, limits in policy.position_account.items():
        items["position.account:" + instrument + ":long"] = ("cap", limits.long)
        items["position.account:" + instrument + ":short"] = ("cap", limits.short)
    for strategy, inner in policy.position_strategies.items():
        for instrument, limits in inner.items():
            prefix = "position.strategy:" + strategy + ":" + instrument
            items[prefix + ":long"] = ("cap", limits.long)
            items[prefix + ":short"] = ("cap", limits.short)
    items["closable_check.enabled"] = ("protect", policy.closable_check_enabled)
    if policy.counters is not None:
        for name in ("orders", "cancels"):
            limits = getattr(policy.counters, name)
            if limits is not None:
                items["counters." + name + ".warn"] = ("cap", Decimal(limits.warn))
                items["counters." + name + ".block"] = ("cap", Decimal(limits.block))
        rate = policy.counters.per_strategy_rate
        if rate is not None:
            items["counters.per_strategy_rate.max_orders"] = ("cap", Decimal(rate.max_orders))
            items["counters.per_strategy_rate.window_ms"] = ("floor", Decimal(rate.window_ms))
    items["self_trade.enabled"] = ("protect", policy.self_trade_enabled)
    if policy.duplicate is not None:
        items["duplicate.window_ms"] = ("floor", Decimal(policy.duplicate.window_ms))
        items["duplicate.deny"] = ("protect", policy.duplicate.action == "deny")
    if policy.loss is not None:
        for name in ("account_day", "account_drawdown"):
            limit = getattr(policy.loss, name)
            if limit is not None:
                items["loss." + name + ".block"] = ("cap", limit.block)
                if limit.warn is not None:
                    items["loss." + name + ".warn"] = ("cap", limit.warn)
        for strategy, entry in policy.loss.strategies.items():
            for name, limit in (("day", entry.day), ("drawdown", entry.drawdown)):
                if limit is not None:
                    key = "loss.strategy_" + name + ":" + strategy
                    items[key + ".block"] = ("cap", limit.block)
                    if limit.warn is not None:
                        items[key + ".warn"] = ("cap", limit.warn)
    items["margin_precheck.mode"] = ("mode", MARGIN_MODES.index(policy.margin_mode))
    if policy.exchange_rules is not None:
        for instrument, rule in policy.exchange_rules.instruments.items():
            prefix = "exchange_rules:" + instrument
            if rule.position_limit is not None:
                items[prefix + ":position_long"] = ("cap", rule.position_limit.long)
                items[prefix + ":position_short"] = ("cap", rule.position_limit.short)
            if rule.daily_open_limit is not None:
                items[prefix + ":daily_open"] = ("cap", rule.daily_open_limit)
            if rule.no_open_from_trading_day is not None:
                items[prefix + ":no_open_from"] = ("day_floor", rule.no_open_from_trading_day)
    for action in policy.breach_actions:
        items["breach:" + action.rule + "|" + action.request + "|" + action.scope] = (
            "protect",
            True,
        )
    for rule in policy.cancel_rules:
        items["cancel:" + rule.rule + "|" + rule.action + "|" + rule.scope] = ("protect", True)
    for spec in policy.rules:
        items["rule:" + spec.rule_id] = ("protect", True)
        spec_text = json.dumps(
            [spec.implementation, spec.version, _plain(spec.params)],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        items["rule:" + spec.rule_id + ":spec"] = ("opaque", spec_text)
    return items


def _direction(kind: str, old: Any, new: Any) -> str:
    if old is _ABSENT and new is _ABSENT:
        return "unchanged"
    if kind == "opaque":
        return "unchanged" if old == new else "loosened"
    if kind == "protect":
        old_on = old is not _ABSENT and old is True
        new_on = new is not _ABSENT and new is True
        if old_on == new_on:
            return "unchanged"
        return "tightened" if new_on else "loosened"
    if kind == "required":
        if old is _ABSENT:
            return "loosened"
        if new is _ABSENT:
            return "tightened"
    elif kind in ("cap", "floor", "day_floor"):
        if old is _ABSENT:
            return "tightened"
        if new is _ABSENT:
            return "loosened"
    elif kind == "mode":
        old = 0 if old is _ABSENT else old
        new = 0 if new is _ABSENT else new
    if old == new:
        return "unchanged"
    higher_is_tighter = kind in ("floor", "mode")
    if kind == "day_floor":
        return "tightened" if new < old else "loosened"
    if (new > old) == higher_is_tighter:
        return "tightened"
    return "loosened"


def classify_change(old: RiskPolicy | None, new: RiskPolicy) -> dict[str, list[str]]:
    """Classify every control/scope item as tightened, loosened or unchanged (D64-12).

    With no previous policy every order was refused, so a first policy is a
    loosening (``policy:bootstrap``).
    """
    result: dict[str, list[str]] = {"tightened": [], "loosened": [], "unchanged": []}
    if old is None:
        result["loosened"].append("policy:bootstrap")
        return result
    old_items, new_items = _items(old), _items(new)
    for key in sorted(set(old_items) | set(new_items)):
        kind = (new_items.get(key) or old_items.get(key))[0]
        old_value = old_items[key][1] if key in old_items else _ABSENT
        new_value = new_items[key][1] if key in new_items else _ABSENT
        result[_direction(kind, old_value, new_value)].append(key)
    return result


def item_family(key: str) -> str:
    """Latch control family affected by a classified item (used for D64-12 latch checks)."""
    if key.startswith("counters."):
        return "counters"
    if key.startswith("loss.account_day"):
        return "loss.account_day"
    if key.startswith("loss.account_drawdown"):
        return "loss.account_drawdown"
    if key.startswith("loss.strategy_day"):
        return "loss.strategy_day"
    if key.startswith("loss.strategy_drawdown"):
        return "loss.strategy_drawdown"
    if key.startswith(("breach:", "cancel:")):
        rule = key.split(":", 1)[1].split("|", 1)[0]
        return rule if rule in LOSS_RULES else "rule:" + rule
    if key.startswith("rule:"):
        return "rule:" + key[len("rule:") :].split(":", 1)[0]
    return key.split(":", 1)[0].split(".", 1)[0]


__all__ = [
    "BreachAction",
    "CancelRule",
    "CounterPolicy",
    "CustomRuleSpec",
    "DuplicatePolicy",
    "EXCHANGE_RULES_SCHEMA",
    "ExchangeInstrumentRule",
    "ExchangeRuleSet",
    "LossLimit",
    "LossPolicy",
    "MARGIN_MODES",
    "POLICY_SCHEMA",
    "PriceBandPolicy",
    "RatePolicy",
    "RiskPolicy",
    "RiskPolicyError",
    "SideLimits",
    "StrategyLoss",
    "Thresholds",
    "classify_change",
    "item_family",
    "load_document",
    "parse_exchange_rules",
    "validate_policy_document",
]
