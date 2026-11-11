"""Shared fakes and harness for the pre-trade Risk core tests (UNIT/FAKE evidence only).

The fakes stand in for the SDK host ports. They never contact a Gateway,
provider or account.
"""

from __future__ import annotations

import hashlib
from contextlib import ExitStack
from decimal import Decimal
from pathlib import Path

from bt_api_base.market_protocol import MarketInstrumentKey
from bt_api_base.risk_service_protocol import (
    RISK_ADMIN_OPERATIONS,
    RISK_ORDER_OPERATIONS,
    RiskOrderView,
    RiskParentView,
    canonical_risk_json,
)

from bt_api_risk.core.admission import AccountScope
from bt_api_risk.pretrade import (
    AccountSnapshot,
    CallerIdentity,
    ControlReply,
    GatewayReply,
    InstrumentFacts,
    MarginRateFact,
    ObservedExecutionEvent,
    PolicyStore,
    PretradeEngine,
    PretradeLedger,
    PriceFact,
    RuleRegistry,
    StrategyFinancialFact,
)
from bt_api_risk.risk_order_journal import RiskOrderJournal

ROUTE = "CTP___FUTURE"
ACCOUNT = "acct-scope-ref"
DAY = "20261112"
NEXT_DAY = "20261113"
ACTOR = "risk-svc"
SCOPE = AccountScope(provider="ctp", account_id="acct-hash", environment="simnow")


def instrument(instrument_id: str, venue: str = "SHFE") -> MarketInstrumentKey:
    return MarketInstrumentKey(
        provider="ctp",
        venue=venue,
        environment="simnow",
        product_type="FUTURE",
        instrument_id=instrument_id,
        native_symbol=instrument_id,
    )


RB = instrument("rb2701")
HC = instrument("hc2701")
M = instrument("m2701", "DCE")


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_view(
    *,
    strategy: str = "strat-a",
    key: str = "k1",
    side: str = "BUY",
    offset: str | None = "OPEN",
    qty: str = "1",
    price: str | None = "100",
    inst: MarketInstrumentKey = RB,
    origin: str = "strategy",
    parent_ref: str | None = None,
    child_id: str | None = None,
    position_side: str = "NET",
    trading_day: str | None = None,
) -> RiskOrderView:
    return RiskOrderView(
        account_scope=ACCOUNT,
        route=ROUTE,
        strategy_ref=strategy,
        origin=origin,
        request_key=key,
        instrument=inst,
        side=side,
        offset=offset,
        position_side=position_side,
        quantity=Decimal(qty),
        quantity_unit="lot",
        order_type="MARKET" if price is None else "LIMIT",
        limit_price=None if price is None else Decimal(price),
        trading_day=trading_day,
        parent_ref=parent_ref,
        child_id=child_id,
    )


def payload_of(view: RiskOrderView) -> str:
    return canonical_risk_json(view.to_mapping())


def make_parent(
    *,
    strategy: str = "strat-a",
    parent_ref: str = "P1",
    side: str = "BUY",
    offset: str | None = "OPEN",
    total: str = "5",
    price: str | None = "100",
    inst: MarketInstrumentKey = RB,
    created: str = DAY,
    valid_until: str = NEXT_DAY,
) -> RiskParentView:
    return RiskParentView(
        account_scope=ACCOUNT,
        route=ROUTE,
        strategy_ref=strategy,
        parent_ref=parent_ref,
        instrument=inst,
        side=side,
        offset=offset,
        position_side="NET",
        total_quantity=Decimal(total),
        quantity_unit="lot",
        limit_price=None if price is None else Decimal(price),
        created_trading_day=created,
        valid_until_trading_day=valid_until,
    )


def caller(
    *strategies: str,
    role: str = "strategy",
    principal: str | None = None,
    run: str | None = "run-1",
    operations=None,
) -> CallerIdentity:
    strategies = strategies or ("strat-a",)
    return CallerIdentity(
        principal_ref=principal or ("p-" + strategies[0]),
        actor_ref="actor-" + strategies[0],
        role=role,
        strategy_refs=frozenset(strategies),
        run_id=run,
        operations=frozenset(RISK_ORDER_OPERATIONS if operations is None else operations),
    )


OPERATOR = CallerIdentity(
    principal_ref="operator-1",
    actor_ref="ops",
    role="operator",
    strategy_refs=frozenset(),
    run_id=None,
    operations=frozenset(RISK_ADMIN_OPERATIONS),
)


def base_policy(**sections) -> dict:
    document = {
        "schema": "bt_api_risk.policy.v1",
        "policy_id": "test-policy",
        "account": {"route": ROUTE, "account_scope": ACCOUNT},
        "per_order": {
            "max_quantity": {
                strategy: {"rb2701": "10", "hc2701": "10", "m2701": "10"}
                for strategy in ("strat-a", "strat-b", "strat-c")
            }
        },
    }
    document.update(sections)
    return document


class Clock:
    def __init__(self, value: int = 1_800_000_000_000_000_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value

    def advance_ms(self, ms: int) -> None:
        self.value += ms * 1_000_000


class FakeFacts:
    """In-memory FactsPort."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.day: str | None = DAY
        self.prices: dict[str, PriceFact | None] = {}
        self.instruments: dict[str, InstrumentFacts | None] = {}
        self.account: AccountSnapshot | None = None
        self.strategies: dict[str, StrategyFinancialFact | None] = {}
        self.margins: dict[str, MarginRateFact | None] = {}
        self.market_refs: dict[str, dict] = {}
        for item in (RB, HC, M):
            self.set_price(item, "100")
            self.instruments[item.instrument_id] = InstrumentFacts(
                instrument=item, multiplier=Decimal(10), tick_size=Decimal(1)
            )
        self.set_account()

    def set_price(
        self, item: MarketInstrumentKey, price: str | None, *, age_ms: int = 0, quality: bool = True
    ) -> None:
        if price is None:
            self.prices[item.instrument_id] = None
            return
        stamp = self.clock() - age_ms * 1_000_000
        self.prices[item.instrument_id] = PriceFact(
            instrument=item,
            last_price=Decimal(price),
            source_time_ns=stamp,
            received_time_ns=stamp,
            quality_ok=quality,
        )

    def set_account(
        self,
        positions=None,
        *,
        complete: bool = True,
        available: str = "1000000",
        close_profit: str = "0",
        position_profit: str = "0",
        commission: str = "0",
        equity: str = "1000000",
        day: str | None = None,
        as_of_ns: int | None = None,
    ):
        self.account = AccountSnapshot(
            as_of_ns=self.clock() if as_of_ns is None else as_of_ns,
            trading_day=day or self.day,
            positions={
                key: (Decimal(today), Decimal(yesterday))
                for key, (today, yesterday) in (positions or {}).items()
            },
            balance=Decimal(equity),
            available=Decimal(available),
            margin=Decimal(0),
            close_profit=Decimal(close_profit),
            position_profit=Decimal(position_profit),
            commission=Decimal(commission),
            equity=Decimal(equity),
            currency="CNY",
            complete=complete,
        )

    def reference_price(self, item):
        return self.prices.get(item.instrument_id)

    def market_ref(self, item):
        return self.market_refs.get(item.instrument_id)

    def instrument_facts(self, item):
        return self.instruments.get(item.instrument_id)

    def account_snapshot(self):
        return self.account

    def strategy_financial(self, strategy_ref):
        return self.strategies.get(strategy_ref)

    def margin_rate(self, item):
        return self.margins.get(item.instrument_id)

    def trading_day(self):
        return self.day


class FakeGateway:
    """GatewayOrderPort fake with a command table keyed by request key."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.commands: dict[str, dict] = {}
        self.script: dict[str, list] = {}
        self.hooks: dict[str, object] = {}

    def _scripted(self, method: str, kwargs: dict):
        hook = self.hooks.get(method)
        if hook is not None:
            hook(kwargs)
        queue = self.script.get(method)
        if queue:
            reply = queue.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply(kwargs) if callable(reply) else reply
        return None

    def count(self, method: str) -> int:
        return sum(1 for name, _ in self.calls if name == method)

    def reply_for(self, key: str, state: str, **overrides) -> GatewayReply:
        command = self.commands.get(key, {})
        values = {
            "outcome": "OBSERVED",
            "state": state,
            "reservation_id": command.get("reservation_id"),
            "digest": command.get("digest"),
            "owner_generation": "owner-1",
            "reservation_generation": "res-gen-1",
            "version": 1,
        }
        values.update(overrides)
        return GatewayReply(**values)

    def reserve(self, **kwargs):
        self.calls.append(("reserve", kwargs))
        key = kwargs["request_key"]
        hook = self.hooks.get("reserve")
        if hook is not None:  # a crash hook runs before the Gateway records anything
            hook(kwargs)
        self.commands[key] = {
            "digest": sha(kwargs["canonical_payload"]),
            "reservation_id": "res-" + key,
            "state": "RESERVED",
        }
        queue = self.script.get("reserve")
        scripted = None
        if queue:
            scripted = queue.pop(0)
            if isinstance(scripted, Exception):
                raise scripted
        if scripted is not None:
            return scripted
        return self.reply_for(key, "RESERVED")

    def dispatch(self, **kwargs):
        self.calls.append(("dispatch", kwargs))
        scripted = self._scripted("dispatch", kwargs)
        if scripted is not None:
            return scripted
        self.commands[kwargs["request_key"]]["state"] = "DISPATCHING"
        return self.reply_for(kwargs["request_key"], "DISPATCHING", outcome="QUEUED")

    def status(self, **kwargs):
        self.calls.append(("status", kwargs))
        scripted = self._scripted("status", kwargs)
        if scripted is not None:
            return scripted
        command = self.commands.get(kwargs["request_key"])
        if command is None:
            return GatewayReply("OBSERVED", code="NOT_FOUND")
        return self.reply_for(kwargs["request_key"], command["state"])

    def release(self, **kwargs):
        self.calls.append(("release", kwargs))
        scripted = self._scripted("release", kwargs)
        if scripted is not None:
            return scripted
        self.commands[kwargs["request_key"]]["state"] = "RELEASED"
        return self.reply_for(kwargs["request_key"], "RELEASED")

    def cancel(self, **kwargs):
        self.calls.append(("cancel", kwargs))
        return GatewayReply("OBSERVED")


class FakeControl:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.applied: dict[str, dict] = {}
        self.script: dict[str, list] = {}

    def _scripted(self, method: str, kwargs: dict):
        queue = self.script.get(method)
        if queue:
            reply = queue.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply
        return None

    def count(self, method: str) -> int:
        return sum(1 for name, _ in self.calls if name == method)

    def apply(self, **kwargs):
        self.calls.append(("apply", kwargs))
        scripted = self._scripted("apply", kwargs)
        if scripted is not None:
            return scripted
        self.applied[kwargs["cause_id"]] = kwargs
        return ControlReply("OBSERVED", cause_id=kwargs["cause_id"], active=True, version=1)

    def status(self, **kwargs):
        self.calls.append(("status", kwargs))
        scripted = self._scripted("status", kwargs)
        if scripted is not None:
            return scripted
        active = kwargs["cause_id"] in self.applied
        return ControlReply("OBSERVED", cause_id=kwargs["cause_id"], active=active)

    def cancel_scope(self, **kwargs):
        self.calls.append(("cancel_scope", kwargs))
        scripted = self._scripted("cancel_scope", kwargs)
        if scripted is not None:
            return scripted
        return ControlReply("OBSERVED")


class Harness:
    """Owns the journal, writer fence, ledger and engine for one test."""

    def __init__(
        self,
        path: Path,
        *,
        registry: RuleRegistry | None = None,
        clock: Clock | None = None,
        facts: FakeFacts | None = None,
        gateway: FakeGateway | None = None,
        control: FakeControl | None = None,
    ) -> None:
        self.path = path
        self.stack = ExitStack()
        self.clock = clock or Clock()
        self.facts = facts or FakeFacts(self.clock)
        self.gateway = gateway or FakeGateway()
        self.control = control or FakeControl()
        self.registry = registry or RuleRegistry()
        self.engine: PretradeEngine | None = None
        self.open()

    def open(self) -> PretradeEngine:
        self.journal = RiskOrderJournal(self.path, writer_id="risk-test")
        self.fence = self.stack.enter_context(self.journal.writer_fence(SCOPE))
        self.ledger = PretradeLedger(self.journal, self.fence)
        self.store = PolicyStore(self.ledger)
        self.engine = PretradeEngine(
            self.ledger,
            self.store,
            self.registry,
            self.facts,
            self.gateway,
            self.control,
            account_scope=ACCOUNT,
            route=ROUTE,
            now_ns=self.clock,
            reservation_ttl_seconds=10.0,
            actor_principal=ACTOR,
        )
        return self.engine

    def restart(self) -> PretradeEngine:
        """Simulate a crash and restart on the same database file."""
        self.stack.close()
        self.stack = ExitStack()
        return self.open()

    def close(self) -> None:
        self.stack.close()

    # convenience -------------------------------------------------------------
    def publish(self, document: dict, reason: str | None = "test", **kwargs):
        engine = self.engine
        version = engine.status_summary()["policy_version"] or 0
        return engine.publish_policy(OPERATOR, document, version, reason, **kwargs)

    def verify_stream(self, epoch: str = "e1") -> None:
        self.engine.reset_observations(epoch, -1)

    def reserve(self, view: RiskOrderView, who: CallerIdentity | None = None, run: str = "run-1"):
        return self.engine.reserve(who or caller(view.strategy_ref), view, payload_of(view), run)

    def dispatch(self, view: RiskOrderView, reserved, who: CallerIdentity | None = None):
        return self.engine.dispatch(
            who or caller(view.strategy_ref),
            view.request_key,
            reserved.permit_id,
            reserved.reservation_id,
            view.digest(),
        )

    def place(self, view: RiskOrderView, who: CallerIdentity | None = None):
        reserved = self.reserve(view, who)
        if reserved.outcome != "RESERVED":
            return reserved
        return self.dispatch(view, reserved, who)


def event(
    seq: int,
    *,
    kind: str = "order",
    strategy: str | None = None,
    origin: str = "external",
    key: str | None = None,
    reservation_id: str | None = None,
    order_ref: str | None = None,
    inst: MarketInstrumentKey = RB,
    side: str = "BUY",
    offset: str | None = "OPEN",
    status: str = "accepted",
    qty: str = "1",
    filled: str = "0",
    price: str | None = "100",
    trade_id: str | None = None,
    trade_qty: str | None = None,
    trade_price: str = "100",
    epoch: str = "e1",
    day: str | None = DAY,
) -> ObservedExecutionEvent:
    if key is None and reservation_id is None and order_ref is None:
        order_ref = "ext-" + str(seq)
    return ObservedExecutionEvent(
        epoch=epoch,
        sequence=seq,
        kind=kind,
        strategy_ref=strategy,
        origin=origin,
        request_key=key,
        reservation_id=reservation_id,
        instrument=inst,
        side=side,
        offset=offset,
        status=status,
        quantity=Decimal(qty),
        filled_quantity=Decimal(filled),
        limit_price=None if price is None else Decimal(price),
        trade_id=trade_id,
        trade_price=None if trade_id is None else Decimal(trade_price),
        trade_quantity=None if trade_id is None else Decimal(trade_qty or qty),
        trading_day=day,
        order_ref=order_ref,
    )


def test_support_fakes_are_consistent(tmp_path):
    harness = Harness(tmp_path / "risk.db")
    try:
        assert harness.engine.status_summary()["available"] is False
        assert harness.facts.trading_day() == DAY
    finally:
        harness.close()
