"""Pre-trade Risk engine (freeze 64.01 sections 4, 5, 7, 8).

The engine authorizes the authenticated caller, derives the order effect
from the explicit offset (INV64-04), evaluates L1+L2 at reserve and L3 at
claim inside one ledger transaction each, and only then calls the Gateway.
It never holds a ledger transaction while calling a port. Occupancy is
released only on a NOT_SENT proof (freeze section 5): a definite Gateway
refusal of the reserve call, or a Gateway status/release reply in a terminal
RELEASED/EXPIRED/NOT_SENT state whose digest, reservation id and generations
match the permit. NOT_FOUND, timeouts and local TTL expiry are never proof.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from decimal import Decimal
from typing import Any

from bt_api_base.market_protocol import MarketInstrumentKey
from bt_api_base.risk_service_protocol import (
    RiskOrderResult,
    RiskOrderView,
    RiskParentView,
)

from .controls import (
    Exposure,
    FactSnapshot,
    OrderShape,
    check_closable,
    check_exchange_rules,
    check_margin,
    check_notional_cap,
    check_position,
    check_price_band,
    check_quantity_cap,
    derive_effect,
    loss_values,
    margin_per_unit,
    self_trade,
)
from .facts import (
    TERMINAL_STATUSES,
    AccountSnapshot,
    InstrumentFacts,
    MarginRateFact,
    ObservedExecutionEvent,
    PriceFact,
    StrategyFinancialFact,
)
from .ledger import OCCUPYING_STATES, WORKING_STATES, LedgerTxn, Parent, Permit, PretradeLedger, T
from .policy import (
    LossPolicy,
    RiskPolicy,
    RiskPolicyError,
    classify_change,
    item_family,
    load_document,
    validate_policy_document,
)
from .policy_store import ActivePolicy, PolicyStore, activate
from .ports import (
    CallerIdentity,
    ControlReply,
    GatewayReply,
    instrument_scope_value,
)
from .rules import RuleConfigError, RuleContext, RuleDecision, RuleRegistry, run_rule

NOT_SENT_STATES = frozenset({"RELEASED", "EXPIRED", "NOT_SENT"})
SENT_STATES = frozenset({"DISPATCHING", "SENT"})
_OUTCOME_BY_STATE = {
    "RESERVING": "UNKNOWN",
    "RESERVED": "RESERVED",
    "CLAIMED": "UNKNOWN",
    "DISPATCHED": "DISPATCHED",
    "RELEASING": "UNKNOWN",
    "RELEASED": "RELEASED",
    "DENIED": "DENIED",
    "UNKNOWN": "UNKNOWN",
    "TERMINAL": "TERMINAL",
}
_MAX_PAYLOAD = 1_048_576
_NS_PER_MS = 1_000_000
_MAX_GATEWAY_TTL_SECONDS = 30.0


class RiskRequestError(ValueError):
    """A request so malformed that no typed result can name it (finite code)."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RiskAdminError(RuntimeError):
    """Finite refusal of an operator (admin) operation."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RiskEngineConfigError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _ref(value: object, limit: int = 256) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and value.isprintable()
        and len(value) <= limit
    )


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def proves_not_sent(reply: object, permit: Permit) -> bool:
    """NOT_SENT proof from a Gateway status/release reply (freeze section 5, item 2)."""
    if type(reply) is not GatewayReply:
        return False
    if reply.outcome != "OBSERVED" or reply.state not in NOT_SENT_STATES:
        return False
    if reply.digest is None or reply.digest != permit.payload_digest:
        return False
    if permit.reservation_id is not None and reply.reservation_id != permit.reservation_id:
        return False
    if permit.owner_generation is not None and reply.owner_generation != permit.owner_generation:
        return False
    return (
        permit.reservation_generation is None
        or reply.reservation_generation == permit.reservation_generation
    )


def reserve_refused(reply: GatewayReply) -> bool:
    """NOT_SENT proof for the reserve call only (freeze section 5, item 1)."""
    return reply.outcome in ("REQUEST_DENIED", "TRANSPORT_NOT_STARTED")


@dataclass(frozen=True)
class RiskParentResult:
    """Answer of risk.parent.* (64.10). Quantities are exact decimals."""

    parent_ref: str
    outcome: str  # RESERVED | DENIED | RELEASED | NOT_FOUND
    state: str | None = None  # ACTIVE | FROZEN | RELEASED | DENIED
    code: str | None = None
    total_quantity: Decimal | None = None
    allocated_quantity: Decimal | None = None
    unallocated_quantity: Decimal | None = None
    policy_version: str | None = None


@dataclass(frozen=True)
class PolicyPublishResult:
    version: int
    policy_id: str
    digest: str
    published: bool
    classification: dict


@dataclass
class _Breach:
    control: str  # latch family: counters | loss.* | rule:<id>
    rule: str  # breach_actions / cancel_rules rule name
    scope_kind: str
    strategy_ref: str | None
    instrument: MarketInstrumentKey | None
    latch_code: str
    reason: str
    modes: tuple[tuple[str, str], ...] = ()  # (mode, scope_kind)


@dataclass
class _Evaluation:
    code: str | None = None
    warnings: list[str] = field(default_factory=list)
    breaches: list[_Breach] = field(default_factory=list)
    margin_per_unit: Decimal | None = None
    credit: Decimal = Decimal(0)


class PretradeEngine:
    """Independent Risk service core for one account (D64-15)."""

    def __init__(
        self,
        ledger: PretradeLedger,
        policy_store: PolicyStore,
        rules: RuleRegistry,
        facts,
        gateway,
        control,
        *,
        account_scope: str,
        route: str,
        now_ns: Callable[[], int],
        reservation_ttl_seconds: float,
        actor_principal: str,
    ) -> None:
        if type(ledger) is not PretradeLedger or type(policy_store) is not PolicyStore:
            raise RiskEngineConfigError("RISK_ENGINE_LEDGER_REQUIRED")
        if policy_store.ledger is not ledger or not isinstance(rules, RuleRegistry):
            raise RiskEngineConfigError("RISK_ENGINE_CONFIG_INVALID")
        if not (_ref(account_scope) and _ref(route) and _ref(actor_principal) and callable(now_ns)):
            raise RiskEngineConfigError("RISK_ENGINE_CONFIG_INVALID")
        if (
            type(reservation_ttl_seconds) not in (int, float)
            or not reservation_ttl_seconds > 0
            or reservation_ttl_seconds > _MAX_GATEWAY_TTL_SECONDS
        ):
            raise RiskEngineConfigError("RISK_ENGINE_TTL_INVALID")
        self._ledger = ledger
        self._store = policy_store
        self._rules = rules
        self._facts = facts
        self._gateway = gateway
        self._control = control
        self._account_scope = account_scope
        self._route = route
        self._clock = now_ns
        self._ttl = float(reservation_ttl_seconds)
        self._actor = actor_principal
        self._origin = "risk:" + actor_principal
        self._active: ActivePolicy | None = policy_store.load(rules)

    # ================================================================== helpers

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0:
            raise RiskEngineConfigError("RISK_ENGINE_CLOCK_INVALID")
        return value

    def _fact(self, name: str, expected: type, *args: Any) -> Any:
        try:
            value = getattr(self._facts, name)(*args)
        except Exception:
            return None
        return value if type(value) is expected else None

    def _gather(self, instrument: MarketInstrumentKey, strategy_ref: str | None) -> FactSnapshot:
        trading_day = self._fact("trading_day", str)
        if trading_day is not None and (len(trading_day) != 8 or not trading_day.isdigit()):
            trading_day = None
        return FactSnapshot(
            now_ns=self._now(),
            trading_day=trading_day,
            reference=self._fact("reference_price", PriceFact, instrument),
            instrument=self._fact("instrument_facts", InstrumentFacts, instrument),
            account=self._fact("account_snapshot", AccountSnapshot),
            strategy=None
            if strategy_ref is None
            else self._fact("strategy_financial", StrategyFinancialFact, strategy_ref),
            margin_rate=self._fact("margin_rate", MarginRateFact, instrument),
        )

    def _gateway_call(self, name: str, **kwargs: Any) -> GatewayReply:
        try:
            reply = getattr(self._gateway, name)(**kwargs)
        except Exception:
            return GatewayReply("UNKNOWN", code="RISK_PORT_EXCEPTION")
        if type(reply) is not GatewayReply:
            return GatewayReply("UNKNOWN", code="RISK_PORT_REPLY_INVALID")
        return reply

    def _control_call(self, name: str, **kwargs: Any) -> ControlReply:
        try:
            reply = getattr(self._control, name)(**kwargs)
        except Exception:
            return ControlReply("UNKNOWN", code="RISK_PORT_EXCEPTION")
        if type(reply) is not ControlReply:
            return ControlReply("UNKNOWN", code="RISK_PORT_REPLY_INVALID")
        return reply

    @staticmethod
    def _instrument_of(text: str) -> MarketInstrumentKey:
        return MarketInstrumentKey.from_dict(json.loads(text))

    def _result(self, permit: Permit) -> RiskOrderResult:
        outcome = _OUTCOME_BY_STATE[permit.state]
        if permit.code is not None:
            outcome = "DENIED"
        return RiskOrderResult(
            request_key=permit.request_key,
            outcome=outcome,
            state=permit.state,
            permit_id=permit.permit_id,
            reservation_id=permit.reservation_id,
            code=permit.code,
            gateway_code=permit.gateway_code,
            gateway_state=permit.gateway_state,
            policy_version=str(permit.policy_version),
            view_digest=permit.view_digest,
        )

    @staticmethod
    def _deny(request_key: str, code: str) -> RiskOrderResult:
        return RiskOrderResult(request_key=request_key, outcome="DENIED", code=code)

    def _authorize(self, caller: object, operation: str, strategy_ref: str) -> str | None:
        if (
            type(caller) is not CallerIdentity
            or operation not in caller.operations
            or caller.role not in ("strategy", "execution")
            or strategy_ref not in caller.strategy_refs
        ):
            return "risk_unauthorized"
        return None

    def _audit_refusal(self, kind: str, code: str, **fields: Any) -> None:
        now = self._now()
        with self._ledger.transaction() as txn:
            txn.audit(kind, at_ns=now, code=code, **fields)

    def _policy_version(self) -> int:
        return 0 if self._active is None else self._active.version

    # ================================================================== order shape and exposure

    @staticmethod
    def _shape(view: RiskOrderView) -> OrderShape:
        effect, position_side, bucket = derive_effect(
            view.side,
            view.offset,
            view.instrument.venue,  # type: ignore[arg-type]
        )
        return OrderShape(
            strategy_ref=view.strategy_ref,
            instrument_id=view.instrument.instrument_id,
            venue=view.instrument.venue,
            side=view.side,
            offset=view.offset,  # type: ignore[arg-type]
            effect=effect,
            position_side=position_side,
            bucket=bucket,
            quantity=view.quantity,
            limit_price=view.limit_price,
            parent_ref=view.parent_ref,
        )

    @staticmethod
    def _unallocated(txn: LedgerTxn, parent: Parent, exclude: str | None) -> Decimal:
        if parent.state not in ("ACTIVE", "FROZEN"):
            return Decimal(0)
        used = sum(
            (
                child.allocation
                for child in txn.children(parent.strategy_ref, parent.parent_ref)
                if child.permit_id != exclude
            ),
            Decimal(0),
        )
        return max(Decimal(0), parent.total_quantity - used)

    def _exposure(
        self,
        txn: LedgerTxn,
        order: OrderShape,
        facts: FactSnapshot,
        exclude: str | None,
        credit: Decimal,
    ) -> Exposure:
        cursor = txn.cursor()
        verified = cursor["continuity"] == "VERIFIED"
        side = order.position_side
        strat_open = acct_open = day_inflight_open = Decimal(0)
        close = {"TODAY": Decimal(0), "YESTERDAY": Decimal(0), "ALL": Decimal(0)}

        def add(
            effect: str, position_side: str, bucket: str, quantity: Decimal, strategy: str | None
        ):
            nonlocal strat_open, acct_open, day_inflight_open
            if effect == "INCREASE":
                day_inflight_open += quantity
                if position_side == side:
                    acct_open += quantity
                    if strategy == order.strategy_ref:
                        strat_open += quantity
            elif position_side == side:
                for name in ("TODAY", "YESTERDAY", "ALL") if bucket == "UNKNOWN" else (bucket,):
                    close[name] += quantity

        permits = txn.permits_in(OCCUPYING_STATES, order.instrument_id)
        permits += txn.terminal_with_pending_fills(order.instrument_id)
        for permit in permits:
            if permit.permit_id != exclude:
                add(
                    permit.effect,
                    permit.position_side,
                    permit.bucket,
                    permit.occupancy,
                    permit.strategy_ref,
                )
        for parent in txn.holding_parents(order.instrument_id):
            add(
                parent.effect,
                parent.position_side,
                parent.bucket,
                self._unallocated(txn, parent, exclude),
                parent.strategy_ref,
            )
        for row in txn.working_orders(order.instrument_id):
            remaining = Decimal(row["quantity"]) - Decimal(row["filled_quantity"])
            if remaining <= 0:
                continue
            for effect, position_side, bucket in _possible_effects(
                row["side"], row["order_offset"], order.venue
            ):
                add(effect, position_side, bucket, remaining, row["strategy_ref"])

        post_open = Decimal(0)
        post_close = {"TODAY": Decimal(0), "YESTERDAY": Decimal(0), "ALL": Decimal(0)}
        account = facts.usable_account()
        if account is not None:
            for trade in txn.trades_after(order.instrument_id, account.as_of_ns):  # type: ignore[arg-type]
                quantity = Decimal(trade["quantity"])
                for effect, position_side, bucket in _possible_effects(
                    trade["side"], trade["order_offset"], order.venue
                ):
                    if position_side != side:
                        continue
                    if effect == "INCREASE":
                        post_open += quantity
                    else:
                        for name in (
                            ("TODAY", "YESTERDAY", "ALL") if bucket == "UNKNOWN" else (bucket,)
                        ):
                            post_close[name] += quantity

        uncovered: Decimal | None = Decimal(0)
        active = self._active
        if active is not None and active.policy.margin_mode != "off" and order.is_open:
            for permit in txn.permits_in(OCCUPYING_STATES):
                if permit.permit_id == exclude or permit.effect != "INCREASE":
                    continue
                if permit.margin_per_unit is None:
                    uncovered = None
                    break
                uncovered += permit.margin_per_unit * permit.occupancy
            if uncovered is not None:
                for parent in txn.holding_parents():
                    if parent.effect != "INCREASE":
                        continue
                    unallocated = self._unallocated(txn, parent, exclude)
                    if unallocated == 0:
                        continue
                    if parent.margin_per_unit is None:
                        uncovered = None
                        break
                    uncovered += parent.margin_per_unit * unallocated
                    if (
                        order.parent_ref == parent.parent_ref
                        and order.strategy_ref == parent.strategy_ref
                    ):
                        uncovered -= parent.margin_per_unit * credit

        day_open = Decimal(0)
        if facts.trading_day is not None:
            day_open = txn.counter(order.instrument_id, facts.trading_day, "open_volume")
        return Exposure(
            continuity_verified=verified,
            strategy_positions_verified=verified,
            strategy_position=txn.position(order.strategy_ref, order.instrument_id, side),
            strategy_inflight_open=strat_open,
            account_inflight_open=acct_open,
            post_snapshot_open=post_open,
            post_snapshot_close=post_close,
            account_inflight_close=close,
            day_open_volume=day_open,
            day_inflight_open=day_inflight_open,
            uncovered_margin=uncovered,
            envelope_credit=credit,
        )

    # ================================================================== latches and breaches

    @staticmethod
    def _latch_code(txn: LedgerTxn, strategy_ref: str, instrument_id: str) -> str | None:
        for latch in txn.active_latches():
            kind, value = latch["scope_kind"], latch["scope_value"]
            if (
                kind == "account"
                or (kind == "strategy" and value == strategy_ref)
                or (kind == "instrument" and value == instrument_id)
            ):
                return latch["code"]
        return None

    def _cause_id(
        self, control: str, scope_kind: str, scope_value: str, trading_day: str, mode: str
    ) -> str:
        if control == "counters":
            material = self._account_scope + "|" + scope_value + "|" + trading_day
            return "risk-r04-" + _sha(material)[:24]
        material = "|".join(
            (self._account_scope, control, scope_kind, scope_value, trading_day, mode)
        )
        return "risk-ctl-" + _sha(material)[:32]

    @staticmethod
    def _scope_values(breach: _Breach, scope_kind: str) -> tuple[str, str] | None:
        """(latch scope value, Gateway control scope value) for a scope kind."""
        if scope_kind == "account":
            return "", ""
        if scope_kind == "strategy":
            return (
                None if breach.strategy_ref is None else (breach.strategy_ref, breach.strategy_ref)
            )
        if breach.instrument is None:
            return None
        return breach.instrument.instrument_id, instrument_scope_value(breach.instrument)

    def _apply_breach(
        self,
        txn: LedgerTxn,
        breach: _Breach,
        trading_day: str,
        now: int,
        post: list[tuple[str, str]],
    ) -> None:
        policy = None if self._active is None else self._active.policy
        scopes = {breach.scope_kind}
        modes = list(breach.modes)
        if policy is not None:
            modes.extend(
                (action.request, action.scope)
                for action in policy.breach_actions
                if action.rule == breach.rule
            )
            cancels = policy.cancel_rules_for(breach.rule)
        else:
            cancels = ()
        scopes.update(kind for _, kind in modes)
        scopes.update(rule.scope for rule in cancels)
        latch_ids: dict[str, str] = {}
        for kind in sorted(scopes):
            values = self._scope_values(breach, kind)
            if values is None:
                continue
            latch, created = txn.ensure_latch(
                scope_kind=kind,
                scope_value=values[0],
                control=breach.control,
                code=breach.latch_code,
                reason=breach.reason,
                trading_day=trading_day,
                now_ns=now,
            )
            latch_ids[kind] = latch["latch_id"]
            if created:
                txn.audit(
                    "latch_set",
                    at_ns=now,
                    strategy_ref=breach.strategy_ref,
                    instrument_id=None
                    if breach.instrument is None
                    else breach.instrument.instrument_id,
                    policy_version=self._policy_version(),
                    code=breach.latch_code,
                    detail={
                        "control": breach.control,
                        "scope_kind": kind,
                        "latch_id": latch["latch_id"],
                    },
                )
        stop_new_causes: dict[str, str] = {}
        for mode, kind in modes:
            values = self._scope_values(breach, kind)
            if values is None or kind not in latch_ids:
                continue
            cause = self._cause_id(breach.control, kind, values[0], trading_day, mode)
            if mode == "STOP_NEW":
                stop_new_causes[kind] = cause
            if txn.ensure_control_intent(
                cause_id=cause,
                mode=mode,
                scope_kind=kind,
                scope_value=values[1],
                latch_id=latch_ids[kind],
                rule=breach.control,
                now_ns=now,
            ):
                txn.audit(
                    "control_intent",
                    at_ns=now,
                    policy_version=self._policy_version(),
                    code=breach.latch_code,
                    detail={"cause_id": cause, "mode": mode, "scope_kind": kind},
                )
            post.append(("control", cause))
        for rule in cancels:
            values = self._scope_values(breach, rule.scope)
            if values is None or rule.scope not in latch_ids:
                continue
            wait = None
            if rule.action == "stop_new_and_cancel":
                wait = stop_new_causes.get(rule.scope)
                if wait is None:
                    wait = self._cause_id(
                        breach.control, rule.scope, values[0], trading_day, "STOP_NEW"
                    )
                    if txn.ensure_control_intent(
                        cause_id=wait,
                        mode="STOP_NEW",
                        scope_kind=rule.scope,
                        scope_value=values[1],
                        latch_id=latch_ids[rule.scope],
                        rule=breach.control,
                        now_ns=now,
                    ):
                        txn.audit(
                            "control_intent",
                            at_ns=now,
                            code=breach.latch_code,
                            detail={"cause_id": wait, "mode": "STOP_NEW", "scope_kind": rule.scope},
                        )
                    post.append(("control", wait))
            material = "|".join(
                (
                    self._account_scope,
                    breach.control,
                    rule.scope,
                    values[0],
                    trading_day,
                    rule.action,
                )
            )
            operation = "risk-cancel-" + _sha(material)[:32]
            if txn.ensure_cancel_intent(
                operation_id=operation,
                source="rule:" + breach.rule,
                scope_kind=rule.scope,
                scope_value=values[1],
                latch_id=latch_ids[rule.scope],
                wait_cause_id=wait,
                now_ns=now,
            ):
                txn.audit(
                    "cancel_intent",
                    at_ns=now,
                    code=breach.latch_code,
                    detail={
                        "operation_id": operation,
                        "action": rule.action,
                        "scope_kind": rule.scope,
                    },
                )
            post.append(("cancel", operation))

    def _run_post(self, post: list[tuple[str, str]]) -> None:
        seen: set[tuple[str, str]] = set()
        for item in post:
            if item in seen:
                continue
            seen.add(item)
            if item[0] == "control":
                self._apply_control(item[1])
            else:
                self._apply_cancel(item[1])

    def _apply_control(self, cause_id: str, *, query_first: bool = False) -> None:
        now = self._now()
        with self._ledger.transaction() as txn:
            intent = txn.control_intent(cause_id)
            if intent is None or intent["state"] in ("APPLIED", "REJECTED", "SUPERSEDED"):
                return
            if intent["latch_id"] is not None:
                latch = txn.latch(intent["latch_id"])
                if latch is None or not latch["active"]:
                    txn.update_control_intent(
                        cause_id, intent["row_version"], state="SUPERSEDED", updated_ns=now
                    )
                    txn.audit("control_superseded", at_ns=now, detail={"cause_id": cause_id})
                    return
        if query_first:
            status = self._control_call("status", cause_id=cause_id)
            if status.outcome == "OBSERVED" and status.active is True:
                self._record_control(cause_id, intent["row_version"], status)
                return
        reply = self._control_call(
            "apply",
            cause_id=cause_id,
            mode=intent["mode"],
            scope_kind=intent["scope_kind"],
            scope_value=intent["scope_value"],
        )
        self._record_control(cause_id, intent["row_version"], reply)

    def _record_control(self, cause_id: str, row_version: int, reply: ControlReply) -> None:
        if reply.outcome == "OBSERVED" and reply.active is not False:
            state = "APPLIED"
        elif reply.outcome == "REQUEST_DENIED":
            state = "REJECTED"
        elif reply.outcome == "TRANSPORT_NOT_STARTED":
            state = "PENDING"
        else:
            state = "UNKNOWN"
        now = self._now()
        with self._ledger.transaction() as txn:
            intent = txn.control_intent(cause_id)
            if intent is None or intent["row_version"] != row_version:
                return
            txn.update_control_intent(
                cause_id,
                row_version,
                state=state,
                attempts=intent["attempts"] + 1,
                last_outcome=reply.outcome,
                last_code=reply.code,
                gw_version=reply.version,
                updated_ns=now,
            )
            txn.audit(
                "control_reply",
                at_ns=now,
                code=reply.code,
                detail={"cause_id": cause_id, "outcome": reply.outcome, "state": state},
            )
        if state == "APPLIED":
            with self._ledger.transaction() as txn:
                waiting = [
                    row["operation_id"]
                    for row in txn.cancel_intents(("WAITING_CONTROL",))
                    if row["wait_cause_id"] == cause_id
                ]
            for operation in waiting:
                self._apply_cancel(operation)

    def _apply_cancel(self, operation_id: str) -> None:
        now = self._now()
        with self._ledger.transaction() as txn:
            intent = txn.cancel_intent(operation_id)
            if intent is None or intent["state"] in ("ACCEPTED", "REJECTED", "SUPERSEDED"):
                return
            if intent["latch_id"] is not None:
                latch = txn.latch(intent["latch_id"])
                if latch is None or not latch["active"]:
                    txn.update_cancel_intent(
                        operation_id, intent["row_version"], state="SUPERSEDED", updated_ns=now
                    )
                    txn.audit("cancel_superseded", at_ns=now, detail={"operation_id": operation_id})
                    return
            if intent["wait_cause_id"] is not None:
                control = txn.control_intent(intent["wait_cause_id"])
                if control is None or control["state"] in ("REJECTED", "SUPERSEDED"):
                    txn.update_cancel_intent(
                        operation_id, intent["row_version"], state="SUPERSEDED", updated_ns=now
                    )
                    txn.audit("cancel_superseded", at_ns=now, detail={"operation_id": operation_id})
                    return
                if control["state"] != "APPLIED":
                    return
        reply = self._control_call(
            "cancel_scope",
            operation_id=operation_id,
            scope_kind=intent["scope_kind"],
            scope_value=intent["scope_value"],
        )
        state = {
            "OBSERVED": "ACCEPTED",
            "REQUEST_DENIED": "REJECTED",
            "TRANSPORT_NOT_STARTED": "PENDING",
        }.get(reply.outcome, "UNKNOWN")
        now = self._now()
        with self._ledger.transaction() as txn:
            current = txn.cancel_intent(operation_id)
            if current is None or current["row_version"] != intent["row_version"]:
                return
            txn.update_cancel_intent(
                operation_id,
                intent["row_version"],
                state=state,
                attempts=current["attempts"] + 1,
                last_outcome=reply.outcome,
                last_code=reply.code,
                updated_ns=now,
            )
            txn.audit(
                "cancel_reply",
                at_ns=now,
                code=reply.code,
                detail={"operation_id": operation_id, "outcome": reply.outcome, "state": state},
            )

    # ================================================================== loss (R-07)

    def _loss_breaches(
        self,
        txn: LedgerTxn,
        policy: RiskPolicy,
        strategy_ref: str | None,
        facts: FactSnapshot,
        ev: _Evaluation,
    ) -> str | None:
        loss = policy.loss
        if loss is None:
            return None
        trading_day, now = facts.trading_day, facts.now_ns
        if trading_day is None:
            return "risk_pnl_unknown"
        code: str | None = None
        if loss.account_day is not None or loss.account_drawdown is not None:
            account = facts.usable_account()
            if account is None:
                return "risk_pnl_unknown"
            if loss.account_day is not None:
                profit = loss_values(account)
                if profit is None:
                    return "risk_pnl_unknown"
                code = (
                    self._loss_limit(
                        -profit, loss.account_day, "loss.account_day", "account", None, ev
                    )
                    or code
                )
            if loss.account_drawdown is not None:
                if account.equity is None:
                    return "risk_pnl_unknown"
                row = txn.day_value("account", trading_day)
                high = account.equity
                start = None
                if row is not None:
                    if row["high_water"] is not None:
                        high = max(high, Decimal(row["high_water"]))
                    if row["day_start"] is not None:
                        start = Decimal(row["day_start"])
                txn.set_day_value(
                    "account", trading_day, day_start=start, high_water=high, now_ns=now
                )
                code = (
                    self._loss_limit(
                        high - account.equity,
                        loss.account_drawdown,
                        "loss.account_drawdown",
                        "account",
                        None,
                        ev,
                    )
                    or code
                )
        entry = None if strategy_ref is None else loss.strategies.get(strategy_ref)
        if entry is not None:
            fact = facts.strategy
            if (
                fact is None
                or not fact.complete
                or fact.trading_day != trading_day
                or fact.value is None
                or fact.strategy_ref != strategy_ref
            ):
                return "risk_pnl_unknown"
            subject = "strategy:" + strategy_ref  # type: ignore[operator]
            row = txn.day_value(subject, trading_day)
            day_start = fact.day_start_value
            if day_start is None and row is not None and row["day_start"] is not None:
                day_start = Decimal(row["day_start"])
            if day_start is None:
                day_start = fact.value
            high = max(fact.value, day_start)
            if row is not None and row["high_water"] is not None:
                high = max(high, Decimal(row["high_water"]))
            txn.set_day_value(
                subject, trading_day, day_start=day_start, high_water=high, now_ns=now
            )
            if entry.day is not None:
                code = (
                    self._loss_limit(
                        day_start - fact.value,
                        entry.day,
                        "loss.strategy_day",
                        "strategy",
                        strategy_ref,
                        ev,
                    )
                    or code
                )
            if entry.drawdown is not None:
                code = (
                    self._loss_limit(
                        high - fact.value,
                        entry.drawdown,
                        "loss.strategy_drawdown",
                        "strategy",
                        strategy_ref,
                        ev,
                    )
                    or code
                )
        return code

    @staticmethod
    def _loss_limit(
        loss: Decimal, limit, rule: str, scope_kind: str, strategy_ref: str | None, ev: _Evaluation
    ) -> str | None:
        if loss >= limit.block:
            ev.breaches.append(
                _Breach(
                    control=rule,
                    rule=rule,
                    scope_kind=scope_kind,
                    strategy_ref=strategy_ref,
                    instrument=None,
                    latch_code="risk_breach_latched",
                    reason=rule,
                )
            )
            return "risk_loss_limit"
        if limit.warn is not None and loss >= limit.warn:
            ev.warnings.append("risk_loss_limit")
        return None

    # ================================================================== evaluation (L1 + L2)

    def _rule_context(
        self,
        phase: str,
        view: RiskOrderView | None,
        parent: RiskParentView | None,
        order: OrderShape,
        facts: FactSnapshot,
        counters: dict,
        params,
        active: ActivePolicy,
    ) -> RuleContext:
        return RuleContext(
            phase=phase,
            view=view,
            parent=parent,
            effect=order.effect,
            facts=facts,
            counters=dict(counters),
            trading_day=facts.trading_day or "",
            params=params,
            policy_version=active.version,
        )

    def _counters(
        self, txn: LedgerTxn, order: OrderShape, facts: FactSnapshot, policy: RiskPolicy
    ) -> dict[str, int]:
        day = facts.trading_day or ""
        recent = 0
        rate = None if policy.counters is None else policy.counters.per_strategy_rate
        if rate is not None:
            recent = txn.claims_since(
                order.strategy_ref, facts.now_ns - rate.window_ms * _NS_PER_MS
            )
        return {
            "orders": int(txn.counter(order.instrument_id, day, "order")),
            "cancels": int(txn.counter(order.instrument_id, day, "cancel")),
            "strategy_recent_orders": recent,
        }

    def _custom_rules(
        self,
        txn: LedgerTxn,
        phase: str,
        view: RiskOrderView | None,
        parent: RiskParentView | None,
        order: OrderShape,
        facts: FactSnapshot,
        active: ActivePolicy,
        ev: _Evaluation,
    ) -> str | None:
        if not active.custom:
            return None
        counters = self._counters(txn, order, facts, active.policy)
        for spec, rule, expected in active.custom:
            ctx = self._rule_context(
                phase, view, parent, order, facts, counters, spec.params, active
            )
            decision = run_rule(rule, expected, ctx)
            if decision.code == "risk_rule_failed":
                txn.audit(
                    "rule_failed",
                    at_ns=facts.now_ns,
                    strategy_ref=order.strategy_ref,
                    instrument_id=order.instrument_id,
                    policy_version=active.version,
                    code="risk_rule_failed",
                    detail={"rule_id": spec.rule_id},
                )
            self._custom_breach(spec.rule_id, decision, order, view, parent, active, ev, txn, facts)
            if decision.outcome == "DENY":
                return decision.code
            if decision.outcome == "WARN":
                ev.warnings.append(decision.code)  # type: ignore[arg-type]
        return None

    def _custom_breach(
        self,
        rule_id: str,
        decision: RuleDecision,
        order: OrderShape,
        view: RiskOrderView | None,
        parent: RiskParentView | None,
        active: ActivePolicy,
        ev: _Evaluation,
        txn: LedgerTxn,
        facts: FactSnapshot,
    ) -> None:
        breach = decision.breach
        if breach is None:
            return
        expected_value = {
            "account": "",
            "strategy": order.strategy_ref,
            "instrument": order.instrument_id,
        }[breach.scope_kind]
        configured = any(
            action.request == breach.action
            for action in active.policy.breach_action_for(rule_id, breach.scope_kind)
        )
        if breach.scope_value != expected_value or not configured:
            txn.audit(
                "breach_request_not_configured",
                at_ns=facts.now_ns,
                strategy_ref=order.strategy_ref,
                instrument_id=order.instrument_id,
                policy_version=active.version,
                detail={"rule_id": rule_id},
            )
            return
        instrument = (
            view.instrument if view is not None else (None if parent is None else parent.instrument)
        )
        ev.breaches.append(
            _Breach(
                control="rule:" + rule_id,
                rule=rule_id,
                scope_kind=breach.scope_kind,
                strategy_ref=order.strategy_ref,
                instrument=instrument,
                latch_code="risk_breach_latched",
                reason="rule:" + rule_id,
                modes=((breach.action, breach.scope_kind),),
            )
        )

    def _check_parent(
        self,
        txn: LedgerTxn,
        order: OrderShape,
        caller: CallerIdentity | None,
        facts: FactSnapshot,
        exclude: str | None,
        ev: _Evaluation,
    ) -> str | None:
        parent = txn.parent(order.strategy_ref, order.parent_ref)  # type: ignore[arg-type]
        if parent is None or parent.state in ("DENIED", "RELEASED"):
            return "risk_parent_unavailable"
        if parent.state == "FROZEN":
            return "risk_parent_frozen"
        if caller is not None and caller.run_id != parent.run_id:
            txn.update_parent(parent, state="FROZEN", updated_ns=facts.now_ns)
            txn.audit(
                "parent_frozen",
                at_ns=facts.now_ns,
                strategy_ref=parent.strategy_ref,
                instrument_id=parent.instrument_id,
                code="risk_parent_frozen",
                detail={"parent_ref": parent.parent_ref},
            )
            return "risk_parent_frozen"
        if facts.trading_day is None or facts.trading_day > parent.valid_until_trading_day:
            return "risk_parent_unavailable"
        if (
            order.instrument_id != parent.instrument_id
            or order.side != parent.side
            or order.offset != parent.offset
        ):
            return "risk_parent_envelope_exceeded"
        if parent.limit_price is not None:
            if order.limit_price is None:
                return "risk_parent_envelope_exceeded"
            if order.side == "BUY" and order.limit_price > parent.limit_price:
                return "risk_parent_envelope_exceeded"
            if order.side == "SELL" and order.limit_price < parent.limit_price:
                return "risk_parent_envelope_exceeded"
        if order.quantity > self._unallocated(txn, parent, exclude):
            return "risk_parent_envelope_exceeded"
        ev.credit = order.quantity
        return None

    def _evaluate(
        self,
        txn: LedgerTxn,
        active: ActivePolicy | None,
        order: OrderShape,
        view: RiskOrderView | None,
        parent: RiskParentView | None,
        facts: FactSnapshot,
        *,
        exclude: str | None,
        caller: CallerIdentity | None,
    ) -> _Evaluation:
        """L1 + L2 checks; the first DENY stops evaluation."""
        ev = _Evaluation()
        if active is None:
            ev.code = "risk_policy_unavailable"
            return ev
        policy = active.policy
        if facts.trading_day is None:
            ev.code = "risk_trading_day_unavailable"
            return ev
        if (
            view is not None
            and view.trading_day is not None
            and view.trading_day != facts.trading_day
        ):
            ev.code = "risk_request_invalid"
            return ev
        if order.parent_ref is not None and view is not None:
            ev.code = self._check_parent(txn, order, caller, facts, exclude, ev)
            if ev.code:
                return ev
        if order.is_open:
            ev.code = self._latch_code(txn, order.strategy_ref, order.instrument_id)
            if ev.code:
                return ev
        if view is not None:
            for check in (
                check_quantity_cap(policy, order),
                check_notional_cap(policy, order, facts),
                check_price_band(policy, order, facts),
            ):
                if check is not None:
                    ev.code = check
                    return ev
            duplicate = self._duplicate(txn, policy, order, facts, view.request_key)
            if duplicate == "deny":
                ev.code = "risk_duplicate_order"
                return ev
            if duplicate == "warn":
                ev.warnings.append("risk_duplicate_order")
        exposure = self._exposure(txn, order, facts, exclude, ev.credit)
        for check in (
            check_position(policy, order, facts, exposure),
            check_closable(policy, order, facts, exposure),
        ):
            if check is not None:
                ev.code = check
                return ev
        if order.is_open:
            ev.code = self._loss_breaches(txn, policy, order.strategy_ref, facts, ev)
            if ev.code:
                return ev
            margin = check_margin(policy, order, facts, exposure)
            if margin is not None and policy.margin_mode == "deny":
                ev.code = margin
                return ev
            if margin is not None:
                ev.warnings.append(margin)
            if view is not None:
                ev.code = check_exchange_rules(policy, order, facts, exposure)
                if ev.code:
                    return ev
        ev.code = self._custom_rules(txn, "reserve", view, parent, order, facts, active, ev)
        if ev.code:
            return ev
        ev.margin_per_unit = margin_per_unit(order, facts)
        return ev

    @staticmethod
    def _duplicate(
        txn: LedgerTxn, policy: RiskPolicy, order: OrderShape, facts: FactSnapshot, request_key: str
    ) -> str | None:
        duplicate = policy.duplicate
        if duplicate is None:
            return None
        since = facts.now_ns - duplicate.window_ms * _NS_PER_MS
        for permit in txn.permits_since(order.strategy_ref, order.instrument_id, since):
            if (
                permit.request_key != request_key
                and permit.side == order.side
                and permit.offset == order.offset
                and permit.limit_price == order.limit_price
                and permit.quantity == order.quantity
            ):
                return duplicate.action
        return None

    # ================================================================== reserve

    def reserve(
        self,
        caller: CallerIdentity,
        view: RiskOrderView,
        canonical_payload: str,
        run_id: str | None,
    ) -> RiskOrderResult:
        """risk.order.reserve: L1 + L2 in one transaction, then the Gateway delegate reserve."""
        if type(view) is not RiskOrderView:
            raise RiskRequestError("risk_request_invalid")
        key = view.request_key
        code = self._authorize(caller, "risk.order.reserve", view.strategy_ref)
        if code is None and (
            view.account_scope != self._account_scope or view.route != self._route
        ):
            code = "risk_unauthorized"
        if code is None and ((view.origin == "execution") != (caller.role == "execution")):
            code = "risk_unauthorized"
        if code is not None:
            self._audit_refusal("reserve_refused", code, request_key=key)
            return self._deny(key, code)
        if (
            type(canonical_payload) is not str
            or not canonical_payload
            or len(canonical_payload) > _MAX_PAYLOAD
            or (run_id is not None and not _ref(run_id))
            or view.offset is None
        ):
            self._audit_refusal(
                "reserve_refused",
                "risk_request_invalid",
                request_key=key,
                strategy_ref=view.strategy_ref,
            )
            return self._deny(key, "risk_request_invalid")
        order = self._shape(view)
        if view.position_side != "NET" and view.position_side != order.position_side:
            self._audit_refusal(
                "reserve_refused",
                "risk_request_invalid",
                request_key=key,
                strategy_ref=view.strategy_ref,
            )
            return self._deny(key, "risk_request_invalid")
        view_digest = view.digest()
        payload_digest = _sha(canonical_payload)
        with self._ledger.transaction() as txn:
            existing = txn.permit_by_key(view.strategy_ref, key)
        if existing is not None:
            return self._reserve_retry(existing, caller, view_digest, payload_digest)

        facts = self._gather(view.instrument, view.strategy_ref)
        post: list[tuple[str, str]] = []
        now = facts.now_ns
        permit_id = uuid.uuid4().hex
        with self._ledger.transaction() as txn:
            active = self._active
            ev = self._evaluate(txn, active, order, view, None, facts, exclude=None, caller=caller)
            version = self._policy_version()
            txn.insert_permit(
                {
                    "permit_id": permit_id,
                    "strategy_ref": view.strategy_ref,
                    "request_key": key,
                    "run_id": run_id,
                    "principal_ref": caller.principal_ref,
                    "origin": view.origin,
                    "view_json": json.dumps(
                        view.to_mapping(), sort_keys=True, separators=(",", ":")
                    ),
                    "view_digest": view_digest,
                    "payload_json": canonical_payload,
                    "payload_digest": payload_digest,
                    "instrument_id": order.instrument_id,
                    "instrument_json": json.dumps(view.instrument.to_dict(), sort_keys=True),
                    "side": order.side,
                    "order_offset": order.offset,
                    "effect": order.effect,
                    "position_side": order.position_side,
                    "bucket": order.bucket,
                    "quantity": T(order.quantity),
                    "limit_price": T(order.limit_price),
                    "parent_ref": view.parent_ref,
                    "child_id": view.child_id,
                    "trading_day": facts.trading_day or "",
                    "policy_version": version,
                    "state": "DENIED" if ev.code else "RESERVING",
                    "code": ev.code,
                    "margin_per_unit": T(ev.margin_per_unit),
                    "created_ns": now,
                    "expires_ns": now + int(self._ttl * 1_000_000_000),
                    "updated_ns": now,
                }
            )
            txn.audit(
                "reserve_refused" if ev.code else "reserve",
                at_ns=now,
                strategy_ref=view.strategy_ref,
                request_key=key,
                permit_id=permit_id,
                instrument_id=order.instrument_id,
                effect=order.effect,
                policy_version=version,
                code=ev.code,
                detail={"warnings": sorted(set(ev.warnings)), "view_digest": view_digest},
            )
            for breach in ev.breaches:
                self._apply_breach(txn, breach, facts.trading_day or "", now, post)
        self._run_post(post)
        if ev.code:
            with self._ledger.transaction() as txn:
                return self._result(txn.permit(permit_id))  # type: ignore[arg-type]
        reply = self._gateway_call(
            "reserve",
            strategy_ref=view.strategy_ref,
            run_id=run_id,
            request_key=key,
            canonical_payload=canonical_payload,
            parent_ref=view.parent_ref,
            child_id=view.child_id,
            ttl_seconds=self._ttl,
        )
        return self._result(self._record_reserve(permit_id, reply))

    def _reserve_retry(
        self, permit: Permit, caller: CallerIdentity, view_digest: str, payload_digest: str
    ) -> RiskOrderResult:
        if (
            permit.view_digest != view_digest
            or permit.payload_digest != payload_digest
            or permit.principal_ref != caller.principal_ref
        ):
            self._audit_refusal(
                "reserve_conflict",
                "risk_request_conflict",
                strategy_ref=permit.strategy_ref,
                request_key=permit.request_key,
                permit_id=permit.permit_id,
            )
            return self._deny(permit.request_key, "risk_request_conflict")
        if permit.state in ("RESERVING", "UNKNOWN"):
            permit = self._resolve(permit)
        return self._result(permit)

    def _record_reserve(self, permit_id: str, reply: GatewayReply) -> Permit:
        now = self._now()
        with self._ledger.transaction() as txn:
            permit = txn.permit(permit_id)
            assert permit is not None
            if permit.state != "RESERVING":
                return permit
            digest_ok = reply.digest is None or reply.digest == permit.payload_digest
            if (
                reply.outcome == "OBSERVED"
                and reply.state == "RESERVED"
                and reply.reservation_id is not None
                and digest_ok
            ):
                fields = {
                    "state": "RESERVED",
                    "reservation_id": reply.reservation_id,
                    "gw_version": reply.version,
                    "gw_digest": reply.digest,
                    "owner_generation": reply.owner_generation,
                    "reservation_generation": reply.reservation_generation,
                    "gateway_state": reply.state,
                    "gateway_code": reply.code,
                }
                kind = "reserve_recorded"
            elif reserve_refused(reply):
                fields = {
                    "state": "DENIED",
                    "code": "risk_gateway_refused",
                    "gateway_code": reply.code,
                    "gateway_state": reply.state,
                }
                kind = "reserve_gateway_refused"
            else:
                fields = {
                    "state": "UNKNOWN",
                    "gateway_code": reply.code,
                    "gateway_state": reply.state,
                }
                kind = "reserve_unknown"
            txn.transition(permit, ("RESERVING",), updated_ns=now, **fields)
            txn.audit(
                kind,
                at_ns=now,
                strategy_ref=permit.strategy_ref,
                request_key=permit.request_key,
                permit_id=permit_id,
                instrument_id=permit.instrument_id,
                effect=permit.effect,
                policy_version=permit.policy_version,
                code=fields.get("code"),
                detail={"gateway_outcome": reply.outcome},
            )
            return txn.permit(permit_id)  # type: ignore[return-value]

    # ================================================================== dispatch (claim, L3)

    def _caller_permit(
        self, caller: object, operation: str, request_key: object, permit_id: object
    ) -> tuple[Permit | None, RiskOrderResult | None]:
        if not _ref(request_key):
            raise RiskRequestError("risk_request_invalid")
        if (
            type(caller) is not CallerIdentity
            or operation not in caller.operations
            or caller.role not in ("strategy", "execution")
        ):
            return None, self._deny(request_key, "risk_unauthorized")  # type: ignore[arg-type]
        permit = None
        if _ref(permit_id):
            with self._ledger.transaction() as txn:
                permit = txn.permit(permit_id)  # type: ignore[arg-type]
        if permit is None or permit.request_key != request_key:
            return None, self._deny(request_key, "risk_permit_mismatch")  # type: ignore[arg-type]
        if permit.strategy_ref not in caller.strategy_refs:
            return None, self._deny(request_key, "risk_unauthorized")  # type: ignore[arg-type]
        if permit.principal_ref != caller.principal_ref:
            return None, self._deny(request_key, "risk_permit_mismatch")  # type: ignore[arg-type]
        return permit, None

    def dispatch(
        self,
        caller: CallerIdentity,
        request_key: str,
        permit_id: str,
        reservation_id: str,
        view_digest: str,
    ) -> RiskOrderResult:
        """risk.order.dispatch: L3 + conditional RESERVED -> CLAIMED, then the Gateway dispatch."""
        permit, refusal = self._caller_permit(caller, "risk.order.dispatch", request_key, permit_id)
        if refusal is not None:
            self._audit_refusal("dispatch_refused", refusal.code, request_key=request_key)  # type: ignore[arg-type]
            return refusal
        assert permit is not None
        if permit.reservation_id != reservation_id or permit.view_digest != view_digest:
            self._audit_refusal(
                "dispatch_refused",
                "risk_permit_mismatch",
                request_key=request_key,
                permit_id=permit.permit_id,
            )
            return self._deny(request_key, "risk_permit_mismatch")
        if permit.state == "UNKNOWN":
            return self._result(self._resolve(permit))
        if permit.state == "RELEASING":
            return self._result(self._finish_release(permit))
        if permit.state == "CLAIMED":
            # Caller retry with the same identity: query first; re-send only while the
            # Gateway still holds the reservation without a dispatch marker.
            reply = self._gateway_call(
                "status",
                strategy_ref=permit.strategy_ref,
                run_id=permit.run_id,
                request_key=permit.request_key,
            )
            if (
                reply.outcome == "OBSERVED"
                and reply.state == "RESERVED"
                and reply.reservation_id == permit.reservation_id
            ):
                return self._send_dispatch(permit)
            return self._result(self._apply_status(permit, reply))
        if permit.state != "RESERVED":
            return self._result(permit)

        instrument = self._instrument_of(permit.instrument_json)
        facts = self._gather(instrument, permit.strategy_ref)
        view = RiskOrderView.from_mapping(json.loads(permit.view_json))
        order = self._shape(view)
        post: list[tuple[str, str]] = []
        now = facts.now_ns
        with self._ledger.transaction() as txn:
            current = txn.permit(permit.permit_id)
            if current is None or current.row_version != permit.row_version:
                current = None
            else:
                ev = self._evaluate_claim(txn, current, view, order, facts, caller)
                version = self._policy_version()
                if ev.code is None:
                    claimed = txn.transition(
                        current, ("RESERVED",), state="CLAIMED", claimed_ns=now, updated_ns=now
                    )
                    if claimed:
                        txn.add_counter(
                            order.instrument_id, facts.trading_day or "", "order", Decimal(1)
                        )
                    kind = "claim" if claimed else "claim_lost"
                else:
                    claimed = False
                    txn.transition(
                        current, ("RESERVED",), state="RELEASING", code=ev.code, updated_ns=now
                    )
                    kind = "claim_refused"
                txn.audit(
                    kind,
                    at_ns=now,
                    strategy_ref=current.strategy_ref,
                    request_key=current.request_key,
                    permit_id=current.permit_id,
                    instrument_id=current.instrument_id,
                    effect=current.effect,
                    policy_version=version,
                    code=ev.code,
                    detail={"warnings": sorted(set(ev.warnings))},
                )
                if claimed or ev.code is not None:
                    for breach in ev.breaches:
                        self._apply_breach(txn, breach, facts.trading_day or "", now, post)
                current = txn.permit(permit.permit_id)
        self._run_post(post)
        if current is None:
            with self._ledger.transaction() as txn:
                return self._result(txn.permit(permit.permit_id))  # type: ignore[arg-type]
        if current.state == "RELEASING":
            return self._result(self._release_via_gateway(current))
        if current.state != "CLAIMED":
            return self._result(current)
        return self._send_dispatch(current)

    def _evaluate_claim(
        self,
        txn: LedgerTxn,
        permit: Permit,
        view: RiskOrderView,
        order: OrderShape,
        facts: FactSnapshot,
        caller: CallerIdentity,
    ) -> _Evaluation:
        active = self._active
        if active is None:
            return _Evaluation(code="risk_policy_unavailable")
        if facts.trading_day is None:
            return _Evaluation(code="risk_trading_day_unavailable")
        if active.version != permit.policy_version:
            # D64-12: a permit reserved under an older version is re-checked against the latest.
            ev = self._evaluate(
                txn, active, order, view, None, facts, exclude=permit.permit_id, caller=caller
            )
            if ev.code is not None:
                return ev
        else:
            ev = _Evaluation()
        if permit.expires_ns is not None and facts.now_ns > permit.expires_ns:
            ev.code = "risk_permit_expired"
            return ev
        if order.parent_ref is not None:
            parent = txn.parent(order.strategy_ref, order.parent_ref)
            if parent is None or parent.state != "ACTIVE":
                ev.code = (
                    "risk_parent_frozen"
                    if (parent is not None and parent.state == "FROZEN")
                    else "risk_parent_unavailable"
                )
                return ev
        if order.is_open:
            ev.code = self._latch_code(txn, order.strategy_ref, order.instrument_id)
            if ev.code:
                return ev
        ev.code = check_price_band(active.policy, order, facts)
        if ev.code:
            return ev
        if active.policy.self_trade_enabled:
            if txn.cursor()["continuity"] != "VERIFIED":
                ev.code = "risk_self_trade_unverifiable"
                return ev
            resting = [
                (other.side, other.limit_price)
                for other in txn.permits_in(WORKING_STATES, order.instrument_id)
                if other.permit_id != permit.permit_id
            ]
            resting.extend(
                (row["side"], None if row["limit_price"] is None else Decimal(row["limit_price"]))
                for row in txn.working_orders(order.instrument_id)
            )
            if self_trade(order.side, order.limit_price, resting):
                ev.code = "risk_self_trade"
                return ev
        ev.code = self._custom_rules(txn, "claim", view, None, order, facts, active, ev)
        if ev.code:
            return ev
        if active.policy.counters is not None:
            counters = self._counters(txn, order, facts, active.policy)
            rule, expected = active.r04
            ctx = self._rule_context(
                "claim", view, None, order, facts, counters, _r04_params(active.policy), active
            )
            decision = run_rule(rule, expected, ctx)
            if decision.outcome == "DENY":
                ev.code = decision.code
                return ev
            if decision.outcome == "WARN":
                ev.warnings.append(decision.code)  # type: ignore[arg-type]
            if decision.breach is not None:
                ev.breaches.append(
                    _Breach(
                        control="counters",
                        rule="counters",
                        scope_kind="instrument",
                        strategy_ref=order.strategy_ref,
                        instrument=view.instrument,
                        latch_code=rule.CODE,
                        reason="R-04",  # type: ignore[attr-defined]
                        modes=(("STOP_NEW", "instrument"),),
                    )
                )
        return ev

    def _send_dispatch(self, permit: Permit) -> RiskOrderResult:
        instrument = self._instrument_of(permit.instrument_json)
        try:
            market_ref = self._facts.market_ref(instrument)
        except Exception:
            market_ref = None
        if market_ref is not None and type(market_ref) is not dict:
            market_ref = None
        reply = self._gateway_call(
            "dispatch",
            strategy_ref=permit.strategy_ref,
            run_id=permit.run_id,
            request_key=permit.request_key,
            market_ref=market_ref,
        )
        now = self._now()
        with self._ledger.transaction() as txn:
            current = txn.permit(permit.permit_id)
            assert current is not None
            if current.state != "CLAIMED":
                return self._result(current)
            if reply.outcome in ("QUEUED", "OBSERVED") and reply.state in SENT_STATES:
                fields = {"state": "DISPATCHED"}
                kind = "dispatched"
            elif reply.outcome == "TRANSPORT_NOT_STARTED":
                fields = {}
                kind = "dispatch_not_started"
            else:
                fields = {"state": "UNKNOWN"}
                kind = "dispatch_unknown"
            txn.transition(
                current,
                ("CLAIMED",),
                gateway_state=reply.state,
                gateway_code=reply.code,
                updated_ns=now,
                **fields,
            )
            txn.audit(
                kind,
                at_ns=now,
                strategy_ref=current.strategy_ref,
                request_key=current.request_key,
                permit_id=current.permit_id,
                instrument_id=current.instrument_id,
                effect=current.effect,
                policy_version=current.policy_version,
                detail={"gateway_outcome": reply.outcome},
            )
            return self._result(txn.permit(permit.permit_id))  # type: ignore[arg-type]

    # ================================================================== release and resolution

    def release(self, caller: CallerIdentity, request_key: str, permit_id: str) -> RiskOrderResult:
        """risk.order.release: only a RESERVED permit can be released, with Gateway proof."""
        permit, refusal = self._caller_permit(caller, "risk.order.release", request_key, permit_id)
        if refusal is not None:
            return refusal
        assert permit is not None
        if permit.state == "RELEASING":
            return self._result(self._finish_release(permit))
        if permit.state == "UNKNOWN":
            return self._result(self._resolve(permit))
        if permit.state != "RESERVED":
            return self._result(permit)
        now = self._now()
        with self._ledger.transaction() as txn:
            current = txn.permit(permit.permit_id)
            moved = current is not None and txn.transition(
                current, ("RESERVED",), state="RELEASING", updated_ns=now
            )
            if moved:
                txn.audit(
                    "release_requested",
                    at_ns=now,
                    strategy_ref=permit.strategy_ref,
                    request_key=permit.request_key,
                    permit_id=permit.permit_id,
                    instrument_id=permit.instrument_id,
                    policy_version=permit.policy_version,
                )
            current = txn.permit(permit.permit_id)
        assert current is not None
        if not moved:
            return self._result(current)
        return self._result(self._release_via_gateway(current))

    def _release_via_gateway(self, permit: Permit) -> Permit:
        reply = self._gateway_call(
            "release",
            strategy_ref=permit.strategy_ref,
            run_id=permit.run_id,
            request_key=permit.request_key,
            operation_id="risk-release-" + permit.permit_id,
        )
        now = self._now()
        with self._ledger.transaction() as txn:
            current = txn.permit(permit.permit_id)
            assert current is not None
            if current.state != "RELEASING":
                return current
            state = "RELEASED" if proves_not_sent(reply, current) else "UNKNOWN"
            txn.transition(
                current,
                ("RELEASING",),
                state=state,
                gateway_state=reply.state,
                gateway_code=reply.code,
                updated_ns=now,
            )
            txn.audit(
                "released" if state == "RELEASED" else "release_unknown",
                at_ns=now,
                strategy_ref=current.strategy_ref,
                request_key=current.request_key,
                permit_id=current.permit_id,
                instrument_id=current.instrument_id,
                policy_version=current.policy_version,
                code=current.code,
                detail={"gateway_outcome": reply.outcome},
            )
            return txn.permit(permit.permit_id)  # type: ignore[return-value]

    def _finish_release(self, permit: Permit) -> Permit:
        reply = self._gateway_call(
            "status",
            strategy_ref=permit.strategy_ref,
            run_id=permit.run_id,
            request_key=permit.request_key,
        )
        if proves_not_sent(reply, permit):
            return self._apply_status(permit, reply)
        if reply.outcome == "OBSERVED" and reply.state == "RESERVED":
            return self._release_via_gateway(permit)
        if reply.outcome == "TRANSPORT_NOT_STARTED":
            return permit
        return self._apply_status(permit, reply)

    def _resolve(self, permit: Permit) -> Permit:
        reply = self._gateway_call(
            "status",
            strategy_ref=permit.strategy_ref,
            run_id=permit.run_id,
            request_key=permit.request_key,
        )
        return self._apply_status(permit, reply)

    def _apply_status(self, permit: Permit, reply: GatewayReply) -> Permit:
        now = self._now()
        with self._ledger.transaction() as txn:
            current = txn.permit(permit.permit_id)
            assert current is not None
            if current.row_version != permit.row_version:
                return current
            fields = _status_fields(current, reply)
            if fields:
                txn.transition(
                    current,
                    (current.state,),
                    gateway_state=reply.state,
                    gateway_code=reply.code,
                    updated_ns=now,
                    **fields,
                )
                txn.audit(
                    "settle" if fields.get("state") == "RELEASED" else "resolve",
                    at_ns=now,
                    strategy_ref=current.strategy_ref,
                    request_key=current.request_key,
                    permit_id=current.permit_id,
                    instrument_id=current.instrument_id,
                    policy_version=current.policy_version,
                    detail={
                        "from": current.state,
                        "to": fields.get("state", current.state),
                        "gateway_outcome": reply.outcome,
                    },
                )
            return txn.permit(permit.permit_id)  # type: ignore[return-value]

    def status(
        self, caller: CallerIdentity, request_key: str, *, strategy_ref: str | None = None
    ) -> RiskOrderResult:
        """risk.order.status: persisted state; NOT_FOUND is never a NOT_SENT proof."""
        if not _ref(request_key):
            raise RiskRequestError("risk_request_invalid")
        if (
            type(caller) is not CallerIdentity
            or "risk.order.status" not in caller.operations
            or caller.role not in ("strategy", "execution")
            or (strategy_ref is not None and strategy_ref not in caller.strategy_refs)
        ):
            return self._deny(request_key, "risk_unauthorized")
        strategies = [strategy_ref] if strategy_ref is not None else sorted(caller.strategy_refs)
        with self._ledger.transaction() as txn:
            found = [
                permit
                for permit in (txn.permit_by_key(item, request_key) for item in strategies)
                if permit is not None
            ]
        if not found:
            return RiskOrderResult(request_key=request_key, outcome="NOT_FOUND")
        if len(found) > 1:
            return self._deny(request_key, "risk_request_invalid")
        return self._result(found[0])

    # ================================================================== parents (64.10)

    def _parent_result(
        self, txn: LedgerTxn, parent: Parent, outcome: str | None = None
    ) -> RiskParentResult:
        unallocated = self._unallocated(txn, parent, None)
        allocated = sum(
            (child.allocation for child in txn.children(parent.strategy_ref, parent.parent_ref)),
            Decimal(0),
        )
        if outcome is None:
            outcome = {
                "ACTIVE": "RESERVED",
                "FROZEN": "RESERVED",
                "RELEASED": "RELEASED",
                "DENIED": "DENIED",
            }[parent.state]
        return RiskParentResult(
            parent_ref=parent.parent_ref,
            outcome=outcome,
            state=parent.state,
            code=parent.code,
            total_quantity=parent.total_quantity,
            allocated_quantity=allocated,
            unallocated_quantity=unallocated,
            policy_version=str(parent.policy_version),
        )

    def _parent_caller(self, caller: object, operation: str, strategy_ref: str | None) -> bool:
        return (
            type(caller) is CallerIdentity
            and caller.role == "execution"
            and operation in caller.operations
            and (strategy_ref is None or strategy_ref in caller.strategy_refs)
        )

    def parent_reserve(self, caller: CallerIdentity, parent: RiskParentView) -> RiskParentResult:
        """risk.parent.reserve: whole-envelope reservation (R-03, R-03b, R-07, R-08)."""
        if type(parent) is not RiskParentView:
            raise RiskRequestError("risk_request_invalid")
        ref = parent.parent_ref
        if not self._parent_caller(caller, "risk.parent.reserve", parent.strategy_ref) or (
            parent.account_scope != self._account_scope or parent.route != self._route
        ):
            self._audit_refusal("parent_refused", "risk_unauthorized", detail={"parent_ref": ref})
            return RiskParentResult(ref, "DENIED", code="risk_unauthorized")
        if parent.offset is None:
            return RiskParentResult(ref, "DENIED", code="risk_request_invalid")
        effect, position_side, bucket = derive_effect(
            parent.side, parent.offset, parent.instrument.venue
        )
        if parent.position_side != "NET" and parent.position_side != position_side:
            return RiskParentResult(ref, "DENIED", code="risk_request_invalid")
        digest = parent.digest()
        with self._ledger.transaction() as txn:
            existing = txn.parent(parent.strategy_ref, ref)
            if existing is not None:
                if existing.view_digest != digest or existing.principal_ref != caller.principal_ref:
                    return RiskParentResult(ref, "DENIED", code="risk_request_conflict")
                return self._parent_result(txn, existing)
        order = OrderShape(
            strategy_ref=parent.strategy_ref,
            instrument_id=parent.instrument.instrument_id,
            venue=parent.instrument.venue,
            side=parent.side,
            offset=parent.offset,
            effect=effect,
            position_side=position_side,
            bucket=bucket,
            quantity=parent.total_quantity,
            limit_price=parent.limit_price,
        )
        facts = self._gather(parent.instrument, parent.strategy_ref)
        now = facts.now_ns
        post: list[tuple[str, str]] = []
        with self._ledger.transaction() as txn:
            if facts.trading_day is not None and (
                facts.trading_day > parent.valid_until_trading_day
                or parent.created_trading_day > facts.trading_day
            ):
                ev = _Evaluation(code="risk_parent_unavailable")
            else:
                ev = self._evaluate(
                    txn, self._active, order, None, parent, facts, exclude=None, caller=caller
                )
            version = self._policy_version()
            txn.insert_parent(
                {
                    "strategy_ref": parent.strategy_ref,
                    "parent_ref": ref,
                    "run_id": caller.run_id,
                    "principal_ref": caller.principal_ref,
                    "view_json": json.dumps(parent.to_mapping(), sort_keys=True),
                    "view_digest": digest,
                    "instrument_id": order.instrument_id,
                    "instrument_json": json.dumps(parent.instrument.to_dict(), sort_keys=True),
                    "side": parent.side,
                    "order_offset": parent.offset,
                    "effect": effect,
                    "position_side": position_side,
                    "bucket": bucket,
                    "total_quantity": T(parent.total_quantity),
                    "limit_price": T(parent.limit_price),
                    "created_trading_day": parent.created_trading_day,
                    "valid_until_trading_day": parent.valid_until_trading_day,
                    "policy_version": version,
                    "state": "DENIED" if ev.code else "ACTIVE",
                    "code": ev.code,
                    "margin_per_unit": T(ev.margin_per_unit),
                    "created_ns": now,
                    "updated_ns": now,
                }
            )
            txn.audit(
                "parent_refused" if ev.code else "parent_reserve",
                at_ns=now,
                strategy_ref=parent.strategy_ref,
                instrument_id=order.instrument_id,
                effect=effect,
                policy_version=version,
                code=ev.code,
                detail={"parent_ref": ref, "warnings": sorted(set(ev.warnings))},
            )
            for breach in ev.breaches:
                self._apply_breach(txn, breach, facts.trading_day or "", now, post)
            result = self._parent_result(txn, txn.parent(parent.strategy_ref, ref))  # type: ignore[arg-type]
        self._run_post(post)
        return result

    def _find_parent(
        self, txn: LedgerTxn, caller: CallerIdentity, parent_ref: str
    ) -> Parent | None:
        found = [
            parent
            for parent in (
                txn.parent(strategy, parent_ref) for strategy in sorted(caller.strategy_refs)
            )
            if parent is not None
        ]
        return found[0] if len(found) == 1 else None

    def parent_release(self, caller: CallerIdentity, parent_ref: str) -> RiskParentResult:
        """risk.parent.release: releases only the unallocated part; children keep theirs."""
        if not _ref(parent_ref):
            raise RiskRequestError("risk_request_invalid")
        if not self._parent_caller(caller, "risk.parent.release", None):
            return RiskParentResult(parent_ref, "DENIED", code="risk_unauthorized")
        now = self._now()
        with self._ledger.transaction() as txn:
            parent = self._find_parent(txn, caller, parent_ref)
            if parent is None:
                return RiskParentResult(parent_ref, "NOT_FOUND")
            if parent.principal_ref != caller.principal_ref:
                return RiskParentResult(parent_ref, "DENIED", code="risk_permit_mismatch")
            if parent.state in ("ACTIVE", "FROZEN"):
                txn.update_parent(parent, state="RELEASED", updated_ns=now)
                txn.audit(
                    "parent_release",
                    at_ns=now,
                    strategy_ref=parent.strategy_ref,
                    instrument_id=parent.instrument_id,
                    policy_version=parent.policy_version,
                    detail={"parent_ref": parent_ref},
                )
                parent = txn.parent(parent.strategy_ref, parent_ref)
            return self._parent_result(txn, parent)  # type: ignore[arg-type]

    def parent_status(self, caller: CallerIdentity, parent_ref: str) -> RiskParentResult:
        if not _ref(parent_ref):
            raise RiskRequestError("risk_request_invalid")
        if not self._parent_caller(caller, "risk.parent.status", None):
            return RiskParentResult(parent_ref, "DENIED", code="risk_unauthorized")
        with self._ledger.transaction() as txn:
            parent = self._find_parent(txn, caller, parent_ref)
            if parent is None:
                return RiskParentResult(parent_ref, "NOT_FOUND")
            return self._parent_result(txn, parent)

    # ================================================================== observations (L4)

    def reset_observations(self, epoch: str, head_sequence: int) -> None:
        """The host (re)subscribed from sequence 0; the projection is VERIFIED once the
        replay reaches ``head_sequence`` (-1 for an empty stream)."""
        if not _ref(epoch) or type(head_sequence) is not int or head_sequence < -1:
            raise RiskRequestError("risk_request_invalid")
        now = self._now()
        with self._ledger.transaction() as txn:
            cursor = {
                "epoch": epoch,
                "last_sequence": -1,
                "head_sequence": head_sequence,
                "continuity": "VERIFIED" if head_sequence < 0 else "REPLAYING",
                "verified_from_zero": 1,
                "gap_reason": None,
            }
            txn.save_cursor(cursor, now)
            txn.audit("observation_reset", at_ns=now, detail={"head_sequence": head_sequence})

    def mark_observation_gap(self, reason: str) -> None:
        if not _ref(reason, 96):
            raise RiskRequestError("risk_request_invalid")
        now = self._now()
        with self._ledger.transaction() as txn:
            cursor = txn.cursor()
            cursor["continuity"] = "UNVERIFIED"
            cursor["gap_reason"] = reason
            txn.save_cursor(cursor, now)
            txn.audit("observation_gap", at_ns=now, detail={"reason": reason})

    def apply_observations(self, events: Sequence[ObservedExecutionEvent]) -> int:
        """Apply events and the cursor in one transaction; return the last applied sequence.

        The caller acknowledges the stream only up to the returned sequence.
        """
        if isinstance(events, (str, bytes)) or not all(
            type(event) is ObservedExecutionEvent for event in events
        ):
            raise RiskRequestError("risk_request_invalid")
        day = self._fact("trading_day", str)
        now = self._now()
        post: list[tuple[str, str]] = []
        with self._ledger.transaction() as txn:
            cursor = txn.cursor()
            for event in events:
                if cursor["epoch"] != event.epoch:
                    cursor.update(
                        epoch=event.epoch,
                        continuity="UNVERIFIED",
                        gap_reason="epoch_changed",
                        head_sequence=None,
                        last_sequence=event.sequence - 1,
                    )
                if event.sequence <= cursor["last_sequence"]:
                    continue  # duplicate redelivery; identities are already applied.
                if event.sequence != cursor["last_sequence"] + 1:
                    cursor.update(continuity="UNVERIFIED", gap_reason="sequence_gap")
                self._apply_event(txn, event, event.trading_day or day, now, post)
                cursor["last_sequence"] = event.sequence
                if (
                    cursor["continuity"] == "REPLAYING"
                    and cursor["head_sequence"] is not None
                    and cursor["last_sequence"] >= cursor["head_sequence"]
                ):
                    cursor["continuity"] = "VERIFIED"
            txn.save_cursor(cursor, now)
            last = cursor["last_sequence"]
        self._run_post(post)
        return last

    def _apply_event(
        self,
        txn: LedgerTxn,
        event: ObservedExecutionEvent,
        day: str | None,
        now: int,
        post: list[tuple[str, str]],
    ) -> None:
        instrument_id = event.instrument.instrument_id
        identity = event.order_identity
        ours = (
            event.origin == self._origin
            and event.request_key is not None
            and event.strategy_ref is not None
        )
        permit = txn.permit_by_key(event.strategy_ref, event.request_key) if ours else None  # type: ignore[arg-type]
        terminal_status = "rejected" if event.kind == "order_error" else event.status
        row = txn.order(identity)
        count_day = day or "unknown"
        if row is None:
            txn.insert_order(
                {
                    "identity": identity,
                    "origin": event.origin,
                    "strategy_ref": event.strategy_ref,
                    "request_key": event.request_key,
                    "reservation_id": event.reservation_id,
                    "order_ref": event.order_ref,
                    "permit_id": None if permit is None else permit.permit_id,
                    "instrument_id": instrument_id,
                    "instrument_json": json.dumps(event.instrument.to_dict(), sort_keys=True),
                    "side": event.side,
                    "order_offset": event.offset,
                    "limit_price": T(event.limit_price),
                    "quantity": T(event.quantity),
                    "filled_quantity": T(event.filled_quantity),
                    "status": terminal_status,
                    "terminal": int(terminal_status in TERMINAL_STATUSES),
                    "counted_order": 0,
                    "counted_cancel": 0,
                    "counted_reject": 0,
                    "bypass": int(permit is None),
                    "trading_day": day,
                    "last_epoch": event.epoch,
                    "last_sequence": event.sequence,
                    "updated_ns": now,
                }
            )
            row = txn.order(identity)
            if permit is None or permit.claimed_ns is None:
                # Bypass / external / unmatched orders, and own orders seen at the venue
                # without a Risk claim, are counted at first sight (R-04, L4).
                count = txn.add_counter(instrument_id, count_day, "order", Decimal(1))
                txn.update_order(identity, {"counted_order": 1})
                self._count_breach(txn, event, "orders", int(count), count_day, now, post)
                txn.audit(
                    "bypass_observed" if permit is None else "unclaimed_order_observed",
                    at_ns=now,
                    strategy_ref=event.strategy_ref,
                    instrument_id=instrument_id,
                    detail={"origin_kind": event.origin.split(":")[0]},
                )
        else:
            update: dict[str, Any] = {
                "last_epoch": event.epoch,
                "last_sequence": event.sequence,
                "updated_ns": now,
            }
            if not row["terminal"]:
                update["status"] = terminal_status
                update["terminal"] = int(terminal_status in TERMINAL_STATUSES)
            filled = max(Decimal(row["filled_quantity"]), event.filled_quantity)
            update["filled_quantity"] = T(filled)
            if row["permit_id"] is None and permit is not None:
                update["permit_id"] = permit.permit_id
            txn.update_order(identity, update)
            row = txn.order(identity)
        assert row is not None
        if row["status"] == "cancelled" and not row["counted_cancel"]:
            count = txn.add_counter(instrument_id, count_day, "cancel", Decimal(1))
            txn.update_order(identity, {"counted_cancel": 1})
            self._count_breach(txn, event, "cancels", int(count), count_day, now, post)
        if row["status"] == "rejected" and not row["counted_reject"]:
            txn.add_counter(instrument_id, count_day, "order_rejected_local", Decimal(1))
            txn.update_order(identity, {"counted_reject": 1})
        if event.kind == "cancel_error" and txn.mark_seen(event.epoch, event.sequence):
            txn.add_counter(instrument_id, count_day, "cancel_rejected", Decimal(1))
        if event.kind == "trade" and not txn.has_trade(event.trade_id):  # type: ignore[arg-type]
            self._apply_trade(txn, event, identity, permit, day, now)
            if permit is not None:
                permit = txn.permit(permit.permit_id)
        if permit is not None:
            self._settle_from_event(txn, permit, event, terminal_status, now)

    def _apply_trade(
        self,
        txn: LedgerTxn,
        event: ObservedExecutionEvent,
        identity: str,
        permit: Permit | None,
        day: str | None,
        now: int,
    ) -> None:
        quantity = event.trade_quantity
        assert quantity is not None
        instrument_id = event.instrument.instrument_id
        if event.offset is None:
            effect, position_side, bucket = "UNKNOWN", None, "UNKNOWN"
        else:
            effect, position_side, bucket = derive_effect(
                event.side, event.offset, event.instrument.venue
            )
        txn.insert_trade(
            {
                "trade_id": event.trade_id,
                "identity": identity,
                "permit_id": None if permit is None else permit.permit_id,
                "strategy_ref": event.strategy_ref,
                "origin": event.origin,
                "instrument_id": instrument_id,
                "side": event.side,
                "order_offset": event.offset,
                "position_side": position_side,
                "effect": effect,
                "bucket": bucket,
                "price": T(event.trade_price),
                "quantity": T(quantity),
                "trading_day": day,
                "applied_ns": now,
                "epoch": event.epoch,
                "sequence": event.sequence,
            }
        )
        holder = event.strategy_ref or ""
        if position_side is not None:
            delta = quantity if effect == "INCREASE" else -quantity
            txn.add_position(holder, instrument_id, position_side, delta)
        elif event.strategy_ref is not None:
            txn.audit(
                "position_effect_unknown",
                at_ns=now,
                strategy_ref=event.strategy_ref,
                instrument_id=instrument_id,
            )
        if effect in ("INCREASE", "UNKNOWN") and day is not None:
            txn.add_counter(instrument_id, day, "open_volume", quantity)
        if permit is not None:
            txn.update_permit(
                permit.permit_id,
                permit.row_version,
                trades_quantity=T(permit.trades_quantity + quantity),
                updated_ns=now,
            )

    def _settle_from_event(
        self, txn: LedgerTxn, permit: Permit, event: ObservedExecutionEvent, status: str, now: int
    ) -> None:
        if permit.state == "TERMINAL":
            return
        order_filled = T(max(permit.order_filled, event.filled_quantity))
        if status in TERMINAL_STATUSES:
            target = "TERMINAL"
        elif status == "unknown":
            target = "UNKNOWN"
        else:
            target = "DISPATCHED"
        fields: dict[str, Any] = {"order_filled": order_filled}
        if permit.state in ("RELEASED", "DENIED") or permit.code is not None:
            # A refusal or NOT_SENT conclusion was contradicted by the venue: the order is
            # real, so report its actual state (no refusal code), keep worst case and audit.
            txn.audit(
                "not_sent_contradicted",
                at_ns=now,
                strategy_ref=permit.strategy_ref,
                request_key=permit.request_key,
                permit_id=permit.permit_id,
                instrument_id=permit.instrument_id,
                code=permit.code,
            )
            fields["code"] = None
        if target != permit.state:
            fields["state"] = target
        txn.update_permit(permit.permit_id, permit.row_version, updated_ns=now, **fields)
        if target != permit.state:
            txn.audit(
                "settle",
                at_ns=now,
                strategy_ref=permit.strategy_ref,
                request_key=permit.request_key,
                permit_id=permit.permit_id,
                instrument_id=permit.instrument_id,
                effect=permit.effect,
                policy_version=permit.policy_version,
                detail={"from": permit.state, "to": target, "status": status},
            )

    def _count_breach(
        self,
        txn: LedgerTxn,
        event: ObservedExecutionEvent,
        kind: str,
        count: int,
        day: str,
        now: int,
        post: list[tuple[str, str]],
    ) -> None:
        active = self._active
        if active is None or active.policy.counters is None or day == "unknown":
            return
        limits = getattr(active.policy.counters, kind)
        if limits is None or count < limits.block:
            return
        breach = _Breach(
            control="counters",
            rule="counters",
            scope_kind="instrument",
            strategy_ref=event.strategy_ref,
            instrument=event.instrument,
            latch_code="risk_order_count_limit",
            reason="R-04",
            modes=(("STOP_NEW", "instrument"),),
        )
        self._apply_breach(txn, breach, day, now, post)

    # ================================================================== maintenance

    def recover(self) -> dict[str, int]:
        """On start: resolve RESERVING/CLAIMED/RELEASING/UNKNOWN permits by Gateway status."""
        with self._ledger.transaction() as txn:
            pending = txn.permits_in(("RESERVING", "CLAIMED", "RELEASING", "UNKNOWN"))
        counts = {"checked": 0}
        for permit in pending:
            counts["checked"] += 1
            if permit.state == "RELEASING":
                self._finish_release(permit)
            else:
                self._resolve(permit)
        self._retry_intents()
        return counts

    def maintain(self) -> dict[str, int]:
        """Expire RESERVED permits via status/release, resolve UNKNOWN, retry intents, L4 R-07."""
        now = self._now()
        with self._ledger.transaction() as txn:
            expired = [
                permit
                for permit in txn.permits_in(("RESERVED",))
                if permit.expires_ns is not None and permit.expires_ns <= now
            ]
            unknown = txn.permits_in(("UNKNOWN",))
            releasing = txn.permits_in(("RELEASING",))
        for permit in expired:
            reply = self._gateway_call(
                "status",
                strategy_ref=permit.strategy_ref,
                run_id=permit.run_id,
                request_key=permit.request_key,
            )
            if proves_not_sent(reply, permit):
                self._apply_status(permit, reply)
            elif reply.outcome == "OBSERVED" and reply.state == "RESERVED":
                with self._ledger.transaction() as txn:
                    current = txn.permit(permit.permit_id)
                    moved = current is not None and txn.transition(
                        current, ("RESERVED",), state="RELEASING", updated_ns=self._now()
                    )
                    current = txn.permit(permit.permit_id)
                if moved and current is not None:
                    self._release_via_gateway(current)
        for permit in unknown:
            self._resolve(permit)
        for permit in releasing:
            self._finish_release(permit)
        self._evaluate_loss_l4()
        self._retry_intents()
        return {"expired": len(expired), "unknown": len(unknown), "releasing": len(releasing)}

    def _evaluate_loss_l4(self) -> None:
        active = self._active
        if active is None or active.policy.loss is None:
            return
        loss = active.policy.loss
        trading_day = self._fact("trading_day", str)
        account = self._fact("account_snapshot", AccountSnapshot)
        subjects: list[tuple[str | None, StrategyFinancialFact | None]] = []
        if loss.account_day is not None or loss.account_drawdown is not None:
            subjects.append((None, None))
        subjects.extend(
            (strategy, self._fact("strategy_financial", StrategyFinancialFact, strategy))
            for strategy in sorted(loss.strategies)
        )
        now = self._now()
        post: list[tuple[str, str]] = []
        with self._ledger.transaction() as txn:
            for strategy, fact in subjects:
                facts = FactSnapshot(
                    now_ns=now,
                    trading_day=trading_day,
                    reference=None,
                    instrument=None,
                    account=account,
                    strategy=fact,
                    margin_rate=None,
                )
                ev = _Evaluation()
                policy = active.policy
                if strategy is not None:
                    # Evaluate only the strategy entry, not the account entries again.
                    policy = _strategy_only(policy)
                self._loss_breaches(txn, policy, strategy, facts, ev)
                for breach in ev.breaches:
                    self._apply_breach(txn, breach, trading_day or "", now, post)
        self._run_post(post)

    def _retry_intents(self) -> None:
        with self._ledger.transaction() as txn:
            controls = [
                (row["cause_id"], row["state"])
                for row in txn.control_intents(("PENDING", "UNKNOWN"))
            ]
            cancels = [
                row["operation_id"]
                for row in txn.cancel_intents(("PENDING", "UNKNOWN", "WAITING_CONTROL"))
            ]
        for cause_id, state in controls:
            self._apply_control(cause_id, query_first=state == "UNKNOWN")
        for operation in cancels:
            self._apply_cancel(operation)

    # ================================================================== admin

    @staticmethod
    def _require_operator(operator: object, operation: str) -> CallerIdentity:
        if (
            type(operator) is not CallerIdentity
            or operator.role != "operator"
            or operation not in operator.operations
        ):
            raise RiskAdminError("risk_unauthorized")
        return operator

    @staticmethod
    def _reason(reason: object, *, required: bool) -> str | None:
        if reason is None or reason == "":
            if required:
                raise RiskAdminError("risk_admin_reason_required")
            return None
        if not _ref(reason, 1024):
            raise RiskAdminError("risk_admin_reason_invalid")
        return reason  # type: ignore[return-value]

    def publish_policy(
        self,
        operator: CallerIdentity,
        raw: object,
        expected_version: int,
        reason: str | None,
        *,
        exchange_rules_text: object = None,
    ) -> PolicyPublishResult:
        """risk.policy.publish: CAS on the effective version; loosening needs a reason and
        no active latch in a loosened control family (D64-12)."""
        operator = self._require_operator(operator, "risk.policy.publish")
        if type(expected_version) is not int or expected_version < 0:
            raise RiskAdminError("policy_version_conflict")
        reason = self._reason(reason, required=False)
        try:
            policy = validate_policy_document(
                raw, exchange_rules_text=exchange_rules_text, rule_allowlist=self._rules.allowlist
            )
            document = load_document(raw)
        except RiskPolicyError as error:
            raise RiskAdminError(error.code) from None
        if policy.route != self._route or policy.account_scope != self._account_scope:
            raise RiskAdminError("policy_account_mismatch")
        rules_text = exchange_rules_text
        if type(rules_text) is bytes:
            rules_text = rules_text.decode("utf-8")
        document_json = json.dumps(
            document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        now = self._now()
        with self._ledger.transaction() as txn:
            row = txn.latest_policy()
            current = 0 if row is None else int(row["version"])
            if expected_version != current:
                raise RiskAdminError("policy_version_conflict")
            if row is not None and row["digest"] == policy.digest:
                return PolicyPublishResult(
                    current,
                    policy.policy_id,
                    policy.digest,
                    False,
                    {"tightened": [], "loosened": [], "unchanged": []},
                )
            old = None
            if row is not None:
                try:
                    old = validate_policy_document(
                        row["document_json"],
                        exchange_rules_text=row["exchange_rules_text"],
                        rule_allowlist=self._rules.allowlist,
                    )
                except RiskPolicyError:
                    old = None  # unreadable predecessor: treated like a bootstrap below
            classification = classify_change(old, policy)
            if classification["loosened"]:
                if reason is None:
                    raise RiskAdminError("policy_loosening_reason_required")
                families = {item_family(item) for item in classification["loosened"]}
                latches = txn.active_latches()
                # Without a comparable predecessor no latch may be active at all.
                if (old is None and latches) or any(
                    latch["control"] in families for latch in latches
                ):
                    raise RiskAdminError("policy_loosening_latched")
            try:
                active = activate(current + 1, policy, self._rules)
            except RuleConfigError:
                raise RiskAdminError("policy_rule_not_allowed") from None
            txn.insert_policy(
                version=current + 1,
                policy_id=policy.policy_id,
                digest=policy.digest,
                document_json=document_json,
                exchange_rules_text=rules_text,
                published_ns=now,
                operator_ref=operator.principal_ref,
                reason=reason,
                classification_json=json.dumps(classification, sort_keys=True),
            )
            txn.audit(
                "policy_publish",
                at_ns=now,
                policy_version=current + 1,
                detail={
                    "policy_id": policy.policy_id,
                    "digest": policy.digest,
                    "operator": operator.principal_ref,
                    "tightened": len(classification["tightened"]),
                    "loosened": classification["loosened"][:64],
                    "reason_given": reason is not None,
                },
            )
        self._active = active
        return PolicyPublishResult(
            current + 1, policy.policy_id, policy.digest, True, classification
        )

    def list_latches(self, *, active_only: bool = False) -> list[dict]:
        with self._ledger.transaction() as txn:
            rows = txn.active_latches() if active_only else txn.all_latches()
        return [_row_dict(row) for row in rows]

    def release_latch(
        self, operator: CallerIdentity, latch_id: str, expected_version: int, reason: str
    ) -> dict:
        """risk.latch.release: the only way a local latch is cleared (D64-09/D64-21)."""
        operator = self._require_operator(operator, "risk.latch.release")
        reason = self._reason(reason, required=True)
        if not _ref(latch_id) or type(expected_version) is not int:
            raise RiskAdminError("latch_not_found")
        now = self._now()
        with self._ledger.transaction() as txn:
            row = txn.latch(latch_id)
            if row is None:
                raise RiskAdminError("latch_not_found")
            if not row["active"]:
                raise RiskAdminError("latch_not_active")
            if row["row_version"] != expected_version:
                raise RiskAdminError("latch_version_conflict")
            if not txn.release_latch(
                latch_id,
                expected_version,
                released_by=operator.principal_ref,
                released_ns=now,
                release_reason=reason,
            ):  # type: ignore[arg-type]
                raise RiskAdminError("latch_version_conflict")
            txn.audit(
                "latch_release",
                at_ns=now,
                code=row["code"],
                detail={
                    "latch_id": latch_id,
                    "control": row["control"],
                    "scope_kind": row["scope_kind"],
                    "operator": operator.principal_ref,
                },
            )
            row = txn.latch(latch_id)
        return _row_dict(row)

    def list_unknown(self) -> list[dict]:
        with self._ledger.transaction() as txn:
            permits = txn.permits_in(("UNKNOWN",))
        return [
            {
                "permit_id": permit.permit_id,
                "strategy_ref": permit.strategy_ref,
                "request_key": permit.request_key,
                "instrument_id": permit.instrument_id,
                "side": permit.side,
                "offset": permit.offset,
                "quantity": permit.quantity,
                "occupancy": permit.occupancy,
                "reservation_id": permit.reservation_id,
                "gateway_state": permit.gateway_state,
                "gateway_code": permit.gateway_code,
                "trading_day": permit.trading_day,
                "created_ns": permit.created_ns,
                "updated_ns": permit.updated_ns,
            }
            for permit in permits
        ]

    def export_counts(self, trading_day: str, fmt: str) -> str:
        """risk.counts.export for operator reporting (not a regulatory submission)."""
        if type(trading_day) is not str or len(trading_day) != 8 or not trading_day.isdigit():
            raise RiskAdminError("risk_request_invalid")
        if fmt not in ("json", "csv"):
            raise RiskAdminError("risk_request_invalid")
        with self._ledger.transaction() as txn:
            rows = [
                (row["instrument_id"], row["kind"], row["value"])
                for row in txn.counters_for_day(trading_day)
            ]
        if fmt == "json":
            return json.dumps(
                {
                    "schema": "bt_api_risk.counts.v1",
                    "route": self._route,
                    "account_scope": self._account_scope,
                    "trading_day": trading_day,
                    "counts": [
                        {"instrument_id": instrument, "kind": kind, "value": value}
                        for instrument, kind, value in rows
                    ],
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["trading_day", "instrument_id", "kind", "value"])
        for instrument, kind, value in rows:
            writer.writerow([trading_day, instrument, kind, value])
        return buffer.getvalue()

    def read_audit(self, after: int, limit: int) -> list[dict]:
        if type(after) is not int or type(limit) is not int or after < 0 or not 0 < limit <= 1000:
            raise RiskAdminError("risk_request_invalid")
        with self._ledger.transaction() as txn:
            rows = txn.read_audit(after, limit)
        result = []
        for row in rows:
            item = {key: value for key, value in dict(row).items() if key != "detail_json"}
            item["detail"] = json.loads(row["detail_json"])
            result.append(item)
        return result

    def request_cancel(
        self, operator: CallerIdentity, operation_id: str, scope_kind: str, scope_value: str
    ) -> dict:
        """risk.cancel.request: an operator cancel intent forwarded to the Gateway control port."""
        operator = self._require_operator(operator, "risk.cancel.request")
        if (
            not _ref(operation_id)
            or scope_kind not in ("account", "strategy", "instrument")
            or type(scope_value) is not str
            or (scope_kind == "account") != (scope_value == "")
            or (scope_value and not _ref(scope_value))
        ):
            raise RiskAdminError("risk_request_invalid")
        now = self._now()
        with self._ledger.transaction() as txn:
            created = txn.ensure_cancel_intent(
                operation_id=operation_id,
                source="operator:" + operator.principal_ref,
                scope_kind=scope_kind,
                scope_value=scope_value,
                latch_id=None,
                wait_cause_id=None,
                now_ns=now,
            )
            row = txn.cancel_intent(operation_id)
            if not created and (
                row["scope_kind"] != scope_kind or row["scope_value"] != scope_value
            ):
                raise RiskAdminError("risk_request_conflict")
            if created:
                txn.audit(
                    "cancel_intent",
                    at_ns=now,
                    detail={
                        "operation_id": operation_id,
                        "scope_kind": scope_kind,
                        "operator": operator.principal_ref,
                    },
                )
        self._apply_cancel(operation_id)
        with self._ledger.transaction() as txn:
            row = txn.cancel_intent(operation_id)
        return _row_dict(row)

    def status_summary(self) -> dict:
        """risk.status / risk.admin.status (no account numbers, no paths)."""
        active = self._active
        trading_day = self._fact("trading_day", str)
        with self._ledger.transaction() as txn:
            cursor = txn.cursor()
            summary = {
                "available": active is not None,
                "policy_version": None if active is None else active.version,
                "policy_id": None if active is None else active.policy.policy_id,
                "policy_digest": None if active is None else active.policy.digest,
                "policy_load_error": self._store.load_error,
                "observation": {
                    "continuity": cursor["continuity"],
                    "epoch": cursor["epoch"],
                    "last_sequence": cursor["last_sequence"],
                    "verified_from_zero": bool(cursor["verified_from_zero"]),
                    "gap_reason": cursor["gap_reason"],
                },
                "bypass_orders": txn.bypass_count(),
                "unknown_permits": len(txn.permits_in(("UNKNOWN",))),
                "active_latches": len(txn.active_latches()),
                "pending_control_intents": len(txn.control_intents(("PENDING", "UNKNOWN"))),
                "pending_cancel_intents": len(
                    txn.cancel_intents(("PENDING", "UNKNOWN", "WAITING_CONTROL"))
                ),
                "counts": []
                if trading_day is None
                else [
                    {
                        "instrument_id": row["instrument_id"],
                        "kind": row["kind"],
                        "value": row["value"],
                    }
                    for row in txn.counters_for_day(trading_day)
                ],
            }
        return summary


def _row_dict(row) -> dict:
    """Plain mapping of a ledger row without its storage scope key."""
    return {key: value for key, value in dict(row).items() if key != "scope_key"}


def _status_fields(permit: Permit, reply: GatewayReply) -> dict[str, Any]:
    """Map a Gateway status reply to a permit transition (empty dict: no change)."""
    if proves_not_sent(reply, permit):
        return {"state": "RELEASED"}
    observed = reply.outcome == "OBSERVED"
    reservation_ok = permit.reservation_id is None or reply.reservation_id == permit.reservation_id
    sent = observed and reply.state in SENT_STATES and reservation_ok
    state = permit.state
    if state == "RESERVING":
        if (
            observed
            and reply.state == "RESERVED"
            and reply.reservation_id is not None
            and reply.digest == permit.payload_digest
        ):
            return {
                "state": "RESERVED",
                "reservation_id": reply.reservation_id,
                "gw_version": reply.version,
                "gw_digest": reply.digest,
                "owner_generation": reply.owner_generation,
                "reservation_generation": reply.reservation_generation,
            }
        return {"state": "UNKNOWN"}
    if state == "RESERVED":
        return {"state": "UNKNOWN"} if sent else {}
    if state == "CLAIMED":
        if sent:
            return {"state": "DISPATCHED"}
        if (observed and reply.state == "RESERVED") or reply.outcome == "TRANSPORT_NOT_STARTED":
            return {}
        return {"state": "UNKNOWN"}
    if state == "UNKNOWN":
        return {"state": "DISPATCHED"} if sent else {}
    if state == "RELEASING":
        return {"state": "UNKNOWN"} if reply.outcome != "TRANSPORT_NOT_STARTED" else {}
    return {}


def _possible_effects(side: str, offset: str | None, venue: str) -> list[tuple[str, str, str]]:
    if offset is not None:
        return [derive_effect(side, offset, venue)]
    # Unknown offset (external): conservatively both an open and a close.
    open_side = "LONG" if side == "BUY" else "SHORT"
    close_side = "LONG" if side == "SELL" else "SHORT"
    return [("INCREASE", open_side, "OPEN"), ("REDUCE", close_side, "UNKNOWN")]


def _r04_params(policy: RiskPolicy) -> dict:
    counters = policy.counters
    assert counters is not None
    return {
        "orders": None
        if counters.orders is None
        else {"warn": counters.orders.warn, "block": counters.orders.block},
        "cancels": None
        if counters.cancels is None
        else {"warn": counters.cancels.warn, "block": counters.cancels.block},
        "per_strategy_rate": None
        if counters.per_strategy_rate is None
        else {
            "max_orders": counters.per_strategy_rate.max_orders,
            "window_ms": counters.per_strategy_rate.window_ms,
        },
    }


def _strategy_only(policy: RiskPolicy) -> RiskPolicy:
    loss = policy.loss
    assert loss is not None
    return replace(policy, loss=LossPolicy(None, None, loss.strategies))


__all__ = [
    "NOT_SENT_STATES",
    "PolicyPublishResult",
    "PretradeEngine",
    "RiskAdminError",
    "RiskEngineConfigError",
    "RiskParentResult",
    "RiskRequestError",
    "proves_not_sent",
    "reserve_refused",
]
