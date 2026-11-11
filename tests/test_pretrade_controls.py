"""Control catalog R-01..R-08 and R-11 through the real reserve/dispatch path (UNIT/FAKE)."""

from __future__ import annotations

from decimal import Decimal

import pytest
from test_pretrade_support import (
    DAY,
    HC,
    NEXT_DAY,
    OPERATOR,
    RB,
    Harness,
    M,
    base_policy,
    caller,
    event,
    instrument,
    make_view,
)

from bt_api_risk.pretrade import (
    GatewayReply,
    InstrumentFacts,
    MarginRateFact,
    StrategyFinancialFact,
    crosses,
)


@pytest.fixture
def harness(tmp_path):
    item = Harness(tmp_path / "risk.db")
    yield item
    item.close()


def ready(harness, **sections):
    harness.publish(base_policy(**sections))
    harness.verify_stream()
    return harness


# ------------------------------------------------------------------ R-01 / R-01b


def test_r01_cap_boundary_open_and_close_and_unconfigured(harness):
    ready(harness, closable_check={"enabled": False})
    assert harness.reserve(make_view(key="a", qty="10")).outcome == "RESERVED"
    over = harness.reserve(make_view(key="b", qty="11"))
    assert over.code == "risk_order_quantity_exceeds_cap"
    close_over = harness.reserve(make_view(key="c", qty="11", side="SELL", offset="CLOSE"))
    assert close_over.code == "risk_order_quantity_exceeds_cap"
    # strat-z is an authorized caller but the policy has no R-01 limit for it (INV64-03)
    unconfigured = harness.reserve(make_view(key="d", strategy="strat-z"))
    assert unconfigured.code == "risk_limit_unconfigured"
    other_instrument = make_view(key="e", inst=instrument("ag2701"))
    assert harness.reserve(other_instrument).code == "risk_limit_unconfigured"
    # a caller without the strategy grant is refused before any policy check
    assert harness.reserve(make_view(key="f", strategy="strat-b"), caller("strat-a")).code == (
        "risk_unauthorized"
    )


def test_r01b_notional_boundary_and_missing_facts(harness):
    document = base_policy(closable_check={"enabled": False})
    document["per_order"]["max_notional"] = {"strat-a": {"rb2701": "2000"}}
    harness.publish(document)
    harness.verify_stream()
    # 2 x 100 x 10 = 2000 passes; 2 x 101 x 10 = 2020 refused
    assert harness.reserve(make_view(key="a", qty="2", price="100")).outcome == "RESERVED"
    assert harness.reserve(make_view(key="b", qty="2", price="101")).code == (
        "risk_order_notional_exceeds_cap"
    )
    harness.facts.instruments["rb2701"] = None
    assert harness.reserve(make_view(key="c")).code == "risk_instrument_facts_unavailable"
    close = harness.reserve(make_view(key="d", side="SELL", offset="CLOSE"))
    assert close.outcome == "RESERVED"  # R-01b does not refuse CLOSE on missing facts
    harness.facts.instruments["rb2701"] = InstrumentFacts(
        instrument=RB, multiplier=Decimal(10), tick_size=Decimal(1)
    )
    harness.facts.set_price(RB, None)
    assert (
        harness.reserve(make_view(key="e", price=None)).code == "risk_reference_price_unavailable"
    )


# ------------------------------------------------------------------ R-02


def band(**overrides):
    value = {"enabled": True, "max_deviation_ticks": {"rb2701": "5"}, "max_reference_age_ms": 1000}
    value.update(overrides)
    return value


def test_r02_band_boundary_stale_reference_and_market_orders(harness):
    ready(harness, price_band=band(), closable_check={"enabled": False})
    assert harness.reserve(make_view(key="a", price="105")).outcome == "RESERVED"
    assert harness.reserve(make_view(key="b", price="106")).code == "risk_price_band_exceeded"
    assert harness.reserve(make_view(key="c", price=None)).code == "risk_price_band_market_order"
    market_close = make_view(key="d", price=None, side="SELL", offset="CLOSE")
    assert harness.reserve(market_close).code == "risk_price_band_market_order"
    # limit CLOSE is not band-checked by default
    assert harness.reserve(
        make_view(key="e", price="200", side="SELL", offset="CLOSE")
    ).outcome == ("RESERVED")
    harness.facts.set_price(RB, "100", age_ms=1001)
    assert (
        harness.reserve(make_view(key="f", price="100")).code == "risk_reference_price_unavailable"
    )
    harness.facts.set_price(RB, "100", quality=False)
    assert (
        harness.reserve(make_view(key="g", price="100")).code == "risk_reference_price_unavailable"
    )
    harness.facts.set_price(RB, None)
    assert (
        harness.reserve(make_view(key="h", price="100")).code == "risk_reference_price_unavailable"
    )
    unconfigured = harness.reserve(make_view(key="i", inst=HC))
    assert unconfigured.code == "risk_limit_unconfigured"


def test_r02_apply_to_close_bps_mode_and_dispatch_recheck(harness):
    ready(
        harness,
        price_band=band(
            apply_to_close=True, max_deviation_ticks={}, max_deviation_bps={"rb2701": "100"}
        ),
        closable_check={"enabled": False},
    )
    # 1% of 100 = 1.0
    assert harness.reserve(make_view(key="a", price="101")).outcome == "RESERVED"
    assert harness.reserve(make_view(key="b", price="101.01")).code == "risk_price_band_exceeded"
    close = make_view(key="c", price="98", side="SELL", offset="CLOSE")
    assert harness.reserve(close).code == "risk_price_band_exceeded"
    view = make_view(key="d", price="100")
    reserved = harness.reserve(view)
    harness.clock.advance_ms(2000)  # reference now stale at claim (L3 recheck)
    result = harness.dispatch(view, reserved)
    assert result.outcome == "DENIED" and result.code == "risk_reference_price_unavailable"
    assert harness.gateway.count("dispatch") == 0


# ------------------------------------------------------------------ R-03


def test_r03_strategy_and_account_worst_case_position(harness):
    ready(
        harness,
        position={
            "account": {"rb2701": {"long": "6", "short": "6"}},
            "strategies": {"strat-a": {"rb2701": {"long": "4", "short": "4"}}},
        },
    )
    harness.facts.set_account({("rb2701", "LONG"): ("1", "0")})
    harness.clock.advance_ms(1)
    # strat-a fill of 1 observed from the stream after the account snapshot
    harness.engine.apply_observations(
        [
            event(
                0,
                kind="trade",
                strategy="strat-a",
                origin="self",
                key="old",
                status="filled",
                filled="1",
                trade_id="t0",
            ),
        ]
    )
    # strategy worst = position 1 + in flight + this order
    assert harness.reserve(make_view(key="a", qty="2")).outcome == "RESERVED"  # 1 + 0 + 2 = 3
    assert harness.reserve(make_view(key="b", qty="1")).outcome == "RESERVED"  # 1 + 2 + 1 = 4
    assert harness.reserve(make_view(key="c", qty="1")).code == "risk_position_limit_exceeded"
    # strat-b has no strategy limit; account worst = 1 (snapshot) + 1 (trade after snapshot)
    # + 3 in flight + 1 = 6 passes, + 2 fails
    assert harness.reserve(make_view(key="d", strategy="strat-b")).outcome == "RESERVED"
    assert harness.reserve(make_view(key="e", strategy="strat-b")).code == (
        "risk_position_limit_exceeded"
    )
    # CLOSE is not limited by R-03
    close = make_view(key="f", side="SELL", offset="CLOSE_TODAY", strategy="strat-b")
    assert harness.reserve(close).outcome == "RESERVED"


def test_r03_unknown_facts_refuse_open(harness):
    ready(
        harness,
        position={
            "account": {"rb2701": {"long": "6", "short": "6"}},
            "strategies": {"strat-a": {"hc2701": {"long": "1", "short": "1"}}},
        },
    )
    harness.facts.set_account(complete=False)
    assert harness.reserve(make_view(key="a")).code == "risk_position_facts_unavailable"
    harness.facts.set_account()
    harness.engine.mark_observation_gap("disconnect")
    assert harness.reserve(make_view(key="b", inst=HC)).code == "risk_position_facts_unavailable"


# ------------------------------------------------------------------ R-03b


def test_r03b_closable_with_buckets_and_other_strategies_in_flight(harness):
    ready(harness)
    harness.facts.set_account({("rb2701", "LONG"): ("2", "3")})
    # SHFE: plain CLOSE draws on yesterday (3); CLOSE_TODAY on today (2)
    assert harness.reserve(make_view(key="a", side="SELL", offset="CLOSE", qty="2")).outcome == (
        "RESERVED"
    )
    other = make_view(key="b", strategy="strat-b", side="SELL", offset="CLOSE", qty="2")
    assert harness.reserve(other).code == "risk_closable_exceeded"
    assert (
        harness.reserve(
            make_view(key="c", strategy="strat-b", side="SELL", offset="CLOSE", qty="1")
        ).outcome
        == "RESERVED"
    )
    today = make_view(key="d", side="SELL", offset="CLOSE_TODAY", qty="2")
    assert harness.reserve(today).outcome == "RESERVED"
    assert harness.reserve(make_view(key="e", side="SELL", offset="CLOSE_TODAY")).code == (
        "risk_closable_exceeded"
    )
    # No short position at all: zero closable (D63-49)
    assert harness.reserve(make_view(key="f", side="BUY", offset="CLOSE")).code == (
        "risk_closable_exceeded"
    )


def test_r03b_non_dated_venue_uses_total_and_unverified_refuses(harness):
    ready(harness)
    harness.facts.set_account({("m2701", "SHORT"): ("1", "1")})
    assert (
        harness.reserve(
            make_view(key="a", inst=M, side="BUY", offset="CLOSE_TODAY", qty="2")
        ).outcome
        == "RESERVED"
    )
    harness.facts.set_account(complete=False)
    assert harness.reserve(make_view(key="b", inst=M, side="BUY", offset="CLOSE")).code == (
        "risk_closable_unverified"
    )
    harness.facts.set_account({("m2701", "SHORT"): ("5", "5")})
    harness.engine.mark_observation_gap("seq")
    harness.publish(base_policy(self_trade={"enabled": False}))
    assert harness.reserve(make_view(key="c", inst=M, side="BUY", offset="CLOSE")).code == (
        "risk_closable_unverified"
    )


# ------------------------------------------------------------------ R-05


def test_r05_crossing_table():
    assert crosses("BUY", Decimal(100), Decimal(100)) is True
    assert crosses("BUY", Decimal(99), Decimal(100)) is False
    assert crosses("SELL", Decimal(100), Decimal(100)) is True
    assert crosses("SELL", Decimal(101), Decimal(100)) is False
    assert crosses("BUY", None, Decimal(105)) is True
    assert crosses("SELL", Decimal(1), None) is True


def test_r05_self_trade_against_working_orders_of_all_strategies(harness):
    ready(harness, closable_check={"enabled": False})
    assert harness.place(
        make_view(key="b1", strategy="strat-b", side="SELL", price="100")
    ).outcome == ("DISPATCHED")
    crossing = make_view(key="a1", side="BUY", price="100")
    reserved = harness.reserve(crossing)
    result = harness.dispatch(crossing, reserved)
    assert result.outcome == "DENIED" and result.code == "risk_self_trade"
    passive = make_view(key="a2", side="BUY", price="99")
    assert harness.place(passive).outcome == "DISPATCHED"
    # the same strategy is covered too
    same = make_view(key="b2", strategy="strat-b", side="BUY", price="101")
    assert harness.place(same).code == "risk_self_trade"
    # market order crosses any opposite working order
    assert harness.place(make_view(key="a3", side="SELL", price=None)).code == "risk_self_trade"


def test_r05_same_direction_close_and_reverse_open_is_not_self_trade(harness):
    ready(harness, closable_check={"enabled": False})
    assert harness.place(make_view(key="a1", side="SELL", offset="CLOSE", price="100")).outcome == (
        "DISPATCHED"
    )
    assert (
        harness.place(
            make_view(key="b1", strategy="strat-b", side="SELL", offset="OPEN", price="99")
        ).outcome
        == "DISPATCHED"
    )


def test_r05_unknown_and_external_orders_are_active(harness):
    ready(harness, closable_check={"enabled": False})
    harness.gateway.script["dispatch"] = [GatewayReply("UNKNOWN", code="TIMEOUT")]
    assert harness.place(
        make_view(key="b1", strategy="strat-b", side="SELL", price="100")
    ).state == ("UNKNOWN")
    assert harness.place(make_view(key="a1", side="BUY", price="100")).code == "risk_self_trade"
    # an external working order (bypass) without a price crosses anything
    harness.engine.apply_observations([event(0, side="BUY", price=None, inst=HC)])
    assert (
        harness.place(make_view(key="a2", inst=HC, side="SELL", price="200")).code
        == "risk_self_trade"
    )
    harness.engine.apply_observations(
        [event(1, side="BUY", price=None, inst=HC, status="cancelled", order_ref="ext-0")]
    )
    assert (
        harness.place(make_view(key="a3", inst=HC, side="SELL", price="200")).outcome
        == "DISPATCHED"
    )


def test_r05_unverified_stream_refuses_open_and_close(harness):
    ready(harness, closable_check={"enabled": False})
    harness.engine.mark_observation_gap("disconnect")
    assert harness.place(make_view(key="a")).code == "risk_self_trade_unverifiable"
    close = make_view(key="b", side="SELL", offset="CLOSE")
    assert harness.place(close).code == "risk_self_trade_unverifiable"


# ------------------------------------------------------------------ R-06


def test_r06_warn_deny_window_and_same_key_retry(harness):
    ready(harness, duplicate={"window_ms": 1000, "action": "deny"})
    first = make_view(key="a")
    assert harness.reserve(first).outcome == "RESERVED"
    assert harness.reserve(first).outcome == "RESERVED"  # same request key: idempotent, not dup
    assert harness.reserve(make_view(key="b")).code == "risk_duplicate_order"
    assert harness.reserve(make_view(key="c", price="101")).outcome == "RESERVED"
    harness.clock.advance_ms(1001)
    assert harness.reserve(make_view(key="d")).outcome == "RESERVED"
    harness.publish(base_policy(duplicate={"window_ms": 1000, "action": "warn"}))
    warned = harness.reserve(make_view(key="e"))
    assert warned.outcome == "RESERVED"
    audit = harness.engine.read_audit(0, 1000)
    assert any("risk_duplicate_order" in row["detail"].get("warnings", []) for row in audit)


# ------------------------------------------------------------------ R-07


def test_r07_account_day_loss_breach_latch_and_close_allowed(harness):
    ready(
        harness,
        loss={"account_day": {"warn": "500", "block": "1000"}},
        breach_actions=[{"rule": "loss.account_day", "request": "stop_new", "scope": "account"}],
        closable_check={"enabled": False},
    )
    harness.facts.set_account(close_profit="-600", position_profit="-300", commission="99")
    assert harness.reserve(make_view(key="a")).outcome == "RESERVED"  # loss 999 < 1000
    harness.facts.set_account(close_profit="-600", position_profit="-300", commission="100")
    breach = harness.reserve(make_view(key="b"))
    assert breach.code == "risk_loss_limit"
    assert [call[1]["scope_kind"] for call in harness.control.calls if call[0] == "apply"] == [
        "account"
    ]
    assert harness.control.calls[0][1]["mode"] == "STOP_NEW"
    harness.facts.set_account()  # loss recovered, but the latch holds
    assert harness.reserve(make_view(key="c", inst=HC)).code == "risk_breach_latched"
    close = make_view(key="d", side="SELL", offset="CLOSE")
    assert harness.reserve(close).outcome == "RESERVED"
    harness.facts.day = NEXT_DAY  # trading day change does not clear the latch (D64-09)
    harness.facts.set_account()
    assert harness.reserve(make_view(key="e")).code == "risk_breach_latched"


def test_r07_unknown_pnl_and_strategy_scope(harness):
    ready(
        harness,
        loss={"strategies": {"strat-a": {"day": {"block": "50"}, "drawdown": {"block": "80"}}}},
    )
    assert harness.reserve(make_view(key="a")).code == "risk_pnl_unknown"
    assert harness.reserve(make_view(key="b", strategy="strat-b")).outcome == "RESERVED"
    harness.facts.strategies["strat-a"] = StrategyFinancialFact(
        "strat-a", DAY, Decimal("1000"), 1, True, day_start_value=Decimal("1040")
    )
    assert harness.reserve(make_view(key="c")).outcome == "RESERVED"  # loss 40 < 50
    harness.facts.strategies["strat-a"] = StrategyFinancialFact(
        "strat-a", DAY, Decimal("990"), 2, True, day_start_value=Decimal("1040")
    )
    assert harness.reserve(make_view(key="d")).code == "risk_loss_limit"
    latches = harness.engine.list_latches(active_only=True)
    assert [(row["scope_kind"], row["scope_value"]) for row in latches] == [("strategy", "strat-a")]
    assert harness.reserve(make_view(key="e", strategy="strat-b")).outcome == "RESERVED"
    assert harness.control.count("apply") == 0  # no breach_actions configured


# ------------------------------------------------------------------ R-08


def test_r08_off_warn_deny_and_uncovered_occupancy(harness):
    ready(harness)
    harness.facts.set_account(available="2000")
    harness.facts.margins["rb2701"] = MarginRateFact(RB, Decimal("0.1"), Decimal("0.1"), 1, True)
    # 1 lot = 100 x 10 x 0.1 = 100 margin
    assert harness.reserve(make_view(key="a", qty="10")).outcome == "RESERVED"  # off
    harness.publish(base_policy(margin_precheck={"mode": "warn"}))
    assert harness.reserve(make_view(key="b", qty="10")).outcome == "RESERVED"  # warn only
    harness.publish(base_policy(margin_precheck={"mode": "deny"}), reason=None)
    # uncovered: 20 lots in flight = 2000, available 2000 -> any new lot refused
    assert harness.reserve(make_view(key="c")).code == "risk_margin_insufficient"
    harness.facts.set_account(available="2100")
    assert harness.reserve(make_view(key="d")).outcome == "RESERVED"
    harness.facts.margins["rb2701"] = None
    assert harness.reserve(make_view(key="e")).code == "risk_margin_facts_unavailable"
    close = make_view(key="f", side="SELL", offset="CLOSE")
    harness.facts.set_account({("rb2701", "LONG"): ("0", "5")})
    assert harness.reserve(close).outcome == "RESERVED"


# ------------------------------------------------------------------ R-11


RULES = (
    "schema: bt_api_risk.exchange_rules.v1\nrule_set_id: test\ninstruments:\n"
    "  rb2701: {position_limit: {long: '3', short: '3'}, daily_open_limit: '4'}\n"
    "  hc2701: {no_open_from_trading_day: '" + NEXT_DAY + "'}\n"
)


def test_r11_exchange_rules(harness):
    document = base_policy(exchange_rules={"file": "exchange.yaml"})
    harness.engine.publish_policy(OPERATOR, document, 0, "bootstrap", exchange_rules_text=RULES)
    harness.verify_stream()
    assert harness.reserve(make_view(key="a", qty="3")).outcome == "RESERVED"
    assert harness.reserve(make_view(key="b", qty="1")).code == "risk_exchange_rule_exceeded"
    assert harness.reserve(make_view(key="c", inst=HC)).outcome == "RESERVED"
    harness.facts.day = NEXT_DAY
    harness.facts.set_account()
    assert harness.reserve(make_view(key="d", inst=HC)).code == "risk_exchange_rule_exceeded"
    harness.facts.set_account(complete=False)
    assert harness.reserve(make_view(key="e", qty="1")).code == "risk_exchange_rule_unavailable"
    harness.engine.mark_observation_gap("gap")
    harness.facts.set_account()
    harness.facts.day = DAY
    assert harness.reserve(make_view(key="f", qty="1", strategy="strat-b")).code in (
        "risk_exchange_rule_unavailable",
    )


def test_r11_daily_open_counts_filled_opens_of_all_origins(harness):
    rules = RULES.replace("position_limit: {long: '3', short: '3'}, ", "")
    harness.engine.publish_policy(
        OPERATOR, base_policy(exchange_rules={"file": "x"}), 0, "boot", exchange_rules_text=rules
    )
    harness.verify_stream()
    harness.engine.apply_observations(
        [
            event(
                0,
                kind="trade",
                status="filled",
                qty="3",
                filled="3",
                trade_id="ext-t1",
                side="SELL",
            ),
        ]
    )
    assert harness.reserve(make_view(key="a", qty="1")).outcome == "RESERVED"
    assert harness.reserve(make_view(key="b", qty="1")).code == "risk_exchange_rule_exceeded"
