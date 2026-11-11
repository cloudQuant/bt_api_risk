"""R-04 counters, local latches, control/cancel intents and the rule extension (UNIT/FAKE)."""

from __future__ import annotations

import hashlib

import pytest
from test_pretrade_support import (
    ACCOUNT,
    DAY,
    HC,
    NEXT_DAY,
    OPERATOR,
    Harness,
    base_policy,
    caller,
    event,
    make_view,
)

from bt_api_risk.pretrade import (
    BreachRequest,
    ControlReply,
    GatewayReply,
    RiskAdminError,
    RiskRule,
    RuleDecision,
    RuleRegistry,
)

COUNTERS = {"orders": {"warn": 2, "block": 3}}
R04_CAUSE = (
    "risk-r04-" + hashlib.sha256((ACCOUNT + "|rb2701|" + DAY).encode("utf-8")).hexdigest()[:24]
)


@pytest.fixture
def harness(tmp_path):
    item = Harness(tmp_path / "risk.db")
    item.publish(base_policy(counters=COUNTERS, closable_check={"enabled": False}))
    item.verify_stream()
    yield item
    item.close()


def place(harness, key, **kwargs):
    return harness.place(make_view(key=key, **kwargs))


def test_r04_counts_at_claim_including_unknown_and_blocks_at_the_threshold(harness):
    assert place(harness, "a1", price="99").outcome == "DISPATCHED"
    harness.gateway.script["dispatch"] = [GatewayReply("UNKNOWN", code="TIMEOUT")]
    assert place(harness, "a2", price="98").state == "UNKNOWN"  # UNKNOWN still counted as sent
    # reserve alone does not count
    assert harness.reserve(make_view(key="r-only", price="97")).outcome == "RESERVED"
    assert harness.control.count("apply") == 0
    # third claimed order reaches block=3: it passes, then the instrument is latched
    assert place(harness, "a3", price="96").outcome == "DISPATCHED"
    applies = [call[1] for call in harness.control.calls if call[0] == "apply"]
    assert applies == [
        {
            "cause_id": R04_CAUSE,
            "mode": "STOP_NEW",
            "scope_kind": "instrument",
            "scope_value": "SHFE:rb2701",
        }
    ]
    # every strategy's OPEN on rb2701 is refused; CLOSE and other instruments are not
    assert place(harness, "b1", strategy="strat-b", price="95").code == "risk_order_count_limit"
    assert harness.dispatch(
        make_view(key="r-only", price="97"), harness.engine.status(caller("strat-a"), "r-only")
    ).code == ("risk_order_count_limit")
    close = place(harness, "a4", side="SELL", offset="CLOSE", price="200")
    assert close.outcome == "DISPATCHED"
    assert place(harness, "a5", inst=HC).outcome == "DISPATCHED"
    assert harness.control.count("apply") == 1  # applied once, deterministic cause id
    counts = harness.engine.export_counts(DAY, "json")
    assert '"instrument_id":"rb2701","kind":"order","value":"4"' in counts


def test_r04_warn_threshold_is_audited(harness):
    place(harness, "a1", price="99")
    place(harness, "a2", price="98")
    warnings = [row for row in harness.engine.read_audit(0, 1000) if row["kind"] == "claim"]
    assert "risk_order_count_limit" in warnings[-1]["detail"]["warnings"]


def test_bypass_orders_and_cancels_are_counted_from_observations(harness):
    # an external order and a strategy-direct order (bypassing Risk) count at first sight
    harness.engine.apply_observations(
        [
            event(0, origin="external", price="90"),
            event(1, origin="self", strategy="strat-b", key="direct-1", price="91"),
            event(1, origin="self", strategy="strat-b", key="direct-1", price="91"),  # redelivery
            event(
                2, origin="self", strategy="strat-b", key="direct-1", price="91", status="cancelled"
            ),
            event(
                3, origin="self", strategy="strat-b", key="direct-1", price="91", status="cancelled"
            ),
        ]
    )
    summary = harness.engine.status_summary()
    assert summary["bypass_orders"] == 2
    counts = {(row["kind"]): row["value"] for row in summary["counts"]}
    assert counts == {"order": "2", "cancel": "1"}
    # bypass orders push the account x instrument count to block=3 with one more claim
    assert place(harness, "a1", price="80").outcome == "DISPATCHED"
    assert place(harness, "a2", price="79").code == "risk_order_count_limit"


def test_cancel_block_from_observations_latches_and_requests_stop_new(tmp_path):
    harness = Harness(tmp_path / "risk.db")
    try:
        harness.publish(base_policy(counters={"cancels": {"warn": 1, "block": 2}}))
        harness.verify_stream()
        harness.engine.apply_observations(
            [
                event(0, order_ref="x1", status="cancelled"),
                event(1, order_ref="x2", status="cancelled"),
            ]
        )
        assert [call[1]["scope_value"] for call in harness.control.calls] == ["SHFE:rb2701"]
        assert place(harness, "a1").code == "risk_order_count_limit"
    finally:
        harness.close()


def test_unreachable_control_keeps_the_latch_and_retries_the_same_cause(harness):
    harness.control.script["apply"] = [
        RuntimeError("down"),
        ControlReply("TRANSPORT_NOT_STARTED", code="NOT_READY"),
    ]
    for index in range(3):
        place(harness, "a" + str(index), price=str(99 - index))
    assert place(harness, "b1", strategy="strat-b", price="90").code == "risk_order_count_limit"
    intents = harness.engine.status_summary()["pending_control_intents"]
    assert intents == 1
    harness.engine.maintain()  # UNKNOWN: status first, then the same cause id again
    harness.engine.maintain()
    applies = [call[1]["cause_id"] for call in harness.control.calls if call[0] == "apply"]
    assert applies == [R04_CAUSE, R04_CAUSE, R04_CAUSE]
    assert harness.engine.status_summary()["pending_control_intents"] == 0
    assert all(call[1].get("mode") != "RESUME" for call in harness.control.calls)


def test_latch_survives_day_change_and_restart_and_only_an_operator_releases_it(harness):
    for index in range(3):
        place(harness, "a" + str(index), price=str(99 - index))
    harness.facts.day = NEXT_DAY
    harness.facts.set_account()
    harness.restart()
    assert place(harness, "n1").code == "risk_order_count_limit"  # new day: count 0, latch kept
    latch = harness.engine.list_latches(active_only=True)[0]
    assert latch["control"] == "counters" and latch["scope_value"] == "rb2701"
    with pytest.raises(RiskAdminError) as error:
        harness.engine.release_latch(
            caller("strat-a"), latch["latch_id"], latch["row_version"], "x"
        )
    assert error.value.code == "risk_unauthorized"
    with pytest.raises(RiskAdminError) as error:
        harness.engine.release_latch(OPERATOR, latch["latch_id"], latch["row_version"] + 1, "x")
    assert error.value.code == "latch_version_conflict"
    with pytest.raises(RiskAdminError) as error:
        harness.engine.release_latch(OPERATOR, latch["latch_id"], latch["row_version"], "")
    assert error.value.code == "risk_admin_reason_required"
    released = harness.engine.release_latch(
        OPERATOR, latch["latch_id"], latch["row_version"], "checked with broker"
    )
    assert released["active"] == 0 and released["released_by"] == "operator-1"
    assert place(harness, "n2").outcome == "DISPATCHED"


def test_released_latch_same_day_still_refuses_while_count_is_at_block(harness):
    for index in range(3):
        place(harness, "a" + str(index), price=str(99 - index))
    latch = harness.engine.list_latches(active_only=True)[0]
    harness.engine.release_latch(OPERATOR, latch["latch_id"], latch["row_version"], "ok")
    assert place(harness, "a9", price="90").code == "risk_order_count_limit"
    assert place(harness, "c1", side="SELL", offset="CLOSE", price="200").outcome == "DISPATCHED"


def test_per_strategy_rate_window(tmp_path):
    harness = Harness(tmp_path / "risk.db")
    try:
        harness.publish(
            base_policy(counters={"per_strategy_rate": {"max_orders": 2, "window_ms": 1000}})
        )
        harness.verify_stream()
        assert place(harness, "a1", price="99").outcome == "DISPATCHED"
        assert place(harness, "a2", price="98", inst=HC).outcome == "DISPATCHED"
        assert place(harness, "a3", price="97").code == "risk_order_count_limit"
        assert place(harness, "b1", strategy="strat-b", price="96").outcome == "DISPATCHED"
        harness.clock.advance_ms(1001)
        assert place(harness, "a4", price="95").outcome == "DISPATCHED"
    finally:
        harness.close()


def test_breach_cancel_rules_and_operator_cancel(tmp_path):
    harness = Harness(tmp_path / "risk.db")
    try:
        harness.publish(
            base_policy(
                loss={"account_day": {"block": "100"}},
                breach_actions=[
                    {"rule": "loss.account_day", "request": "freeze", "scope": "account"}
                ],
                cancel_rules=[
                    {
                        "rule": "loss.account_day",
                        "action": "stop_new_and_cancel",
                        "scope": "account",
                    }
                ],
            )
        )
        harness.verify_stream()
        harness.facts.set_account(close_profit="-100")
        assert harness.reserve(make_view(key="a")).code == "risk_loss_limit"
        names = [(call[0], call[1].get("mode")) for call in harness.control.calls]
        # FREEZE as configured, STOP_NEW before the cancel, then the cancel itself
        assert names == [("apply", "FREEZE"), ("apply", "STOP_NEW"), ("cancel_scope", None)]
        result = harness.engine.request_cancel(
            OPERATOR, "ops-cancel-1", "instrument", "SHFE:rb2701"
        )
        assert result["state"] == "ACCEPTED"
        harness.engine.request_cancel(OPERATOR, "ops-cancel-1", "instrument", "SHFE:rb2701")
        assert harness.control.count("cancel_scope") == 2  # idempotent on the operation id
        with pytest.raises(RiskAdminError):
            harness.engine.request_cancel(OPERATOR, "ops-cancel-1", "account", "")
        with pytest.raises(RiskAdminError):
            harness.engine.request_cancel(caller("strat-a"), "ops-cancel-2", "account", "")
    finally:
        harness.close()


def test_pending_control_is_superseded_when_the_latch_is_released(tmp_path):
    harness = Harness(tmp_path / "risk.db")
    try:
        harness.publish(
            base_policy(
                loss={"account_day": {"block": "100"}},
                breach_actions=[
                    {"rule": "loss.account_day", "request": "stop_new", "scope": "account"}
                ],
            )
        )
        harness.verify_stream()
        harness.control.script["apply"] = [ControlReply("TRANSPORT_NOT_STARTED")]
        harness.facts.set_account(close_profit="-100")
        harness.reserve(make_view(key="a"))
        latch = harness.engine.list_latches(active_only=True)[0]
        harness.engine.release_latch(OPERATOR, latch["latch_id"], latch["row_version"], "ok")
        harness.engine.maintain()
        assert harness.control.count("apply") == 1  # not re-sent after release
    finally:
        harness.close()


# ------------------------------------------------------------------ rule extension (Q32)


class MaxPriceRule(RiskRule):
    version = 1

    def evaluate(self, ctx):
        if ctx.phase == "claim" and ctx.view.limit_price > int(ctx.params["max_price"]):
            return RuleDecision(
                "DENY",
                "risk_price_band_exceeded",
                BreachRequest("STOP_NEW", "strategy", ctx.view.strategy_ref),
            )
        return RuleDecision("PASS")


class ExplodingRule(RiskRule):
    version = 1

    def evaluate(self, ctx):
        raise ValueError("boom")


class GarbageRule(RiskRule):
    version = 1

    def evaluate(self, ctx):
        return "PASS"


class UnknownCodeRule(RiskRule):
    version = 1

    def evaluate(self, ctx):
        return object.__new__(RuleDecision)


class DriftedRule(RiskRule):
    version = 2  # the trusted config still expects version 1


class AlwaysPassRule(RiskRule):
    version = 1
    calls = 0

    def evaluate(self, ctx):
        AlwaysPassRule.calls += 1
        return RuleDecision("PASS")


def _impl(cls) -> str:
    return __name__ + ":" + cls.__name__


def _rule_harness(tmp_path, cls, *, breach=False, extra=()):
    allow = {_impl(cls): 1}
    allow.update({_impl(item): 1 for item in extra})
    harness = Harness(tmp_path / "risk.db", registry=RuleRegistry(allow))
    rules = [
        {"id": "custom", "implementation": _impl(cls), "version": 1, "params": {"max_price": 100}}
    ]
    rules.extend(
        {"id": "x" + item.__name__, "implementation": _impl(item), "version": 1} for item in extra
    )
    sections = {"rules": rules}
    if breach:
        sections["breach_actions"] = [
            {"rule": "custom", "request": "stop_new", "scope": "strategy"}
        ]
    harness.publish(base_policy(**sections))
    harness.verify_stream()
    return harness


def test_registered_custom_rule_changes_the_decision_through_the_real_path(tmp_path):
    harness = _rule_harness(tmp_path, MaxPriceRule, breach=True)
    try:
        assert place(harness, "a1", price="100").outcome == "DISPATCHED"
        refused = place(harness, "a2", price="101")
        assert refused.code == "risk_price_band_exceeded" and refused.state == "RELEASED"
        assert [call[1]["scope_kind"] for call in harness.control.calls] == ["strategy"]
        assert place(harness, "a3", price="90").code == "risk_breach_latched"
        assert place(harness, "b1", strategy="strat-b", price="90").outcome == "DISPATCHED"
    finally:
        harness.close()


def test_unconfigured_breach_request_is_not_honoured(tmp_path):
    harness = _rule_harness(tmp_path, MaxPriceRule, breach=False)
    try:
        assert place(harness, "a2", price="101").code == "risk_price_band_exceeded"
        assert harness.control.count("apply") == 0
        assert harness.engine.list_latches() == []
        assert any(
            row["kind"] == "breach_request_not_configured"
            for row in harness.engine.read_audit(0, 1000)
        )
    finally:
        harness.close()


@pytest.mark.parametrize("cls", [ExplodingRule, GarbageRule, UnknownCodeRule, DriftedRule])
def test_failing_rules_fail_closed_and_are_audited(tmp_path, cls):
    harness = _rule_harness(tmp_path, cls)
    try:
        result = harness.reserve(make_view(key="a1"))
        assert result.outcome == "DENIED" and result.code == "risk_rule_failed"
        assert any(row["kind"] == "rule_failed" for row in harness.engine.read_audit(0, 1000))
    finally:
        harness.close()


def test_a_later_rule_never_turns_an_earlier_deny_into_pass(tmp_path):
    AlwaysPassRule.calls = 0
    harness = _rule_harness(tmp_path, ExplodingRule, extra=(AlwaysPassRule,))
    try:
        assert harness.reserve(make_view(key="a1")).code == "risk_rule_failed"
        assert AlwaysPassRule.calls == 0
        assert harness.reserve(make_view(key="a2", qty="11")).code == (
            "risk_order_quantity_exceeds_cap"
        )
    finally:
        harness.close()


def test_policy_cannot_name_an_unlisted_rule_class(tmp_path):
    harness = Harness(tmp_path / "risk.db", registry=RuleRegistry({_impl(MaxPriceRule): 1}))
    try:
        document = base_policy(rules=[{"id": "evil", "implementation": "os:system", "version": 1}])
        with pytest.raises(RiskAdminError) as error:
            harness.publish(document)
        assert error.value.code == "policy_rule_not_allowed"
        wrong_version = base_policy(
            rules=[{"id": "c", "implementation": _impl(MaxPriceRule), "version": 2}]
        )
        with pytest.raises(RiskAdminError):
            harness.publish(wrong_version)
    finally:
        harness.close()


def test_registry_refuses_non_rule_classes(tmp_path):
    registry = RuleRegistry({__name__ + ":Harness": 1})
    harness = Harness(tmp_path / "risk.db", registry=registry)
    try:
        document = base_policy(
            rules=[{"id": "c", "implementation": __name__ + ":Harness", "version": 1}]
        )
        with pytest.raises(RiskAdminError) as error:
            harness.publish(document)
        assert error.value.code == "policy_rule_not_allowed"
    finally:
        harness.close()
