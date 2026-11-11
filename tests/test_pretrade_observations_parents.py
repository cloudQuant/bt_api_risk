"""Observation stream projection (L4) and parent envelopes (64.10). UNIT/FAKE evidence."""

from __future__ import annotations

from decimal import Decimal

import pytest
from test_pretrade_support import (
    ACTOR,
    DAY,
    HC,
    NEXT_DAY,
    OPERATOR,
    Harness,
    base_policy,
    caller,
    event,
    make_parent,
    make_view,
)

from bt_api_risk.pretrade import GatewayReply, RiskFactError, RiskRequestError

OURS = "risk:" + ACTOR


@pytest.fixture
def harness(tmp_path):
    item = Harness(tmp_path / "risk.db")
    item.publish(
        base_policy(
            closable_check={"enabled": False},
            position={"strategies": {"strat-a": {"rb2701": {"long": "5", "short": "5"}}}},
        )
    )
    item.verify_stream()
    yield item
    item.close()


def state(harness, key, strategy="strat-a"):
    return harness.engine.status(caller(strategy), key).state


def own(seq, key, **kwargs):
    return event(seq, origin=OURS, strategy="strat-a", key=key, **kwargs)


# ------------------------------------------------------------------ own delegated orders


def test_observations_settle_own_orders_and_fills_move_to_positions(harness):
    view = make_view(key="a", qty="3")
    assert harness.place(view).outcome == "DISPATCHED"
    last = harness.engine.apply_observations(
        [
            own(0, "a", qty="3", status="accepted"),
            own(
                1,
                "a",
                kind="trade",
                qty="3",
                filled="2",
                status="partially_filled",
                trade_id="t1",
                trade_qty="2",
            ),
        ]
    )
    assert last == 1
    assert state(harness, "a") == "DISPATCHED"
    # worst case = 2 filled + 1 in flight; one more lot fits the strategy limit of 5
    assert harness.reserve(make_view(key="b", qty="2", price="90")).outcome == "RESERVED"
    assert harness.reserve(make_view(key="c", qty="1", price="89")).code == (
        "risk_position_limit_exceeded"
    )
    # unfilled remainder is released only on terminal status
    harness.engine.apply_observations([own(2, "a", qty="3", filled="2", status="cancelled")])
    assert state(harness, "a") == "TERMINAL"
    assert harness.reserve(make_view(key="d", qty="1", price="88")).outcome == "RESERVED"


def test_terminal_before_trade_keeps_occupancy_for_unreported_fills(harness):
    assert harness.place(make_view(key="a", qty="4")).outcome == "DISPATCHED"
    harness.engine.apply_observations([own(0, "a", qty="4", filled="4", status="filled")])
    assert state(harness, "a") == "TERMINAL"
    assert harness.reserve(make_view(key="b", qty="2", price="90")).code == (
        "risk_position_limit_exceeded"
    )
    harness.engine.apply_observations(
        [
            own(
                1,
                "a",
                kind="trade",
                qty="4",
                filled="4",
                status="filled",
                trade_id="t1",
                trade_qty="4",
            ),
        ]
    )
    assert harness.reserve(make_view(key="c", qty="1", price="90")).outcome == "RESERVED"
    assert harness.reserve(make_view(key="d", qty="1", price="89")).code == (
        "risk_position_limit_exceeded"
    )


def test_gateway_unknown_status_and_contradicted_release_keep_worst_case(harness):
    assert harness.place(make_view(key="a")).outcome == "DISPATCHED"
    harness.engine.apply_observations([own(0, "a", status="unknown")])
    assert state(harness, "a") == "UNKNOWN"
    released = make_view(key="b", price="90")
    reserved = harness.reserve(released)
    harness.engine.release(caller("strat-a"), "b", reserved.permit_id)
    assert state(harness, "b") == "RELEASED"
    harness.engine.apply_observations([own(1, "b", status="accepted", price="90")])
    assert state(harness, "b") == "DISPATCHED"
    assert harness.engine.status(caller("strat-a"), "b").outcome == "DISPATCHED"
    assert any(row["kind"] == "not_sent_contradicted" for row in harness.engine.read_audit(0, 999))
    # the venue order that Risk never claimed is still counted for R-04
    counts = {
        (row["instrument_id"], row["kind"]): row["value"]
        for row in harness.engine.status_summary()["counts"]
    }
    assert counts[("rb2701", "order")] == "2"


def test_venue_order_for_a_risk_refused_permit_reports_the_live_order(tmp_path):
    harness = Harness(tmp_path / "risk.db")
    try:
        harness.publish(base_policy(closable_check={"enabled": False}))
        harness.verify_stream()
        harness.gateway.script["reserve"] = [GatewayReply("REQUEST_DENIED", code="X")]
        assert harness.reserve(make_view(key="g")).code == "risk_gateway_refused"
        harness.engine.apply_observations([own(0, "g", status="accepted")])
        result = harness.engine.status(caller("strat-a"), "g")
        assert (result.outcome, result.code) == ("DISPATCHED", None)
    finally:
        harness.close()


def test_dedupe_by_identity_and_trade_id(harness):
    trade = event(
        0,
        kind="trade",
        origin="self",
        strategy="strat-a",
        key="direct",
        status="filled",
        qty="2",
        filled="2",
        trade_id="T-1",
    )
    harness.engine.apply_observations([trade, trade])
    assert harness.engine.apply_observations([trade]) == 0  # redelivery is skipped
    # replay from 0 in the same epoch does not double count
    harness.engine.reset_observations("e1", 0)
    assert harness.engine.status_summary()["observation"]["continuity"] == "REPLAYING"
    harness.engine.apply_observations([trade])
    assert harness.engine.status_summary()["observation"]["continuity"] == "VERIFIED"
    summary = {row["kind"]: row["value"] for row in harness.engine.status_summary()["counts"]}
    assert summary["order"] == "1" and summary["open_volume"] == "2"
    # strategy position 2: three more lots fit a limit of 5, four do not
    assert harness.reserve(make_view(key="x", qty="4")).code == "risk_position_limit_exceeded"
    assert harness.reserve(make_view(key="y", qty="3")).outcome == "RESERVED"


def test_gap_makes_facts_unverified_until_reset_and_replay(harness):
    harness.engine.apply_observations([event(0, order_ref="o0")])
    assert harness.engine.apply_observations([event(2, order_ref="o2")]) == 2  # gap at 1
    observation = harness.engine.status_summary()["observation"]
    assert observation["continuity"] == "UNVERIFIED" and observation["gap_reason"] == "sequence_gap"
    assert harness.place(make_view(key="a")).code == "risk_position_facts_unavailable"
    assert harness.place(make_view(key="b", inst=HC)).code == "risk_self_trade_unverifiable"
    close = make_view(key="c", inst=HC, side="SELL", offset="CLOSE")
    assert harness.place(close).code == "risk_self_trade_unverifiable"
    harness.engine.reset_observations("e2", 2)
    harness.engine.apply_observations(
        [
            event(0, order_ref="o0", epoch="e2"),
            event(1, order_ref="o1", epoch="e2"),
        ]
    )
    assert harness.engine.status_summary()["observation"]["continuity"] == "REPLAYING"
    harness.engine.apply_observations([event(2, order_ref="o2", epoch="e2")])
    assert harness.engine.status_summary()["observation"]["continuity"] == "VERIFIED"
    assert harness.place(make_view(key="d", inst=HC)).outcome == "DISPATCHED"
    counts = {
        (row["instrument_id"], row["kind"]): row["value"]
        for row in harness.engine.status_summary()["counts"]
    }
    # o0 and o2 were already counted; the replay adds only o1 (dedupe by identity)
    assert counts[("rb2701", "order")] == "3"
    assert counts[("hc2701", "order")] == "1"


def test_epoch_change_without_reset_is_unverified(harness):
    harness.engine.apply_observations([event(0, order_ref="o0")])
    harness.engine.apply_observations([event(1, order_ref="o1", epoch="other")])
    assert harness.engine.status_summary()["observation"]["gap_reason"] == "epoch_changed"
    harness.engine.mark_observation_gap("disconnect")
    assert harness.engine.status_summary()["observation"]["gap_reason"] == "disconnect"


def test_invalid_observation_batch_is_refused():
    with pytest.raises(RiskFactError) as error:
        event(0, kind="trade")  # a trade needs trade_id/quantity/price
    assert error.value.code == "RISK_OBSERVATION_INVALID"
    with pytest.raises(RiskFactError):
        event(0, qty="1", filled="2")


def test_apply_observations_requires_typed_events(harness):
    with pytest.raises(RiskRequestError):
        harness.engine.apply_observations([{"sequence": 0}])


# ------------------------------------------------------------------ parents (64.10)


EXEC = caller("strat-a", role="execution", principal="exec-1", run="exec-run-1")


def child(key, qty="1", price="100", **kwargs):
    return make_view(
        key=key, qty=qty, price=price, origin="execution", parent_ref="P1", child_id=key, **kwargs
    )


def test_parent_envelope_reserves_whole_quantity_and_children_draw_down(harness):
    parent = harness.engine.parent_reserve(EXEC, make_parent(total="4"))
    assert parent.outcome == "RESERVED" and parent.unallocated_quantity == Decimal(4)
    # the strategy limit of 5 already holds 4 for the envelope
    assert harness.reserve(make_view(key="s1", qty="2", price="90")).code == (
        "risk_position_limit_exceeded"
    )
    assert harness.place(child("c1", qty="3"), EXEC).outcome == "DISPATCHED"
    assert harness.reserve(child("c2", qty="2"), EXEC).code == "risk_parent_envelope_exceeded"
    status = harness.engine.parent_status(EXEC, "P1")
    assert (status.allocated_quantity, status.unallocated_quantity) == (Decimal(3), Decimal(1))
    assert harness.reserve(make_view(key="s2", qty="1", price="90")).outcome == "RESERVED"


def test_parent_scope_checks(harness):
    harness.engine.parent_reserve(EXEC, make_parent(total="4", price="100"))
    assert harness.reserve(child("c1", price="101"), EXEC).code == "risk_parent_envelope_exceeded"
    assert harness.reserve(child("c2", price=None), EXEC).code == "risk_parent_envelope_exceeded"
    assert harness.reserve(child("c3", inst=HC), EXEC).code == "risk_parent_envelope_exceeded"
    assert harness.reserve(child("c4", side="SELL", price="100"), EXEC).code == (
        "risk_parent_envelope_exceeded"
    )
    orphan = make_view(key="c5", origin="execution", parent_ref="NOPE", child_id="c5")
    assert harness.reserve(orphan, EXEC).code == "risk_parent_unavailable"
    assert harness.reserve(child("c6", price="99"), EXEC).outcome == "RESERVED"


def test_parent_release_frees_only_unallocated_and_unknown_children_keep_theirs(harness):
    harness.engine.parent_reserve(EXEC, make_parent(total="4"))
    harness.gateway.script["dispatch"] = [GatewayReply("UNKNOWN", code="TIMEOUT")]
    assert harness.place(child("c1", qty="2"), EXEC).state == "UNKNOWN"
    released = harness.engine.parent_release(EXEC, "P1")
    assert released.state == "RELEASED" and released.unallocated_quantity == Decimal(0)
    assert released.allocated_quantity == Decimal(2)
    assert harness.reserve(make_view(key="s1", qty="3", price="90")).outcome == "RESERVED"
    assert harness.reserve(make_view(key="s2", qty="1", price="89")).code == (
        "risk_position_limit_exceeded"
    )
    assert harness.reserve(child("c2"), EXEC).code == "risk_parent_unavailable"


def test_released_child_returns_its_allocation(harness):
    harness.engine.parent_reserve(EXEC, make_parent(total="2"))
    view = child("c1", qty="2")
    reserved = harness.reserve(view, EXEC)
    harness.engine.release(EXEC, "c1", reserved.permit_id)
    assert harness.engine.parent_status(EXEC, "P1").unallocated_quantity == Decimal(2)
    assert harness.reserve(child("c2", qty="2"), EXEC).outcome == "RESERVED"


def test_execution_restart_freezes_the_parent_for_new_children(harness):
    harness.engine.parent_reserve(EXEC, make_parent(total="4"))
    first = child("c1")
    assert harness.place(first, EXEC).outcome == "DISPATCHED"
    restarted = caller("strat-a", role="execution", principal="exec-1", run="exec-run-2")
    assert harness.reserve(child("c2"), restarted).code == "risk_parent_frozen"
    assert harness.reserve(child("c3"), EXEC).code == "risk_parent_frozen"
    # already sent children still settle from the observation stream
    harness.engine.apply_observations(
        [
            event(0, origin=OURS, strategy="strat-a", key="c1", status="filled", filled="1"),
        ]
    )
    assert state(harness, "c1") == "TERMINAL"
    assert harness.engine.parent_status(EXEC, "P1").state == "FROZEN"


def test_parent_cross_day_keeps_identity_and_rechecks_children(harness):
    harness.engine.parent_reserve(EXEC, make_parent(total="4", valid_until=NEXT_DAY))
    assert harness.place(child("c1"), EXEC).outcome == "DISPATCHED"
    harness.facts.day = NEXT_DAY
    harness.facts.set_account()
    tighter = base_policy(
        closable_check={"enabled": False},
        position={"strategies": {"strat-a": {"rb2701": {"long": "5", "short": "5"}}}},
    )
    tighter["per_order"]["max_quantity"]["strat-a"]["rb2701"] = "1"
    harness.engine.publish_policy(OPERATOR, tighter, 1, None)
    assert harness.reserve(child("c2", qty="2"), EXEC).code == "risk_order_quantity_exceeds_cap"
    assert harness.place(child("c3"), EXEC).outcome == "DISPATCHED"
    status = harness.engine.parent_status(EXEC, "P1")
    assert status.total_quantity == Decimal(4) and status.allocated_quantity == Decimal(2)
    harness.facts.day = "20261116"
    harness.facts.set_account()
    assert harness.reserve(child("c4"), EXEC).code == "risk_parent_unavailable"
    assert harness.engine.parent_reserve(
        EXEC, make_parent(parent_ref="P2", created=DAY, valid_until=NEXT_DAY)
    ).code == ("risk_parent_unavailable")


def test_parent_authorization_and_idempotency(harness):
    assert (
        harness.engine.parent_reserve(caller("strat-a"), make_parent()).code == "risk_unauthorized"
    )
    first = harness.engine.parent_reserve(EXEC, make_parent(total="3"))
    assert harness.engine.parent_reserve(EXEC, make_parent(total="3")) == first
    assert harness.engine.parent_reserve(EXEC, make_parent(total="2")).code == (
        "risk_request_conflict"
    )
    assert harness.engine.parent_status(EXEC, "missing").outcome == "NOT_FOUND"
    close_today = make_parent(parent_ref="P3", side="SELL", offset="CLOSE_TODAY")
    harness.facts.set_account({("rb2701", "LONG"): ("5", "5")})
    assert harness.engine.parent_reserve(EXEC, close_today).outcome == "RESERVED"
    yesterday_child = make_view(
        key="y1",
        origin="execution",
        parent_ref="P3",
        child_id="y1",
        side="SELL",
        offset="CLOSE_YESTERDAY",
    )
    assert harness.reserve(yesterday_child, EXEC).code == "risk_parent_envelope_exceeded"
