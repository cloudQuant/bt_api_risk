"""Permit state machine, NOT_SENT proof, crash points and races (freeze 64.01 section 5).

UNIT/FAKE evidence: fake Gateway ports, a real SQLite ledger and writer fence.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from test_pretrade_support import (
    HC,
    OPERATOR,
    RB,
    Harness,
    base_policy,
    caller,
    make_view,
    payload_of,
    sha,
)

from bt_api_risk.pretrade import GatewayReply, RiskAdminError, proves_not_sent
from bt_api_risk.pretrade.ledger import Permit


class Crash(BaseException):
    """Simulated process death at a port call (not caught by the engine)."""


@pytest.fixture
def harness(tmp_path):
    item = Harness(tmp_path / "risk.db")
    item.publish(base_policy(closable_check={"enabled": False}))
    item.verify_stream()
    yield item
    item.close()


def permit_state(harness, key: str, strategy: str = "strat-a") -> str:
    return harness.engine.status(caller(strategy), key).state


# ------------------------------------------------------------------ proof predicate


def _permit(**overrides) -> Permit:
    values = {
        "permit_id": "p",
        "strategy_ref": "s",
        "request_key": "k",
        "run_id": None,
        "principal_ref": "pr",
        "origin": "strategy",
        "view_json": "{}",
        "view_digest": "0" * 64,
        "payload_json": "{}",
        "payload_digest": "d" * 64,
        "instrument_id": "rb2701",
        "instrument_json": "{}",
        "side": "BUY",
        "offset": "OPEN",
        "effect": "INCREASE",
        "position_side": "LONG",
        "bucket": "OPEN",
        "quantity": Decimal(1),
        "limit_price": Decimal(1),
        "parent_ref": None,
        "child_id": None,
        "trading_day": "20261112",
        "policy_version": 1,
        "state": "RESERVED",
        "row_version": 1,
        "code": None,
        "gateway_code": None,
        "gateway_state": None,
        "reservation_id": "r1",
        "gw_version": 1,
        "gw_digest": None,
        "owner_generation": "o1",
        "reservation_generation": "g1",
        "margin_per_unit": None,
        "trades_quantity": Decimal(0),
        "order_filled": Decimal(0),
        "created_ns": 1,
        "expires_ns": None,
        "claimed_ns": None,
        "updated_ns": 1,
    }
    values.update(overrides)
    return Permit(**values)


def _reply(**overrides) -> GatewayReply:
    values = {
        "outcome": "OBSERVED",
        "state": "RELEASED",
        "reservation_id": "r1",
        "digest": "d" * 64,
        "owner_generation": "o1",
        "reservation_generation": "g1",
    }
    values.update(overrides)
    return GatewayReply(**values)


@pytest.mark.parametrize("state", ["RELEASED", "EXPIRED", "NOT_SENT"])
def test_terminal_matching_status_is_proof(state):
    assert proves_not_sent(_reply(state=state), _permit()) is True


@pytest.mark.parametrize(
    "reply",
    [
        _reply(state="SENT"),
        _reply(state="DISPATCHING"),
        _reply(state="UNKNOWN"),
        _reply(state=None, code="NOT_FOUND"),
        _reply(outcome="UNKNOWN"),
        _reply(outcome="REQUEST_DENIED"),
        _reply(outcome="TRANSPORT_NOT_STARTED"),
        _reply(digest=None),
        _reply(digest="e" * 64),
        _reply(reservation_id="r2"),
        _reply(owner_generation="o2"),
        _reply(reservation_generation="g2"),
        None,
    ],
)
def test_non_matching_or_non_terminal_status_is_not_proof(reply):
    assert proves_not_sent(reply, _permit()) is False


# ------------------------------------------------------------------ idempotency


def test_reserve_retry_returns_persisted_state_without_second_gateway_call(harness):
    view = make_view()
    first = harness.reserve(view)
    again = harness.reserve(view)
    assert first == again and first.outcome == "RESERVED"
    assert harness.gateway.count("reserve") == 1


def test_conflicting_digest_for_the_same_key_is_refused(harness):
    first = harness.reserve(make_view(qty="1"))
    conflict = harness.reserve(make_view(qty="2"))
    assert conflict.outcome == "DENIED" and conflict.code == "risk_request_conflict"
    assert harness.engine.status(caller("strat-a"), "k1").permit_id == first.permit_id
    other_principal = caller("strat-a", principal="someone-else")
    assert harness.reserve(make_view(), other_principal).code == "risk_request_conflict"


def test_dispatch_retry_does_not_dispatch_twice_and_mismatches_are_refused(harness):
    view = make_view()
    reserved = harness.reserve(view)
    assert harness.dispatch(view, reserved).outcome == "DISPATCHED"
    assert harness.dispatch(view, reserved).outcome == "DISPATCHED"
    assert harness.gateway.count("dispatch") == 1
    engine = harness.engine
    who = caller("strat-a")
    assert engine.dispatch(who, "k1", reserved.permit_id, "res-other", view.digest()).code == (
        "risk_permit_mismatch"
    )
    assert engine.dispatch(
        who, "k1", reserved.permit_id, reserved.reservation_id, "0" * 64
    ).code == ("risk_permit_mismatch")
    assert (
        engine.dispatch(who, "k1", "no-such-permit", reserved.reservation_id, view.digest()).code
        == "risk_permit_mismatch"
    )
    assert (
        engine.dispatch(
            caller("strat-b"), "k1", reserved.permit_id, reserved.reservation_id, view.digest()
        ).code
        == "risk_unauthorized"
    )
    impostor = caller("strat-a", principal="impostor")
    assert (
        engine.dispatch(
            impostor, "k1", reserved.permit_id, reserved.reservation_id, view.digest()
        ).code
        == "risk_permit_mismatch"
    )


def test_authorization_and_derived_effect_rules(harness):
    no_ops = caller("strat-a", operations=())
    assert harness.reserve(make_view(), no_ops).code == "risk_unauthorized"
    execution_view = make_view(origin="execution", parent_ref="P", child_id="c1")
    assert harness.reserve(execution_view, caller("strat-a")).code == "risk_unauthorized"
    operator_like = caller("strat-a", role="operator")
    assert harness.reserve(make_view(key="k2"), operator_like).code == "risk_unauthorized"
    assert harness.reserve(make_view(key="k3", offset=None)).code == "risk_request_invalid"
    contradiction = make_view(key="k4", side="BUY", offset="OPEN", position_side="SHORT")
    assert harness.reserve(contradiction).code == "risk_request_invalid"
    # unauthorized requests leave no permit behind (no request-key squatting)
    assert harness.engine.status(caller("strat-a"), "k1").outcome == "NOT_FOUND"


def test_status_not_found_is_scoped_to_the_callers_strategies(harness):
    harness.reserve(make_view(strategy="strat-b", key="secret"))
    assert harness.engine.status(caller("strat-a"), "secret").outcome == "NOT_FOUND"
    assert harness.engine.status(caller("strat-b"), "secret").outcome == "RESERVED"


# ------------------------------------------------------------------ Gateway reserve answers


@pytest.mark.parametrize("outcome", ["REQUEST_DENIED", "TRANSPORT_NOT_STARTED"])
def test_definite_gateway_refusal_on_reserve_releases_occupancy(tmp_path, outcome):
    harness = Harness(tmp_path / "risk.db")
    try:
        harness.publish(base_policy(position={"account": {"rb2701": {"long": "1", "short": "1"}}}))
        harness.verify_stream()
        harness.gateway.script["reserve"] = [GatewayReply(outcome, code="STRATEGY_STOPPED")]
        refused = harness.reserve(make_view(key="a"))
        assert refused.outcome == "DENIED" and refused.code == "risk_gateway_refused"
        assert refused.gateway_code == "STRATEGY_STOPPED"
        # occupancy freed: the account limit of 1 admits another order
        assert harness.reserve(make_view(key="b")).outcome == "RESERVED"
    finally:
        harness.close()


def test_uncertain_reserve_answer_keeps_worst_case_occupancy(tmp_path):
    harness = Harness(tmp_path / "risk.db")
    try:
        harness.publish(base_policy(position={"account": {"rb2701": {"long": "1", "short": "1"}}}))
        harness.verify_stream()
        harness.gateway.script["reserve"] = [GatewayReply("UNKNOWN", code="TIMEOUT")]
        uncertain = harness.reserve(make_view(key="a"))
        assert uncertain.outcome == "UNKNOWN" and uncertain.state == "UNKNOWN"
        assert [row["request_key"] for row in harness.engine.list_unknown()] == ["a"]
        assert harness.reserve(make_view(key="b")).code == "risk_position_limit_exceeded"
        # a status of NOT_FOUND is never a NOT_SENT proof
        del harness.gateway.commands["a"]
        harness.engine.maintain()
        assert permit_state(harness, "a") == "UNKNOWN"
    finally:
        harness.close()


# ------------------------------------------------------------------ crash points (section 4.3)


def test_crash_after_reserving_commit_with_gateway_not_found_stays_unknown(harness):
    def crash(kwargs):
        raise Crash()

    harness.gateway.hooks["reserve"] = crash
    with pytest.raises(Crash):
        harness.reserve(make_view(key="a"))
    harness.gateway.hooks.clear()
    harness.restart()
    assert permit_state(harness, "a") == "RESERVING"
    harness.engine.recover()
    assert permit_state(harness, "a") == "UNKNOWN"
    assert harness.engine.list_unknown()[0]["occupancy"] == Decimal(1)


def test_crash_after_gateway_reserved_recovers_reserved(harness):
    view = make_view(key="a")

    def crash_after(kwargs):
        harness.gateway.commands["a"] = {
            "digest": sha(kwargs["canonical_payload"]),
            "reservation_id": "res-a",
            "state": "RESERVED",
        }
        raise Crash()

    harness.gateway.hooks["reserve"] = crash_after
    with pytest.raises(Crash):
        harness.reserve(view)
    harness.gateway.hooks.clear()
    harness.restart()
    harness.engine.recover()
    result = harness.reserve(view)  # same identity: persisted state, no second reserve
    assert result.outcome == "RESERVED" and result.reservation_id == "res-a"
    assert harness.gateway.count("reserve") == 1


def test_reserved_with_gateway_expired_becomes_released_after_restart(harness):
    view = make_view(key="a")
    harness.reserve(view)
    harness.restart()
    harness.gateway.commands["a"]["state"] = "EXPIRED"
    harness.engine.recover()
    assert permit_state(harness, "a") == "RESERVED"  # recover does not expire RESERVED
    harness.clock.advance_ms(10_001)
    harness.engine.maintain()
    assert permit_state(harness, "a") == "RELEASED"


def test_local_ttl_expiry_alone_is_not_proof(harness):
    harness.reserve(make_view(key="a"))
    harness.clock.advance_ms(60_000)
    harness.gateway.script["status"] = [GatewayReply("UNKNOWN", code="TIMEOUT")]
    harness.engine.maintain()
    assert permit_state(harness, "a") == "RESERVED"
    # a still-RESERVED Gateway reservation is released through the Gateway with proof
    harness.engine.maintain()
    assert permit_state(harness, "a") == "RELEASED"
    assert harness.gateway.count("release") == 1


@pytest.mark.parametrize(
    ("gateway_state", "expected"),
    [
        ("DISPATCHING", "DISPATCHED"),
        ("SENT", "DISPATCHED"),
        ("RELEASED", "RELEASED"),
        ("EXPIRED", "RELEASED"),
    ],
)
def test_crash_after_claim_commit_resolves_by_gateway_status(harness, gateway_state, expected):
    view = make_view(key="a")
    reserved = harness.reserve(view)

    def crash(kwargs):
        harness.gateway.commands["a"]["state"] = gateway_state
        raise Crash()

    harness.gateway.hooks["dispatch"] = crash
    with pytest.raises(Crash):
        harness.dispatch(view, reserved)
    harness.gateway.hooks.clear()
    harness.restart()
    assert permit_state(harness, "a") == "CLAIMED"
    harness.engine.recover()
    assert permit_state(harness, "a") == expected
    assert harness.gateway.count("dispatch") == 1  # Risk never re-dispatches on its own


def test_crash_after_claim_with_gateway_still_reserved_stays_claimed_and_caller_may_retry(harness):
    view = make_view(key="a")
    reserved = harness.reserve(view)

    def crash(kwargs):
        raise Crash()

    harness.gateway.hooks["dispatch"] = crash
    with pytest.raises(Crash):
        harness.dispatch(view, reserved)
    harness.gateway.hooks.clear()
    harness.restart()
    harness.engine.recover()
    assert permit_state(harness, "a") == "CLAIMED"
    assert harness.dispatch(view, reserved).outcome == "DISPATCHED"
    assert harness.engine.export_counts("20261112", "json").count('"value":"1"') == 1


def test_claimed_retry_queries_the_gateway_before_resending(harness):
    view = make_view(key="a")
    reserved = harness.reserve(view)

    def crash(kwargs):
        harness.gateway.commands["a"]["state"] = "SENT"  # the Gateway already sent it
        raise Crash()

    harness.gateway.hooks["dispatch"] = crash
    with pytest.raises(Crash):
        harness.dispatch(view, reserved)
    harness.gateway.hooks.clear()
    harness.restart()
    assert harness.dispatch(view, reserved).outcome == "DISPATCHED"  # caller retry, no recover
    assert harness.gateway.count("dispatch") == 1  # never a second dispatch


def test_crash_during_release_resolves_released_after_restart(harness):
    view = make_view(key="a")
    reserved = harness.reserve(view)

    def crash(kwargs):
        harness.gateway.commands["a"]["state"] = "RELEASED"
        raise Crash()

    harness.gateway.hooks["release"] = crash
    with pytest.raises(Crash):
        harness.engine.release(caller("strat-a"), "a", reserved.permit_id)
    harness.gateway.hooks.clear()
    harness.restart()
    assert permit_state(harness, "a") == "RELEASING"
    harness.engine.recover()
    assert permit_state(harness, "a") == "RELEASED"


def test_transport_not_started_on_dispatch_keeps_claimed_and_counts_once(harness):
    view = make_view(key="a")
    reserved = harness.reserve(view)
    harness.gateway.script["dispatch"] = [GatewayReply("TRANSPORT_NOT_STARTED", code="NOT_READY")]
    first = harness.dispatch(view, reserved)
    assert first.state == "CLAIMED" and first.gateway_code == "NOT_READY"
    assert harness.dispatch(view, reserved).outcome == "DISPATCHED"
    assert harness.gateway.count("dispatch") == 2
    counts = harness.engine.export_counts("20261112", "csv").splitlines()
    assert counts == ["trading_day,instrument_id,kind,value", "20261112,rb2701,order,1"]


def test_dispatch_rejected_or_uncertain_by_gateway_is_unknown(harness):
    view = make_view(key="a")
    reserved = harness.reserve(view)
    harness.gateway.script["dispatch"] = [GatewayReply("REQUEST_DENIED", code="CONTROL_STOP_NEW")]
    result = harness.dispatch(view, reserved)
    assert result.state == "UNKNOWN" and result.gateway_code == "CONTROL_STOP_NEW"
    harness.gateway.commands["a"]["state"] = "RELEASED"
    harness.engine.maintain()
    assert permit_state(harness, "a") == "RELEASED"


def test_release_requires_proof(harness):
    view = make_view(key="a")
    reserved = harness.reserve(view)
    harness.gateway.script["release"] = [GatewayReply("OBSERVED", state="RELEASED")]  # no digest
    result = harness.engine.release(caller("strat-a"), "a", reserved.permit_id)
    assert result.state == "UNKNOWN"
    view_b = make_view(key="b")
    reserved_b = harness.reserve(view_b)
    assert (
        harness.engine.release(caller("strat-a"), "b", reserved_b.permit_id).outcome == "RELEASED"
    )


def test_expired_permit_is_refused_at_dispatch_and_released(harness):
    view = make_view(key="a")
    reserved = harness.reserve(view)
    harness.clock.advance_ms(10_001)
    result = harness.dispatch(view, reserved)
    assert result.code == "risk_permit_expired" and result.state == "RELEASED"
    assert harness.gateway.count("dispatch") == 0


# ------------------------------------------------------------------ claim vs release race


def test_release_in_flight_wins_over_a_concurrent_dispatch(harness):
    view = make_view(key="a")
    reserved = harness.reserve(view)
    observed = {}

    def during_release(kwargs):
        # The permit is RELEASING here; a dispatch for the same permit must not claim it.
        harness.gateway.hooks.pop("release")
        observed["dispatch"] = harness.dispatch(view, reserved)

    harness.gateway.hooks["release"] = during_release
    released = harness.engine.release(caller("strat-a"), "a", reserved.permit_id)
    assert observed["dispatch"].outcome != "DISPATCHED"
    assert harness.gateway.count("dispatch") == 0
    assert released.outcome == "RELEASED"


def test_claim_in_flight_wins_over_a_concurrent_release(harness):
    view = make_view(key="a")
    reserved = harness.reserve(view)
    observed = {}

    def during_dispatch(kwargs):
        harness.gateway.hooks.pop("dispatch")
        observed["release"] = harness.engine.release(caller("strat-a"), "a", reserved.permit_id)

    harness.gateway.hooks["dispatch"] = during_dispatch
    assert harness.dispatch(view, reserved).outcome == "DISPATCHED"
    assert observed["release"].state == "CLAIMED"
    assert harness.gateway.count("release") == 0


def test_conditional_update_lets_only_one_of_claim_and_release_win(harness):
    reserved = harness.reserve(make_view(key="a"))
    with harness.ledger.transaction() as txn:
        permit = txn.permit(reserved.permit_id)
        assert txn.transition(permit, ("RESERVED",), state="CLAIMED", claimed_ns=1, updated_ns=1)
        # the release path still holds the stale RESERVED snapshot
        assert not txn.transition(permit, ("RESERVED",), state="RELEASING", updated_ns=1)
        assert txn.permit(reserved.permit_id).state == "CLAIMED"


# ------------------------------------------------------------------ D63-04 / S-06 vs the old gate


def test_s06_old_gate_freezes_the_account_while_new_engine_scopes_occupancy(tmp_path):
    """Strategy A has an UNKNOWN close on rb2701; strategy B opens hc2701."""
    from bt_api_risk import (
        AccountScope,
        DurableRiskGate,
        IntentAction,
        RiskDeniedError,
        RiskIntent,
    )
    from bt_api_risk import RiskPolicy as LegacyPolicy

    scope = AccountScope(provider="ctp", account_id="acct", environment="sim")
    gate = DurableRiskGate(
        tmp_path / "legacy.db",
        LegacyPolicy(
            policy_id="legacy",
            max_increase_notional=Decimal("1000"),
            max_increase_count=5,
            permit_ttl_seconds=10.0,
        ),
    )
    try:
        close = RiskIntent(
            intent_id="a-close",
            scope=scope,
            action=IntentAction.REDUCE,
            notional=Decimal(0),
            payload_fingerprint="a",
        )
        gate.claim_for_dispatch(gate.reserve(close).permit_id, close)  # dispatch outcome unknown
        open_b = RiskIntent(
            intent_id="b-open",
            scope=scope,
            action=IntentAction.INCREASE,
            notional=Decimal(10),
            payload_fingerprint="b",
        )
        with pytest.raises(RiskDeniedError) as denied:
            gate.reserve(open_b)
        # Old behaviour (S-06): an account-wide latch refuses every other strategy's OPEN.
        assert denied.value.code in ("FROZEN", "STOP_NEW_ACTIVE")
    finally:
        gate.close()

    harness = Harness(tmp_path / "new.db")
    try:
        harness.publish(base_policy())
        harness.verify_stream()
        harness.facts.set_account({("rb2701", "LONG"): ("0", "3")})
        harness.gateway.script["dispatch"] = [GatewayReply("UNKNOWN", code="TIMEOUT")]
        a_close = make_view(key="a-close", side="SELL", offset="CLOSE", qty="3")
        assert harness.place(a_close).state == "UNKNOWN"
        b_open = make_view(key="b-open", strategy="strat-b", inst=HC)
        assert harness.place(b_open).outcome == "DISPATCHED"
        # A's worst-case occupancy stays: the account has no more closable yesterday longs.
        assert harness.engine.list_unknown()[0]["occupancy"] == Decimal(3)
        another_close = make_view(
            key="c-close", strategy="strat-c", side="SELL", offset="CLOSE", price="101"
        )
        assert harness.reserve(another_close).code == "risk_closable_exceeded"
    finally:
        harness.close()


def test_admin_reads_list_unknown_audit_and_counts(harness):
    harness.gateway.script["reserve"] = [GatewayReply("UNKNOWN", code="TIMEOUT")]
    harness.reserve(make_view(key="u1", inst=RB))
    audit = harness.engine.read_audit(0, 1000)
    kinds = [row["kind"] for row in audit]
    assert "policy_publish" in kinds and "reserve" in kinds and "reserve_unknown" in kinds
    assert all("acct-hash" not in str(row) for row in audit)  # no raw account identifiers
    assert harness.engine.read_audit(audit[-1]["seq"], 10) == []
    with pytest.raises(RiskAdminError) as error:
        harness.engine.read_audit(0, 0)
    assert error.value.code == "risk_request_invalid"
    summary = harness.engine.status_summary()
    assert summary["unknown_permits"] == 1
    with pytest.raises(RiskAdminError) as error:
        harness.engine.release_latch(OPERATOR, "missing", 1, "x")
    assert error.value.code == "latch_not_found"
    assert payload_of(make_view()) != ""
