"""Policy schema bt_api_risk.policy.v1 and hot update (D64-12). UNIT evidence only."""

from __future__ import annotations

import json
from decimal import Decimal

import pytest
from test_pretrade_support import (
    DAY,
    OPERATOR,
    Harness,
    base_policy,
    make_view,
)

from bt_api_risk.pretrade import (
    RiskAdminError,
    RiskPolicyError,
    classify_change,
    validate_policy_document,
)

YAML_POLICY = """
schema: bt_api_risk.policy.v1
policy_id: ops-2026-11
account: {route: CTP___FUTURE, account_scope: acct-scope-ref}
per_order:
  max_quantity:
    strat-a: {rb2701: "5"}
  max_notional:
    strat-a: {rb2701: 100000}
price_band:
  enabled: true
  max_deviation_ticks: {rb2701: "10"}
  max_reference_age_ms: 3000
counters:
  orders: {warn: 400, block: 500}
duplicate: {window_ms: 1000, action: warn}
margin_precheck: {mode: off}
breach_actions:
  - {rule: loss.account_day, request: stop_new, scope: account}
loss:
  account_day: {warn: "1000", block: "5000"}
"""


def _code(raw, **kwargs) -> str:
    with pytest.raises(RiskPolicyError) as error:
        validate_policy_document(raw, **kwargs)
    return error.value.code


def test_yaml_policy_parses_with_exact_decimals_and_off_stays_a_string():
    policy = validate_policy_document(YAML_POLICY)
    assert policy.max_quantity["strat-a"]["rb2701"] == Decimal("5")
    assert policy.max_notional["strat-a"]["rb2701"] == Decimal("100000")
    # YAML 1.1 would read `off` as False; the strict loader keeps it as the mode string.
    assert policy.margin_mode == "off"
    assert policy.price_band.enabled is True and policy.price_band.max_reference_age_ms == 3000
    assert policy.counters.orders.block == 500
    assert policy.breach_actions[0].request == "STOP_NEW"
    # Identity: policy id plus a sha256 over the canonical content.
    assert len(policy.digest) == 64
    assert json.loads(policy.canonical)["policy_id"] == "ops-2026-11"
    assert validate_policy_document(YAML_POLICY).digest == policy.digest


def test_defaults_self_trade_and_closable_on_margin_off():
    policy = validate_policy_document(base_policy())
    assert policy.self_trade_enabled is True
    assert policy.closable_check_enabled is True
    assert policy.margin_mode == "off"
    explicit = validate_policy_document(
        base_policy(self_trade={"enabled": False}, closable_check={"enabled": False})
    )
    assert explicit.self_trade_enabled is False and explicit.closable_check_enabled is False


@pytest.mark.parametrize(
    ("sections", "code"),
    [
        ({"surprise": 1}, "policy_unknown_key"),
        (
            {
                "price_band": {
                    "enabled": True,
                    "max_deviation_ticks": {"rb2701": "5"},
                    "max_reference_age_ms": 100,
                    "typo": 1,
                }
            },
            "policy_unknown_key",
        ),
        (
            {"price_band": {"enabled": True, "max_reference_age_ms": 100}},
            "policy_control_incomplete",
        ),
        (
            {"price_band": {"enabled": True, "max_deviation_ticks": {"rb2701": "5"}}},
            "policy_control_incomplete",
        ),
        ({"price_band": {"max_deviation_ticks": {"rb2701": "5"}}}, "policy_missing_key"),
        ({"counters": {"orders": {"warn": 5}}}, "policy_missing_key"),
        ({"counters": {"orders": {"warn": 6, "block": 5}}}, "policy_invalid_value"),
        ({"counters": {}}, "policy_control_incomplete"),
        ({"duplicate": {"window_ms": 100}}, "policy_missing_key"),
        ({"duplicate": {"window_ms": 100, "action": "ignore"}}, "policy_invalid_value"),
        ({"margin_precheck": {"mode": "strict"}}, "policy_invalid_value"),
        ({"margin_precheck": {"mode": False}}, "policy_invalid_value"),
        ({"self_trade": {"enabled": True, "on_unverifiable": "allow"}}, "policy_invalid_value"),
        ({"loss": {"account_day": {"warn": "5"}}}, "policy_missing_key"),
        (
            {"breach_actions": [{"rule": "loss.account_day", "request": "stop_new"}]},
            "policy_missing_key",
        ),
        (
            {
                "breach_actions": [
                    {"rule": "loss.account_day", "request": "stop_new", "scope": "strategy"}
                ]
            },
            "policy_invalid_value",
        ),
        (
            {
                "breach_actions": [
                    {"rule": "loss.account_day", "request": "resume", "scope": "account"}
                ]
            },
            "policy_invalid_value",
        ),
        (
            {"cancel_rules": [{"rule": "loss.account_day", "scope": "account"}]},
            "policy_missing_key",
        ),
        ({"exchange_rules": {"file": "rules.yaml"}}, "policy_exchange_rules_unavailable"),
        (
            {"rules": [{"id": "x", "implementation": "mod:Cls", "version": 1}]},
            "policy_rule_not_allowed",
        ),
        ({"position": {"account": {"rb2701": {"long": "5"}}}}, "policy_missing_key"),
    ],
)
def test_invalid_sections_are_configuration_errors(sections, code):
    assert _code(base_policy(**sections)) == code


def test_numbers_refuse_floats_nan_bool_and_nonpositive_values():
    for bad in (1.5, "NaN", "Infinity", True, 0, "-1", "", " 5"):
        document = base_policy()
        document["per_order"]["max_quantity"]["strat-a"]["rb2701"] = bad
        code = _code(document)
        assert code in ("policy_float_refused", "policy_invalid_number")
    assert _code(YAML_POLICY.replace('{rb2701: "5"}', "{rb2701: 5.0}")) == "policy_float_refused"
    assert _code('{"schema": "bt_api_risk.policy.v1", "x": 1.0}') == "policy_float_refused"


def test_documents_with_duplicate_keys_wrong_schema_or_missing_r01_are_refused():
    assert _code("schema: bt_api_risk.policy.v1\nschema: x\n") == "policy_duplicate_key"
    document = base_policy()
    document["schema"] = "bt_api_risk.policy.v2"
    assert _code(document) == "policy_schema_unsupported"
    document = base_policy()
    del document["per_order"]["max_quantity"]
    assert _code(document) == "policy_missing_key"
    document = base_policy()
    del document["per_order"]
    assert _code(document) == "policy_missing_key"


def test_errors_never_echo_document_values():
    document = base_policy()
    document["per_order"]["max_quantity"]["strat-a"]["rb2701"] = "SECRET-VALUE-123"
    with pytest.raises(RiskPolicyError) as error:
        validate_policy_document(document)
    assert "SECRET" not in str(error.value)


def test_exchange_rule_file_is_parsed_and_bound_into_the_digest():
    rules = (
        "schema: bt_api_risk.exchange_rules.v1\nrule_set_id: shfe-2026\n"
        "instruments:\n  rb2701: {position_limit: {long: '20', short: '20'}, daily_open_limit: 30}\n"
    )
    document = base_policy(exchange_rules={"file": "rules/exchange.yaml"})
    first = validate_policy_document(document, exchange_rules_text=rules)
    second = validate_policy_document(document, exchange_rules_text=rules.replace("30", "31"))
    assert first.exchange_rules.instruments["rb2701"].daily_open_limit == Decimal(30)
    assert first.digest != second.digest
    assert _code(document, exchange_rules_text="schema: other\n") in (
        "policy_missing_key",
        "policy_schema_unsupported",
    )


def test_classify_change_tighten_loosen_unchanged():
    old = validate_policy_document(base_policy(counters={"orders": {"warn": 5, "block": 10}}))
    tighter_doc = base_policy(counters={"orders": {"warn": 5, "block": 8}})
    tighter_doc["per_order"]["max_quantity"]["strat-a"]["rb2701"] = "3"
    tighter = validate_policy_document(tighter_doc)
    result = classify_change(old, tighter)
    assert result["loosened"] == []
    assert "counters.orders.block" in result["tightened"]
    assert "per_order.max_quantity:strat-a:rb2701" in result["tightened"]
    looser = validate_policy_document(
        base_policy(counters={"orders": {"warn": 5, "block": 20}}, self_trade={"enabled": False})
    )
    result = classify_change(old, looser)
    assert "counters.orders.block" in result["loosened"]
    assert "self_trade.enabled" in result["loosened"]
    # margin off -> deny is a tightening; removing a cap is a loosening
    denies = validate_policy_document(
        base_policy(counters={"orders": {"warn": 5, "block": 10}}, margin_precheck={"mode": "deny"})
    )
    assert "margin_precheck.mode" in classify_change(old, denies)["tightened"]
    assert classify_change(None, old)["loosened"] == ["policy:bootstrap"]


# ------------------------------------------------------------------ hot update through the engine


@pytest.fixture
def harness(tmp_path):
    item = Harness(tmp_path / "risk.db")
    yield item
    item.close()


def test_publish_is_cas_on_the_effective_version(harness):
    engine = harness.engine
    assert engine.publish_policy(OPERATOR, base_policy(), 0, "bootstrap").version == 1
    with pytest.raises(RiskAdminError) as error:
        engine.publish_policy(OPERATOR, base_policy(policy_id="other"), 0, "stale")
    assert error.value.code == "policy_version_conflict"
    # Identical content is not a new version.
    assert engine.publish_policy(OPERATOR, base_policy(), 1, None).published is False


def test_bootstrap_and_loosening_need_a_reason_and_operator(harness):
    engine = harness.engine
    with pytest.raises(RiskAdminError) as error:
        engine.publish_policy(OPERATOR, base_policy(), 0, None)
    assert error.value.code == "policy_loosening_reason_required"
    with pytest.raises(RiskAdminError) as error:
        engine.publish_policy(harness_caller_not_operator(), base_policy(), 0, "x")
    assert error.value.code == "risk_unauthorized"
    with pytest.raises(RiskAdminError) as error:
        engine.publish_policy(
            OPERATOR,
            {
                **base_policy(),
                "account": {"route": "CTP___FUTURE", "account_scope": "another-account"},
            },
            0,
            "x",
        )
    assert error.value.code == "policy_account_mismatch"


def harness_caller_not_operator():
    from test_pretrade_support import caller

    return caller("strat-a")


def test_pure_tightening_takes_effect_immediately_without_reason(harness):
    harness.publish(base_policy())
    harness.verify_stream()
    tighter = base_policy()
    tighter["per_order"]["max_quantity"]["strat-a"]["rb2701"] = "2"
    result = harness.engine.publish_policy(OPERATOR, tighter, 1, None)
    assert result.published and result.classification["loosened"] == []
    denied = harness.reserve(make_view(qty="3"))
    assert denied.outcome == "DENIED" and denied.code == "risk_order_quantity_exceeds_cap"


def test_loosening_refused_while_a_latch_in_that_family_is_active(harness):
    counters = {"orders": {"warn": 1, "block": 1}}
    harness.publish(base_policy(counters=counters))
    harness.verify_stream()
    assert harness.place(make_view(key="a1")).outcome == "DISPATCHED"
    latch = harness.engine.list_latches(active_only=True)[0]
    looser = base_policy(counters={"orders": {"warn": 1, "block": 5}})
    with pytest.raises(RiskAdminError) as error:
        harness.engine.publish_policy(OPERATOR, looser, 1, "raise threshold")
    assert error.value.code == "policy_loosening_latched"
    harness.engine.release_latch(OPERATOR, latch["latch_id"], latch["row_version"], "checked")
    assert harness.engine.publish_policy(OPERATOR, looser, 1, "raise threshold").version == 2


def test_dispatch_rechecks_a_reserved_permit_against_the_latest_version(harness):
    harness.publish(base_policy())
    harness.verify_stream()
    view = make_view(qty="5")
    reserved = harness.reserve(view)
    assert reserved.outcome == "RESERVED" and reserved.policy_version == "1"
    tighter = base_policy()
    tighter["per_order"]["max_quantity"]["strat-a"]["rb2701"] = "4"
    harness.engine.publish_policy(OPERATOR, tighter, 1, None)
    result = harness.dispatch(view, reserved)
    assert result.outcome == "DENIED" and result.code == "risk_order_quantity_exceeds_cap"
    assert result.state == "RELEASED"  # Gateway release proof freed the occupancy
    assert harness.gateway.count("dispatch") == 0


def test_policy_versions_survive_restart_and_trading_day_is_required(harness):
    harness.publish(base_policy())
    harness.restart()
    summary = harness.engine.status_summary()
    assert summary["policy_version"] == 1 and summary["available"] is True
    harness.verify_stream()
    harness.facts.day = None
    assert harness.reserve(make_view()).code == "risk_trading_day_unavailable"
    harness.facts.day = DAY
    assert harness.reserve(make_view(key="k2")).outcome == "RESERVED"


def test_no_policy_refuses_every_order(harness):
    harness.verify_stream()
    result = harness.reserve(make_view())
    assert result.outcome == "DENIED" and result.code == "risk_policy_unavailable"
