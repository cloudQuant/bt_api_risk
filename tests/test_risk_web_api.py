"""Risk operator Web API v1 (64.13 interface) over a fake admin caller.

Evidence level: UNIT/FAKE. The admin caller is a trusted host fixture; no Risk
service, transport, Gateway or account is involved.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import re
import subprocess
import sys
from pathlib import Path
from types import MappingProxyType

import httpx
import pytest
from bt_api_base.risk_service_protocol import RISK_ADMIN_OPERATIONS, RISK_ORDER_OPERATIONS
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import bt_api_risk.web.app as module
from bt_api_risk.web.app import (
    API_PREFIX,
    AuthenticatedRiskSession,
    RiskAdminCallError,
    create_app,
    run_local,
)

ORIGIN = "http://127.0.0.1:8710"
TOKEN = "s" * 64
CSRF = "c" * 64
LATCH_ID = "0f" * 16
DOC = Path(__file__).resolve().parents[1] / "docs" / "risk-web-api-v1.md"

LATCH = {
    "latch_id": LATCH_ID,
    "control": "counters.orders",
    "scope_kind": "instrument",
    "scope_value": "SHFE.rb2601",
    "reason": "risk_order_count_limit",
    "trading_day": "20261112",
    "version": 1,
    "active": True,
    "released_by": None,
    "released_at": None,
}
PERMIT = {
    "request_key": "rk-1",
    "strategy_ref": "strategy-a",
    "permit_id": "permit-1",
    "reservation_id": None,
    "state": "UNKNOWN",
    "instrument": "SHFE.rb2601",
    "side": "BUY",
    "offset": "OPEN",
    "quantity": "1",
    "since": 1762905600000000000,
}
DOCUMENT = {
    "schema": "bt_api_risk.policy.v1",
    "policy_id": "desk-policy",
    "per_order": {"max_quantity": {"strategy-a": {"SHFE.rb2601": "2"}}},
}


def default_replies():
    return {
        "risk.admin.status": {"status": "OBSERVED", "summary": {"available": True, "unknown_permits": 1}},
        "risk.policy.read": {
            "status": "OBSERVED",
            "version": 3,
            "policy_id": "desk-policy",
            "digest": "d" * 64,
            "document": DOCUMENT,
            "exchange_rules_digest": None,
        },
        "risk.policy.publish": {
            "status": "OBSERVED",
            "version": 4,
            "policy_id": "desk-policy",
            "digest": "e" * 64,
            "classification": {"tightened": ["per_order.max_quantity"], "loosened": [], "unchanged": []},
        },
        "risk.latch.list": {"status": "OBSERVED", "latches": [LATCH]},
        "risk.latch.release": {
            "status": "OBSERVED",
            "latch": {**LATCH, "version": 2, "active": 0, "released_by": "operator-a",
                      "released_at": 1762905600000000000},
        },
        "risk.unknown.list": {"status": "OBSERVED", "permits": [PERMIT]},
        "risk.counts.export": lambda args: {
            "status": "OBSERVED", "format": args["format"],
            "content": "trading_day,instrument_id,kind,value\n20261112,SHFE.rb2601,orders,3\n",
        },
        "risk.audit.read": lambda args: {
            "status": "OBSERVED",
            "records": [{"seq": args["after"] + 1, "kind": "policy_publish", "detail": {"loosened": []}}],
            "next_after": args["after"] + 1,
        },
        "risk.cancel.request": lambda args: {
            "status": "OBSERVED", "operation_id": args["operation_id"], "state": "PENDING",
        },
        "risk.cancel.status": lambda args: {
            "status": "OBSERVED", "operation_id": args["operation_id"], "state": "APPLIED",
            "gateway": {"result": "APPLIED"},
        },
    }


class FakeRisk:
    """Records every admin call; replies as the Risk operator port would."""

    def __init__(self):
        self.calls = []
        self.replies = default_replies()
        self.error = None

    def __call__(self, operation, arguments, timeout_seconds):
        self.calls.append((operation, copy.deepcopy(arguments), timeout_seconds))
        if self.error is not None:
            raise self.error
        reply = self.replies[operation]
        return reply(arguments) if callable(reply) else copy.deepcopy(reply)


def make(operations=RISK_ADMIN_OPERATIONS, risk=None, client=("127.0.0.1", 50000), **kwargs):
    risk = risk if risk is not None else FakeRisk()
    session = AuthenticatedRiskSession("operator-a", "desk-1", CSRF, frozenset(operations))

    def authenticate(request):
        if request.headers.get("x-risk-session") != TOKEN:
            raise ValueError("password=hunter2 must never reach a response")
        return session

    app = create_app(origin=ORIGIN, authenticate=authenticate, admin_caller=risk, **kwargs)
    return TestClient(app, base_url=ORIGIN, client=client), risk


READ = {"X-Risk-Session": TOKEN}
WRITE = {**READ, "Origin": ORIGIN, "X-CSRF-Token": CSRF}

PUBLISH = {"expected_version": 3, "document": DOCUMENT, "reason": "tighten caps after review"}
RELEASE = {"expected_version": 1, "reason": "checked with the desk"}
CANCEL = {"operation_id": "cancel-1", "scope_kind": "instrument", "scope_value": "SHFE.rb2601"}

# (method, path under API_PREFIX, body, operation, arguments sent to Risk)
HAPPY = [
    ("GET", "/status", None, "risk.admin.status", {}),
    ("GET", "/policy", None, "risk.policy.read", {}),
    ("POST", "/policy", PUBLISH, "risk.policy.publish", {**PUBLISH, "exchange_rules_text": None}),
    ("POST", "/policy", {**PUBLISH, "exchange_rules_text": "rules: []\n"}, "risk.policy.publish",
     {**PUBLISH, "exchange_rules_text": "rules: []\n"}),
    ("GET", "/latches", None, "risk.latch.list", {"active_only": False}),
    ("GET", "/latches?active_only=true", None, "risk.latch.list", {"active_only": True}),
    ("POST", f"/latches/{LATCH_ID}/release", RELEASE, "risk.latch.release", {"latch_id": LATCH_ID, **RELEASE}),
    ("GET", "/unknown", None, "risk.unknown.list", {}),
    ("GET", "/counts/20261112", None, "risk.counts.export", {"trading_day": "20261112", "format": "json"}),
    ("GET", "/counts/20261112?format=csv", None, "risk.counts.export",
     {"trading_day": "20261112", "format": "csv"}),
    ("GET", "/audit", None, "risk.audit.read", {"after": 0, "limit": 100}),
    ("GET", "/audit?after=41&limit=1000", None, "risk.audit.read", {"after": 41, "limit": 1000}),
    ("POST", "/cancel", CANCEL, "risk.cancel.request", CANCEL),
    ("POST", "/cancel", {"operation_id": "cancel-2", "scope_kind": "account", "scope_value": ""},
     "risk.cancel.request", {"operation_id": "cancel-2", "scope_kind": "account", "scope_value": ""}),
    ("GET", "/cancel/cancel-1", None, "risk.cancel.status", {"operation_id": "cancel-1"}),
]
POSTS = [("/policy", PUBLISH), (f"/latches/{LATCH_ID}/release", RELEASE), ("/cancel", CANCEL)]
GETS = ["/status", "/policy", "/latches", "/unknown", "/counts/20261112", "/audit", "/cancel/cancel-1"]


def send(client, method, path, body=None, headers=None):
    url = API_PREFIX + path
    if method == "GET":
        return client.get(url, headers=headers)
    return client.post(url, json=body, headers=headers)


@pytest.mark.parametrize("method,path,body,operation,arguments", HAPPY)
def test_every_route_happy_path(method, path, body, operation, arguments):
    client, risk = make()
    response = send(client, method, path, body, READ if method == "GET" else WRITE)
    assert response.status_code == 200, response.text
    assert risk.calls == [(operation, arguments, 5.0)]
    reply = default_replies()[operation]
    expected = reply(arguments) if callable(reply) else reply
    if operation == "risk.latch.release":
        expected = {**expected, "latch": {**expected["latch"], "active": False}}
    assert response.json() == expected
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_cancel_status_not_found_is_404_and_frozen_wire_containers_are_copied():
    client, risk = make()
    risk.replies["risk.cancel.status"] = lambda args: {"status": "NOT_FOUND", "operation_id": args["operation_id"]}
    response = client.get(API_PREFIX + "/cancel/cancel-9", headers=READ)
    assert response.status_code == 404 and response.json() == {"status": "NOT_FOUND", "operation_id": "cancel-9"}
    # The SDK runtime hands back read-only mappings and tuples.
    frozen = MappingProxyType({"status": "OBSERVED", "latches": (MappingProxyType(LATCH),)})
    risk.replies["risk.latch.list"] = lambda args: frozen
    response = client.get(API_PREFIX + "/latches", headers=READ)
    assert response.status_code == 200 and response.json() == {"status": "OBSERVED", "latches": [LATCH]}


def test_session_route_returns_csrf_and_narrowed_operations_without_calling_risk():
    client, risk = make(operations={"risk.admin.status", "risk.latch.list"})
    body = client.get(API_PREFIX + "/session", headers=READ).json()
    assert body["api_version"] == 1 and body["csrf_token"] == CSRF
    assert body["operations"] == ["risk.admin.status", "risk.latch.list"]
    assert re.fullmatch(r"[0-9a-f]{64}", body["namespace"])
    assert "operator-a" not in json.dumps(body)
    assert client.get(API_PREFIX + "/session?x=1", headers=READ).status_code == 422
    assert risk.calls == []


@pytest.mark.parametrize("code,status", [
    ("policy_version_conflict", 409),
    ("policy_loosening_latched", 409),
    ("latch_version_conflict", 409),
    ("latch_not_active", 409),
    ("latch_not_found", 409),
    ("risk_unauthorized", 409),
    ("risk_request_conflict", 409),
    ("risk_request_invalid", 422),
    ("risk_admin_reason_required", 422),
    ("policy_invalid_value", 422),
    ("policy_account_mismatch", 422),
])
def test_risk_refusal_maps_to_409_or_422_with_the_finite_code(code, status):
    client, risk = make()
    for operation in RISK_ADMIN_OPERATIONS:
        risk.replies[operation] = {"status": "REQUEST_REJECTED", "code": code}
    for path, body in POSTS:
        response = send(client, "POST", path, body, WRITE)
        assert response.status_code == status
        assert response.json() == {"status": "REQUEST_REJECTED", "code": code}
    response = client.get(API_PREFIX + "/policy", headers=READ)
    assert response.status_code == status and response.json()["code"] == code
    assert len(risk.calls) == len(POSTS) + 1  # one call per request, never repeated


@pytest.mark.parametrize("error,status,body", [
    (RiskAdminCallError("NOT_SENT", "QUEUE_FULL"), 503, {"status": "NOT_SENT", "code": "QUEUE_FULL"}),
    (RiskAdminCallError("NOT_SENT", "secret-value-123"), 503, {"status": "NOT_SENT", "code": "REQUEST_NOT_SENT"}),
    (RiskAdminCallError("REFUSED", "DENIED"), 409, {"status": "REQUEST_REJECTED", "code": "DENIED"}),
    (RiskAdminCallError("REFUSED", "HANDLER_FAILED"), 502, {"status": "UNKNOWN", "code": "RISK_OUTCOME_UNKNOWN"}),
    (RiskAdminCallError("TIMEOUT"), 504, {"status": "UNKNOWN", "code": "RISK_TIMEOUT"}),
    (RiskAdminCallError("UNKNOWN"), 502, {"status": "UNKNOWN", "code": "RISK_OUTCOME_UNKNOWN"}),
    (RiskAdminCallError("bogus-kind", "x"), 502, {"status": "UNKNOWN", "code": "RISK_OUTCOME_UNKNOWN"}),
    (TimeoutError("password=hunter2"), 504, {"status": "UNKNOWN", "code": "RISK_TIMEOUT"}),
    (RuntimeError("client_secret_key=hunter2"), 502, {"status": "UNKNOWN", "code": "RISK_OUTCOME_UNKNOWN"}),
])
def test_transport_failure_is_value_free_and_never_retried(error, status, body):
    client, risk = make()
    risk.error = error
    for method, path, payload in [("POST", "/policy", PUBLISH), ("POST", "/cancel", CANCEL), ("GET", "/status", None)]:
        risk.calls.clear()
        response = send(client, method, path, payload, WRITE if method == "POST" else READ)
        assert response.status_code == status and response.json() == body
        assert "hunter2" not in response.text and "secret-value" not in response.text
        assert len(risk.calls) == 1


def _bad_replies():
    good = default_replies()
    latch = good["risk.latch.list"]
    return [
        ("risk.admin.status", "GET", "/status", None, ["not", "a", "mapping"]),
        ("risk.admin.status", "GET", "/status", None, {"status": "DONE", "summary": {}}),
        ("risk.admin.status", "GET", "/status", None, {"status": "OBSERVED", "summary": {}, "extra": 1}),
        ("risk.admin.status", "GET", "/status", None, {"status": "OBSERVED", "summary": {"api_key": "k"}}),
        ("risk.admin.status", "GET", "/status", None, {"status": "OBSERVED", "summary": {"x": float("nan")}}),
        ("risk.admin.status", "GET", "/status", None, {"status": "REQUEST_REJECTED", "code": "Bad Code 7"}),
        ("risk.admin.status", "GET", "/status", None, {"status": "REQUEST_REJECTED", "code": "x", "detail": "v"}),
        ("risk.policy.read", "GET", "/policy", None, {**good["risk.policy.read"], "version": True}),
        ("risk.policy.read", "GET", "/policy", None,
         {**good["risk.policy.read"], "document": {"auth_code": "hunter2"}}),
        ("risk.policy.publish", "POST", "/policy", PUBLISH, {**good["risk.policy.publish"], "version": 0}),
        ("risk.policy.publish", "POST", "/policy", PUBLISH,
         {**good["risk.policy.publish"], "classification": {"tightened": []}}),
        ("risk.latch.list", "GET", "/latches", None, {"status": "OBSERVED", "latches": [{**LATCH, "extra": 1}]}),
        ("risk.latch.list", "GET", "/latches", None, {"status": "OBSERVED", "latches": [{**LATCH, "active": 2}]}),
        ("risk.latch.list", "GET", "/latches?active_only=true", None,
         {"status": "OBSERVED", "latches": [{**LATCH, "active": False}]}),
        ("risk.latch.release", "POST", f"/latches/{LATCH_ID}/release", RELEASE,
         {"status": "OBSERVED", "latch": {**LATCH, "active": False, "latch_id": "other"}}),
        # A release answer that still shows the latch active.
        ("risk.latch.release", "POST", f"/latches/{LATCH_ID}/release", RELEASE,
         {"status": "OBSERVED", "latch": LATCH}),
        ("risk.latch.release", "POST", f"/latches/{LATCH_ID}/release", RELEASE, latch),
        ("risk.unknown.list", "GET", "/unknown", None, {"status": "OBSERVED", "permits": [{"request_key": "rk"}]}),
        ("risk.counts.export", "GET", "/counts/20261112?format=csv", None,
         {"status": "OBSERVED", "format": "json", "content": "{}"}),
        ("risk.audit.read", "GET", "/audit?after=9", None, {"status": "OBSERVED", "records": [], "next_after": 3}),
        ("risk.audit.read", "GET", "/audit?limit=1", None,
         {"status": "OBSERVED", "records": [{}, {}], "next_after": 2}),
        ("risk.cancel.request", "POST", "/cancel", CANCEL,
         {"status": "OBSERVED", "operation_id": "someone-else", "state": "PENDING"}),
        ("risk.cancel.status", "GET", "/cancel/cancel-1", None, {"status": "NOT_FOUND", "operation_id": "cancel-2"}),
        ("risk.cancel.status", "GET", "/cancel/cancel-1", None,
         {"status": "OBSERVED", "operation_id": "cancel-1", "state": "APPLIED", "gateway": "text"}),
    ]


@pytest.mark.parametrize("operation,method,path,body,reply", _bad_replies())
def test_malformed_reply_is_502_unknown_without_values(operation, method, path, body, reply):
    client, risk = make()
    risk.replies[operation] = lambda args, reply=reply: reply
    response = send(client, method, path, body, WRITE if method == "POST" else READ)
    assert response.status_code == 502
    assert response.json() == {"status": "UNKNOWN", "code": "RISK_REPLY_INVALID"}
    assert len(risk.calls) == 1


def _every_request():
    return [("GET", path, None) for path in GETS] + [("POST", path, body) for path, body in POSTS]


def test_unauthenticated_and_wrong_token_are_refused_before_any_call():
    client, risk = make()
    for method, path, body in _every_request() + [("GET", "/session", None)]:
        for headers in ({}, {"X-Risk-Session": "t" * 64}, {"X-Risk-Session": TOKEN + "0"}):
            extra = {"Origin": ORIGIN, "X-CSRF-Token": CSRF} if method == "POST" else {}
            response = send(client, method, path, body, {**headers, **extra})
            assert response.status_code == 401, (method, path)
            assert response.json() == {"error": "AUTHENTICATION_REQUIRED"}
            assert "hunter2" not in response.text
    # Authentication runs before request validation: a malformed body still answers 401.
    response = client.post(API_PREFIX + "/policy", json={"x": "client_secret"},
                           headers={"Origin": ORIGIN, "X-CSRF-Token": CSRF})
    assert response.status_code == 401
    assert risk.calls == []


def test_authenticate_returning_anything_but_a_session_is_refused():
    risk = FakeRisk()
    app = create_app(origin=ORIGIN, authenticate=lambda request: {"principal_ref": "operator-a"},
                     admin_caller=risk)
    client = TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 50000))
    assert client.get(API_PREFIX + "/status", headers=READ).status_code == 401
    assert client.post(API_PREFIX + "/cancel", json=CANCEL, headers=WRITE).status_code == 401
    assert risk.calls == []


@pytest.mark.parametrize("path,body", POSTS)
def test_writes_need_the_session_csrf_token(path, body):
    client, risk = make()
    for token in (None, "", "c" * 63, "d" * 64, CSRF + "c", ("é" * 64).encode("latin-1")):
        headers = {**READ, "Origin": ORIGIN}
        if token is not None:
            headers["X-CSRF-Token"] = token
        response = send(client, "POST", path, body, headers)
        assert response.status_code == 403 and response.json() == {"error": "CSRF_DENIED"}
    assert risk.calls == []
    # Reads need no CSRF token.
    assert client.get(API_PREFIX + "/status", headers=READ).status_code == 200


@pytest.mark.parametrize("path,body", POSTS)
def test_writes_need_the_configured_origin(path, body):
    client, risk = make()
    headers = {**READ, "X-CSRF-Token": CSRF}
    for origin in (None, "http://evil.invalid", "http://127.0.0.1:8711", "null", "http://localhost:8710"):
        extra = {} if origin is None else {"Origin": origin}
        response = send(client, "POST", path, body, {**headers, **extra})
        assert response.status_code == 403 and response.json() == {"error": "ORIGIN_DENIED"}
    assert risk.calls == []


def test_a_cross_origin_read_is_refused_and_a_plain_read_is_served():
    client, risk = make()
    response = client.get(API_PREFIX + "/status", headers={**READ, "Origin": "http://evil.invalid"})
    assert response.status_code == 403 and response.json() == {"error": "ORIGIN_DENIED"}
    assert risk.calls == []
    assert client.get(API_PREFIX + "/status", headers={**READ, "Origin": ORIGIN}).status_code == 200


def test_transport_guards_peer_host_method_size_and_media_type():
    remote, risk = make(client=("192.0.2.10", 50000))
    response = remote.get(API_PREFIX + "/status", headers=READ)
    assert response.status_code == 403 and response.json() == {"error": "LOCAL_ACCESS_REQUIRED"}
    named, _ = make(client=("testclient", 50000))
    assert named.get(API_PREFIX + "/status", headers=READ).json() == {"error": "LOCAL_ACCESS_REQUIRED"}
    client, risk = make()
    response = client.get(API_PREFIX + "/status", headers={**READ, "Host": "attacker.invalid:8710"})
    assert response.status_code == 403 and response.json() == {"error": "HOST_DENIED"}
    for method in ("PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
        response = client.request(method, API_PREFIX + "/policy", headers=WRITE)
        assert response.status_code == 405
        if method != "HEAD":
            assert response.json() == {"error": "METHOD_DENIED"}
    response = client.post(API_PREFIX + "/cancel", content=b"operation_id=x", headers={
        **WRITE, "Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 415 and response.json() == {"error": "CONTENT_TYPE_DENIED"}
    big = {**CANCEL, "scope_value": "x" * 9000}
    response = client.post(API_PREFIX + "/cancel", json=big, headers=WRITE)
    assert response.status_code == 413 and response.json() == {"error": "BODY_SIZE_INVALID"}
    # A policy document may be larger than the other bodies, within its own bound.
    large = {**PUBLISH, "document": {**DOCUMENT, "notes": "n" * 20000}}
    assert client.post(API_PREFIX + "/policy", json=large, headers=WRITE).status_code == 200
    huge = {**PUBLISH, "document": {**DOCUMENT, "notes": "n" * 600_000}}
    assert client.post(API_PREFIX + "/policy", json=huge, headers=WRITE).status_code == 413
    chunked = client.post(API_PREFIX + "/cancel", content=iter([json.dumps(CANCEL).encode()]),
                          headers={**WRITE, "Content-Type": "application/json"})
    assert chunked.status_code == 413 and chunked.json() == {"error": "BODY_SIZE_INVALID"}
    assert [call[0] for call in risk.calls] == ["risk.policy.publish"]


def test_operations_outside_the_session_are_refused_before_any_call():
    client, risk = make(operations={"risk.admin.status", "risk.policy.read", "risk.latch.list"})
    for path, body in POSTS:
        response = send(client, "POST", path, body, WRITE)
        assert response.status_code == 403 and response.json() == {"error": "OPERATION_NOT_GRANTED"}
    assert client.get(API_PREFIX + "/audit", headers=READ).json() == {"error": "OPERATION_NOT_GRANTED"}
    assert client.get(API_PREFIX + "/policy", headers=READ).status_code == 200
    assert [call[0] for call in risk.calls] == ["risk.policy.read"]


INVALID = [
    ("POST", "/policy", {**PUBLISH, "client_secret_key": "SECRETVALUE"}),
    ("POST", "/policy", {**PUBLISH, "expected_version": "3"}),
    ("POST", "/policy", {**PUBLISH, "expected_version": True}),
    ("POST", "/policy", {**PUBLISH, "expected_version": 3.0}),
    ("POST", "/policy", {**PUBLISH, "expected_version": -1}),
    ("POST", "/policy", {**PUBLISH, "expected_version": 2**63}),
    ("POST", "/policy", {k: v for k, v in PUBLISH.items() if k != "reason"}),
    ("POST", "/policy", {k: v for k, v in PUBLISH.items() if k != "expected_version"}),
    ("POST", "/policy", {**PUBLISH, "reason": ""}),
    ("POST", "/policy", {**PUBLISH, "reason": " padded"}),
    ("POST", "/policy", {**PUBLISH, "reason": "line\nbreak"}),
    ("POST", "/policy", {**PUBLISH, "reason": "r" * 1025}),
    ("POST", "/policy", {**PUBLISH, "document": "schema: bt_api_risk.policy.v1"}),
    ("POST", "/policy", {**PUBLISH, "document": ["SECRETVALUE"]}),
    ("POST", "/policy", {**PUBLISH, "exchange_rules_text": ""}),
    ("POST", "/policy", {**PUBLISH, "exchange_rules_text": "a\x00b"}),
    ("POST", f"/latches/{LATCH_ID}/release", {**RELEASE, "latch_id": "other"}),
    ("POST", f"/latches/{LATCH_ID}/release", {"expected_version": 1}),
    ("POST", f"/latches/{LATCH_ID}/release", {**RELEASE, "expected_version": None}),
    ("POST", "/latches/%20padded/release", RELEASE),
    ("POST", "/cancel", {**CANCEL, "scope_kind": "strategy"}),
    ("POST", "/cancel", {**CANCEL, "scope_kind": "ACCOUNT"}),
    ("POST", "/cancel", {**CANCEL, "operation_id": ""}),
    ("POST", "/cancel", {**CANCEL, "operation_id": 7}),
    ("POST", "/cancel", {**CANCEL, "scope_value": " SHFE"}),
    ("POST", "/cancel", {**CANCEL, "account_ref": "SECRETVALUE"}),
    ("POST", "/cancel", {k: v for k, v in CANCEL.items() if k != "scope_value"}),
    ("GET", "/status?verbose=1", None),
    ("GET", "/latches?active_only=yes", None),
    ("GET", "/latches?active_only=true&active_only=false", None),
    ("GET", "/counts/2026-11-12", None),
    ("GET", "/counts/20261331", None),
    ("GET", "/counts/20261112?format=xml", None),
    ("GET", "/counts/20261112?format=csv&x=1", None),
    ("GET", "/audit?limit=0", None),
    ("GET", "/audit?limit=1001", None),
    ("GET", "/audit?after=-1", None),
    ("GET", "/audit?after=01", None),
    ("GET", "/audit?after=1e3", None),
    ("GET", "/cancel/%20x", None),
]


@pytest.mark.parametrize("method,path,body", INVALID)
def test_extra_fields_and_loose_types_are_refused_without_echo(method, path, body):
    client, risk = make()
    response = send(client, method, path, body, WRITE if method == "POST" else READ)
    assert response.status_code == 422, response.text
    assert response.json() == {"error": "REQUEST_INVALID"}
    assert risk.calls == []


@pytest.mark.parametrize("raw", [
    b'{"operation_id":"a","operation_id":"b","scope_kind":"account","scope_value":""}',
    b'{"operation_id":"a","scope_kind":"account","scope_value":"",',
    b'\xff\xfe',
    b'[]',
])
def test_malformed_json_bodies_are_refused(raw):
    client, risk = make()
    response = client.post(API_PREFIX + "/cancel", content=raw,
                           headers={**WRITE, "Content-Type": "application/json"})
    assert response.status_code == 422 and response.json() == {"error": "REQUEST_INVALID"}
    publish = b'{"expected_version":1,"reason":"r","document":{"x":NaN}}'
    response = client.post(API_PREFIX + "/policy", content=publish,
                           headers={**WRITE, "Content-Type": "application/json"})
    assert response.status_code == 422
    assert risk.calls == []


def test_a_second_non_page_client_uses_the_same_api_with_the_same_token():
    client, risk = make()
    first = [client.get(API_PREFIX + "/latches?active_only=true", headers=READ),
             client.post(API_PREFIX + "/cancel", json=CANCEL, headers=WRITE)]

    async def plain_http():
        # A different HTTP stack with no page involved: only the token and the API.
        transport = httpx.ASGITransport(app=client.app, client=("127.0.0.1", 41000))
        async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as other:
            session = (await other.get(API_PREFIX + "/session", headers=READ)).json()
            return [await other.get(API_PREFIX + "/latches?active_only=true", headers=READ),
                    await other.post(API_PREFIX + "/cancel", json=CANCEL, headers={
                        **READ, "Origin": ORIGIN, "X-CSRF-Token": session["csrf_token"]})]

    second = asyncio.run(plain_http())
    assert [r.status_code for r in first] == [r.status_code for r in second] == [200, 200]
    assert [r.json() for r in first] == [r.json() for r in second]
    assert risk.calls[:2] == risk.calls[2:]
    assert [c[0] for c in risk.calls] == ["risk.latch.list", "risk.cancel.request"] * 2


def test_the_app_holds_no_state_and_calls_risk_only_on_request():
    risk = FakeRisk()
    client, _ = make(risk=risk)
    assert risk.calls == []  # creating the app sends nothing
    for path in GETS:
        assert client.get(API_PREFIX + path, headers=READ).status_code == 200
    writes = {"risk.policy.publish", "risk.latch.release", "risk.cancel.request"}
    assert not [c for c in risk.calls if c[0] in writes]  # no read ever releases or cancels
    risk.error = RiskAdminCallError("UNKNOWN")
    assert client.post(API_PREFIX + "/cancel", json=CANCEL, headers=WRITE).status_code == 502
    risk.error = None
    # An UNKNOWN write is not repeated by the adapter; the client asks by status.
    assert [c[0] for c in risk.calls].count("risk.cancel.request") == 1
    assert client.get(API_PREFIX + "/cancel/cancel-1", headers=READ).status_code == 200


def test_only_operator_operations_are_reachable():
    app = make()[0].app
    routes = [route for route in app.routes if isinstance(route, APIRoute)]
    assert all(route.path.startswith(API_PREFIX + "/") for route in routes)
    operations = {route[2] for route in module._ROUTES}
    assert operations == RISK_ADMIN_OPERATIONS and not operations & RISK_ORDER_OPERATIONS
    client, risk = make()
    for path in ("/order/reserve", "/order", "/parent/reserve", "/status/../order"):
        assert client.post(API_PREFIX + path, json={}, headers=WRITE).status_code in (404, 405)
    with pytest.raises(ValueError, match="INVALID_RISK_WEB_SESSION"):
        AuthenticatedRiskSession("operator-a", "desk-1", CSRF, frozenset({"risk.order.reserve"}))
    with pytest.raises(ValueError, match="INVALID_RISK_WEB_SESSION"):
        AuthenticatedRiskSession("operator-a", "desk-1", "short", frozenset())
    with pytest.raises(ValueError, match="INVALID_RISK_WEB_SESSION"):
        AuthenticatedRiskSession("operator-a", "desk-1", CSRF, {"risk.admin.status"})
    assert risk.calls == []


def test_create_app_refuses_non_local_origins_and_bad_settings():
    for origin in ("http://0.0.0.0:8710", "http://192.0.2.1:8710", "http://example.com",
                   "ftp://127.0.0.1:8710", "http://user:pw@127.0.0.1:8710", "http://127.0.0.1:8710/x"):
        with pytest.raises(ValueError, match="INVALID_LOCAL_ORIGIN"):
            create_app(origin=origin, authenticate=lambda r: None, admin_caller=FakeRisk())
    with pytest.raises(ValueError, match="AUTHENTICATION_REQUIRED"):
        create_app(origin=ORIGIN, authenticate=None, admin_caller=FakeRisk())
    with pytest.raises(ValueError, match="INVALID_TIMEOUT"):
        create_app(origin=ORIGIN, authenticate=lambda r: None, admin_caller=FakeRisk(), timeout_seconds=0)


def test_run_local_binds_127_0_0_1_only(monkeypatch):
    import uvicorn

    seen = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: seen.append(kwargs))
    app = make()[0].app
    for origin in ("http://0.0.0.0:8710", "http://localhost:8710", "http://[::1]:8710",
                   "http://192.168.1.2:8710", "https://127.0.0.1:8710", "http://127.0.0.1"):
        with pytest.raises(ValueError, match="LOOPBACK_ORIGIN_REQUIRED"):
            run_local(app, origin=origin)
    assert seen == []
    run_local(app, origin=ORIGIN)
    assert seen == [{"host": "127.0.0.1", "port": 8710, "proxy_headers": False, "server_header": False}]


def test_risk_and_pretrade_import_without_fastapi():
    import bt_api_base

    import bt_api_risk

    paths = [str(Path(bt_api_risk.__file__).resolve().parents[1]),
             str(Path(bt_api_base.__file__).resolve().parents[1])]
    script = r"""
import importlib, importlib.abc, json, sys
sys.path[:0] = json.loads(sys.argv[1])
blocked = {"fastapi", "starlette", "uvicorn", "httpx"}

class NoWeb(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in blocked:
            raise ModuleNotFoundError(fullname)

sys.meta_path.insert(0, NoWeb())
import bt_api_risk, bt_api_risk.pretrade, bt_api_risk.web
assert "PretradeEngine" in dir(bt_api_risk.pretrade)
for attempt in (lambda: importlib.import_module("bt_api_risk.web.app"),
                lambda: bt_api_risk.web.create_app):
    try:
        attempt()
    except ModuleNotFoundError:
        pass
    else:
        raise SystemExit("web adapter imported without FastAPI")
loaded = sorted(n for n in sys.modules if n.split(".")[0] in blocked)
assert not loaded, loaded
print("NO_WEB_OK")
"""
    result = subprocess.run(  # noqa: S603 -- fixed interpreter and literal script, no shell.
        [sys.executable, "-I", "-B", "-c", script, json.dumps(paths)],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "NO_WEB_OK"


def _section(heading):
    text = DOC.read_text("utf-8")
    start = text.index("\n## " + heading + "\n")
    end = text.find("\n## ", start + 1)
    return text[start:] if end == -1 else text[start:end]


def test_reference_lists_exactly_the_routes_and_every_code():
    rows = re.findall(r"^\| `([A-Z]+)` \| `(/[^`]*)` \| `?([a-z.]*|—)`? \|", _section("4. Routes"), re.M)
    documented = {(method, path) for method, path, _ in rows}
    app = make()[0].app
    served = {(m, r.path) for r in app.routes if isinstance(r, APIRoute) for m in r.methods}
    assert len(rows) == len(documented) and documented == served
    by_route = {(method, path): operation for method, path, operation in rows}
    for method, path, operation, *_ in module._ROUTES:
        assert by_route[(method, API_PREFIX + path)] == operation
    source = inspect.getsource(module)
    codes = set(re.findall(r"_(?:error|outcome)\(\s*\d{3},\s*(?:\"[A-Z_]+\",\s*)?\"([A-Z][A-Z_]+)\"", source))
    codes |= set(re.findall(r"_RefusalError\(\s*\d{3},\s*\"([A-Z][A-Z_]+)\"", source))
    codes |= set(re.findall(r"return \d{3}, \"([A-Z][A-Z_]+)\"", source))
    codes |= module._SERVICE_REFUSAL_CODES | module._NOT_SENT_CODES
    statuses = set(re.findall(r"_outcome\(\s*\S+,\s*\"([A-Z][A-Z_]+)\"", source)) | {"OBSERVED", "NOT_FOUND"}
    assert {"AUTHENTICATION_REQUIRED", "CSRF_DENIED", "ORIGIN_DENIED", "REQUEST_INVALID",
            "RISK_REPLY_INVALID", "RISK_TIMEOUT", "OPERATION_NOT_GRANTED"} <= codes
    assert {"NOT_SENT", "UNKNOWN", "REQUEST_REJECTED"} <= statuses
    table = _section("6. Status values and codes")
    missing = sorted(name for name in codes | statuses if f"`{name}`" not in table)
    assert missing == []
