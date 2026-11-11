"""Local, versioned HTTP adapter over the Risk service's operator port (64.13, interface only).

The host supplies authentication (revalidated on every request), the session's CSRF
token and one admin caller::

    admin_caller(operation: str, arguments: dict, timeout_seconds: float) -> Mapping

The caller sends exactly one ``risk.*`` operator operation over the operator's own
authenticated registration (mount ``application.risk_admin``) and returns the Risk
service's reply, or raises :class:`RiskAdminCallError` with a finite outcome class.

This module holds no risk state and grants nothing: the Risk service authorizes,
validates, executes and audits every call. It never retries a call, never sends an
order operation (``risk.order.*``/``risk.parent.*``), never releases a latch or
cancels anything except on an explicit request, and never starts, stops or changes
the Risk service. Errors carry finite codes only, never values or exception text.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Optional
from urllib.parse import parse_qsl, urlsplit

from bt_api_base.risk_service_protocol import RISK_ADMIN_OPERATIONS
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.concurrency import run_in_threadpool

API_PREFIX = "/api/v1/risk"
API_VERSION = 1

_MAX_BODY_BYTES = 8192
_MAX_POLICY_BODY_BYTES = 524_288
_MAX_INT = 2**63 - 1
_MAX_REASON_CHARS = 1024
_MAX_AUDIT_LIMIT = 1000
_SECRET_KEYS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "apikey",
    "privatekey",
    "authcode",
    "authorization",
    "cookie",
)
_RISK_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,18}")
_TRADING_DAY = re.compile(r"[0-9]{8}")
# Refusals by the Risk service host's Registry of a call to the operator port, given in
# its own reply correlated to that call, before any handler ran: the call changed nothing.
# The host's caller reports them as ``RiskAdminCallError("REFUSED", code)``.
_SERVICE_REFUSAL_CODES = frozenset(
    {
        "CAPABILITY_UNAVAILABLE",
        "CLOSED",
        "DENIED",
        "NOT_REGISTERED",
        "POLICY_REQUIREMENT_UNMET",
        "SCOPE_DENIED",
        "STALE_EPOCH",
    }
)
# Reasons a host's caller can prove that the request never left the Web host process.
_NOT_SENT_CODES = frozenset(
    {
        "ROUTE_UNAVAILABLE",
        "NOT_READY",
        "QUEUE_FULL",
        "TIMEOUT_BEFORE_START",
        "CLOSED_BEFORE_START",
        "REQUEST_NOT_SENT",
        "WRONG_PROCESS",
        "OWNER_THREAD_REENTRY",
        "INVALID_ARGUMENTS",
    }
)
# Risk refusals of a well-formed request that depend on the service's current state.
_STATE_CONFLICT_CODES = frozenset({"policy_version_conflict", "policy_loosening_latched"})
_LATCH_FIELDS = frozenset(
    {
        "latch_id",
        "control",
        "scope_kind",
        "scope_value",
        "reason",
        "trading_day",
        "version",
        "active",
        "released_by",
        "released_at",
    }
)
_PERMIT_FIELDS = frozenset(
    {
        "request_key",
        "strategy_ref",
        "permit_id",
        "reservation_id",
        "state",
        "instrument",
        "side",
        "offset",
        "quantity",
        "since",
    }
)
_CALL_KINDS = frozenset({"NOT_SENT", "REFUSED", "TIMEOUT", "UNKNOWN"})


def _ref(value: object, limit: int = 256) -> bool:
    if type(value) is not str or not value or value != value.strip() or not value.isprintable():
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= limit
    except UnicodeError:
        return False


def _count(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_INT


def _scalar(value: object) -> bool:
    return value is None or type(value) in (bool, int, str) or (
        type(value) is float and math.isfinite(value)
    )


class RiskAdminCallError(Exception):
    """Raised by a host's admin caller with a finite outcome class.

    ``NOT_SENT``: provably never left the Web host process. ``REFUSED``: the Risk
    service host refused this call in its own correlated reply before any handler
    ran. ``TIMEOUT``: no reply in time after the request may have been sent.
    ``UNKNOWN``: anything else that cannot be proven either way.
    """

    def __init__(self, kind: str, code: str = "") -> None:
        self.kind = kind if kind in _CALL_KINDS else "UNKNOWN"
        self.code = code if type(code) is str else ""
        super().__init__(self.kind)


@dataclass(frozen=True)
class AuthenticatedRiskSession:
    """Returned by the host's authentication on every request, never parsed from JSON.

    ``operations`` narrows which operator operations this session may ask the Web
    host to send; it is not an authorization. The Risk service still authorizes
    every call for the registered principal.
    """

    principal_ref: str
    actor_ref: str
    csrf_token: str = field(repr=False)
    operations: frozenset = frozenset()

    def __post_init__(self) -> None:
        if not _ref(self.principal_ref) or not _ref(self.actor_ref):
            raise ValueError("INVALID_RISK_WEB_SESSION")
        if (
            type(self.csrf_token) is not str
            or not self.csrf_token.isascii()
            or not 32 <= len(self.csrf_token) <= 256
        ):
            raise ValueError("INVALID_RISK_WEB_SESSION")
        if type(self.operations) is not frozenset or not self.operations <= RISK_ADMIN_OPERATIONS:
            raise ValueError("INVALID_RISK_WEB_SESSION")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class PolicyPublishRequest(_Strict):
    """``POST /api/v1/risk/policy`` body (``risk.policy.publish``)."""

    expected_version: int
    document: dict[str, Any]
    reason: str
    # pydantic evaluates this annotation at run time; ``str | None`` fails on Python 3.9.
    exchange_rules_text: Optional[str] = None  # noqa: UP045


class LatchReleaseRequest(_Strict):
    """``POST /api/v1/risk/latches/{latch_id}/release`` body (``risk.latch.release``)."""

    expected_version: int
    reason: str


class CancelRequest(_Strict):
    """``POST /api/v1/risk/cancel`` body (``risk.cancel.request``)."""

    operation_id: str
    scope_kind: Literal["account", "instrument"]
    scope_value: str


class _RefusalError(Exception):
    def __init__(self, status_code: int, code: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code


def _invalid() -> _RefusalError:
    return _RefusalError(422, "REQUEST_INVALID")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _no_constant(_name):
    raise ValueError("non-finite number")


def _json_document(value: object, depth: int = 0, budget: list | None = None) -> None:
    """Bound a request document; the Risk service validates its content."""
    budget = [100_000] if budget is None else budget
    budget[0] -= 1
    if budget[0] < 0 or depth > 32:
        raise _invalid()
    if value is None or type(value) in (bool, int, str):
        if type(value) is int and abs(value) > _MAX_INT:
            raise _invalid()
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise _invalid()
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise _invalid()
            _json_document(item, depth + 1, budget)
        return
    if type(value) is list:
        for item in value:
            _json_document(item, depth + 1, budget)
        return
    raise _invalid()


def _copy_safe(value: Any) -> Any:
    """Plain, bounded copy of a Risk reply; any credential-like key refuses the reply."""
    budget = [200_000]

    def copy(item: Any, depth: int) -> Any:
        budget[0] -= 1
        if budget[0] < 0 or depth > 32:
            raise ValueError("RISK_REPLY_INVALID")
        if item is None or type(item) in (bool, int, str):
            return item
        if type(item) is float:
            if math.isfinite(item):
                return item
            raise ValueError("RISK_REPLY_INVALID")
        if isinstance(item, Mapping):
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError("RISK_REPLY_INVALID")
                normalized = re.sub(r"[^a-z0-9]", "", key.lower())
                if any(secret in normalized for secret in _SECRET_KEYS):
                    raise ValueError("RISK_REPLY_INVALID")
                result[key] = copy(child, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            return [copy(child, depth + 1) for child in item]
        raise ValueError("RISK_REPLY_INVALID")

    return copy(value, 0)


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("RISK_REPLY_INVALID")


def _observed(reply: dict, keys: tuple) -> None:
    _require(reply.get("status") == "OBSERVED" and set(reply) == {"status", *keys})


def _latch_row(row: object) -> dict:
    _require(type(row) is dict and set(row) == _LATCH_FIELDS)
    _require(_ref(row["latch_id"]) and _count(row["version"]))
    active = row["active"]
    _require(type(active) is bool or (type(active) is int and active in (0, 1)))
    row["active"] = bool(active)
    _require(all(_scalar(row[name]) for name in _LATCH_FIELDS))
    return row


def _check_status(reply: dict, arguments: dict) -> int:
    _observed(reply, ("summary",))
    _require(type(reply["summary"]) is dict)
    return 200


def _check_policy_read(reply: dict, arguments: dict) -> int:
    _observed(reply, ("version", "policy_id", "digest", "document", "exchange_rules_digest"))
    _require(_count(reply["version"]) and _ref(reply["policy_id"]) and _ref(reply["digest"]))
    _require(type(reply["document"]) is dict)
    _require(reply["exchange_rules_digest"] is None or _ref(reply["exchange_rules_digest"]))
    return 200


def _check_policy_publish(reply: dict, arguments: dict) -> int:
    _observed(reply, ("version", "policy_id", "digest", "classification"))
    _require(_count(reply["version"]) and reply["version"] >= 1)
    _require(_ref(reply["policy_id"]) and _ref(reply["digest"]))
    classification = reply["classification"]
    _require(
        type(classification) is dict
        and set(classification) == {"tightened", "loosened", "unchanged"}
        and all(
            type(items) is list and all(type(item) is str for item in items)
            for items in classification.values()
        )
    )
    return 200


def _check_latch_list(reply: dict, arguments: dict) -> int:
    _observed(reply, ("latches",))
    _require(type(reply["latches"]) is list)
    rows = [_latch_row(row) for row in reply["latches"]]
    # An active-only list that shows a released latch would mislead the operator.
    _require(not arguments["active_only"] or all(row["active"] for row in rows))
    return 200


def _check_latch_release(reply: dict, arguments: dict) -> int:
    _observed(reply, ("latch",))
    row = _latch_row(reply["latch"])
    _require(row["latch_id"] == arguments["latch_id"] and row["active"] is False)
    return 200


def _check_unknown(reply: dict, arguments: dict) -> int:
    _observed(reply, ("permits",))
    _require(type(reply["permits"]) is list)
    for row in reply["permits"]:
        _require(type(row) is dict and set(row) == _PERMIT_FIELDS)
        _require(all(_scalar(row[name]) for name in _PERMIT_FIELDS))
        _require(_ref(row["request_key"]) and _ref(row["state"]))
    return 200


def _check_counts(reply: dict, arguments: dict) -> int:
    _observed(reply, ("format", "content"))
    _require(reply["format"] == arguments["format"] and type(reply["content"]) is str)
    return 200


def _check_audit(reply: dict, arguments: dict) -> int:
    _observed(reply, ("records", "next_after"))
    records = reply["records"]
    _require(type(records) is list and len(records) <= arguments["limit"])
    _require(all(type(record) is dict for record in records))
    _require(_count(reply["next_after"]) and reply["next_after"] >= arguments["after"])
    return 200


def _check_cancel_request(reply: dict, arguments: dict) -> int:
    _observed(reply, ("operation_id", "state"))
    _require(reply["operation_id"] == arguments["operation_id"] and _ref(reply["state"]))
    return 200


def _check_cancel_status(reply: dict, arguments: dict) -> int:
    if reply.get("status") == "NOT_FOUND":
        _require(set(reply) == {"status", "operation_id"})
        _require(reply["operation_id"] == arguments["operation_id"])
        return 404
    _observed(reply, ("operation_id", "state", "gateway"))
    _require(reply["operation_id"] == arguments["operation_id"] and _ref(reply["state"]))
    _require(reply["gateway"] is None or type(reply["gateway"]) is dict)
    return 200


def _rejection(reply: dict) -> str | None:
    """The finite code of the Risk service's ``REQUEST_REJECTED`` reply, else None."""
    if reply.get("status") != "REQUEST_REJECTED":
        return None
    _require(set(reply) == {"status", "code"})
    code = reply["code"]
    _require(type(code) is str and _RISK_CODE.fullmatch(code) is not None)
    return code


def _refusal_status(code: str) -> int:
    """422 when Risk refused the request's content, 409 when it refused in its current state."""
    if (
        code == "risk_request_invalid"
        or code.startswith("risk_admin_reason_")
        or (code.startswith("policy_") and code not in _STATE_CONFLICT_CODES)
    ):
        return 422
    return 409


def _local_origin(origin: object) -> tuple[str, str]:
    if type(origin) is not str:
        raise ValueError("INVALID_LOCAL_ORIGIN")
    parsed = urlsplit(origin)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("INVALID_LOCAL_ORIGIN")
    try:
        local = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        local = False
    if not local:
        raise ValueError("INVALID_LOCAL_ORIGIN")
    return origin.rstrip("/"), parsed.netloc.lower()


def _query(request: Request, allowed: frozenset) -> dict:
    raw = request.url.query
    if not raw:
        return {}
    try:
        pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True, max_num_fields=8)
    except ValueError:
        raise _invalid() from None
    result: dict = {}
    for key, value in pairs:
        if key not in allowed or key in result:
            raise _invalid()
        result[key] = value
    return result


def _decimal(value: str, *, low: int, high: int) -> int:
    if _DECIMAL.fullmatch(value) is None:
        raise _invalid()
    number = int(value)
    if not low <= number <= high:
        raise _invalid()
    return number


async def _json_body(request: Request, limit: int) -> object:
    body = await request.body()
    if len(body) > limit:
        raise _RefusalError(413, "BODY_SIZE_INVALID")
    try:
        return json.loads(
            body.decode("utf-8"), object_pairs_hook=_unique_pairs, parse_constant=_no_constant
        )
    except (UnicodeError, ValueError, RecursionError):
        raise _invalid() from None


def _model(model: type, value: object) -> Any:
    try:
        return model.model_validate(value)
    except (ValidationError, ValueError, TypeError):
        raise _invalid() from None


def _reason(value: str) -> str:
    if not _ref(value, _MAX_REASON_CHARS * 4) or len(value) > _MAX_REASON_CHARS:
        raise _invalid()
    return value


def _version(value: int) -> int:
    if not _count(value):
        raise _invalid()
    return value


def _path_ref(request: Request, name: str) -> str:
    value = request.path_params.get(name)
    if not _ref(value):
        raise _invalid()
    return value


async def _parse_none(request: Request) -> dict:
    _query(request, frozenset())
    return {}


async def _parse_latch_list(request: Request) -> dict:
    query = _query(request, frozenset({"active_only"}))
    flag = query.get("active_only", "false")
    if flag not in ("true", "false"):
        raise _invalid()
    return {"active_only": flag == "true"}


async def _parse_counts(request: Request) -> dict:
    query = _query(request, frozenset({"format"}))
    day = request.path_params.get("trading_day")
    fmt = query.get("format", "json")
    if type(day) is not str or _TRADING_DAY.fullmatch(day) is None or fmt not in ("json", "csv"):
        raise _invalid()
    try:
        if datetime.strptime(day, "%Y%m%d").strftime("%Y%m%d") != day:
            raise ValueError
    except ValueError:
        raise _invalid() from None
    return {"trading_day": day, "format": fmt}


async def _parse_audit(request: Request) -> dict:
    query = _query(request, frozenset({"after", "limit"}))
    after = _decimal(query.get("after", "0"), low=0, high=_MAX_INT)
    limit = _decimal(query.get("limit", "100"), low=1, high=_MAX_AUDIT_LIMIT)
    return {"after": after, "limit": limit}


async def _parse_cancel_status(request: Request) -> dict:
    _query(request, frozenset())
    return {"operation_id": _path_ref(request, "operation_id")}


async def _parse_publish(request: Request) -> dict:
    _query(request, frozenset())
    body = _model(PolicyPublishRequest, await _json_body(request, _MAX_POLICY_BODY_BYTES))
    _json_document(body.document)
    rules = body.exchange_rules_text
    if rules is not None and (
        not rules or any(not ch.isprintable() and ch not in "\n\r\t" for ch in rules)
    ):
        raise _invalid()
    return {
        "expected_version": _version(body.expected_version),
        "document": body.document,
        "reason": _reason(body.reason),
        "exchange_rules_text": body.exchange_rules_text,
    }


async def _parse_latch_release(request: Request) -> dict:
    _query(request, frozenset())
    latch_id = _path_ref(request, "latch_id")
    body = _model(LatchReleaseRequest, await _json_body(request, _MAX_BODY_BYTES))
    return {
        "latch_id": latch_id,
        "expected_version": _version(body.expected_version),
        "reason": _reason(body.reason),
    }


async def _parse_cancel(request: Request) -> dict:
    _query(request, frozenset())
    body = _model(CancelRequest, await _json_body(request, _MAX_BODY_BYTES))
    value = body.scope_value
    if not _ref(body.operation_id) or (value and not _ref(value)):
        raise _invalid()
    return {
        "operation_id": body.operation_id,
        "scope_kind": body.scope_kind,
        "scope_value": value,
    }


# (method, path under API_PREFIX, operation, parser, reply check, write)
_ROUTES = (
    ("GET", "/status", "risk.admin.status", _parse_none, _check_status, False),
    ("GET", "/policy", "risk.policy.read", _parse_none, _check_policy_read, False),
    ("POST", "/policy", "risk.policy.publish", _parse_publish, _check_policy_publish, True),
    ("GET", "/latches", "risk.latch.list", _parse_latch_list, _check_latch_list, False),
    (
        "POST",
        "/latches/{latch_id}/release",
        "risk.latch.release",
        _parse_latch_release,
        _check_latch_release,
        True,
    ),
    ("GET", "/unknown", "risk.unknown.list", _parse_none, _check_unknown, False),
    ("GET", "/counts/{trading_day}", "risk.counts.export", _parse_counts, _check_counts, False),
    ("GET", "/audit", "risk.audit.read", _parse_audit, _check_audit, False),
    ("POST", "/cancel", "risk.cancel.request", _parse_cancel, _check_cancel_request, True),
    (
        "GET",
        "/cancel/{operation_id}",
        "risk.cancel.status",
        _parse_cancel_status,
        _check_cancel_status,
        False,
    ),
)
# Only operator operations are reachable, each from exactly one route.
if {route[2] for route in _ROUTES} != RISK_ADMIN_OPERATIONS or len(_ROUTES) != len(
    RISK_ADMIN_OPERATIONS
):
    raise ImportError("RISK_WEB_ROUTES_MISMATCH")

_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
}


def _error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status_code)


def _outcome(status_code: int, status: str, code: str) -> JSONResponse:
    return JSONResponse({"status": status, "code": code}, status_code=status_code)


def _call_failure(error: RiskAdminCallError) -> JSONResponse:
    if error.kind == "NOT_SENT":
        code = error.code if error.code in _NOT_SENT_CODES else "REQUEST_NOT_SENT"
        return _outcome(503, "NOT_SENT", code)
    if error.kind == "REFUSED" and error.code in _SERVICE_REFUSAL_CODES:
        return _outcome(409, "REQUEST_REJECTED", error.code)
    if error.kind == "TIMEOUT":
        return _outcome(504, "UNKNOWN", "RISK_TIMEOUT")
    return _outcome(502, "UNKNOWN", "RISK_OUTCOME_UNKNOWN")


def create_app(
    *,
    origin: str,
    authenticate: Callable[[Request], AuthenticatedRiskSession],
    admin_caller: Callable[[str, dict, float], Mapping],
    timeout_seconds: float = 5.0,
) -> FastAPI:
    """Create the local-only adapter; ``authenticate`` and ``admin_caller`` are trusted host code.

    ``authenticate`` must revalidate the caller on every request and raise (or return
    something else than an :class:`AuthenticatedRiskSession`) to refuse it.
    ``admin_caller`` must use the operator's own registration on the Risk service's
    operator port, send at most once per invocation and never retry.
    """
    origin, authority = _local_origin(origin)
    if not callable(authenticate) or not callable(admin_caller):
        raise ValueError("AUTHENTICATION_REQUIRED")
    if type(timeout_seconds) not in (float, int) or not 0 < timeout_seconds <= 30:
        raise ValueError("INVALID_TIMEOUT")
    timeout = float(timeout_seconds)
    app = FastAPI(
        title="Risk local operator API", docs_url=None, redoc_url=None, openapi_url=None
    )

    def transport_refusal(request: Request) -> tuple[int, str] | None:
        try:
            host = request.client.host if request.client else ""
            if not ipaddress.ip_address(host).is_loopback:
                return 403, "LOCAL_ACCESS_REQUIRED"
        except ValueError:
            return 403, "LOCAL_ACCESS_REQUIRED"
        if request.headers.get("host", "").lower() != authority:
            return 403, "HOST_DENIED"
        if request.method not in ("GET", "POST"):
            return 405, "METHOD_DENIED"
        supplied_origin = request.headers.get("origin")
        if (supplied_origin is not None or request.method == "POST") and supplied_origin != origin:
            return 403, "ORIGIN_DENIED"
        if request.method == "POST":
            limit = (
                _MAX_POLICY_BODY_BYTES
                if request.url.path == API_PREFIX + "/policy"
                else _MAX_BODY_BYTES
            )
            length = request.headers.get("content-length", "")
            if (
                len(length) > 7
                or not length.isascii()
                or not length.isdigit()
                or int(length) > limit
            ):
                return 413, "BODY_SIZE_INVALID"
            if request.url.path.startswith(API_PREFIX + "/"):
                media = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if media != "application/json":
                    return 415, "CONTENT_TYPE_DENIED"
        return None

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        refusal = transport_refusal(request)
        if refusal is None:
            response = await call_next(request)
        else:
            response = _error(*refusal)
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    def session_for(request: Request, *, write: bool) -> AuthenticatedRiskSession:
        try:
            session = authenticate(request)
        except Exception:
            raise _RefusalError(401, "AUTHENTICATION_REQUIRED") from None
        if type(session) is not AuthenticatedRiskSession:
            raise _RefusalError(401, "AUTHENTICATION_REQUIRED")
        if write:
            token = request.headers.get("x-csrf-token", "")
            if not token.isascii() or not hmac.compare_digest(token, session.csrf_token):
                raise _RefusalError(403, "CSRF_DENIED")
        return session

    async def invoke(request: Request, operation: str, parse, check, write: bool) -> JSONResponse:
        try:
            session = session_for(request, write=write)
            if operation not in session.operations:
                raise _RefusalError(403, "OPERATION_NOT_GRANTED")
            arguments = await parse(request)
        except _RefusalError as refusal:
            return _error(refusal.status_code, refusal.code)
        # One call, never repeated: a lost or late answer stays UNKNOWN for the client to
        # resolve by reading (status, latch list, policy version or cancel status).
        wire = json.loads(json.dumps(arguments))
        try:
            reply = await run_in_threadpool(admin_caller, operation, wire, timeout)
        except RiskAdminCallError as error:
            return _call_failure(error)
        except TimeoutError:
            return _outcome(504, "UNKNOWN", "RISK_TIMEOUT")
        except Exception:
            return _outcome(502, "UNKNOWN", "RISK_OUTCOME_UNKNOWN")
        try:
            plain = _copy_safe(reply)
            _require(type(plain) is dict)
            code = _rejection(plain)
            if code is not None:
                return _outcome(_refusal_status(code), "REQUEST_REJECTED", code)
            status_code = check(plain, arguments)
        except Exception:
            return _outcome(502, "UNKNOWN", "RISK_REPLY_INVALID")
        return JSONResponse(plain, status_code=status_code)

    @app.get(API_PREFIX + "/session")
    async def session_route(request: Request):
        try:
            session = session_for(request, write=False)
            _query(request, frozenset())
        except _RefusalError as refusal:
            return _error(refusal.status_code, refusal.code)
        namespace = hashlib.sha256(
            (session.principal_ref + "\0" + session.actor_ref).encode("utf-8")
        ).hexdigest()
        return JSONResponse(
            {
                "api_version": API_VERSION,
                "csrf_token": session.csrf_token,
                "namespace": namespace,
                "operations": sorted(session.operations),
            }
        )

    def add(method: str, path: str, operation: str, parse, check, write: bool) -> None:
        async def endpoint(request: Request):
            return await invoke(request, operation, parse, check, write)

        endpoint.__name__ = "risk_" + operation.replace(".", "_")
        app.add_api_route(API_PREFIX + path, endpoint, methods=[method])

    for method, path, operation, parse, check, write in _ROUTES:
        add(method, path, operation, parse, check, write)
    return app


def run_local(app: FastAPI, *, origin: str) -> None:
    """Serve on 127.0.0.1 only, at the origin's port; never behind proxy headers."""
    parsed = urlsplit(origin) if type(origin) is str else None
    try:
        port = parsed.port if parsed is not None else None
    except ValueError:
        port = None
    if (
        parsed is None
        or parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("LOOPBACK_ORIGIN_REQUIRED")
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=port, proxy_headers=False, server_header=False)
