"""R ``portfolio_analytics`` control plane: durable tasks and four operations.

This module is the serving adapter for the fixed ``portfolio_analytics`` role.
It owns exactly the ``service.risk_analysis`` operations
(``analysis.submit``, ``analysis.query``, ``analysis.cancel``,
``analysis.input_upload``) and is deliberately not an order, account, or
provider interface: V1 inputs use :mod:`bt_api_risk.portfolio_analytics`; V2
inputs carry explicit offline spot, NAV, loss, and scenario datasets for the
accepted deterministic metrics. No optional analytics or ML dependency
(``numpy``/``sklearn`` and friends) is imported here.

Execution model
---------------
``AnalysisTaskStore`` is durable (SQLite) and shared by exactly one
``PortfolioAnalyticsTaskService``. The host drives ``maintain`` on its owner
thread; each invocation sweeps expired pending tasks and advances at most one
new task claim per elapsed second of the injected store clock. V1 and V2 are
dispatched to bounded spawned processes and polled asynchronously.
``max_concurrent_tasks``
limits non-terminal submissions per scope; ``max_concurrent_workers`` is a
separate host-wide cap on active child processes. A monotonic execution
deadline starts only when the child enters its worker function, after any queue
delay. A cancelled, timed out, or shutting-down worker is not made terminal
until its process has been reaped and its pipes closed. ``running`` rows found
when the store is opened are failed closed as ``TASK_INTERRUPTED`` instead of
being silently re-executed.

Every error surfaced to a caller is one of this module's constant code
strings; no caller-supplied value is ever echoed in a rejection.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing
from multiprocessing.connection import wait as wait_for_connections
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Final

from bt_api_base.service_protocol import WireScope

from bt_api_risk.portfolio_analytics import (
    CashBalanceV1,
    ExternalCapitalFlowV1,
    ExternalFlowCoverageV1,
    FxObservationV1,
    PortfolioAnalyticsError,
    PortfolioAnalyticsFactsV1,
    PortfolioAnalyticsModelProfileV1,
    PortfolioAnalyticsRequestV1,
    PortfolioAnalyticsService,
    PortfolioMembershipV1,
    PortfolioValuationPointV1,
    SpotPositionV1,
    _canonical_json,
    _facts_payload,
    _request_payload,
)
from bt_api_risk.portfolio_analytics_v2 import (
    PortfolioAnalyticsFactsV2,
    PortfolioAnalyticsRequestV2,
    PortfolioAnalyticsServiceV2,
    parse_facts_v2,
    parse_request_v2,
)
from bt_api_risk.service_component import _valid_wire_text

_TASK_REF_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SUPPORTED_SOURCE_MODES: Final[frozenset[str]] = frozenset({"research", "imported", "paper"})
_MAX_PAYLOAD_DEPTH: Final[int] = 32
_EXECUTOR_GATE_NS: Final[int] = 1_000_000_000
_WORKER_STARTUP_TIMEOUT_NS: Final[int] = 10_000_000_000
_WORKER_STOP_GRACE_SECONDS: Final[float] = 0.5
_MAX_WORKER_FRAME_BYTES: Final[int] = 1_048_576
_TERMINAL_STATES: Final[frozenset[str]] = frozenset(
    {"succeeded", "unavailable", "failed", "cancelled", "expired"}
)
_TASK_SCOPE_FIELDS: Final[tuple[str, ...]] = (
    "execution_domain_ref",
    "account_ref",
    "account_refs",
    "strategy_ref",
    "run_id",
    "manual_book_ref",
    "portfolio_ref",
    "group_id",
    "leg_id",
)

_FACTS_KEYS: Final[frozenset[str]] = frozenset(
    {
        "beginning",
        "ending",
        "external_flows",
        "facts_snapshot_ref",
        "flow_coverage",
        "fx_observations",
        "membership",
        "portfolio_ref",
        "source_generation",
        "source_mode",
        "source_ref",
        "source_version",
        "valuation_basis_ref",
        "version",
    }
)
_POINT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "as_of_ns",
        "cash_balances",
        "covered_asset_classes",
        "covered_member_refs",
        "coverage_complete",
        "snapshot_ref",
        "source_cursor",
        "source_generation",
        "spot_positions",
        "valuation_cut_policy",
        "valuation_date_utc",
    }
)
_CASH_KEYS: Final[frozenset[str]] = frozenset(
    {"amount", "balance_ref", "currency", "member_ref"}
)
_SPOT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "base_currency",
        "instrument_metadata_ref",
        "instrument_metadata_version",
        "instrument_ref",
        "member_ref",
        "position_ref",
        "price_as_of_ns",
        "price_observation_ref",
        "price_source_cursor",
        "price_source_generation",
        "price_source_ref",
        "price_source_version",
        "price_unit",
        "price_valid_until_ns",
        "product_kind",
        "quantity",
        "quote_currency",
        "unit_price",
    }
)
_FLOW_KEYS: Final[frozenset[str]] = frozenset(
    {
        "amount",
        "currency",
        "direction",
        "effective_at_ns",
        "flow_ref",
        "source_cursor",
        "source_generation",
        "source_ref",
        "source_version",
    }
)
_COVERAGE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "complete",
        "end_as_of_ns",
        "end_cursor",
        "source_generation",
        "source_ref",
        "source_version",
        "start_as_of_ns",
        "start_cursor",
    }
)
_FX_KEYS: Final[frozenset[str]] = frozenset(
    {
        "as_of_ns",
        "base_currency",
        "direction",
        "observation_ref",
        "quote_currency",
        "rate",
        "rate_unit",
        "source_cursor",
        "source_generation",
        "source_ref",
        "source_version",
        "valid_until_ns",
    }
)
_MEMBERSHIP_KEYS: Final[frozenset[str]] = frozenset(
    {
        "content_sha256",
        "effective_end_date_utc_exclusive",
        "effective_start_date_utc",
        "member_refs",
        "membership_version",
        "portfolio_ref",
        "source_ref",
        "source_version",
    }
)
_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "membership_version",
        "period_end_date_utc",
        "period_start_date_utc",
        "portfolio_ref",
        "reporting_currency",
        "version",
    }
)


class AnalysisTaskError(ValueError):
    """Finite control-plane/store error that does not include caller values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _now_ns() -> int:
    return time.time_ns()


def _invalid_input() -> None:
    raise AnalysisTaskError("INVALID_INPUT")


def _plain(value: object, *, depth: int = 0) -> object:
    """Copy wire-frozen or decoded JSON into bounded plain containers."""

    if depth > _MAX_PAYLOAD_DEPTH:
        _invalid_input()
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str:
                _invalid_input()
            result[key] = _plain(item, depth=depth + 1)
        return result
    if type(value) in (list, tuple):
        return [_plain(item, depth=depth + 1) for item in value]
    return value


def _exact_object(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        _invalid_input()
    return value  # type: ignore[return-value]


def _array(value: object) -> list[object]:
    if type(value) is not list:
        _invalid_input()
    return value  # type: ignore[return-value]


def _decimal_text(value: object) -> Decimal:
    if type(value) is not str:
        _invalid_input()
    try:
        return Decimal(value)
    except (InvalidOperation, ValueError):
        _invalid_input()


def _date_text(value: object) -> date:
    if type(value) is not str:
        _invalid_input()
    try:
        return date.fromisoformat(value)
    except ValueError:
        _invalid_input()


def _optional_date_text(value: object) -> date | None:
    if value is None:
        return None
    return _date_text(value)


def _parse_membership(value: object) -> PortfolioMembershipV1:
    obj = _exact_object(_plain(value), _MEMBERSHIP_KEYS)
    return PortfolioMembershipV1(
        portfolio_ref=obj["portfolio_ref"],
        membership_version=obj["membership_version"],
        member_refs=tuple(_array(obj["member_refs"])),
        effective_start_date_utc=_date_text(obj["effective_start_date_utc"]),
        effective_end_date_utc_exclusive=_optional_date_text(
            obj["effective_end_date_utc_exclusive"]
        ),
        source_ref=obj["source_ref"],
        source_version=obj["source_version"],
        content_sha256=obj["content_sha256"],
    )


def _parse_cash_balance(value: object) -> CashBalanceV1:
    obj = _exact_object(_plain(value), _CASH_KEYS)
    return CashBalanceV1(
        balance_ref=obj["balance_ref"],
        member_ref=obj["member_ref"],
        currency=obj["currency"],
        amount=_decimal_text(obj["amount"]),
    )


def _parse_spot_position(value: object) -> SpotPositionV1:
    obj = _exact_object(_plain(value), _SPOT_KEYS)
    return SpotPositionV1(
        position_ref=obj["position_ref"],
        member_ref=obj["member_ref"],
        instrument_ref=obj["instrument_ref"],
        product_kind=obj["product_kind"],
        base_currency=obj["base_currency"],
        quote_currency=obj["quote_currency"],
        price_unit=obj["price_unit"],
        quantity=_decimal_text(obj["quantity"]),
        unit_price=_decimal_text(obj["unit_price"]),
        price_as_of_ns=obj["price_as_of_ns"],
        price_valid_until_ns=obj["price_valid_until_ns"],
        price_source_ref=obj["price_source_ref"],
        price_source_version=obj["price_source_version"],
        price_source_generation=obj["price_source_generation"],
        price_source_cursor=obj["price_source_cursor"],
        price_observation_ref=obj["price_observation_ref"],
        instrument_metadata_ref=obj["instrument_metadata_ref"],
        instrument_metadata_version=obj["instrument_metadata_version"],
    )


def _parse_valuation_point(value: object) -> PortfolioValuationPointV1:
    obj = _exact_object(_plain(value), _POINT_KEYS)
    if type(obj["coverage_complete"]) is not bool:
        _invalid_input()
    return PortfolioValuationPointV1(
        valuation_date_utc=_date_text(obj["valuation_date_utc"]),
        as_of_ns=obj["as_of_ns"],
        snapshot_ref=obj["snapshot_ref"],
        source_generation=obj["source_generation"],
        source_cursor=obj["source_cursor"],
        valuation_cut_policy=obj["valuation_cut_policy"],
        coverage_complete=obj["coverage_complete"],
        covered_member_refs=tuple(_array(obj["covered_member_refs"])),
        covered_asset_classes=tuple(_array(obj["covered_asset_classes"])),
        cash_balances=tuple(_parse_cash_balance(row) for row in _array(obj["cash_balances"])),
        spot_positions=tuple(
            _parse_spot_position(row) for row in _array(obj["spot_positions"])
        ),
    )


def _parse_external_flow(value: object) -> ExternalCapitalFlowV1:
    obj = _exact_object(_plain(value), _FLOW_KEYS)
    return ExternalCapitalFlowV1(
        flow_ref=obj["flow_ref"],
        direction=obj["direction"],
        amount=_decimal_text(obj["amount"]),
        currency=obj["currency"],
        effective_at_ns=obj["effective_at_ns"],
        source_ref=obj["source_ref"],
        source_version=obj["source_version"],
        source_generation=obj["source_generation"],
        source_cursor=obj["source_cursor"],
    )


def _parse_flow_coverage(value: object) -> ExternalFlowCoverageV1:
    obj = _exact_object(_plain(value), _COVERAGE_KEYS)
    return ExternalFlowCoverageV1(
        source_ref=obj["source_ref"],
        source_version=obj["source_version"],
        source_generation=obj["source_generation"],
        start_as_of_ns=obj["start_as_of_ns"],
        end_as_of_ns=obj["end_as_of_ns"],
        start_cursor=obj["start_cursor"],
        end_cursor=obj["end_cursor"],
        complete=obj["complete"],
    )


def _parse_fx_observation(value: object) -> FxObservationV1:
    obj = _exact_object(_plain(value), _FX_KEYS)
    return FxObservationV1(
        observation_ref=obj["observation_ref"],
        base_currency=obj["base_currency"],
        quote_currency=obj["quote_currency"],
        direction=obj["direction"],
        rate_unit=obj["rate_unit"],
        rate=_decimal_text(obj["rate"]),
        as_of_ns=obj["as_of_ns"],
        valid_until_ns=obj["valid_until_ns"],
        source_ref=obj["source_ref"],
        source_version=obj["source_version"],
        source_generation=obj["source_generation"],
        source_cursor=obj["source_cursor"],
    )


def _parse_facts_payload(
    value: object,
) -> PortfolioAnalyticsFactsV1 | PortfolioAnalyticsFactsV2:
    """Strictly reconstruct one facts cut from its canonical wire payload.

    V1 retains the existing facts projection. V2 dispatches to its own exact
    codec. Every object key set, container kind, and strictly typed leaf is
    re-validated by the schema's dataclasses; deviations map to one finite
    ``INVALID_INPUT`` code.
    """

    try:
        plain = _plain(value)
        if type(plain) is not dict or type(plain.get("version")) is not int:
            _invalid_input()
        if plain["version"] == 2:
            return parse_facts_v2(plain)
        obj = _exact_object(plain, _FACTS_KEYS)
        if obj["version"] != 1:
            _invalid_input()
        return PortfolioAnalyticsFactsV1(
            portfolio_ref=obj["portfolio_ref"],
            source_mode=obj["source_mode"],
            source_ref=obj["source_ref"],
            source_version=obj["source_version"],
            source_generation=obj["source_generation"],
            snapshot_ref=obj["facts_snapshot_ref"],
            valuation_basis_ref=obj["valuation_basis_ref"],
            membership=_parse_membership(obj["membership"]),
            beginning=_parse_valuation_point(obj["beginning"]),
            ending=_parse_valuation_point(obj["ending"]),
            external_flows=tuple(
                _parse_external_flow(row) for row in _array(obj["external_flows"])
            ),
            flow_coverage=_parse_flow_coverage(obj["flow_coverage"]),
            fx_observations=tuple(
                _parse_fx_observation(row) for row in _array(obj["fx_observations"])
            ),
        )
    except AnalysisTaskError:
        raise
    except PortfolioAnalyticsError:
        _invalid_input()
    except (TypeError, ValueError, KeyError, OverflowError):
        _invalid_input()


def _parse_request_payload(
    value: object,
) -> PortfolioAnalyticsRequestV1 | PortfolioAnalyticsRequestV2:
    """Strictly reconstruct one analysis request from its canonical payload."""

    try:
        plain = _plain(value)
        if type(plain) is not dict or type(plain.get("version")) is not int:
            _invalid_input()
        if plain["version"] == 2:
            return parse_request_v2(plain)
        obj = _exact_object(plain, _REQUEST_KEYS)
        if obj["version"] != 1:
            _invalid_input()
        return PortfolioAnalyticsRequestV1(
            portfolio_ref=obj["portfolio_ref"],
            membership_version=obj["membership_version"],
            period_start_date_utc=_date_text(obj["period_start_date_utc"]),
            period_end_date_utc=_date_text(obj["period_end_date_utc"]),
            reporting_currency=obj["reporting_currency"],
        )
    except AnalysisTaskError:
        raise
    except PortfolioAnalyticsError:
        _invalid_input()
    except (TypeError, ValueError, KeyError, OverflowError):
        _invalid_input()


def _task_reference(value: object) -> str:
    if type(value) is not str or _TASK_REF_PATTERN.fullmatch(value) is None:
        raise AnalysisTaskError("INVALID_REFERENCE")
    return value


def _task_scope(scope: object) -> str:
    """Validate one exact run-free portfolio scope and return its canonical JSON.

    Analysis tasks are portfolio control-plane objects: the scope must be a
    genuine ``WireScope`` template with a portfolio selection, must not be
    bound to a strategy run, and every populated field is validated wire text.
    The canonical JSON is the store's scope identity, so two requests are the
    same owner only when their full scopes agree field for field.
    """

    if type(scope) is not WireScope:
        raise AnalysisTaskError("INVALID_SCOPE")
    try:
        fields = vars(scope)
    except TypeError:
        raise AnalysisTaskError("INVALID_SCOPE") from None
    if type(fields) is not dict or set(fields) != set(_TASK_SCOPE_FIELDS):
        raise AnalysisTaskError("INVALID_SCOPE")
    canonical: dict[str, object] = {}
    for name in _TASK_SCOPE_FIELDS:
        value = fields[name]
        if name == "account_refs":
            if type(value) is not tuple or any(
                not _valid_wire_text(account) for account in value
            ):
                raise AnalysisTaskError("INVALID_SCOPE")
            canonical[name] = list(value)
        elif value is None:
            canonical[name] = None
        elif _valid_wire_text(value):
            canonical[name] = value
        else:
            raise AnalysisTaskError("INVALID_SCOPE")
    if canonical["run_id"] is not None or canonical["portfolio_ref"] is None:
        raise AnalysisTaskError("INVALID_SCOPE")
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"))


class AnalysisTaskStore:
    """Durable analysis inputs and tasks for the ``portfolio_analytics`` role.

    The store is operator-owned: it is opened by the trusted resource provider
    and borrowed by the service adapter. Inputs are immutable once uploaded
    (same ID plus same content is an idempotent re-upload; different content is
    rejected). Tasks are scope-owned state machines
    ``pending -> running -> {succeeded, unavailable, failed}`` plus the
    terminal ``cancelled`` and ``expired`` states. Submissions count against a
    per-scope quota of non-terminal tasks and any pending task older than the
    configured TTL is expired fail-closed before removal pressure can grow.
    ``running`` rows found at open time are failed as ``TASK_INTERRUPTED``
    rather than silently restarted.
    """

    def __init__(
        self,
        path: str,
        *,
        model_profile: PortfolioAnalyticsModelProfileV1,
        allowed_source_modes: tuple[str, ...] | list[str],
        max_concurrent_tasks: int = 4,
        max_concurrent_workers: int = 4,
        execution_timeout_seconds: int | float = 30,
        pending_ttl_seconds: int = 900,
        clock: Callable[[], int] = _now_ns,
    ) -> None:
        if type(path) is not str or not path:
            raise AnalysisTaskError("INVALID_STORE_PATH")
        if type(model_profile) is not PortfolioAnalyticsModelProfileV1:
            raise AnalysisTaskError("INVALID_MODEL_PROFILE")
        if type(allowed_source_modes) not in (tuple, list) or not allowed_source_modes:
            raise AnalysisTaskError("INVALID_SOURCE_MODES")
        modes = tuple(allowed_source_modes)
        if any(
            type(mode) is not str or mode not in _SUPPORTED_SOURCE_MODES for mode in modes
        ):
            raise AnalysisTaskError("INVALID_SOURCE_MODES")
        if len(set(modes)) != len(modes):
            raise AnalysisTaskError("DUPLICATE_SOURCE_MODE")
        if type(max_concurrent_tasks) is not int or not 1 <= max_concurrent_tasks <= 64:
            raise AnalysisTaskError("INVALID_TASK_QUOTA")
        if type(max_concurrent_workers) is not int or not 1 <= max_concurrent_workers <= 64:
            raise AnalysisTaskError("INVALID_WORKER_QUOTA")
        if (
            type(execution_timeout_seconds) not in (int, float)
            or not 0 < execution_timeout_seconds <= 3_600
        ):
            raise AnalysisTaskError("INVALID_EXECUTION_TIMEOUT")
        if type(pending_ttl_seconds) is not int or not 1 <= pending_ttl_seconds <= 604_800:
            raise AnalysisTaskError("INVALID_TASK_TTL")
        if not callable(clock):
            raise AnalysisTaskError("INVALID_CLOCK")
        self._model_profile = model_profile
        self._allowed_source_modes = modes
        self._max_concurrent_tasks = max_concurrent_tasks
        self._max_concurrent_workers = max_concurrent_workers
        self._execution_timeout_ns = int(execution_timeout_seconds * 1_000_000_000)
        if self._execution_timeout_ns < 1:
            raise AnalysisTaskError("INVALID_EXECUTION_TIMEOUT")
        self._pending_ttl_ns = pending_ttl_seconds * 1_000_000_000
        self._clock = clock
        self._shutdown_callback: Callable[[], None] | None = None
        self._closed = False
        # Validate the injected clock before any durable state is touched.
        opened_ns = self.now_ns()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._db:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS analysis_inputs ("
                "scope_json TEXT NOT NULL, "
                "input_snapshot_id TEXT NOT NULL, "
                "source_mode TEXT NOT NULL, "
                "input_sha256 TEXT NOT NULL, "
                "facts_json TEXT NOT NULL, "
                "created_ns INTEGER NOT NULL, "
                "PRIMARY KEY (scope_json, input_snapshot_id))"
            )
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS analysis_tasks ("
                "scope_json TEXT NOT NULL, "
                "task_ref TEXT NOT NULL, "
                "owner_principal TEXT NOT NULL, "
                "input_snapshot_id TEXT NOT NULL, "
                "input_sha256 TEXT NOT NULL, "
                "request_json TEXT NOT NULL, "
                "state TEXT NOT NULL, "
                "detail_code TEXT, "
                "result_json TEXT, "
                "created_ns INTEGER NOT NULL, "
                "state_ns INTEGER NOT NULL, "
                "running_token TEXT, "
                "PRIMARY KEY (scope_json, task_ref))"
            )
            task_columns = {
                row[1]
                for row in self._db.execute("PRAGMA table_info(analysis_tasks)")
            }
            if "running_token" not in task_columns:
                self._db.execute(
                    "ALTER TABLE analysis_tasks ADD COLUMN running_token TEXT"
                )
            # Fail closed on restart: a task claimed by a previous process may
            # have produced partial external effects, so it is never silently
            # re-executed.
            self._db.execute(
                "UPDATE analysis_tasks SET state='failed', detail_code='TASK_INTERRUPTED', "
                "state_ns=?, running_token=NULL WHERE state='running'",
                (opened_ns,),
            )

    @property
    def model_profile(self) -> PortfolioAnalyticsModelProfileV1:
        return self._model_profile

    @property
    def model_profile_ref(self) -> str:
        return self._model_profile.model_profile_ref

    @property
    def allowed_source_modes(self) -> tuple[str, ...]:
        return self._allowed_source_modes

    @property
    def max_concurrent_tasks(self) -> int:
        return self._max_concurrent_tasks

    @property
    def max_concurrent_workers(self) -> int:
        """Global child-process cap, separate from each scope's submit quota."""

        return self._max_concurrent_workers

    @property
    def execution_timeout_ns(self) -> int:
        return self._execution_timeout_ns

    def _bind_shutdown_callback(self, callback: Callable[[], None]) -> None:
        """Bind the one task-service cleanup to the Host-owned store close."""

        if self._closed:
            raise AnalysisTaskError("ANALYSIS_STORE_CLOSED")
        if not callable(callback):
            raise AnalysisTaskError("INVALID_SHUTDOWN_CALLBACK")
        if self._shutdown_callback is not None:
            raise AnalysisTaskError("ANALYSIS_SERVICE_ALREADY_BOUND")
        self._shutdown_callback = callback

    def close(self) -> None:
        if self._closed:
            return
        callback = self._shutdown_callback
        if callback is not None:
            # A cleanup failure leaves both the callback and DB open so the
            # owning Host can retry while it still retains the resource.
            callback()
        self._db.close()
        self._closed = True
        self._shutdown_callback = None

    def now_ns(self) -> int:
        value = self._clock()
        if type(value) is not int or value <= 0:
            raise AnalysisTaskError("INVALID_CLOCK")
        return value

    def upload_input(
        self,
        input_snapshot_id: str,
        *,
        facts: PortfolioAnalyticsFactsV1 | PortfolioAnalyticsFactsV2,
        scope_json: str,
    ) -> Mapping[str, object]:
        """Persist one immutable, validated offline fact cut for a scope."""

        input_snapshot_id = _task_reference(input_snapshot_id)
        if type(facts) is PortfolioAnalyticsFactsV1:
            facts_payload = _facts_payload(facts)
        elif type(facts) is PortfolioAnalyticsFactsV2:
            facts_payload = facts.to_payload()
        else:
            raise AnalysisTaskError("INVALID_INPUT")
        if facts.source_mode not in self._allowed_source_modes:
            # Offline research/imported/paper inputs only: the role setting
            # decides which of those modes are acceptable, and anything else
            # (including any live or account-bound feed) is rejected.
            raise AnalysisTaskError("SOURCE_MODE_NOT_ALLOWED")
        payload_json = _canonical_json(facts_payload).decode("ascii")
        if len(payload_json.encode("ascii")) > self._model_profile.max_input_bytes:
            raise AnalysisTaskError("INPUT_LIMIT_EXCEEDED")
        digest = hashlib.sha256(payload_json.encode("ascii")).hexdigest()
        now_ns = self.now_ns()
        with self._db:
            row = self._db.execute(
                "SELECT * FROM analysis_inputs WHERE scope_json=? AND input_snapshot_id=?",
                (scope_json, input_snapshot_id),
            ).fetchone()
            if row is not None:
                if row["input_sha256"] != digest:
                    raise AnalysisTaskError("INPUT_ALREADY_COMPLETE")
                return self._input_payload(row)
            self._db.execute(
                "INSERT INTO analysis_inputs (scope_json, input_snapshot_id, source_mode, "
                "input_sha256, facts_json, created_ns) VALUES (?,?,?,?,?,?)",
                (scope_json, input_snapshot_id, facts.source_mode, digest, payload_json, now_ns),
            )
        return {
            "input_snapshot_id": input_snapshot_id,
            "input_sha256": digest,
            "source_mode": facts.source_mode,
            "created_ns": now_ns,
        }

    def submit_task(
        self,
        task_ref: str,
        input_snapshot_id: str,
        *,
        request: PortfolioAnalyticsRequestV1 | PortfolioAnalyticsRequestV2,
        scope_json: str,
        principal_ref: str,
    ) -> Mapping[str, object]:
        """Create one pending analysis task, or return an identical re-submit.

        A same-reference submit with exactly the same input and request is the
        idempotent re-issue of one task; any other reuse of the reference is a
        conflict. Non-terminal tasks count against the per-scope quota.
        """

        task_ref = _task_reference(task_ref)
        input_snapshot_id = _task_reference(input_snapshot_id)
        if type(request) is PortfolioAnalyticsRequestV1:
            request_payload: dict[str, object] = {
                "membership_version": request.membership_version,
                "period_end_date_utc": request.period_end_date_utc.isoformat(),
                "period_start_date_utc": request.period_start_date_utc.isoformat(),
                "portfolio_ref": request.portfolio_ref,
                "reporting_currency": request.reporting_currency,
                "version": 1,
            }
        elif type(request) is PortfolioAnalyticsRequestV2:
            request_payload = request.to_payload()
        else:
            raise AnalysisTaskError("INVALID_REQUEST")
        if not _valid_wire_text(principal_ref):
            raise AnalysisTaskError("INVALID_REQUEST")
        request_json = _canonical_json(request_payload).decode("ascii")
        now_ns = self.now_ns()
        with self._db:
            row = self._db.execute(
                "SELECT * FROM analysis_tasks WHERE scope_json=? AND task_ref=?",
                (scope_json, task_ref),
            ).fetchone()
            if row is not None:
                if (
                    row["input_snapshot_id"] == input_snapshot_id
                    and row["request_json"] == request_json
                ):
                    return self._task_payload(row)
                raise AnalysisTaskError("TASK_REF_CONFLICT")
            input_row = self._db.execute(
                "SELECT * FROM analysis_inputs WHERE scope_json=? AND input_snapshot_id=?",
                (scope_json, input_snapshot_id),
            ).fetchone()
            if input_row is None:
                raise AnalysisTaskError("INPUT_NOT_FOUND")
            active = self._db.execute(
                "SELECT COUNT(*) FROM analysis_tasks WHERE scope_json=? "
                "AND state IN ('pending','running')",
                (scope_json,),
            ).fetchone()[0]
            if active >= self._max_concurrent_tasks:
                raise AnalysisTaskError("TASK_QUOTA_EXCEEDED")
            self._db.execute(
                "INSERT INTO analysis_tasks (scope_json, task_ref, owner_principal, "
                "input_snapshot_id, input_sha256, request_json, state, detail_code, "
                "result_json, created_ns, state_ns) VALUES (?,?,?,?,?,?,'pending',NULL,NULL,?,?)",
                (
                    scope_json,
                    task_ref,
                    principal_ref,
                    input_snapshot_id,
                    input_row["input_sha256"],
                    request_json,
                    now_ns,
                    now_ns,
                ),
            )
        return {
            "task_ref": task_ref,
            "state": "pending",
            "input_snapshot_id": input_snapshot_id,
            "input_sha256": input_row["input_sha256"],
            "created_ns": now_ns,
            "state_ns": now_ns,
            "detail_code": None,
            "result": None,
        }

    def query_task(self, task_ref: str, *, scope_json: str) -> Mapping[str, object]:
        """Return one scope-owned task projection; reads never mutate state."""

        task_ref = _task_reference(task_ref)
        row = self._db.execute(
            "SELECT * FROM analysis_tasks WHERE scope_json=? AND task_ref=?",
            (scope_json, task_ref),
        ).fetchone()
        if row is None:
            raise AnalysisTaskError("TASK_NOT_FOUND")
        return self._task_payload(row)

    def _task_record(self, task_ref: str, *, scope_json: str) -> Mapping[str, object]:
        """Return the private execution fields needed only by the adapter."""

        task_ref = _task_reference(task_ref)
        row = self._db.execute(
            "SELECT * FROM analysis_tasks WHERE scope_json=? AND task_ref=?",
            (scope_json, task_ref),
        ).fetchone()
        if row is None:
            raise AnalysisTaskError("TASK_NOT_FOUND")
        return {
            "request_json": row["request_json"],
            "running_token": row["running_token"],
            "scope_json": row["scope_json"],
            "state": row["state"],
            "task_ref": row["task_ref"],
        }

    def cancel_task(self, task_ref: str, *, scope_json: str) -> Mapping[str, object]:
        """Cancel a pending task; running work needs adapter cleanup first.

        Terminal states are fixed: a finished, failed, or expired task can
        never be turned into a cancelled one.
        """

        task_ref = _task_reference(task_ref)
        now_ns = self.now_ns()
        with self._db:
            row = self._db.execute(
                "SELECT * FROM analysis_tasks WHERE scope_json=? AND task_ref=?",
                (scope_json, task_ref),
            ).fetchone()
            if row is None:
                raise AnalysisTaskError("TASK_NOT_FOUND")
            state = row["state"]
            if state == "cancelled":
                return self._task_payload(row)
            if state in _TERMINAL_STATES:
                raise AnalysisTaskError("TASK_TERMINAL")
            if state == "running":
                raise AnalysisTaskError("TASK_CLEANUP_REQUIRED")
            self._db.execute(
                "UPDATE analysis_tasks SET state='cancelled', detail_code=NULL, "
                "result_json=NULL, state_ns=?, running_token=NULL "
                "WHERE scope_json=? AND task_ref=? AND state='pending'",
                (now_ns, scope_json, task_ref),
            )
        return {
            "task_ref": task_ref,
            "state": "cancelled",
            "input_snapshot_id": row["input_snapshot_id"],
            "input_sha256": row["input_sha256"],
            "created_ns": row["created_ns"],
            "state_ns": now_ns,
            "detail_code": None,
            "result": None,
        }

    def _cancel_running_task(
        self,
        task_ref: str,
        *,
        scope_json: str,
        running_token: str,
    ) -> Mapping[str, object]:
        """CAS-cancel one running row after the adapter has reaped its worker."""

        task_ref = _task_reference(task_ref)
        if type(running_token) is not str or re.fullmatch(r"[0-9a-f]{32}", running_token) is None:
            raise AnalysisTaskError("TASK_STATE_INVALID")
        now_ns = self.now_ns()
        with self._db:
            cursor = self._db.execute(
                "UPDATE analysis_tasks SET state='cancelled', detail_code=NULL, "
                "result_json=NULL, state_ns=?, running_token=NULL "
                "WHERE scope_json=? AND task_ref=? AND state='running' AND running_token=?",
                (now_ns, scope_json, task_ref, running_token),
            )
        if cursor.rowcount != 1:
            raise AnalysisTaskError("TASK_STATE_INVALID")
        return self.query_task(task_ref, scope_json=scope_json)

    def sweep_expired(self, now_ns: int) -> int:
        """Expire every pending task older than the TTL; returns the count."""

        threshold = now_ns - self._pending_ttl_ns
        with self._db:
            cursor = self._db.execute(
                "UPDATE analysis_tasks SET state='expired', detail_code='TASK_EXPIRED', "
                "state_ns=?, running_token=NULL WHERE state='pending' AND created_ns <= ?",
                (now_ns, threshold),
            )
        return cursor.rowcount

    def next_executable_task(
        self,
        *,
        exclude: frozenset[tuple[str, str]] = frozenset(),
    ) -> Mapping[str, object] | None:
        """Return the single oldest runnable task, preferring claimed work."""

        cursor = self._db.execute(
            "SELECT * FROM analysis_tasks WHERE state IN ('pending','running') "
            "ORDER BY CASE state WHEN 'running' THEN 0 ELSE 1 END, created_ns, rowid"
        )
        row = next(
            (
                candidate
                for candidate in cursor
                if (candidate["scope_json"], candidate["task_ref"]) not in exclude
            ),
            None,
        )
        if row is None:
            return None
        return {
            "scope_json": row["scope_json"],
            "task_ref": row["task_ref"],
            "state": row["state"],
            "input_snapshot_id": row["input_snapshot_id"],
            "input_sha256": row["input_sha256"],
            "owner_principal": row["owner_principal"],
            "request_json": row["request_json"],
            "running_token": row["running_token"],
        }

    def load_input(self, scope_json: str, input_snapshot_id: str) -> Mapping[str, object]:
        """Return one stored input row for execution."""

        row = self._db.execute(
            "SELECT * FROM analysis_inputs WHERE scope_json=? AND input_snapshot_id=?",
            (scope_json, input_snapshot_id),
        ).fetchone()
        if row is None:
            raise AnalysisTaskError("INPUT_NOT_FOUND")
        return {
            "input_snapshot_id": row["input_snapshot_id"],
            "source_mode": row["source_mode"],
            "input_sha256": row["input_sha256"],
            "facts_json": row["facts_json"],
        }

    def mark_running(
        self,
        scope_json: str,
        task_ref: str,
        now_ns: int,
        *,
        running_token: str,
    ) -> None:
        """Claim one pending task for execution."""

        task_ref = _task_reference(task_ref)
        if type(running_token) is not str or re.fullmatch(r"[0-9a-f]{32}", running_token) is None:
            raise AnalysisTaskError("TASK_STATE_INVALID")
        with self._db:
            cursor = self._db.execute(
                "UPDATE analysis_tasks SET state='running', state_ns=?, running_token=? "
                "WHERE scope_json=? AND task_ref=? AND state='pending'",
                (now_ns, running_token, scope_json, task_ref),
            )
        if cursor.rowcount != 1:
            raise AnalysisTaskError("TASK_STATE_INVALID")

    def finish_task(
        self,
        scope_json: str,
        task_ref: str,
        *,
        state: str,
        detail_code: str | None,
        result_json: str | None,
        now_ns: int,
        running_token: str,
    ) -> None:
        """Store one claimed task's terminal outcome."""

        if state not in {"succeeded", "unavailable", "failed"}:
            raise AnalysisTaskError("TASK_STATE_INVALID")
        task_ref = _task_reference(task_ref)
        if type(running_token) is not str or re.fullmatch(r"[0-9a-f]{32}", running_token) is None:
            raise AnalysisTaskError("TASK_STATE_INVALID")
        with self._db:
            cursor = self._db.execute(
                "UPDATE analysis_tasks SET state=?, detail_code=?, result_json=?, state_ns=?, "
                "running_token=NULL WHERE scope_json=? AND task_ref=? "
                "AND state='running' AND running_token=?",
                (state, detail_code, result_json, now_ns, scope_json, task_ref, running_token),
            )
        if cursor.rowcount != 1:
            raise AnalysisTaskError("TASK_STATE_INVALID")

    @staticmethod
    def _input_payload(row: sqlite3.Row) -> Mapping[str, object]:
        return {
            "input_snapshot_id": row["input_snapshot_id"],
            "input_sha256": row["input_sha256"],
            "source_mode": row["source_mode"],
            "created_ns": row["created_ns"],
        }

    @staticmethod
    def _task_payload(row: sqlite3.Row) -> Mapping[str, object]:
        result_json = row["result_json"]
        return {
            "task_ref": row["task_ref"],
            "state": row["state"],
            "input_snapshot_id": row["input_snapshot_id"],
            "input_sha256": row["input_sha256"],
            "created_ns": row["created_ns"],
            "state_ns": row["state_ns"],
            "detail_code": row["detail_code"],
            "result": None if result_json is None else json.loads(result_json),
        }


class _StoredFactsSource:
    """Package the one stored fact cut as the primitive's trusted source."""

    def __init__(self, facts: PortfolioAnalyticsFactsV1) -> None:
        self._facts = facts

    def read_portfolio_facts(
        self, principal_ref: str, request: PortfolioAnalyticsRequestV1
    ) -> PortfolioAnalyticsFactsV1:
        return self._facts


def _v1_report_input_sha256(
    facts: PortfolioAnalyticsFactsV1,
    request: PortfolioAnalyticsRequestV1,
    *,
    principal_ref: str,
    model_profile: PortfolioAnalyticsModelProfileV1,
    allowed_source_modes: tuple[str, ...],
) -> str:
    """Bind the V1 report digest to every trusted analysis input."""

    service = PortfolioAnalyticsService(
        _StoredFactsSource(facts),
        model_profile,
        allowed_source_modes=allowed_source_modes,
    )
    canonical_input = _canonical_json(
        {
            "facts": _facts_payload(facts),
            "model_profile": service._profile_payload(),
            "principal_ref": principal_ref,
            "request": _request_payload(request),
        }
    )
    return hashlib.sha256(canonical_input).hexdigest()


@dataclass(slots=True)
class _TaskWorker:
    """One host-owned analytics worker and its bounded control/result channel."""

    scope_json: str
    task_ref: str
    running_token: str
    input_sha256: str
    process: object | None
    receive_connection: object
    child_connection: object | None
    process_started: bool
    startup_deadline_ns: int
    launched_monotonic_ns: int
    started_monotonic_ns: int | None = None
    execution_deadline_ns: int | None = None
    result_envelope: dict[str, object] | None = None
    frame_error: str | None = None
    intent: tuple[str, str | None, str | None] | None = None
    exit_code: int | None = None
    process_closed: bool = False
    cleanup_complete: bool = False
    report_input_sha256: str | None = None
    period_too_long: bool = False


def _portfolio_analytics_worker_entry(
    facts_json: str,
    request_json: str,
    input_sha256: str,
    running_token: str,
    send_connection: object,
    model_profile_json: str,
    allowed_source_modes_json: str,
    principal_ref: str,
) -> None:
    """Compute one V1/V2 task from immutable strings; this process never writes DB."""

    connection = send_connection
    try:
        started_ns = time.monotonic_ns()
        connection.send_bytes(  # type: ignore[attr-defined]
            _canonical_json(
                {
                    "kind": "started",
                    "running_token": running_token,
                    "started_monotonic_ns": started_ns,
                }
            )
        )
        state = "failed"
        detail_code: str | None = "TASK_EXECUTION_FAILED"
        result_json: str | None = None
        try:
            facts = _parse_facts_payload(json.loads(facts_json))
            request = _parse_request_payload(json.loads(request_json))
            if type(facts) is PortfolioAnalyticsFactsV1 and type(request) is PortfolioAnalyticsRequestV1:
                profile_payload = json.loads(model_profile_json)
                modes_payload = json.loads(allowed_source_modes_json)
                if (
                    type(profile_payload) is not dict
                    or set(profile_payload)
                    != {
                        "max_fx_age_ns",
                        "max_input_bytes",
                        "max_mark_age_ns",
                        "max_period_days",
                        "model_profile_ref",
                    }
                    or type(modes_payload) is not list
                    or not modes_payload
                    or any(type(mode) is not str for mode in modes_payload)
                    or not _valid_wire_text(principal_ref)
                ):
                    raise AnalysisTaskError("SCHEMA_VERSION_MISMATCH")
                profile = PortfolioAnalyticsModelProfileV1(**profile_payload)
                report = PortfolioAnalyticsService(
                    _StoredFactsSource(facts),
                    profile,
                    allowed_source_modes=tuple(modes_payload),
                ).analyze_snapshot_v1(request, principal_ref=principal_ref)
                payload = report.to_payload()
                if report.status == "AVAILABLE":
                    state, detail_code = "succeeded", None
                else:
                    state = "unavailable"
                    detail_code = report.reason_codes[0] if report.reason_codes else "UNAVAILABLE"
            elif type(facts) is PortfolioAnalyticsFactsV2 and type(request) is PortfolioAnalyticsRequestV2:
                report = PortfolioAnalyticsServiceV2().analyze_snapshot_v2(
                    facts,
                    request,
                    input_sha256=input_sha256,
                )
                payload = report.to_payload()
                if report.status == "AVAILABLE":
                    state, detail_code = "succeeded", None
                else:
                    state = "unavailable"
                    detail_code = next(
                        (
                            item.reason_code
                            for item in (
                                report.spot_exposure,
                                report.max_drawdown,
                                report.historical_var_es,
                                report.stress_scenario,
                            )
                            if item.status == "unavailable"
                        ),
                        "UNAVAILABLE",
                    )
            else:
                raise AnalysisTaskError("SCHEMA_VERSION_MISMATCH")
            encoded_result = _canonical_json(payload)
            if len(encoded_result) > _MAX_WORKER_FRAME_BYTES // 2:
                raise AnalysisTaskError("TASK_RESULT_TOO_LARGE")
            result_json = encoded_result.decode("ascii")
        except AnalysisTaskError as error:
            state, detail_code, result_json = "failed", error.code, None
        except PortfolioAnalyticsError as error:
            state, detail_code, result_json = "failed", error.code, None
        except Exception:
            state, detail_code, result_json = "failed", "TASK_EXECUTION_FAILED", None

        envelope = {
            "completed_monotonic_ns": time.monotonic_ns(),
            "detail_code": detail_code,
            "kind": "result",
            "result_json": result_json,
            "running_token": running_token,
            "state": state,
        }
        encoded_envelope = _canonical_json(envelope)
        if len(encoded_envelope) > _MAX_WORKER_FRAME_BYTES:
            encoded_envelope = _canonical_json(
                {
                    "completed_monotonic_ns": time.monotonic_ns(),
                    "detail_code": "TASK_RESULT_TOO_LARGE",
                    "kind": "result",
                    "result_json": None,
                    "running_token": running_token,
                    "state": "failed",
                }
            )
        connection.send_bytes(encoded_envelope)  # type: ignore[attr-defined]
    except BaseException:
        # An untrusted/raw child traceback is never sent over the service API.
        return
    finally:
        try:
            connection.close()  # type: ignore[attr-defined]
        except BaseException:
            pass


class PortfolioAnalyticsTaskService:
    """Serve exactly the four ``service.risk_analysis`` task actions.

    This is a portfolio task control plane over offline fact inputs, not an
    order/account/provider interface. Each action receives the
    already-authenticated principal and the exact registered scope from the
    SDK registry; the adapter additionally requires a run-free portfolio
    scope and treats it as the task ownership identity. Business rejections
    are returned in-band as ``ok: false`` codes so no side effect is implied.
    ``maintain`` is the host-driven executor hook and never raises.
    """

    SUPPORTED_OPERATIONS: Final[frozenset[str]] = frozenset(
        {"analysis.submit", "analysis.query", "analysis.cancel", "analysis.input_upload"}
    )

    _UPLOAD_ARGUMENTS: Final[frozenset[str]] = frozenset({"input_snapshot_id", "facts"})
    _SUBMIT_ARGUMENTS: Final[frozenset[str]] = frozenset(
        {"task_ref", "input_snapshot_id", "request"}
    )
    _TASK_ARGUMENTS: Final[frozenset[str]] = frozenset({"task_ref"})

    def __init__(
        self,
        store: AnalysisTaskStore,
        *,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if type(store) is not AnalysisTaskStore:
            raise AnalysisTaskError("INVALID_ANALYSIS_TASK_STORE")
        if not callable(monotonic_ns):
            raise AnalysisTaskError("INVALID_MONOTONIC_CLOCK")
        self._store = store
        self._monotonic_ns = monotonic_ns
        self._closed = False
        self._last_step_ns = 0
        self._lock = threading.RLock()
        self._workers: dict[tuple[str, str], _TaskWorker] = {}
        self._store._bind_shutdown_callback(self._close_from_store)

    @property
    def supported_operations(self) -> frozenset[str]:
        return PortfolioAnalyticsTaskService.SUPPORTED_OPERATIONS

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._stop_all_workers()
            self._closed = True

    def _close_from_store(self) -> None:
        """Run worker cleanup before the resource owner closes SQLite."""

        self.close()

    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        scope: WireScope,
        arguments: Mapping[str, object],
    ) -> Mapping[str, object]:
        with self._lock:
            return self._handle_locked(
                operation,
                principal_ref=principal_ref,
                scope=scope,
                arguments=arguments,
            )

    def _handle_locked(
        self,
        operation: str,
        *,
        principal_ref: str,
        scope: WireScope,
        arguments: Mapping[str, object],
    ) -> Mapping[str, object]:
        try:
            if self._closed:
                raise AnalysisTaskError("CLOSED")
            if operation not in self.SUPPORTED_OPERATIONS:
                raise AnalysisTaskError("UNKNOWN_OPERATION")
            if not _valid_wire_text(principal_ref) or type(scope) is not WireScope:
                raise AnalysisTaskError("INVALID_REQUEST")
            if not isinstance(arguments, Mapping):
                raise AnalysisTaskError("INVALID_REQUEST")
            scope_json = _task_scope(scope)
            portfolio_ref = json.loads(scope_json)["portfolio_ref"]
            keys = set(arguments)
            if operation == "analysis.input_upload":
                if keys != self._UPLOAD_ARGUMENTS:
                    raise AnalysisTaskError("INVALID_REQUEST")
                facts = _parse_facts_payload(arguments["facts"])
                if facts.portfolio_ref != portfolio_ref:
                    raise AnalysisTaskError("INPUT_PORTFOLIO_MISMATCH")
                result = self._store.upload_input(
                    arguments["input_snapshot_id"],
                    facts=facts,
                    scope_json=scope_json,
                )
            elif operation == "analysis.submit":
                if keys != self._SUBMIT_ARGUMENTS:
                    raise AnalysisTaskError("INVALID_REQUEST")
                request = _parse_request_payload(arguments["request"])
                if request.portfolio_ref != portfolio_ref:
                    raise AnalysisTaskError("INPUT_PORTFOLIO_MISMATCH")
                result = self._store.submit_task(
                    arguments["task_ref"],
                    arguments["input_snapshot_id"],
                    request=request,
                    scope_json=scope_json,
                    principal_ref=principal_ref,
                )
            elif operation == "analysis.query":
                if keys != self._TASK_ARGUMENTS:
                    raise AnalysisTaskError("INVALID_REQUEST")
                result = self._store.query_task(
                    arguments["task_ref"], scope_json=scope_json
                )
            else:
                if keys != self._TASK_ARGUMENTS:
                    raise AnalysisTaskError("INVALID_REQUEST")
                result = self._cancel_task(
                    arguments["task_ref"], scope_json=scope_json
                )
        except AnalysisTaskError as error:
            return {"ok": False, "code": error.code, "result": {}}
        except sqlite3.Error:
            return {"ok": False, "code": "ANALYSIS_STORAGE_UNAVAILABLE", "result": {}}
        return {"ok": True, "code": "OK", "result": dict(result)}

    def maintain(self, active_registration_ids: frozenset[str]) -> Mapping[str, object]:
        """Advance task execution by at most one gated transition per call.

        The host invokes this hook on its owner thread outside request
        handling. Expiry sweeps run on every invocation; exactly one task
        state transition may pass per elapsed second of the injected store
        clock, so a frozen test clock yields a deterministic progression.
        """

        with self._lock:
            if self._closed:
                return {"ok": False, "code": "CLOSED", "result": {}}
            try:
                now_ns = self._store.now_ns()
                expired = self._store.sweep_expired(now_ns)
                advanced = self._poll_workers()
                if not advanced and now_ns - self._last_step_ns >= _EXECUTOR_GATE_NS:
                    excluded = set(self._workers)
                    while True:
                        task = self._store.next_executable_task(
                            exclude=frozenset(excluded)
                        )
                        if task is None:
                            break
                        key = (task["scope_json"], task["task_ref"])
                        request_version = self._request_version(task["request_json"])
                        if task["state"] == "running" and request_version in {1, 2}:
                            # No child may be silently reconstructed for a
                            # running token whose owner record is absent.
                            excluded.add(key)
                            continue
                        if (
                            task["state"] == "pending"
                            and request_version in {1, 2}
                            and len(self._workers) >= self._store.max_concurrent_workers
                        ):
                            # The per-scope submission quota continues to
                            # count this queued task; it does not consume a
                            # worker slot or acquire an execution deadline.
                            excluded.add(key)
                            continue
                        self._last_step_ns = now_ns
                        advanced = self._advance_task(task, now_ns)
                        break
            except AnalysisTaskError as error:
                return {"ok": False, "code": error.code, "result": {}}
            except sqlite3.Error:
                return {"ok": False, "code": "ANALYSIS_STORAGE_UNAVAILABLE", "result": {}}
            except Exception:
                return {"ok": False, "code": "ANALYSIS_EXECUTION_FAULT", "result": {}}
            return {
                "ok": True,
                "code": "OK",
                "result": {"expired": expired, "advanced": advanced},
            }

    def _advance_task(self, task: Mapping[str, object], now_ns: int) -> bool:
        scope_json = task["scope_json"]
        task_ref = task["task_ref"]
        if task["state"] == "pending":
            running_token = uuid.uuid4().hex
            self._store.mark_running(
                scope_json, task_ref, now_ns, running_token=running_token
            )
            task = {**task, "running_token": running_token, "state": "running"}
            if self._request_version(task["request_json"]) in {1, 2}:
                self._start_worker(task)
            else:
                self._store.finish_task(
                    scope_json,
                    task_ref,
                    state="failed",
                    detail_code="SCHEMA_VERSION_MISMATCH",
                    result_json=None,
                    now_ns=now_ns,
                    running_token=running_token,
                )
            return True

        if self._request_version(task["request_json"]) in {1, 2}:
            # A task that is running without a retained worker is never
            # restarted or assigned a new generation. Leave its token-bound
            # durable row untouched so cleanup uncertainty remains visible.
            return False
        return False

    @staticmethod
    def _request_version(request_json: object) -> int | None:
        if type(request_json) is not str:
            return None
        try:
            value = json.loads(request_json)
        except (TypeError, ValueError):
            return None
        if type(value) is not dict or type(value.get("version")) is not int:
            return None
        return value["version"]

    def _start_worker(self, task: Mapping[str, object]) -> None:
        scope_json = task["scope_json"]
        task_ref = task["task_ref"]
        running_token = task["running_token"]
        state = "failed"
        detail_code = "TASK_EXECUTION_FAILED"
        report_input_sha256: str | None = None
        period_too_long = False
        try:
            stored = self._store.load_input(scope_json, task["input_snapshot_id"])
            if stored["input_sha256"] != task["input_sha256"]:
                raise AnalysisTaskError("INPUT_DIGEST_MISMATCH")
            facts_json = stored["facts_json"]
            if type(facts_json) is not str:
                raise AnalysisTaskError("INVALID_INPUT")
            request = _parse_request_payload(json.loads(task["request_json"]))
            facts = _parse_facts_payload(json.loads(facts_json))
            if type(request) is PortfolioAnalyticsRequestV1 and type(facts) is not PortfolioAnalyticsFactsV1:
                raise AnalysisTaskError("SCHEMA_VERSION_MISMATCH")
            if type(request) is PortfolioAnalyticsRequestV2 and type(facts) is not PortfolioAnalyticsFactsV2:
                raise AnalysisTaskError("SCHEMA_VERSION_MISMATCH")
            if type(request) not in (PortfolioAnalyticsRequestV1, PortfolioAnalyticsRequestV2):
                raise AnalysisTaskError("SCHEMA_VERSION_MISMATCH")
            if type(request) is PortfolioAnalyticsRequestV1:
                period_too_long = (
                    request.period_end_date_utc - request.period_start_date_utc
                ).days > self._store.model_profile.max_period_days
                if not period_too_long:
                    report_input_sha256 = _v1_report_input_sha256(
                        facts,
                        request,
                        principal_ref=task["owner_principal"],
                        model_profile=self._store.model_profile,
                        allowed_source_modes=self._store.allowed_source_modes,
                    )
        except AnalysisTaskError as error:
            detail_code = error.code
            self._store.finish_task(
                scope_json,
                task_ref,
                state=state,
                detail_code=detail_code,
                result_json=None,
                now_ns=self._store.now_ns(),
                running_token=running_token,
            )
            return
        except PortfolioAnalyticsError as error:
            detail_code = error.code
            self._store.finish_task(
                scope_json,
                task_ref,
                state=state,
                detail_code=detail_code,
                result_json=None,
                now_ns=self._store.now_ns(),
                running_token=running_token,
            )
            return
        except Exception:
            self._store.finish_task(
                scope_json,
                task_ref,
                state=state,
                detail_code=detail_code,
                result_json=None,
                now_ns=self._store.now_ns(),
                running_token=running_token,
            )
            return

        try:
            context = multiprocessing.get_context("spawn")
            launched_ns = self._monotonic_ns()
            receive_connection, child_connection = context.Pipe(duplex=False)
        except Exception:
            self._store.finish_task(
                scope_json,
                task_ref,
                state="failed",
                detail_code="TASK_WORKER_START_FAILED",
                result_json=None,
                now_ns=self._store.now_ns(),
                running_token=running_token,
            )
            return
        key = (scope_json, task_ref)
        worker = _TaskWorker(
            scope_json=scope_json,
            task_ref=task_ref,
            running_token=running_token,
            input_sha256=stored["input_sha256"],
            report_input_sha256=report_input_sha256,
            period_too_long=period_too_long,
            process=None,
            receive_connection=receive_connection,
            child_connection=child_connection,
            process_started=False,
            startup_deadline_ns=launched_ns + _WORKER_STARTUP_TIMEOUT_NS,
            launched_monotonic_ns=launched_ns,
        )
        self._workers[key] = worker
        try:
            process = context.Process(
                target=_portfolio_analytics_worker_entry,
                args=(
                    facts_json,
                    task["request_json"],
                    stored["input_sha256"],
                    running_token,
                    child_connection,
                    _canonical_json(
                        {
                            "max_fx_age_ns": self._store.model_profile.max_fx_age_ns,
                            "max_input_bytes": self._store.model_profile.max_input_bytes,
                            "max_mark_age_ns": self._store.model_profile.max_mark_age_ns,
                            "max_period_days": self._store.model_profile.max_period_days,
                            "model_profile_ref": self._store.model_profile.model_profile_ref,
                        }
                    ).decode("ascii"),
                    _canonical_json(list(self._store.allowed_source_modes)).decode("ascii"),
                    task["owner_principal"],
                ),
            )
            worker.process = process
            process.daemon = True
            process.start()  # type: ignore[attr-defined]
            worker.process_started = True
            self._close_connection(worker, "child_connection")
        except Exception:
            # `start()` can fail after creating a child on some runtimes. Use
            # the process object only to establish/reap that exact child.
            process = worker.process
            if process is not None and (
                getattr(process, "pid", None) is not None
                or getattr(process, "_popen", None) is not None
            ):
                worker.process_started = True
            worker.intent = ("failed", "TASK_WORKER_START_FAILED", None)
            self._cleanup_worker(worker, force=True)
            if worker.cleanup_complete:
                self._finalize_worker(worker)

    def _poll_workers(self) -> bool:
        """Poll every retained worker; commit at most one terminal row per tick."""

        for worker in tuple(self._workers.values()):
            if worker.intent is not None:
                self._cleanup_worker(worker, force=True)
            else:
                self._read_worker_frames(worker)
                now_mono_ns = self._monotonic_ns()
                if worker.frame_error is not None:
                    code = (
                        "TASK_WORKER_START_TIMEOUT"
                        if worker.frame_error == "START_TIMEOUT"
                        else "TASK_WORKER_RESULT_INVALID"
                    )
                    worker.intent = ("failed", code, None)
                    self._cleanup_worker(worker, force=True)
                else:
                    alive = self._worker_is_alive(worker)
                    if alive:
                        if (
                            worker.execution_deadline_ns is None
                            and now_mono_ns >= worker.startup_deadline_ns
                        ):
                            worker.intent = ("failed", "TASK_WORKER_START_TIMEOUT", None)
                            self._cleanup_worker(worker, force=True)
                        elif (
                            worker.execution_deadline_ns is not None
                            and now_mono_ns >= worker.execution_deadline_ns
                        ):
                            worker.intent = ("failed", "TASK_EXECUTION_TIMEOUT", None)
                            self._cleanup_worker(worker, force=True)
                    else:
                        self._cleanup_worker(worker, force=False)
                        if worker.cleanup_complete:
                            self._set_result_intent(worker)

            if worker.cleanup_complete:
                if self._finalize_worker(worker):
                    return True
        return False

    def _read_worker_frames(self, worker: _TaskWorker) -> None:
        connection = worker.receive_connection
        if getattr(connection, "closed", True):
            return
        try:
            # Windows Connection.poll() can report ERROR_BROKEN_PIPE after a
            # child has sent its final frame and closed its writer.  Use the
            # public connection.wait readiness API; recv_bytes then provides
            # the normal EOF signal while preserving malformed/truncated-frame
            # errors as failures.
            while wait_for_connections([connection], timeout=0):
                raw = connection.recv_bytes(maxlength=_MAX_WORKER_FRAME_BYTES)  # type: ignore[attr-defined]
                frame = json.loads(raw.decode("ascii", errors="strict"))
                if type(frame) is not dict or _canonical_json(frame) != raw:
                    raise ValueError
                if frame.get("running_token") != worker.running_token:
                    raise ValueError
                if frame.get("kind") == "started":
                    if (
                        set(frame)
                        != {"kind", "running_token", "started_monotonic_ns"}
                        or worker.started_monotonic_ns is not None
                    ):
                        raise ValueError
                    started_ns = frame["started_monotonic_ns"]
                    if type(started_ns) is int and started_ns > worker.startup_deadline_ns:
                        worker.frame_error = "START_TIMEOUT"
                        return
                    if (
                        type(started_ns) is not int
                        or started_ns < worker.launched_monotonic_ns
                        or started_ns > time.monotonic_ns()
                    ):
                        raise ValueError
                    worker.started_monotonic_ns = started_ns
                    worker.execution_deadline_ns = (
                        started_ns + self._store.execution_timeout_ns
                    )
                elif frame.get("kind") == "result":
                    if (
                        set(frame)
                        != {
                            "completed_monotonic_ns",
                            "detail_code",
                            "kind",
                            "result_json",
                            "running_token",
                            "state",
                        }
                        or worker.started_monotonic_ns is None
                        or worker.result_envelope is not None
                    ):
                        raise ValueError
                    worker.result_envelope = frame
                else:
                    raise ValueError
        except EOFError:
            return
        except (
            OSError,
            UnicodeError,
            ValueError,
            TypeError,
            OverflowError,
            RecursionError,
        ):
            worker.frame_error = "INVALID_FRAME"

    def _set_result_intent(self, worker: _TaskWorker) -> None:
        if worker.intent is not None:
            return
        if worker.frame_error is not None:
            worker.intent = ("failed", "TASK_WORKER_RESULT_INVALID", None)
            return
        if worker.exit_code is None or worker.exit_code != 0:
            worker.intent = ("failed", "TASK_WORKER_EXITED", None)
            return
        envelope = worker.result_envelope
        if envelope is None or worker.execution_deadline_ns is None:
            worker.intent = ("failed", "TASK_WORKER_RESULT_MISSING", None)
            return
        completed_ns = envelope.get("completed_monotonic_ns")
        if (
            type(completed_ns) is not int
            or worker.started_monotonic_ns is None
            or completed_ns < worker.started_monotonic_ns
            or completed_ns > self._monotonic_ns()
        ):
            worker.intent = ("failed", "TASK_WORKER_RESULT_INVALID", None)
            return
        if completed_ns > worker.execution_deadline_ns:
            worker.intent = ("failed", "TASK_EXECUTION_TIMEOUT", None)
            return
        try:
            state, detail_code, result_json = self._validate_worker_result(worker, envelope)
        except AnalysisTaskError as error:
            worker.intent = ("failed", error.code, None)
            return
        worker.intent = (state, detail_code, result_json)

    def _validate_worker_result(
        self,
        worker: _TaskWorker,
        envelope: Mapping[str, object],
    ) -> tuple[str, str | None, str | None]:
        state = envelope.get("state")
        detail_code = envelope.get("detail_code")
        result_json = envelope.get("result_json")
        if type(state) is not str:
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
        if state == "failed":
            if (
                type(detail_code) is not str
                or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", detail_code) is None
                or result_json is not None
            ):
                raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
            return "failed", detail_code, None
        if state not in {"succeeded", "unavailable"}:
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
        if (
            (state == "succeeded" and detail_code is not None)
            or (
                state == "unavailable"
                and (
                    type(detail_code) is not str
                    or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", detail_code) is None
                )
            )
            or type(result_json) is not str
        ):
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
        try:
            encoded = result_json.encode("ascii", errors="strict")
        except UnicodeError:
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID") from None
        if len(encoded) > _MAX_WORKER_FRAME_BYTES // 2:
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
        try:
            report = json.loads(result_json)
        except (TypeError, ValueError, OverflowError, RecursionError):
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID") from None
        if type(report) is not dict:
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
        try:
            canonical_report = _canonical_json(report)
        except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID") from None
        if canonical_report != encoded:
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
        request_json = self._store_request_json(worker.scope_json, worker.task_ref)
        try:
            request = _parse_request_payload(json.loads(request_json))
        except (AnalysisTaskError, PortfolioAnalyticsError):
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID") from None
        if type(request) is PortfolioAnalyticsRequestV1:
            expected_keys = {
                "beginning",
                "calculation_ref",
                "decimal_policy",
                "ending",
                "external_cashflow_net",
                "facts_snapshot_ref",
                "flow_source",
                "flow_weight_policy",
                "fx_policy",
                "input_sha256",
                "membership",
                "model_profile_ref",
                "portfolio_ref",
                "reason_codes",
                "reporting_currency",
                "return_method",
                "return_ratio",
                "source",
                "status",
                "version",
            }
            beginning = report.get("beginning")
            ending = report.get("ending")
            membership = report.get("membership")
            flow_source = report.get("flow_source")
            source = report.get("source")
            reason_codes = report.get("reason_codes")
            report_input_sha256 = report.get("input_sha256")
            if (
                type(beginning) is not dict
                or type(ending) is not dict
                or type(membership) is not dict
                or type(flow_source) is not dict
                or type(source) is not dict
                or type(reason_codes) is not list
                or any(type(item) is not str for item in reason_codes)
            ):
                raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
            early_period_unavailable = worker.period_too_long
            if early_period_unavailable:
                report_input_valid = (
                    state == "unavailable"
                    and detail_code == "PERIOD_TOO_LONG"
                    and reason_codes == ["PERIOD_TOO_LONG"]
                    and report_input_sha256 is None
                    and membership.get("content_sha256") is None
                    and flow_source
                    == {
                        "end_cursor": None,
                        "source_ref": None,
                        "source_version": None,
                        "start_cursor": None,
                    }
                    and source
                    == {
                        "generation": None,
                        "mode": None,
                        "source_ref": None,
                        "source_version": None,
                    }
                    and report.get("facts_snapshot_ref") is None
                    and all(
                        beginning.get(name) is None
                        for name in ("as_of_ns", "nav", "snapshot_ref", "source_cursor")
                    )
                    and all(
                        ending.get(name) is None
                        for name in ("as_of_ns", "nav", "snapshot_ref", "source_cursor")
                    )
                    and beginning.get("native_values") == []
                    and ending.get("native_values") == []
                    and report.get("external_cashflow_net") is None
                    and report.get("return_ratio") is None
                )
            else:
                report_input_valid = (
                    type(report_input_sha256) is str
                    and re.fullmatch(r"[0-9a-f]{64}", report_input_sha256) is not None
                    and report_input_sha256 == worker.report_input_sha256
                    and (
                        (state == "succeeded" and reason_codes == [] and detail_code is None)
                        or (
                            state == "unavailable"
                            and bool(reason_codes)
                            and reason_codes == sorted(set(reason_codes))
                            and detail_code == reason_codes[0]
                        )
                    )
                    and type(membership.get("content_sha256")) is str
                    and re.fullmatch(
                        r"[0-9a-f]{64}", membership.get("content_sha256", "")
                    )
                    is not None
                    and all(
                        type(flow_source.get(name)) is str
                        for name in ("end_cursor", "source_ref", "source_version", "start_cursor")
                    )
                    and all(
                        type(source.get(name)) is str
                        for name in ("generation", "mode", "source_ref", "source_version")
                    )
                    and report.get("facts_snapshot_ref") is not None
                )
            valid_v1_shape = (
                type(beginning) is dict
                and set(beginning)
                == {"as_of_ns", "date_utc", "nav", "native_values", "snapshot_ref", "source_cursor"}
                and type(ending) is dict
                and set(ending)
                == {"as_of_ns", "date_utc", "nav", "native_values", "snapshot_ref", "source_cursor"}
                and type(membership) is dict
                and set(membership) == {"content_sha256", "version"}
                and type(flow_source) is dict
                and set(flow_source) == {"end_cursor", "source_ref", "source_version", "start_cursor"}
                and type(source) is dict
                and set(source) == {"generation", "mode", "source_ref", "source_version"}
                and type(report.get("reason_codes")) is list
                and all(type(item) is str for item in report["reason_codes"])
                and type(report.get("version")) is int
                and report.get("version") == 1
                and report_input_valid
                and report.get("calculation_ref") == "spot_nav_modified_dietz_v1"
                and report.get("decimal_policy")
                == (
                    "PRECISION_50_EMIN_NEG999999_EMAX_999999_HALF_EVEN_TRAPS_INVALID_"
                    "DIVISION_OVERFLOW_QUANTIZE_18_CANONICAL_STRING_V1"
                )
                and report.get("flow_weight_policy") == "UTC_CALENDAR_DAY_END_V1"
                and report.get("fx_policy") == "IDENTITY_OR_DIRECT_BASE_TO_REPORTING_V1"
                and report.get("model_profile_ref") == self._store.model_profile_ref
                and report.get("status")
                == ("AVAILABLE" if state == "succeeded" else "UNAVAILABLE")
                and report.get("portfolio_ref") == request.portfolio_ref
                and report.get("reporting_currency") == request.reporting_currency
                and report.get("return_method") == "MODIFIED_DIETZ_ESTIMATE_V1"
                and beginning.get("date_utc") == request.period_start_date_utc.isoformat()
                and ending.get("date_utc") == request.period_end_date_utc.isoformat()
                and type(membership.get("version")) is int
                and membership.get("version") == request.membership_version
                and (
                    source.get("mode") in self._store.allowed_source_modes
                    if not early_period_unavailable
                    else source.get("mode") is None
                )
            )
            if set(report) != expected_keys or not valid_v1_shape:
                raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
            return state, detail_code, result_json

        if type(request) is not PortfolioAnalyticsRequestV2:
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
        expected_keys = {
            "calculation_ref",
            "decimal_serialization_ref",
            "facts_snapshot_ref",
            "input_sha256",
            "metrics",
            "portfolio_ref",
            "provenance",
            "report_sha256",
            "reporting_currency",
            "request_sha256",
            "schema_ref",
            "serialization_ref",
            "status",
            "version",
        }
        if (
            set(report) != expected_keys
            or report.get("schema_ref") != "portfolio_analytics_v2"
            or report.get("version") != 2
            or report.get("input_sha256") != worker.input_sha256
            or report.get("status")
            != ("AVAILABLE" if state == "succeeded" else "UNAVAILABLE")
            or type(report.get("request_sha256")) is not str
        ):
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
        try:
            request_digest = hashlib.sha256(
                request_json.encode("ascii", errors="strict")
            ).hexdigest()
            unsigned = dict(report)
            del unsigned["report_sha256"]
            report_digest = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
        except AnalysisTaskError:
            raise
        except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID") from None
        if request_digest != report.get("request_sha256"):
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
        digest = report.get("report_sha256")
        if type(digest) is not str or report_digest != digest:
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
        return state, detail_code, result_json

    def _store_request_json(self, scope_json: str, task_ref: str) -> str:
        record = self._store._task_record(task_ref, scope_json=scope_json)
        request_json = record["request_json"]
        if type(request_json) is not str:
            raise AnalysisTaskError("TASK_WORKER_RESULT_INVALID")
        return request_json

    def _worker_is_alive(self, worker: _TaskWorker) -> bool:
        if not worker.process_started or worker.process_closed:
            return False
        try:
            return bool(worker.process.is_alive())  # type: ignore[attr-defined]
        except Exception:
            raise AnalysisTaskError("TASK_CLEANUP_UNCERTAIN") from None

    def _cleanup_worker(self, worker: _TaskWorker, *, force: bool) -> None:
        if worker.cleanup_complete:
            return
        process = worker.process
        if worker.process_started and not worker.process_closed:
            if process is None:
                raise AnalysisTaskError("TASK_CLEANUP_UNCERTAIN")
            try:
                alive = bool(process.is_alive())  # type: ignore[attr-defined]
                if alive and force:
                    try:
                        process.terminate()  # type: ignore[attr-defined]
                    except Exception:
                        pass
                    process.join(timeout=_WORKER_STOP_GRACE_SECONDS)  # type: ignore[attr-defined]
                    alive = bool(process.is_alive())  # type: ignore[attr-defined]
                    if alive:
                        try:
                            process.kill()  # type: ignore[attr-defined]
                        except Exception:
                            pass
                        process.join(timeout=_WORKER_STOP_GRACE_SECONDS)  # type: ignore[attr-defined]
                        alive = bool(process.is_alive())  # type: ignore[attr-defined]
                if alive:
                    raise AnalysisTaskError("TASK_CLEANUP_UNCERTAIN")
                process.join(timeout=0)  # type: ignore[attr-defined]
                worker.exit_code = process.exitcode  # type: ignore[attr-defined]
            except AnalysisTaskError:
                raise
            except Exception:
                raise AnalysisTaskError("TASK_CLEANUP_UNCERTAIN") from None

        self._close_connection(worker, "receive_connection")
        self._close_connection(worker, "child_connection")
        if not worker.process_closed:
            if process is not None:
                try:
                    process.close()  # type: ignore[attr-defined]
                except Exception:
                    if worker.process_started:
                        raise AnalysisTaskError("TASK_CLEANUP_UNCERTAIN") from None
                    # No child exists if start never assigned a process handle.
                worker.process_closed = True
            else:
                worker.process_closed = True
        worker.cleanup_complete = True

    @staticmethod
    def _close_connection(worker: _TaskWorker, field: str) -> None:
        connection = getattr(worker, field)
        if connection is None:
            return
        try:
            if not connection.closed:
                connection.close()
            if not connection.closed:
                raise OSError
        except Exception:
            raise AnalysisTaskError("TASK_CLEANUP_UNCERTAIN") from None
        if field == "child_connection":
            worker.child_connection = None

    def _finalize_worker(self, worker: _TaskWorker) -> bool:
        if not worker.cleanup_complete or worker.intent is None:
            return False
        state, detail_code, result_json = worker.intent
        try:
            if state == "cancelled":
                self._store._cancel_running_task(
                    worker.task_ref,
                    scope_json=worker.scope_json,
                    running_token=worker.running_token,
                )
            else:
                self._store.finish_task(
                    worker.scope_json,
                    worker.task_ref,
                    state=state,
                    detail_code=detail_code,
                    result_json=result_json,
                    now_ns=self._store.now_ns(),
                    running_token=worker.running_token,
                )
        except AnalysisTaskError as error:
            if error.code != "TASK_STATE_INVALID":
                raise
            # A stale worker token can never overwrite a newer or terminal
            # durable state. Once this exact child is reaped, discard it.
            current = self._store._task_record(
                worker.task_ref, scope_json=worker.scope_json
            )
            if (
                current["state"] == "running"
                and current["running_token"] == worker.running_token
            ):
                raise
        self._workers.pop((worker.scope_json, worker.task_ref), None)
        return True

    def _cancel_task(self, task_ref: object, *, scope_json: str) -> Mapping[str, object]:
        task_ref = _task_reference(task_ref)
        record = self._store._task_record(task_ref, scope_json=scope_json)
        if record["state"] != "running":
            return self._store.cancel_task(task_ref, scope_json=scope_json)
        running_token = record["running_token"]
        if type(running_token) is not str:
            raise AnalysisTaskError("TASK_CLEANUP_UNCERTAIN")
        worker = self._workers.get((scope_json, task_ref))
        if worker is None:
            if self._request_version(record["request_json"]) not in {1, 2}:
                return self._store._cancel_running_task(
                    task_ref,
                    scope_json=scope_json,
                    running_token=running_token,
                )
            raise AnalysisTaskError("TASK_CLEANUP_UNCERTAIN")
        if worker.intent is None:
            worker.intent = ("cancelled", None, None)
        self._cleanup_worker(worker, force=True)
        if worker.cleanup_complete:
            intent_state = worker.intent[0] if worker.intent is not None else None
            self._finalize_worker(worker)
            if intent_state != "cancelled":
                raise AnalysisTaskError("TASK_TERMINAL")
            return self._store.query_task(task_ref, scope_json=scope_json)
        raise AnalysisTaskError("TASK_CLEANUP_UNCERTAIN")

    def _stop_all_workers(self) -> None:
        cleanup_failed = False
        for worker in tuple(self._workers.values()):
            if worker.intent is None:
                worker.intent = ("failed", "TASK_SERVICE_SHUTDOWN", None)
            try:
                self._cleanup_worker(worker, force=True)
                if worker.cleanup_complete:
                    self._finalize_worker(worker)
            except Exception:
                cleanup_failed = True
        if cleanup_failed or self._workers:
            raise AnalysisTaskError("TASK_CLEANUP_UNCERTAIN")


SUPPORTED_OPERATIONS: Final[frozenset[str]] = PortfolioAnalyticsTaskService.SUPPORTED_OPERATIONS


__all__ = [
    "AnalysisTaskError",
    "AnalysisTaskStore",
    "PortfolioAnalyticsTaskService",
    "SUPPORTED_OPERATIONS",
]
