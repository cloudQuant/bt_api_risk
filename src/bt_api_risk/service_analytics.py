"""R ``portfolio_analytics`` control plane: durable tasks and four operations.

This module is the serving adapter for the fixed ``portfolio_analytics`` role.
It owns exactly the ``service.risk_analysis`` operations
(``analysis.submit``, ``analysis.query``, ``analysis.cancel``,
``analysis.input_upload``) and is deliberately not an order, account, or
provider interface: V1 inputs use :mod:`bt_api_risk.portfolio_analytics`; V2
inputs carry explicit offline spot, NAV, loss, and scenario datasets for the
accepted deterministic metrics. No optional analytics or ML dependency
(``numpy``/``sklearn`` and friends) is imported here.

Execution model (minimal vertical slice)
----------------------------------------
``AnalysisTaskStore`` is durable (SQLite) and shared by exactly one
``PortfolioAnalyticsTaskService``. The host drives ``maintain`` on its owner
thread; each invocation (a) sweeps expired pending tasks without a time gate
and (b) advances at most one task state transition, additionally rate-limited
to one transition per second of the injected store clock. The clock gate keeps
progression deterministic for operators that inject a controllable clock,
while a production wall clock simply paces work at one transition per second.
``running`` rows found when the store is opened are failed closed as
``TASK_INTERRUPTED`` instead of being silently re-executed.

Every error surfaced to a caller is one of this module's constant code
strings; no caller-supplied value is ever echoed in a rejection.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from collections.abc import Callable, Mapping
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
        if type(pending_ttl_seconds) is not int or not 1 <= pending_ttl_seconds <= 604_800:
            raise AnalysisTaskError("INVALID_TASK_TTL")
        if not callable(clock):
            raise AnalysisTaskError("INVALID_CLOCK")
        self._model_profile = model_profile
        self._allowed_source_modes = modes
        self._max_concurrent_tasks = max_concurrent_tasks
        self._pending_ttl_ns = pending_ttl_seconds * 1_000_000_000
        self._clock = clock
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
                "PRIMARY KEY (scope_json, task_ref))"
            )
            # Fail closed on restart: a task claimed by a previous process may
            # have produced partial external effects, so it is never silently
            # re-executed.
            self._db.execute(
                "UPDATE analysis_tasks SET state='failed', detail_code='TASK_INTERRUPTED', "
                "state_ns=? WHERE state='running'",
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

    def close(self) -> None:
        self._db.close()

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

    def cancel_task(self, task_ref: str, *, scope_json: str) -> Mapping[str, object]:
        """Cancel a pending/running task; cancelling a cancelled task is a no-op.

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
            self._db.execute(
                "UPDATE analysis_tasks SET state='cancelled', detail_code=NULL, "
                "result_json=NULL, state_ns=? WHERE scope_json=? AND task_ref=?",
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

    def sweep_expired(self, now_ns: int) -> int:
        """Expire every pending task older than the TTL; returns the count."""

        threshold = now_ns - self._pending_ttl_ns
        with self._db:
            cursor = self._db.execute(
                "UPDATE analysis_tasks SET state='expired', detail_code='TASK_EXPIRED', "
                "state_ns=? WHERE state='pending' AND created_ns <= ?",
                (now_ns, threshold),
            )
        return cursor.rowcount

    def next_executable_task(self) -> Mapping[str, object] | None:
        """Return the single oldest runnable task, preferring claimed work."""

        row = self._db.execute(
            "SELECT * FROM analysis_tasks WHERE state IN ('pending','running') "
            "ORDER BY CASE state WHEN 'running' THEN 0 ELSE 1 END, created_ns, rowid "
            "LIMIT 1"
        ).fetchone()
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

    def mark_running(self, scope_json: str, task_ref: str, now_ns: int) -> None:
        """Claim one pending task for execution."""

        with self._db:
            cursor = self._db.execute(
                "UPDATE analysis_tasks SET state='running', state_ns=? "
                "WHERE scope_json=? AND task_ref=? AND state='pending'",
                (now_ns, scope_json, task_ref),
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
    ) -> None:
        """Store one claimed task's terminal outcome."""

        if state not in {"succeeded", "unavailable", "failed"}:
            raise AnalysisTaskError("TASK_STATE_INVALID")
        with self._db:
            cursor = self._db.execute(
                "UPDATE analysis_tasks SET state=?, detail_code=?, result_json=?, state_ns=? "
                "WHERE scope_json=? AND task_ref=? AND state='running'",
                (state, detail_code, result_json, now_ns, scope_json, task_ref),
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

    def __init__(self, store: AnalysisTaskStore) -> None:
        if type(store) is not AnalysisTaskStore:
            raise AnalysisTaskError("INVALID_ANALYSIS_TASK_STORE")
        self._store = store
        self._closed = False
        self._last_step_ns = 0

    @property
    def supported_operations(self) -> frozenset[str]:
        return PortfolioAnalyticsTaskService.SUPPORTED_OPERATIONS

    def close(self) -> None:
        self._closed = True

    def handle(
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
                result = self._store.cancel_task(
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

        if self._closed:
            return {"ok": False, "code": "CLOSED", "result": {}}
        try:
            now_ns = self._store.now_ns()
            expired = self._store.sweep_expired(now_ns)
            advanced = False
            if now_ns - self._last_step_ns >= _EXECUTOR_GATE_NS:
                task = self._store.next_executable_task()
                if task is not None:
                    self._last_step_ns = now_ns
                    self._advance_task(task, now_ns)
                    advanced = True
        except AnalysisTaskError as error:
            return {"ok": False, "code": error.code, "result": {}}
        except sqlite3.Error:
            return {"ok": False, "code": "ANALYSIS_STORAGE_UNAVAILABLE", "result": {}}
        except Exception:
            return {"ok": False, "code": "ANALYSIS_EXECUTION_FAULT", "result": {}}
        return {"ok": True, "code": "OK", "result": {"expired": expired, "advanced": advanced}}

    def _advance_task(self, task: Mapping[str, object], now_ns: int) -> None:
        scope_json = task["scope_json"]
        task_ref = task["task_ref"]
        if task["state"] == "pending":
            self._store.mark_running(scope_json, task_ref, now_ns)
            return

        state = "failed"
        detail_code: str | None = "TASK_EXECUTION_FAILED"
        result_json: str | None = None
        try:
            stored = self._store.load_input(scope_json, task["input_snapshot_id"])
            if stored["input_sha256"] != task["input_sha256"]:
                raise AnalysisTaskError("INPUT_DIGEST_MISMATCH")
            facts = _parse_facts_payload(json.loads(stored["facts_json"]))
            request = _parse_request_payload(json.loads(task["request_json"]))
            if (
                type(facts) is PortfolioAnalyticsFactsV1
                and type(request) is PortfolioAnalyticsRequestV1
            ):
                service = PortfolioAnalyticsService(
                    _StoredFactsSource(facts),
                    self._store.model_profile,
                    allowed_source_modes=self._store.allowed_source_modes,
                )
                report = service.analyze_snapshot_v1(
                    request, principal_ref=task["owner_principal"]
                )
                report_payload = report.to_payload()
                report_status = report.status
                unavailable_code = (
                    report.reason_codes[0] if report.reason_codes else "UNAVAILABLE"
                )
            elif (
                type(facts) is PortfolioAnalyticsFactsV2
                and type(request) is PortfolioAnalyticsRequestV2
            ):
                report = PortfolioAnalyticsServiceV2().analyze_snapshot_v2(
                    facts,
                    request,
                    input_sha256=stored["input_sha256"],
                )
                report_payload = report.to_payload()
                report_status = report.status
                unavailable_code = next(
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
            result_json = _canonical_json(report_payload).decode("ascii")
            if report_status == "AVAILABLE":
                state, detail_code = "succeeded", None
            else:
                state, detail_code = "unavailable", unavailable_code
        except AnalysisTaskError as error:
            state, detail_code, result_json = "failed", error.code, None
        except PortfolioAnalyticsError as error:
            state, detail_code, result_json = "failed", error.code, None
        except Exception:
            state, detail_code, result_json = "failed", "TASK_EXECUTION_FAILED", None
        self._store.finish_task(
            scope_json,
            task_ref,
            state=state,
            detail_code=detail_code,
            result_json=result_json,
            now_ns=now_ns,
        )


SUPPORTED_OPERATIONS: Final[frozenset[str]] = PortfolioAnalyticsTaskService.SUPPORTED_OPERATIONS


__all__ = [
    "AnalysisTaskError",
    "AnalysisTaskStore",
    "PortfolioAnalyticsTaskService",
    "SUPPORTED_OPERATIONS",
]
