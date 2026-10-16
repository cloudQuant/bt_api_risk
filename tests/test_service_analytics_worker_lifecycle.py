"""Real spawned-worker lifecycle checks for the V2 analytics task service."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
import bt_api_risk.service_analytics as analytics_service_module
from bt_api_base.service_protocol import WireScope
from bt_api_risk.portfolio_analytics import PortfolioAnalyticsModelProfileV1
from bt_api_risk.portfolio_analytics_v2 import (
    LossHistoryFactsV2,
    NavHistoryFactsV2,
    PortfolioAnalyticsFactsV2,
    PortfolioAnalyticsRequestV2,
    ScenarioFactsV2,
    SpotFactsV2,
)
from bt_api_risk.portfolio_metrics_v1 import (
    FX_UNIT_V1,
    LOSS_UNIT_V1,
    PRICE_UNIT_V1,
    SHOCK_UNIT_V1,
    HistoricalLossObservationV1,
    NavObservationV1,
    SpotPositionMetricInputV1,
    SpotPriceFxShockV1,
)
from bt_api_risk.service_analytics import (
    AnalysisTaskError,
    AnalysisTaskStore,
    PortfolioAnalyticsTaskService,
)

_UTC = timezone.utc
_T0 = datetime(2026, 1, 1, tzinfo=_UTC)
_PRINCIPAL = "offline-test-principal"


def _blocked_before_worker_entry(
    target, args, entered_sender, release_receiver
) -> None:
    """Hold a real spawn child on OS pipes before its startup handshake."""

    try:
        entered_sender.send_bytes(b"entered")
        command = release_receiver.recv_bytes(maxlength=16)
    except (EOFError, OSError):
        return
    finally:
        entered_sender.close()
        release_receiver.close()
    if command == b"run":
        target(*args)


class _PipeEntryWaiter:
    def __init__(self, connection) -> None:
        self._connection = connection

    def wait(self, timeout: float) -> bool:
        if self._connection.closed or not self._connection.poll(timeout):
            return False
        try:
            return self._connection.recv_bytes(maxlength=16) == b"entered"
        except (EOFError, OSError):
            return False


class _StartupBarrierContext:
    def __init__(self, context) -> None:
        self._context = context
        self.entered: _PipeEntryWaiter | None = None
        self._parent_connections = []

    def Pipe(self, *, duplex: bool):
        return self._context.Pipe(duplex=duplex)

    def Process(self, *, target, args, **kwargs):
        entered_receiver, entered_sender = self._context.Pipe(duplex=False)
        release_receiver, release_sender = self._context.Pipe(duplex=False)
        self.entered = _PipeEntryWaiter(entered_receiver)
        self._parent_connections.extend((entered_receiver, release_sender))
        process = self._context.Process(
            target=_blocked_before_worker_entry,
            args=(target, args, entered_sender, release_receiver),
            **kwargs,
        )
        return _StartupBarrierProcess(process, (entered_sender, release_receiver))

    def close(self) -> None:
        for connection in self._parent_connections:
            if not connection.closed:
                connection.close()


class _StartupBarrierProcess:
    def __init__(self, process, parent_child_ends) -> None:
        self._process = process
        self._parent_child_ends = parent_child_ends

    def start(self) -> None:
        try:
            self._process.start()
        finally:
            # Close the parent's copies; the child owns these pipe ends now.
            for connection in self._parent_child_ends:
                if not connection.closed:
                    connection.close()

    def __getattr__(self, name):
        return getattr(self._process, name)


def _safe_protocol_code(value: object) -> str:
    if type(value) is str and value in {
        "succeeded",
        "unavailable",
        "failed",
        "cancelled",
    }:
        return value
    if (
        type(value) is str
        and 0 < len(value) <= 64
        and value.isascii()
        and all(
            character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
            for character in value
        )
    ):
        return value
    return type(value).__name__


def _worker_failure_snapshot(
    worker, store, *, expected_request_json: str
) -> dict[str, object]:
    """Keep the first failed real-worker result finite and payload-free."""

    envelope = worker.result_envelope
    result_json = envelope.get("result_json") if envelope is not None else None
    snapshot: dict[str, object] = {
        "frame_error": worker.frame_error,
        "intent": (
            [
                _safe_protocol_code(worker.intent[0]),
                _safe_protocol_code(worker.intent[1]),
            ]
            if worker.intent is not None
            else None
        ),
        "exit_code": worker.exit_code,
        "started": worker.started_monotonic_ns is not None,
        "envelope_keys": sorted(envelope) if type(envelope) is dict else None,
    }
    if envelope is not None:
        kind = envelope.get("kind")
        state = envelope.get("state")
        snapshot.update(
            envelope_kind=(
                kind
                if type(kind) is str and kind in {"started", "result"}
                else "OTHER"
            ),
            envelope_state=(
                _safe_protocol_code(state)
                if type(state) is str
                else type(state).__name__
            ),
            envelope_detail_code=_safe_protocol_code(envelope.get("detail_code")),
        )
    if type(result_json) is not str:
        snapshot["result_json_type"] = type(result_json).__name__
        return snapshot
    try:
        encoded = result_json.encode("ascii", errors="strict")
        report = json.loads(encoded)
    except (
        UnicodeError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
    ) as error:
        snapshot["result_json_parse_error"] = type(error).__name__
        snapshot["result_json_length"] = len(result_json)
        snapshot["result_json_sha256"] = hashlib.sha256(
            result_json.encode("utf-8", errors="replace")
        ).hexdigest()
        return snapshot
    snapshot["result_json_length"] = len(encoded)
    snapshot["result_json_sha256"] = hashlib.sha256(encoded).hexdigest()
    try:
        snapshot["result_json_canonical"] = (
            analytics_service_module._canonical_json(report) == encoded
        )
    except (TypeError, ValueError, OverflowError, RecursionError):
        snapshot["result_json_canonical"] = False
    if type(report) is not dict:
        snapshot["report_type"] = type(report).__name__
        return snapshot
    snapshot.update(
        report_keys=sorted(report),
        schema_ref=(
            report.get("schema_ref")
            if report.get("schema_ref") == "portfolio_analytics_v2"
            else "OTHER"
        ),
        report_version=(
            report.get("version")
            if type(report.get("version")) is int
            else "OTHER"
        ),
        report_status=(
            report.get("status")
            if type(report.get("status")) is str
            and report.get("status") in {"AVAILABLE", "UNAVAILABLE"}
            else "OTHER"
        ),
        input_sha256_matches=(report.get("input_sha256") == worker.input_sha256),
    )
    try:
        task_projection = store.query_task(
            worker.task_ref, scope_json=worker.scope_json
        )
        input_snapshot_id = task_projection.get("input_snapshot_id")
        task_input_sha256 = task_projection.get("input_sha256")
        if type(input_snapshot_id) is not str:
            raise ValueError
        stored_input = store.load_input(worker.scope_json, input_snapshot_id)
        facts_json = stored_input.get("facts_json")
    except Exception as error:
        snapshot["request_store_error"] = type(error).__name__
        return snapshot
    snapshot["task_input_sha256"] = (
        task_input_sha256
        if type(task_input_sha256) is str
        and len(task_input_sha256) == 64
        and all(character in "0123456789abcdef" for character in task_input_sha256)
        else "INVALID"
    )
    snapshot["worker_input_sha256"] = (
        worker.input_sha256
        if type(worker.input_sha256) is str
        and len(worker.input_sha256) == 64
        and all(character in "0123456789abcdef" for character in worker.input_sha256)
        else "INVALID"
    )
    snapshot["report_input_sha256"] = (
        report.get("input_sha256")
        if type(report.get("input_sha256")) is str
        and len(report["input_sha256"]) == 64
        and all(character in "0123456789abcdef" for character in report["input_sha256"])
        else "INVALID"
    )
    snapshot["worker_input_matches_task"] = worker.input_sha256 == task_input_sha256
    if type(facts_json) is str:
        try:
            facts_payload_sha256 = hashlib.sha256(
                facts_json.encode("ascii", errors="strict")
            ).hexdigest()
            snapshot["facts_payload_sha256"] = facts_payload_sha256
            snapshot["task_input_matches_facts_payload"] = (
                task_input_sha256 == facts_payload_sha256
            )
        except UnicodeError:
            snapshot["facts_payload_sha256"] = "NON_ASCII"
            snapshot["task_input_matches_facts_payload"] = False
    else:
        snapshot["facts_payload_sha256"] = "INVALID"
        snapshot["task_input_matches_facts_payload"] = False
    if type(expected_request_json) is str:
        try:
            expected_request_sha256 = hashlib.sha256(
                expected_request_json.encode("ascii", errors="strict")
            ).hexdigest()
            snapshot["stored_request_sha256"] = expected_request_sha256
            snapshot["report_request_sha256"] = (
                report.get("request_sha256")
                if type(report.get("request_sha256")) is str
                and len(report["request_sha256"]) == 64
                and all(
                    character in "0123456789abcdef"
                    for character in report["request_sha256"]
                )
                else "INVALID"
            )
            snapshot["request_sha256_matches"] = (
                report.get("request_sha256") == expected_request_sha256
            )
        except UnicodeError:
            snapshot["request_sha256_matches"] = False
    try:
        report_sha256 = report.get("report_sha256")
        unsigned = dict(report)
        unsigned.pop("report_sha256", None)
        expected_report_sha256 = hashlib.sha256(
            analytics_service_module._canonical_json(unsigned)
        ).hexdigest()
        snapshot["expected_report_sha256"] = expected_report_sha256
        snapshot["reported_report_sha256"] = (
            report_sha256
            if type(report_sha256) is str
            and len(report_sha256) == 64
            and all(character in "0123456789abcdef" for character in report_sha256)
            else "INVALID"
        )
        snapshot["report_sha256_matches"] = report_sha256 == expected_report_sha256
    except (TypeError, ValueError, OverflowError, RecursionError):
        snapshot["report_sha256_matches"] = False
    return snapshot


class _FailFirstCloseConnection:
    def __init__(self, connection) -> None:
        self._connection = connection
        self.close_calls = 0

    @property
    def closed(self) -> bool:
        return self._connection.closed

    def close(self) -> None:
        self.close_calls += 1
        if self.close_calls == 1:
            raise OSError("synthetic first close failure")
        self._connection.close()


class _Clock:
    def __init__(self) -> None:
        self.value = time.time_ns()

    def now(self) -> int:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += seconds * 1_000_000_000


def _facts(portfolio_ref: str, *, rows: int = 1) -> PortfolioAnalyticsFactsV2:
    positions = tuple(
        SpotPositionMetricInputV1(
            position_ref=f"position-{index:05d}",
            as_of_utc=_T0,
            base_currency="BTC",
            quote_currency="USD",
            quantity=Decimal("1"),
            quantity_unit="BTC",
            unit_price=Decimal("10"),
            price_unit=PRICE_UNIT_V1,
            reporting_per_quote=Decimal("1"),
            fx_unit=FX_UNIT_V1,
        )
        for index in range(rows)
    )
    return PortfolioAnalyticsFactsV2(
        portfolio_ref=portfolio_ref,
        source_mode="research",
        source_ref="synthetic-offline-facts",
        source_version="synthetic-offline-facts-v1",
        source_generation="facts-generation-1",
        facts_snapshot_ref="facts-cut-1",
        spot=SpotFactsV2(
            status="available",
            reason_code=None,
            as_of_utc=_T0,
            source_ref="synthetic-spot-source",
            source_version="synthetic-spot-v1",
            source_generation="spot-generation-1",
            source_cursor="spot-cursor-1",
            coverage_complete=True,
            positions=positions,
        ),
        nav_history=NavHistoryFactsV2(
            status="available",
            reason_code=None,
            source_ref="synthetic-nav-source",
            source_version="synthetic-nav-v1",
            source_generation="nav-generation-1",
            coverage_start_utc=_T0,
            coverage_end_utc=_T0 + timedelta(days=1),
            start_cursor="nav-start-1",
            end_cursor="nav-end-1",
            coverage_complete=True,
            observations=(
                NavObservationV1(_T0, Decimal("100"), "USD"),
                NavObservationV1(_T0 + timedelta(days=1), Decimal("110"), "USD"),
            ),
        ),
        loss_history=LossHistoryFactsV2(
            status="available",
            reason_code=None,
            horizon_ref="one-day-v1",
            source_ref="synthetic-loss-source",
            source_version="synthetic-loss-v1",
            source_generation="loss-generation-1",
            coverage_start_utc=_T0,
            coverage_end_utc=_T0 + timedelta(days=1),
            start_cursor="loss-start-1",
            end_cursor="loss-end-1",
            coverage_complete=True,
            observations=(
                HistoricalLossObservationV1(
                    _T0, Decimal("1"), "USD", LOSS_UNIT_V1
                ),
                HistoricalLossObservationV1(
                    _T0 + timedelta(days=1), Decimal("2"), "USD", LOSS_UNIT_V1
                ),
            ),
        ),
        scenario=ScenarioFactsV2(
            status="available",
            reason_code=None,
            scenario_ref="risk-off",
            scenario_version="risk-off-v1",
            source_ref="synthetic-scenario-source",
            source_version="synthetic-scenario-v1",
            source_generation="scenario-generation-1",
            source_cursor="scenario-cursor-1",
            coverage_complete=True,
            shocks=tuple(
                SpotPriceFxShockV1(
                    f"position-{index:05d}",
                    Decimal("0.01"),
                    Decimal("0"),
                    SHOCK_UNIT_V1,
                )
                for index in range(rows)
            ),
        ),
    )


def _request(portfolio_ref: str) -> PortfolioAnalyticsRequestV2:
    return PortfolioAnalyticsRequestV2(
        portfolio_ref=portfolio_ref,
        reporting_currency="USD",
        loss_horizon_ref="one-day-v1",
        confidence=Decimal("0.8"),
        scenario_ref="risk-off",
        scenario_version="risk-off-v1",
    )


def _store(
    path,
    clock: _Clock,
    *,
    max_concurrent_tasks: int = 2,
    max_concurrent_workers: int = 2,
    execution_timeout_seconds: int | float = 30,
) -> AnalysisTaskStore:
    return AnalysisTaskStore(
        str(path),
        model_profile=PortfolioAnalyticsModelProfileV1(
            "offline-portfolio-profile-v1",
            max_mark_age_ns=1_000_000_000_000,
            max_fx_age_ns=1_000_000_000_000,
            max_input_bytes=16_000_000,
        ),
        allowed_source_modes=("research", "imported", "paper"),
        max_concurrent_tasks=max_concurrent_tasks,
        max_concurrent_workers=max_concurrent_workers,
        execution_timeout_seconds=execution_timeout_seconds,
        pending_ttl_seconds=3_600,
        clock=clock.now,
    )


def _upload(
    service: PortfolioAnalyticsTaskService,
    portfolio_ref: str,
    snapshot_ref: str,
    *,
    rows: int = 1,
) -> None:
    response = service.handle(
        "analysis.input_upload",
        principal_ref=_PRINCIPAL,
        scope=WireScope("offline-risk-domain", portfolio_ref=portfolio_ref),
        arguments={
            "input_snapshot_id": snapshot_ref,
            "facts": _facts(portfolio_ref, rows=rows).to_payload(),
        },
    )
    assert response["ok"] is True


def _submit(
    service: PortfolioAnalyticsTaskService,
    portfolio_ref: str,
    task_ref: str,
    snapshot_ref: str,
) -> dict[str, object]:
    return dict(
        service.handle(
            "analysis.submit",
            principal_ref=_PRINCIPAL,
            scope=WireScope("offline-risk-domain", portfolio_ref=portfolio_ref),
            arguments={
                "task_ref": task_ref,
                "input_snapshot_id": snapshot_ref,
                "request": _request(portfolio_ref).to_payload(),
            },
        )
    )


def _query(
    service: PortfolioAnalyticsTaskService, portfolio_ref: str, task_ref: str
) -> dict[str, object]:
    return dict(
        service.handle(
            "analysis.query",
            principal_ref=_PRINCIPAL,
            scope=WireScope("offline-risk-domain", portfolio_ref=portfolio_ref),
            arguments={"task_ref": task_ref},
        )
    )


def test_v2_task_returns_traceable_report_from_real_spawned_worker(tmp_path) -> None:
    clock = _Clock()
    store = _store(tmp_path / "success.sqlite", clock)
    service = PortfolioAnalyticsTaskService(store)
    try:
        _upload(service, "portfolio-success", "cut-success")
        assert _submit(service, "portfolio-success", "task-success", "cut-success")[
            "ok"
        ] is True

        first = service.maintain(frozenset())
        assert first["result"]["advanced"] is True
        worker = next(iter(service._workers.values()))
        assert worker.process_started is True
        assert worker.process is not None
        assert worker.process.pid is not None
        assert _query(service, "portfolio-success", "task-success")["result"][
            "state"
        ] == "running"

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            service.maintain(frozenset())
            state = _query(service, "portfolio-success", "task-success")["result"][
                "state"
            ]
            if state in {"succeeded", "unavailable", "failed"}:
                break
            time.sleep(0.01)

        result = _query(service, "portfolio-success", "task-success")["result"]
        expected_request_json = analytics_service_module._canonical_json(
            _request("portfolio-success").to_payload()
        ).decode("ascii")
        diagnostic = _worker_failure_snapshot(
            worker,
            store,
            expected_request_json=expected_request_json,
        )
        if result["state"] != "succeeded":
            diagnostic_json = json.dumps(
                diagnostic,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            (tmp_path / "worker-failure-diagnostic.json").write_text(
                diagnostic_json,
                encoding="ascii",
            )
            assert result["state"] == "succeeded", diagnostic_json
        assert "request_store_error" not in diagnostic
        assert diagnostic["worker_input_matches_task"] is True
        assert diagnostic["task_input_matches_facts_payload"] is True
        assert diagnostic["request_sha256_matches"] is True
        assert diagnostic["report_sha256_matches"] is True
        report = result["result"]
        assert report["version"] == 2
        assert report["schema_ref"] == "portfolio_analytics_v2"
        assert report["input_sha256"] == result["input_sha256"]
        assert report["status"] == "AVAILABLE"
        assert report["metrics"]["spot_exposure"]["value"][
            "gross_reporting_notional"
        ] == "10"
        assert worker.cleanup_complete is True
        assert worker.process_closed is True
        assert worker.receive_connection.closed is True
        assert worker.child_connection is None
        assert worker.frame_error is None

        # Malformed JSON protocol values must become finite task failures,
        # never leak TypeError/ValueError out of maintain and retain a slot.
        assert worker.result_envelope is not None
        completed_ns = worker.result_envelope["completed_monotonic_ns"]
        for invalid_envelope in (
            {
                **worker.result_envelope,
                "state": [],
                "detail_code": None,
                "result_json": None,
            },
            {
                **worker.result_envelope,
                "state": "succeeded",
                "detail_code": None,
                "result_json": '{"value":NaN}',
            },
        ):
            worker.result_envelope = {
                **invalid_envelope,
                "completed_monotonic_ns": completed_ns,
            }
            worker.intent = None
            service._set_result_intent(worker)
            assert worker.intent == ("failed", "TASK_WORKER_RESULT_INVALID", None)
    finally:
        service.close()
        store.close()


def test_worker_rejects_duplicate_result_frame_after_valid_result(tmp_path) -> None:
    clock = _Clock()
    store = _store(tmp_path / "duplicate-frame.sqlite", clock)
    service = PortfolioAnalyticsTaskService(store)
    receive_connection, send_connection = multiprocessing.get_context(
        "spawn"
    ).Pipe(duplex=False)
    launched_ns = time.monotonic_ns() - 1_000_000
    running_token = "a" * 32
    worker = analytics_service_module._TaskWorker(
        scope_json=analytics_service_module._task_scope(
            WireScope("offline-risk-domain", portfolio_ref="portfolio-duplicate")
        ),
        task_ref="task-duplicate-frame",
        running_token=running_token,
        input_sha256="0" * 64,
        process=None,
        receive_connection=receive_connection,
        child_connection=None,
        process_started=True,
        startup_deadline_ns=launched_ns + 10_000_000_000,
        launched_monotonic_ns=launched_ns,
    )
    try:
        started_ns = time.monotonic_ns()
        started_frame = {
            "kind": "started",
            "running_token": running_token,
            "started_monotonic_ns": started_ns,
        }
        result_frame = {
            "completed_monotonic_ns": started_ns + 1,
            "detail_code": None,
            "kind": "result",
            "result_json": "{}",
            "running_token": running_token,
            "state": "succeeded",
        }
        send_connection.send_bytes(
            analytics_service_module._canonical_json(started_frame)
        )
        send_connection.send_bytes(
            analytics_service_module._canonical_json(result_frame)
        )
        # A second result is an unsolicited extra frame and must invalidate the
        # worker even though the first result frame was already well formed.
        send_connection.send_bytes(
            analytics_service_module._canonical_json(result_frame)
        )

        service._read_worker_frames(worker)

        assert worker.started_monotonic_ns == started_ns
        assert worker.result_envelope == result_frame
        assert worker.frame_error == "INVALID_FRAME"
    finally:
        send_connection.close()
        receive_connection.close()
        service.close()
        store.close()


def test_running_cancel_reaps_worker_and_rejects_its_late_token(tmp_path) -> None:
    clock = _Clock()
    store = _store(
        tmp_path / "cancel.sqlite",
        clock,
        max_concurrent_tasks=1,
        max_concurrent_workers=1,
    )
    service = PortfolioAnalyticsTaskService(store)
    try:
        _upload(service, "portfolio-one", "cut-heavy", rows=10_000)
        _upload(service, "portfolio-two", "cut-small")
        assert _submit(service, "portfolio-one", "task-one", "cut-heavy")["ok"] is True
        rejected = _submit(service, "portfolio-one", "task-one-extra", "cut-heavy")
        assert rejected["ok"] is False and rejected["code"] == "TASK_QUOTA_EXCEEDED"
        assert _submit(service, "portfolio-two", "task-two", "cut-small")["ok"] is True
        assert store.max_concurrent_tasks == 1
        assert store.max_concurrent_workers == 1

        assert service.maintain(frozenset())["result"]["advanced"] is True
        worker_key = next(key for key in service._workers if key[1] == "task-one")
        scope_json = worker_key[0]
        worker = service._workers[worker_key]
        assert worker.process is not None and worker.process.is_alive()
        running_token = worker.running_token

        clock.advance(1)
        assert service.maintain(frozenset())["result"]["advanced"] is False
        assert _query(service, "portfolio-two", "task-two")["result"]["state"] == "pending"
        assert worker.process.is_alive()

        cancelled = service.handle(
            "analysis.cancel",
            principal_ref=_PRINCIPAL,
            scope=WireScope("offline-risk-domain", portfolio_ref="portfolio-one"),
            arguments={"task_ref": "task-one"},
        )
        assert cancelled["ok"] is True
        assert cancelled["result"]["state"] == "cancelled"
        assert worker.cleanup_complete is True
        assert worker.process_closed is True
        assert worker.receive_connection.closed is True
        assert worker.child_connection is None

        with pytest.raises(AnalysisTaskError) as stale:
            store.finish_task(
                scope_json,
                "task-one",
                state="failed",
                detail_code="LATE_RESULT",
                result_json=None,
                now_ns=clock.now(),
                running_token=running_token,
            )
        assert stale.value.code == "TASK_STATE_INVALID"
        assert _query(service, "portfolio-one", "task-one")["result"]["state"] == "cancelled"
    finally:
        service.close()
        store.close()


def test_execution_and_startup_deadlines_reap_workers(tmp_path, monkeypatch) -> None:
    clock = _Clock()
    store = _store(
        tmp_path / "timeout.sqlite",
        clock,
        max_concurrent_workers=1,
        execution_timeout_seconds=0.001,
    )
    service = PortfolioAnalyticsTaskService(store)
    try:
        _upload(service, "portfolio-timeout", "cut-timeout", rows=10_000)
        assert _submit(
            service, "portfolio-timeout", "task-timeout", "cut-timeout"
        )["ok"] is True

        # Queue time is advanced before any worker exists; it is governed by
        # pending TTL and does not consume the child execution budget.
        clock.advance(60)
        assert service.maintain(frozenset())["result"]["advanced"] is True
        worker = next(iter(service._workers.values()))
        assert worker.execution_deadline_ns is None
        assert worker.process is not None and worker.process.is_alive()

        ready_deadline = time.monotonic() + 10
        while worker.started_monotonic_ns is None and time.monotonic() < ready_deadline:
            service._read_worker_frames(worker)
            if worker.started_monotonic_ns is None:
                time.sleep(0.005)
        assert worker.started_monotonic_ns is not None
        assert worker.execution_deadline_ns == (
            worker.started_monotonic_ns + store.execution_timeout_ns
        )
        assert worker.process.is_alive()

        # The child still runs its production entry and real V2 calculation;
        # the controlled parent clock makes the already-started deadline due.
        service._monotonic_ns = lambda: worker.execution_deadline_ns + 1
        service.maintain(frozenset())
        terminal = _query(service, "portfolio-timeout", "task-timeout")["result"]
        assert terminal["state"] == "failed"
        assert terminal["detail_code"] == "TASK_EXECUTION_TIMEOUT"
        assert worker.cleanup_complete is True
        assert worker.process_closed is True
        assert worker.receive_connection.closed is True

        # A second real spawn child is held behind a Pipe barrier before it
        # can send the startup frame. This separates startup timeout from the
        # child-entry execution budget and makes the timeout deterministic.
        _upload(service, "portfolio-start-timeout", "cut-start-timeout")
        assert _submit(
            service,
            "portfolio-start-timeout",
            "task-start-timeout",
            "cut-start-timeout",
        )["ok"] is True
        _upload(service, "portfolio-after-timeout", "cut-after-timeout")
        assert _submit(
            service,
            "portfolio-after-timeout",
            "task-after-start-timeout",
            "cut-after-timeout",
        )["ok"] is True

        spawn_context = multiprocessing.get_context("spawn")
        barrier_context = _StartupBarrierContext(spawn_context)
        monkeypatch.setattr(
            analytics_service_module.multiprocessing,
            "get_context",
            lambda _method: barrier_context,
        )
        service._monotonic_ns = time.monotonic_ns
        clock.advance(1)
        assert service.maintain(frozenset())["result"]["advanced"] is True
        startup_worker = next(iter(service._workers.values()))
        assert startup_worker.task_ref == "task-start-timeout"
        assert barrier_context.entered is not None
        assert barrier_context.entered.wait(timeout=10) is True
        assert startup_worker.started_monotonic_ns is None
        assert startup_worker.execution_deadline_ns is None
        assert startup_worker.process is not None and startup_worker.process.is_alive()

        service._monotonic_ns = lambda: startup_worker.startup_deadline_ns + 1
        service.maintain(frozenset())
        startup_terminal = _query(
            service, "portfolio-start-timeout", "task-start-timeout"
        )["result"]
        assert startup_terminal["state"] == "failed"
        assert startup_terminal["detail_code"] == "TASK_WORKER_START_TIMEOUT"
        assert startup_worker.cleanup_complete is True
        assert startup_worker.process_closed is True
        assert startup_worker.receive_connection.closed is True
        assert startup_worker.child_connection is None
        assert service._workers == {}

        # The timed-out worker's quota is released only after reap; the next
        # queued task can now acquire the sole host worker slot.
        service._monotonic_ns = time.monotonic_ns
        clock.advance(1)
        service.maintain(frozenset())
        next_worker = next(iter(service._workers.values()))
        assert next_worker.task_ref == "task-after-start-timeout"
        assert next_worker.process is not None and next_worker.process.is_alive()
    finally:
        try:
            service.close()
        finally:
            try:
                if "barrier_context" in locals():
                    barrier_context.close()
            finally:
                store.close()


def test_store_close_retries_real_worker_cleanup_after_pipe_close_failure(tmp_path) -> None:
    clock = _Clock()
    database = tmp_path / "callback.sqlite"
    store = _store(database, clock, max_concurrent_workers=1)
    service = PortfolioAnalyticsTaskService(store)
    try:
        with pytest.raises(AnalysisTaskError) as duplicate:
            store._bind_shutdown_callback(lambda: None)
        assert duplicate.value.code == "ANALYSIS_SERVICE_ALREADY_BOUND"

        _upload(service, "portfolio-callback", "cut-callback", rows=10_000)
        assert _submit(
            service,
            "portfolio-callback",
            "task-callback",
            "cut-callback",
        )["ok"] is True
        assert service.maintain(frozenset())["result"]["advanced"] is True
        worker = next(iter(service._workers.values()))
        assert worker.process is not None and worker.process.is_alive()
        flaky_connection = _FailFirstCloseConnection(worker.receive_connection)
        worker.receive_connection = flaky_connection

        with pytest.raises(AnalysisTaskError) as first_close:
            store.close()
        assert first_close.value.code == "TASK_CLEANUP_UNCERTAIN"
        assert store._closed is False
        assert service._closed is False
        assert worker.cleanup_complete is False
        assert worker.process_closed is False
        assert worker.receive_connection.closed is False
        assert flaky_connection.close_calls == 1
        assert _query(service, "portfolio-callback", "task-callback")["result"][
            "state"
        ] == "running"
        assert store._db.execute("SELECT 1").fetchone()[0] == 1

        store.close()
        assert flaky_connection.close_calls == 2
        assert store._closed is True
        assert service._closed is True
        assert worker.cleanup_complete is True
        assert worker.process_closed is True
        assert worker.receive_connection.closed is True
        assert service._workers == {}
        with sqlite3.connect(database) as reader:
            row = reader.execute(
                "SELECT state, detail_code FROM analysis_tasks WHERE task_ref=?",
                ("task-callback",),
            ).fetchone()
        assert row == ("failed", "TASK_SERVICE_SHUTDOWN")
        store.close()
    finally:
        if not service._closed:
            service.close()
        if not store._closed:
            store.close()


def test_store_close_callback_reaps_real_worker_before_shutdown_state(tmp_path) -> None:
    clock = _Clock()
    database = tmp_path / "shutdown.sqlite"
    store = _store(database, clock)
    service = PortfolioAnalyticsTaskService(store)
    try:
        _upload(service, "portfolio-shutdown", "cut-shutdown", rows=10_000)
        assert _submit(
            service, "portfolio-shutdown", "task-shutdown", "cut-shutdown"
        )["ok"] is True
        assert service.maintain(frozenset())["result"]["advanced"] is True
        worker = next(iter(service._workers.values()))
        assert worker.process is not None and worker.process.is_alive()

        store.close()
        assert service._closed is True
        assert worker.cleanup_complete is True
        assert worker.process_closed is True
        assert worker.receive_connection.closed is True
        with sqlite3.connect(database) as reader:
            row = reader.execute(
                "SELECT state, detail_code FROM analysis_tasks WHERE task_ref=?",
                ("task-shutdown",),
            ).fetchone()
        assert row == ("failed", "TASK_SERVICE_SHUTDOWN")
    finally:
        if not service._closed:
            service.close()
        if not store._closed:
            store.close()
