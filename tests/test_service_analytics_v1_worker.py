"""V1 analytics tasks use the bounded spawned-worker lifecycle."""

from __future__ import annotations

import time
from datetime import date
from decimal import Decimal

from bt_api_base.service_protocol import WireScope
from bt_api_risk.portfolio_analytics import (
    CashBalanceV1,
    ExternalCapitalFlowV1,
    ExternalFlowCoverageV1,
    PortfolioAnalyticsFactsV1,
    PortfolioAnalyticsModelProfileV1,
    PortfolioAnalyticsRequestV1,
    PortfolioMembershipV1,
    PortfolioValuationPointV1,
    _facts_payload,
    _request_payload,
)
from bt_api_risk.service_analytics import AnalysisTaskStore, PortfolioAnalyticsTaskService

_DAY_NS = 86_400_000_000_000
_EPOCH = date(1970, 1, 1)
_START = date(2026, 1, 1)
_END = date(2026, 1, 11)
_PRINCIPAL = "offline-v1-worker-principal"
_PORTFOLIO = "offline-v1-worker-portfolio"
_SCOPE = WireScope("offline-analytics-domain", portfolio_ref=_PORTFOLIO)


def _day_end_ns(day: date) -> int:
    return (day - _EPOCH).days * _DAY_NS + _DAY_NS - 1


def _point(day: date, amount: str) -> PortfolioValuationPointV1:
    return PortfolioValuationPointV1(
        valuation_date_utc=day,
        as_of_ns=_day_end_ns(day),
        snapshot_ref=f"offline-cut-{day.isoformat()}",
        source_generation="offline-generation-1",
        source_cursor=f"offline-cursor-{day.isoformat()}",
        valuation_cut_policy="UTC_CALENDAR_DAY_END_V1",
        coverage_complete=True,
        covered_member_refs=("strategy-offline",),
        covered_asset_classes=("cash", "spot"),
        cash_balances=(
            CashBalanceV1(
                balance_ref=f"cash-{day.isoformat()}",
                member_ref="strategy-offline",
                currency="USD",
                amount=Decimal(amount),
            ),
        ),
        spot_positions=(),
    )


def _facts(*, flow_complete: bool) -> PortfolioAnalyticsFactsV1:
    beginning = _point(_START, "100")
    ending = _point(_END, "130")
    return PortfolioAnalyticsFactsV1(
        portfolio_ref=_PORTFOLIO,
        source_mode="imported",
        source_ref="user-offline-import",
        source_version="offline-facts-v1",
        source_generation="offline-generation-1",
        snapshot_ref="offline-dataset-2026-01-v1",
        valuation_basis_ref="cash_spot_after_booked_internal_flows_v1",
        membership=PortfolioMembershipV1(
            portfolio_ref=_PORTFOLIO,
            membership_version=4,
            member_refs=("strategy-offline",),
            effective_start_date_utc=date(2025, 1, 1),
            effective_end_date_utc_exclusive=None,
            source_ref="offline-membership-import",
            source_version="membership-v1",
        ),
        beginning=beginning,
        ending=ending,
        external_flows=(
            ExternalCapitalFlowV1(
                flow_ref="offline-contribution-1",
                direction="CONTRIBUTION",
                amount=Decimal("20"),
                currency="USD",
                effective_at_ns=_day_end_ns(date(2026, 1, 6)),
                source_ref="offline-cashflow-import",
                source_version="cashflow-v1",
                source_generation="offline-generation-1",
                source_cursor="cashflow-cursor-1",
            ),
        ),
        flow_coverage=ExternalFlowCoverageV1(
            source_ref="offline-cashflow-import",
            source_version="cashflow-v1",
            source_generation="offline-generation-1",
            start_as_of_ns=beginning.as_of_ns,
            end_as_of_ns=ending.as_of_ns,
            start_cursor="cashflow-start-1",
            end_cursor="cashflow-end-1",
            complete=flow_complete,
        ),
        fx_observations=(),
    )


def _request() -> PortfolioAnalyticsRequestV1:
    return PortfolioAnalyticsRequestV1(
        portfolio_ref=_PORTFOLIO,
        membership_version=4,
        period_start_date_utc=_START,
        period_end_date_utc=_END,
        reporting_currency="USD",
    )


def _service(path) -> tuple[AnalysisTaskStore, PortfolioAnalyticsTaskService]:
    store = AnalysisTaskStore(
        str(path),
        model_profile=PortfolioAnalyticsModelProfileV1(
            model_profile_ref="offline-v1-worker-profile-v1",
            max_mark_age_ns=31_536_000_000_000_000,
            max_fx_age_ns=31_536_000_000_000_000,
        ),
        allowed_source_modes=("research", "imported", "paper"),
        max_concurrent_tasks=2,
        max_concurrent_workers=1,
        execution_timeout_seconds=15,
        pending_ttl_seconds=3_600,
    )
    return store, PortfolioAnalyticsTaskService(store)


def _submit(
    service: PortfolioAnalyticsTaskService, *, snapshot_ref: str, task_ref: str, facts: PortfolioAnalyticsFactsV1
) -> None:
    uploaded = service.handle(
        "analysis.input_upload",
        principal_ref=_PRINCIPAL,
        scope=_SCOPE,
        arguments={"input_snapshot_id": snapshot_ref, "facts": _facts_payload(facts)},
    )
    assert uploaded["ok"] is True
    submitted = service.handle(
        "analysis.submit",
        principal_ref=_PRINCIPAL,
        scope=_SCOPE,
        arguments={
            "task_ref": task_ref,
            "input_snapshot_id": snapshot_ref,
            "request": _request_payload(_request()),
        },
    )
    assert submitted["ok"] is True


def _finish(
    service: PortfolioAnalyticsTaskService, task_ref: str
) -> tuple[dict[str, object], object]:
    first = service.maintain(frozenset())
    assert first["ok"] is True and first["result"]["advanced"] is True
    worker = next(iter(service._workers.values()))
    assert worker.process_started is True
    assert worker.process is not None and worker.process.pid is not None
    assert service.handle(
        "analysis.query",
        principal_ref=_PRINCIPAL,
        scope=_SCOPE,
        arguments={"task_ref": task_ref},
    )["result"]["state"] == "running"

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        service.maintain(frozenset())
        result = service.handle(
            "analysis.query",
            principal_ref=_PRINCIPAL,
            scope=_SCOPE,
            arguments={"task_ref": task_ref},
        )["result"]
        if result["state"] in {"succeeded", "unavailable", "failed"}:
            break
        time.sleep(0.01)
    else:
        raise AssertionError("V1 analytics worker did not reach a terminal state")
    return result, worker


def _assert_reaped(worker) -> None:
    assert worker.cleanup_complete is True
    assert worker.process_closed is True
    assert worker.receive_connection.closed is True
    assert worker.child_connection is None
    assert worker.frame_error is None
    assert worker.exit_code == 0
    assert worker.process is not None


def test_v1_task_returns_traceable_modified_dietz_from_spawned_worker(tmp_path) -> None:
    store, service = _service(tmp_path / "v1-success.sqlite")
    facts = _facts(flow_complete=True)
    try:
        _submit(service, snapshot_ref="offline-v1-success-cut", task_ref="offline-v1-success-task", facts=facts)
        result, worker = _finish(service, "offline-v1-success-task")

        assert result["state"] == "succeeded"
        report = result["result"]
        assert report["version"] == 1
        assert report["portfolio_ref"] == _PORTFOLIO
        assert report["membership"]["version"] == 4
        assert report["source"]["mode"] == "imported"
        assert report["source"]["source_ref"] == "user-offline-import"
        assert report["beginning"]["snapshot_ref"] == "offline-cut-2026-01-01"
        assert report["ending"]["snapshot_ref"] == "offline-cut-2026-01-11"
        assert report["beginning"]["nav"] == "100"
        assert report["ending"]["nav"] == "130"
        assert report["external_cashflow_net"] == "20"
        assert report["return_method"] == "MODIFIED_DIETZ_ESTIMATE_V1"
        assert report["return_ratio"] == "0.090909090909090909"
        assert len(report["input_sha256"]) == 64
        assert report["input_sha256"] != result["input_sha256"]
        _assert_reaped(worker)
    finally:
        service.close()
        store.close()


def test_v1_incomplete_flow_coverage_is_unavailable_in_spawned_worker(tmp_path) -> None:
    store, service = _service(tmp_path / "v1-unavailable.sqlite")
    facts = _facts(flow_complete=False)
    try:
        _submit(service, snapshot_ref="offline-v1-unavailable-cut", task_ref="offline-v1-unavailable-task", facts=facts)
        result, worker = _finish(service, "offline-v1-unavailable-task")

        assert result["state"] == "unavailable"
        assert result["detail_code"] == "EXTERNAL_FLOW_COVERAGE_INCOMPLETE"
        report = result["result"]
        assert report["version"] == 1
        assert report["status"] == "UNAVAILABLE"
        assert "EXTERNAL_FLOW_COVERAGE_INCOMPLETE" in report["reason_codes"]
        assert report["beginning"]["nav"] is None
        assert report["ending"]["nav"] is None
        assert report["return_ratio"] is None
        assert len(report["input_sha256"]) == 64
        assert report["input_sha256"] != result["input_sha256"]
        _assert_reaped(worker)
    finally:
        service.close()
        store.close()
