"""Typed V2 bundle around the accepted offline portfolio metrics kernels."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from bt_api_risk.portfolio_analytics import PortfolioAnalyticsError
from bt_api_risk.portfolio_analytics_v2 import (
    CANONICAL_SERIALIZATION_V2,
    DECIMAL_SERIALIZATION_V2,
    LossHistoryFactsV2,
    NavHistoryFactsV2,
    PortfolioAnalyticsFactsV2,
    PortfolioAnalyticsRequestV2,
    PortfolioAnalyticsServiceV2,
    ScenarioFactsV2,
    SpotFactsV2,
    parse_facts_v2,
    parse_request_v2,
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

_UTC = timezone.utc
_T0 = datetime(2026, 1, 1, tzinfo=_UTC)
_DIGEST = "a" * 64


def _time(days: int) -> datetime:
    return _T0 + timedelta(days=days)


def _spot(ref: str, *, base: str, quote: str, quantity: str, price: str, fx: str):
    return SpotPositionMetricInputV1(
        position_ref=ref,
        as_of_utc=_T0,
        base_currency=base,
        quote_currency=quote,
        quantity=Decimal(quantity),
        quantity_unit=base,
        unit_price=Decimal(price),
        price_unit=PRICE_UNIT_V1,
        reporting_per_quote=Decimal(fx),
        fx_unit=FX_UNIT_V1,
    )


def _facts() -> PortfolioAnalyticsFactsV2:
    positions = (
        _spot("btc-long", base="BTC", quote="USD", quantity="2", price="100", fx="1"),
        _spot("btc-short", base="BTC", quote="USD", quantity="-0.5", price="100", fx="1"),
        _spot("eth-long", base="ETH", quote="EUR", quantity="3", price="20", fx="1.1"),
    )
    return PortfolioAnalyticsFactsV2(
        portfolio_ref="portfolio-01",
        source_mode="imported",
        source_ref="offline-facts",
        source_version="offline-facts-v2",
        source_generation="generation-7",
        facts_snapshot_ref="snapshot-v2-7",
        spot=SpotFactsV2(
            status="available",
            reason_code=None,
            as_of_utc=_T0,
            source_ref="spot-ledger",
            source_version="spot-ledger-v1",
            source_generation="generation-7",
            source_cursor="spot-cursor-7",
            coverage_complete=True,
            positions=positions,
        ),
        nav_history=NavHistoryFactsV2(
            status="available",
            reason_code=None,
            source_ref="nav-ledger",
            source_version="nav-ledger-v1",
            source_generation="generation-7",
            coverage_start_utc=_time(0),
            coverage_end_utc=_time(3),
            start_cursor="nav-start-0",
            end_cursor="nav-end-3",
            coverage_complete=True,
            observations=tuple(
                NavObservationV1(_time(day), Decimal(nav), "USD")
                for day, nav in enumerate(("100", "120", "90", "110"))
            ),
        ),
        loss_history=LossHistoryFactsV2(
            status="available",
            reason_code=None,
            horizon_ref="one-day-v1",
            source_ref="loss-ledger",
            source_version="loss-ledger-v1",
            source_generation="generation-7",
            coverage_start_utc=_time(0),
            coverage_end_utc=_time(4),
            start_cursor="loss-start-0",
            end_cursor="loss-end-4",
            coverage_complete=True,
            observations=tuple(
                HistoricalLossObservationV1(
                    _time(day), Decimal(str(day + 1)), "USD", LOSS_UNIT_V1
                )
                for day in range(5)
            ),
        ),
        scenario=ScenarioFactsV2(
            status="available",
            reason_code=None,
            scenario_ref="risk-off",
            scenario_version="risk-off-v3",
            source_ref="scenario-catalog",
            source_version="scenario-catalog-v1",
            source_generation="scenario-generation-3",
            source_cursor="scenario-cursor-3",
            coverage_complete=True,
            shocks=(
                SpotPriceFxShockV1("btc-long", Decimal("0.1"), Decimal("0"), SHOCK_UNIT_V1),
                SpotPriceFxShockV1("btc-short", Decimal("0.1"), Decimal("0"), SHOCK_UNIT_V1),
                SpotPriceFxShockV1("eth-long", Decimal("0.2"), Decimal("-0.1"), SHOCK_UNIT_V1),
            ),
        ),
    )


def _request() -> PortfolioAnalyticsRequestV2:
    return PortfolioAnalyticsRequestV2(
        portfolio_ref="portfolio-01",
        reporting_currency="USD",
        loss_horizon_ref="one-day-v1",
        confidence=Decimal("0.8"),
        scenario_ref="risk-off",
        scenario_version="risk-off-v3",
    )


def test_v2_task_bundle_returns_all_four_metrics_with_traceable_hashes() -> None:
    facts = _facts()
    request = _request()
    report = PortfolioAnalyticsServiceV2().analyze_snapshot_v2(
        facts, request, input_sha256=_DIGEST
    )
    payload = report.to_payload()
    metrics = payload["metrics"]

    assert payload["status"] == "AVAILABLE"
    assert payload["calculation_ref"] == "portfolio_metrics_v1_bundle_v2"
    assert payload["serialization_ref"] == CANONICAL_SERIALIZATION_V2
    assert payload["decimal_serialization_ref"] == DECIMAL_SERIALIZATION_V2
    assert metrics["spot_exposure"]["status"] == "available"
    assert metrics["spot_exposure"]["value"]["net_reporting_notional"] == "216"
    assert metrics["spot_exposure"]["value"]["gross_reporting_notional"] == "316"
    assert metrics["max_drawdown"]["value"]["max_drawdown_ratio"] == "-0.25"
    assert metrics["max_drawdown"]["value"]["peak_nav"] == "120"
    assert metrics["max_drawdown"]["value"]["trough_nav"] == "90"
    assert metrics["historical_var_es"]["value"]["var_loss"] == "4"
    assert metrics["historical_var_es"]["value"]["expected_shortfall_loss"] == "5"
    assert metrics["stress_scenario"]["value"]["pnl_reporting_amount"] == "20.28"
    assert payload["provenance"]["spot"]["source_cursor"] == "spot-cursor-7"
    assert payload["provenance"]["nav_history"]["start_cursor"] == "nav-start-0"
    assert payload["provenance"]["loss_history"]["end_cursor"] == "loss-end-4"

    report_digest = payload.pop("report_sha256")
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    assert hashlib.sha256(canonical).hexdigest() == report_digest
    assert report.to_payload() == {**payload, "report_sha256": report_digest}


def test_v2_codec_round_trip_is_canonical_and_schema_strict() -> None:
    facts = _facts()
    request = _request()

    assert parse_facts_v2(facts.to_payload()) == facts
    assert parse_request_v2(request.to_payload()) == request
    zero_cursor = replace(facts, spot=replace(facts.spot, source_cursor="0"))
    assert parse_facts_v2(zero_cursor.to_payload()) == zero_cursor
    with pytest.raises(PortfolioAnalyticsError):
        replace(facts.spot, source_cursor=None)
    with pytest.raises(PortfolioAnalyticsError):
        parse_request_v2({**request.to_payload(), "unexpected": "value"})
    bad_fact_payload = facts.to_payload()
    del bad_fact_payload["spot"]
    with pytest.raises(PortfolioAnalyticsError):
        parse_facts_v2(bad_fact_payload)


def test_unavailable_facts_remain_unavailable_instead_of_becoming_zero() -> None:
    facts = PortfolioAnalyticsFactsV2(
        portfolio_ref="portfolio-01",
        source_mode="research",
        source_ref="offline-facts",
        source_version="offline-facts-v2",
        source_generation="generation-7",
        facts_snapshot_ref="snapshot-v2-empty",
        spot=SpotFactsV2(
            "unavailable", "NO_SOURCE_DATA", None, None, None, None, None, None, ()
        ),
        nav_history=NavHistoryFactsV2(
            "unavailable", "SOURCE_INCOMPLETE", None, None, None, None, None, None, None, None, ()
        ),
        loss_history=LossHistoryFactsV2(
            "unavailable",
            "NO_SOURCE_DATA",
            "one-day-v1",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            (),
        ),
        scenario=ScenarioFactsV2(
            "unavailable",
            "NO_SOURCE_DATA",
            "risk-off",
            "risk-off-v3",
            None,
            None,
            None,
            None,
            None,
            (),
        ),
    )
    report = PortfolioAnalyticsServiceV2().analyze_snapshot_v2(
        facts, _request(), input_sha256=_DIGEST
    )
    payload = report.to_payload()

    assert payload["status"] == "UNAVAILABLE"
    assert all(
        item["status"] == "unavailable" and item["value"] is None
        for item in payload["metrics"].values()
    )


def test_one_unavailable_dataset_does_not_hide_other_available_metrics() -> None:
    facts = _facts()
    partial = replace(
        facts,
        nav_history=NavHistoryFactsV2(
            "unavailable",
            "SOURCE_STALE",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            (),
        ),
    )

    payload = PortfolioAnalyticsServiceV2().analyze_snapshot_v2(
        partial, _request(), input_sha256=_DIGEST
    ).to_payload()
    metrics = payload["metrics"]

    assert payload["status"] == "AVAILABLE"
    assert metrics["max_drawdown"] == {
        "reason_code": "SOURCE_STALE",
        "status": "unavailable",
        "value": None,
    }
    assert metrics["spot_exposure"]["status"] == "available"
    assert metrics["historical_var_es"]["status"] == "available"
    assert metrics["stress_scenario"]["status"] == "available"


def test_scenario_shocks_must_cover_every_spot_row() -> None:
    facts = _facts()
    incomplete = ScenarioFactsV2(
        status="available",
        reason_code=None,
        scenario_ref="risk-off",
        scenario_version="risk-off-v3",
        source_ref="scenario-catalog",
        source_version="scenario-catalog-v1",
        source_generation="scenario-generation-3",
        source_cursor="scenario-cursor-3",
        coverage_complete=True,
        shocks=facts.scenario.shocks[:-1],
    )
    broken = PortfolioAnalyticsFactsV2(
        portfolio_ref=facts.portfolio_ref,
        source_mode=facts.source_mode,
        source_ref=facts.source_ref,
        source_version=facts.source_version,
        source_generation=facts.source_generation,
        facts_snapshot_ref=facts.facts_snapshot_ref,
        spot=facts.spot,
        nav_history=facts.nav_history,
        loss_history=facts.loss_history,
        scenario=incomplete,
    )

    with pytest.raises(PortfolioAnalyticsError) as error:
        PortfolioAnalyticsServiceV2().analyze_snapshot_v2(
            broken, _request(), input_sha256=_DIGEST
        )
    assert error.value.code == "INCOMPLETE_SHOCK_COVERAGE"
