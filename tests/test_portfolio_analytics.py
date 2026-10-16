"""Focused tests for the offline, spot-only portfolio analytics contract."""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from decimal import ROUND_FLOOR, ROUND_HALF_EVEN, Decimal, Inexact, Rounded, localcontext

import pytest

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
    PortfolioAnalyticsSourceUnavailableError,
    PortfolioMembershipV1,
    PortfolioValuationPointV1,
    SpotPositionV1,
)

_NANOSECONDS_PER_DAY = 86_400_000_000_000
_EPOCH = date(1970, 1, 1)
_START = date(2026, 1, 1)
_END = date(2026, 1, 11)
_FLOW_DATE = date(2026, 1, 6)


def _day_end_ns(day: date) -> int:
    return (day - _EPOCH).days * _NANOSECONDS_PER_DAY + _NANOSECONDS_PER_DAY - 1


def _position(day: date, *, price: str = "10", as_of_ns: int | None = None) -> SpotPositionV1:
    cutoff = _day_end_ns(day)
    mark_time = cutoff if as_of_ns is None else as_of_ns
    return SpotPositionV1(
        position_ref="position-a",
        member_ref="strategy-a",
        instrument_ref="ABC-EUR-SPOT",
        product_kind="SPOT",
        base_currency="ABC",
        quote_currency="EUR",
        price_unit="QUOTE_PER_BASE",
        quantity=Decimal("10"),
        unit_price=Decimal(price),
        price_as_of_ns=mark_time,
        price_valid_until_ns=max(cutoff, mark_time),
        price_source_ref="marks",
        price_source_version="marks-v1",
        price_source_generation="marks-generation-1",
        price_source_cursor=f"mark-{day.isoformat()}",
        price_observation_ref=f"observation-{day.isoformat()}",
        instrument_metadata_ref="instrument-catalog",
        instrument_metadata_version="instruments-v1",
    )


def _point(
    day: date,
    *,
    usd_cash: str,
    position: SpotPositionV1 | None = None,
    covered_members: tuple[str, ...] = ("strategy-a",),
    complete: bool = True,
) -> PortfolioValuationPointV1:
    cutoff = _day_end_ns(day)
    return PortfolioValuationPointV1(
        valuation_date_utc=day,
        as_of_ns=cutoff,
        snapshot_ref=f"snapshot-{day.isoformat()}",
        source_generation="portfolio-generation-1",
        source_cursor=f"portfolio-cursor-{day.isoformat()}",
        valuation_cut_policy="UTC_CALENDAR_DAY_END_V1",
        coverage_complete=complete,
        covered_member_refs=covered_members,
        covered_asset_classes=("cash", "spot"),
        cash_balances=(
            CashBalanceV1(
                balance_ref="usd-cash",
                member_ref="strategy-a",
                currency="USD",
                amount=Decimal(usd_cash),
            ),
        ),
        spot_positions=(position or _position(day),),
    )


def _fx(
    day: date,
    rate: str,
    *,
    base: str = "EUR",
    quote: str = "USD",
    as_of_ns: int | None = None,
    valid_until_ns: int | None = None,
) -> FxObservationV1:
    cutoff = _day_end_ns(day)
    observation_time = cutoff if as_of_ns is None else as_of_ns
    validity = cutoff if valid_until_ns is None else valid_until_ns
    return FxObservationV1(
        observation_ref=f"fx-{base}-{quote}-{day.isoformat()}",
        base_currency=base,
        quote_currency=quote,
        direction="BASE_TO_QUOTE",
        rate_unit="QUOTE_PER_BASE",
        rate=Decimal(rate),
        as_of_ns=observation_time,
        valid_until_ns=validity,
        source_ref="fx-source",
        source_version="fx-v1",
        source_generation="fx-generation-1",
        source_cursor=f"fx-cursor-{day.isoformat()}",
    )


def _facts(
    *,
    source_mode: str = "imported",
    beginning: PortfolioValuationPointV1 | None = None,
    ending: PortfolioValuationPointV1 | None = None,
    flows: tuple[ExternalCapitalFlowV1, ...] | None = None,
    flow_complete: bool = True,
    fx: tuple[FxObservationV1, ...] | None = None,
    membership: PortfolioMembershipV1 | None = None,
) -> PortfolioAnalyticsFactsV1:
    begin = beginning or _point(_START, usd_cash="122")
    finish = ending or _point(_END, usd_cash="186")
    selected_flows = flows
    if selected_flows is None:
        selected_flows = (
            ExternalCapitalFlowV1(
                flow_ref="capital-1",
                direction="CONTRIBUTION",
                amount=Decimal("20"),
                currency="USD",
                effective_at_ns=_day_end_ns(_FLOW_DATE),
                source_ref="capital-ledger",
                source_version="capital-v1",
                source_generation="portfolio-generation-1",
                source_cursor="capital-cursor-6",
            ),
        )
    selected_membership = membership or PortfolioMembershipV1(
        portfolio_ref="portfolio-a",
        membership_version=3,
        member_refs=("strategy-a",),
        effective_start_date_utc=date(2025, 1, 1),
        effective_end_date_utc_exclusive=None,
        source_ref="membership-source",
        source_version="membership-v1",
    )
    coverage = ExternalFlowCoverageV1(
        source_ref="capital-ledger",
        source_version="capital-v1",
        source_generation="portfolio-generation-1",
        start_as_of_ns=begin.as_of_ns,
        end_as_of_ns=finish.as_of_ns,
        start_cursor="capital-cursor-start",
        end_cursor="capital-cursor-end",
        complete=flow_complete,
    )
    selected_fx = fx
    if selected_fx is None:
        selected_fx = (_fx(_START, "1.1"), _fx(_END, "1.2"))
    return PortfolioAnalyticsFactsV1(
        portfolio_ref="portfolio-a",
        source_mode=source_mode,
        source_ref="trusted-facts-source",
        source_version="facts-v1",
        source_generation="portfolio-generation-1",
        snapshot_ref="facts-cut-2026-01",
        valuation_basis_ref="cash_spot_after_booked_internal_flows_v1",
        membership=selected_membership,
        beginning=begin,
        ending=finish,
        external_flows=selected_flows,
        flow_coverage=coverage,
        fx_observations=selected_fx,
    )


class FixedFactsSource:
    def __init__(self, facts: PortfolioAnalyticsFactsV1 | None) -> None:
        self.facts = facts
        self.calls: list[tuple[str, PortfolioAnalyticsRequestV1]] = []

    def read_portfolio_facts(
        self, principal_ref: str, request: PortfolioAnalyticsRequestV1
    ) -> PortfolioAnalyticsFactsV1:
        self.calls.append((principal_ref, request))
        if self.facts is None:
            raise PortfolioAnalyticsSourceUnavailableError
        return self.facts


def _request() -> PortfolioAnalyticsRequestV1:
    return PortfolioAnalyticsRequestV1(
        portfolio_ref="portfolio-a",
        membership_version=3,
        period_start_date_utc=_START,
        period_end_date_utc=_END,
        reporting_currency="USD",
    )


def _service(facts: PortfolioAnalyticsFactsV1 | None, *, max_fx_age_days: int = 20):
    source = FixedFactsSource(facts)
    service = PortfolioAnalyticsService(
        source,
        PortfolioAnalyticsModelProfileV1(
            model_profile_ref="spot-valuation-v1",
            max_mark_age_ns=2 * _NANOSECONDS_PER_DAY,
            max_fx_age_ns=max_fx_age_days * _NANOSECONDS_PER_DAY,
        ),
        allowed_source_modes=("research", "imported", "paper"),
    )
    return service, source


def test_spot_nav_and_modified_dietz_use_explicit_fx_and_eod_flow_weight():
    service, source = _service(_facts())

    report = service.analyze_snapshot_v1(_request(), principal_ref="principal-a")

    assert report.status == "AVAILABLE"
    assert report.reason_codes == ()
    assert report.beginning_nav == Decimal("232.000000000000000000")
    assert report.ending_nav == Decimal("306.000000000000000000")
    assert report.external_cashflow_net == Decimal("20.000000000000000000")
    with localcontext() as context:
        context.prec = 50
        expected = (Decimal(54) / Decimal(242)).quantize(
            Decimal("1e-18"), rounding=ROUND_HALF_EVEN
        )
    assert report.modified_dietz_return == expected
    assert report.return_method == "MODIFIED_DIETZ_ESTIMATE_V1"
    assert report.flow_weight_policy == "UTC_CALENDAR_DAY_END_V1"
    assert report.input_sha256 is not None and len(report.input_sha256) == 64
    assert source.calls == [("principal-a", _request())]
    assert report.to_payload()["return_ratio"] == format(expected, "f").rstrip("0").rstrip(".")


def test_calculation_context_is_independent_of_caller_decimal_context():
    service, _ = _service(_facts())
    baseline = service.analyze_snapshot_v1(_request(), principal_ref="principal-a")

    with localcontext() as ambient:
        ambient.prec = 7
        ambient.Emin = -7
        ambient.Emax = 7
        ambient.rounding = ROUND_FLOOR
        ambient.traps[Inexact] = True
        ambient.traps[Rounded] = True
        under_changed_context = service.analyze_snapshot_v1(
            _request(), principal_ref="principal-a"
        )

    assert under_changed_context == baseline
    assert baseline.to_payload()["decimal_policy"] == (
        "PRECISION_50_EMIN_NEG999999_EMAX_999999_HALF_EVEN_TRAPS_INVALID_DIVISION_OVERFLOW_"
        "QUANTIZE_18_CANONICAL_STRING_V1"
    )


def test_foreign_external_flow_uses_fx_at_its_effective_cut():
    flow = ExternalCapitalFlowV1(
        flow_ref="capital-eur-1",
        direction="CONTRIBUTION",
        amount=Decimal("20"),
        currency="EUR",
        effective_at_ns=_day_end_ns(_FLOW_DATE),
        source_ref="capital-ledger",
        source_version="capital-v1",
        source_generation="portfolio-generation-1",
        source_cursor="capital-cursor-6",
    )
    facts = _facts(
        flows=(flow,),
        fx=(_fx(_START, "1.1"), _fx(_FLOW_DATE, "1.15"), _fx(_END, "1.2")),
    )
    service, _ = _service(facts)

    report = service.analyze_snapshot_v1(_request(), principal_ref="principal-a")

    assert report.status == "AVAILABLE"
    assert report.external_cashflow_net == Decimal("23.000000000000000000")
    expected = (Decimal("306") - Decimal("232") - Decimal("23")) / (
        Decimal("232") + Decimal("23") * Decimal("0.5")
    )
    assert report.modified_dietz_return == expected.quantize(
        Decimal("1e-18"), rounding=ROUND_HALF_EVEN
    )


def test_digest_is_recomputed_from_facts_and_stable_for_reordered_fx_rows():
    facts = _facts()
    reordered = replace(facts, fx_observations=tuple(reversed(facts.fx_observations)))
    service_a, _ = _service(facts)
    service_b, _ = _service(reordered)
    report_a = service_a.analyze_snapshot_v1(_request(), principal_ref="principal-a")
    report_b = service_b.analyze_snapshot_v1(_request(), principal_ref="principal-a")
    assert report_a.input_sha256 == report_b.input_sha256

    altered = replace(
        facts,
        ending=replace(facts.ending, spot_positions=(_position(_END, price="11"),)),
    )
    service_c, _ = _service(altered)
    report_c = service_c.analyze_snapshot_v1(_request(), principal_ref="principal-a")
    assert report_c.input_sha256 != report_a.input_sha256


@pytest.mark.parametrize(
    ("fx_rows", "max_fx_age_days", "reason"),
    [
        ((), 20, "FX_RATE_MISSING"),
        (
            (
                _fx(
                    _START,
                    "1.1",
                    as_of_ns=_day_end_ns(_START) + 1,
                    valid_until_ns=_day_end_ns(_START) + 1,
                ),
            ),
            20,
            "FX_RATE_AFTER_CUT",
        ),
        (
            (
                _fx(
                    _START,
                    "1.1",
                    as_of_ns=_day_end_ns(_START) - 1,
                    valid_until_ns=_day_end_ns(_START) - 1,
                ),
                _fx(_END, "1.2"),
            ),
            20,
            "FX_RATE_EXPIRED_AT_CUT",
        ),
        ((_fx(date(2025, 12, 20), "1.1"), _fx(_END, "1.2")), 2, "FX_RATE_STALE"),
        (
            (
                _fx(_START, "0.9090909090909090909090909091", base="USD", quote="EUR"),
                _fx(_END, "0.8333333333333333333333333333", base="USD", quote="EUR"),
            ),
            20,
            "FX_PAIR_DIRECTION_UNSUPPORTED",
        ),
    ],
)
def test_fx_missing_future_expired_stale_or_inverse_is_unavailable(
    fx_rows: tuple[FxObservationV1, ...], max_fx_age_days: int, reason: str
):
    service, _ = _service(_facts(fx=fx_rows), max_fx_age_days=max_fx_age_days)

    report = service.analyze_snapshot_v1(_request(), principal_ref="principal-a")

    assert report.status == "UNAVAILABLE"
    assert reason in report.reason_codes
    assert report.beginning_nav is None
    assert report.ending_nav is None
    assert report.modified_dietz_return is None


def test_stale_or_future_mark_is_unavailable_with_no_zero_substitution():
    stale_mark = _position(_START, as_of_ns=_day_end_ns(_START) - 3 * _NANOSECONDS_PER_DAY)
    facts = _facts(beginning=_point(_START, usd_cash="122", position=stale_mark))
    service, _ = _service(facts)

    stale_report = service.analyze_snapshot_v1(_request(), principal_ref="principal-a")

    assert stale_report.status == "UNAVAILABLE"
    assert "STALE_MARK" in stale_report.reason_codes
    assert stale_report.beginning_nav is None

    future_mark = _position(_START, as_of_ns=_day_end_ns(_START) + 1)
    future_facts = _facts(beginning=_point(_START, usd_cash="122", position=future_mark))
    future_service, _ = _service(future_facts)
    future_report = future_service.analyze_snapshot_v1(_request(), principal_ref="principal-a")
    assert future_report.status == "UNAVAILABLE"
    assert "FUTURE_MARK" in future_report.reason_codes


def test_full_same_membership_version_and_asset_coverage_are_required():
    facts = _facts(beginning=_point(_START, usd_cash="122", covered_members=()))
    service, _ = _service(facts)

    report = service.analyze_snapshot_v1(_request(), principal_ref="principal-a")

    assert report.status == "UNAVAILABLE"
    assert "MEMBERSHIP_COVERAGE_MISMATCH" in report.reason_codes
    assert report.modified_dietz_return is None


def test_same_member_instrument_cannot_be_split_across_currency_pairs():
    first = _position(_START)
    conflicting_currency_pair = replace(first, position_ref="position-2", quote_currency="GBP")
    beginning = replace(
        _point(_START, usd_cash="122"),
        spot_positions=(first, conflicting_currency_pair),
    )
    facts = _facts(
        beginning=beginning
    )
    service, _ = _service(facts)

    report = service.analyze_snapshot_v1(_request(), principal_ref="principal-a")

    assert report.status == "UNAVAILABLE"
    assert "DUPLICATE_SPOT_ASSET_FACT" in report.reason_codes
    assert report.beginning_nav is None


def test_incomplete_flow_source_and_cross_generation_flow_fail_closed():
    incomplete_service, _ = _service(_facts(flow_complete=False))
    incomplete = incomplete_service.analyze_snapshot_v1(_request(), principal_ref="principal-a")
    assert incomplete.status == "UNAVAILABLE"
    assert "EXTERNAL_FLOW_COVERAGE_INCOMPLETE" in incomplete.reason_codes

    changed_flow = ExternalCapitalFlowV1(
        flow_ref="capital-1",
        direction="CONTRIBUTION",
        amount=Decimal("20"),
        currency="USD",
        effective_at_ns=_day_end_ns(_FLOW_DATE),
        source_ref="capital-ledger",
        source_version="capital-v1",
        source_generation="wrong-generation",
        source_cursor="capital-cursor-6",
    )
    generation_service, _ = _service(_facts(flows=(changed_flow,)))
    generation_report = generation_service.analyze_snapshot_v1(
        _request(), principal_ref="principal-a"
    )
    assert generation_report.status == "UNAVAILABLE"
    assert "EXTERNAL_FLOW_SOURCE_MISMATCH" in generation_report.reason_codes


def test_unsupported_source_or_product_is_explicitly_unavailable():
    live_service, _ = _service(_facts(source_mode="live"))
    live_report = live_service.analyze_snapshot_v1(_request(), principal_ref="principal-a")
    assert live_report.status == "UNAVAILABLE"
    assert "SOURCE_MODE_NOT_ALLOWED" in live_report.reason_codes
    assert "LIVE_SOURCE_UNSUPPORTED_IN_V1" in live_report.reason_codes

    future_position = replace(_position(_START), product_kind="FUTURE")
    future_facts = _facts(beginning=_point(_START, usd_cash="122", position=future_position))
    product_service, _ = _service(future_facts)
    product_report = product_service.analyze_snapshot_v1(
        _request(), principal_ref="principal-a"
    )
    assert product_report.status == "UNAVAILABLE"
    assert "UNSUPPORTED_PRODUCT" in product_report.reason_codes


def test_only_external_capital_flow_directions_are_accepted():
    with pytest.raises(PortfolioAnalyticsError, match="INVALID_EXTERNAL_FLOW_DIRECTION"):
        ExternalCapitalFlowV1(
            flow_ref="fee-row",
            direction="FEE",
            amount=Decimal("1"),
            currency="USD",
            effective_at_ns=_day_end_ns(_FLOW_DATE),
            source_ref="capital-ledger",
            source_version="capital-v1",
            source_generation="portfolio-generation-1",
            source_cursor="capital-cursor-6",
        )


def test_source_unavailable_does_not_invent_zero_financial_values():
    service, source = _service(None)

    report = service.analyze_snapshot_v1(_request(), principal_ref="principal-a")

    assert report.status == "UNAVAILABLE"
    assert report.reason_codes == ("SOURCE_FACTS_UNAVAILABLE",)
    assert report.beginning_nav is None
    assert report.ending_nav is None
    assert report.modified_dietz_return is None
    assert len(source.calls) == 1


def test_non_eod_valuation_timestamp_is_rejected_at_fact_boundary():
    with pytest.raises(PortfolioAnalyticsError, match="VALUATION_NOT_AT_UTC_DAY_END"):
        replace(_point(_START, usd_cash="122"), as_of_ns=_day_end_ns(_START) - 1)
