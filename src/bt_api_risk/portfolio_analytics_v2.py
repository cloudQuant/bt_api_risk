"""Versioned offline facts and report for the portfolio metrics task.

V2 integrates the accepted deterministic metrics kernels with the existing
``portfolio_analytics`` task plane. The facts are caller supplied and retain
their declared source cuts; this module does not establish source authenticity,
freshness, or account completeness. Missing datasets are represented as
unavailable rather than as zero-valued observations.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Final

from .portfolio_analytics import (
    PortfolioAnalyticsError,
    _canonical_decimal,
    _require_currency,
    _require_text,
)
from .portfolio_metrics_v1 import (
    DrawdownReportV1,
    HistoricalLossObservationV1,
    HistoricalVarEsReportV1,
    NavObservationV1,
    PortfolioMetricsError,
    SpotExposureReportV1,
    SpotPositionMetricInputV1,
    SpotPriceFxShockV1,
    SpotStressReportV1,
    _MAX_ROWS,
    _require_metric_decimal,
    _require_ref,
    _require_utc,
    calculate_historical_var_es_v1,
    calculate_max_drawdown_v1,
    calculate_spot_exposure_v1,
    calculate_spot_scenario_pnl_v1,
)

PORTFOLIO_ANALYTICS_SCHEMA_V2: Final[str] = "portfolio_analytics_v2"
PORTFOLIO_ANALYTICS_V2_CALCULATION: Final[str] = "portfolio_metrics_v1_bundle_v2"
CANONICAL_SERIALIZATION_V2: Final[str] = "json_sort_keys_compact_ascii_v1"
DECIMAL_SERIALIZATION_V2: Final[str] = "finite_decimal_fixed_point_canonical_v1"
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_MODES: Final[frozenset[str]] = frozenset({"research", "imported", "paper"})
_DATASET_UNAVAILABLE_REASONS: Final[frozenset[str]] = frozenset(
    {
        "NO_SOURCE_DATA",
        "SOURCE_INCOMPLETE",
        "SOURCE_STALE",
        "SOURCE_ERROR",
        "NOT_APPLICABLE",
    }
)
_METRIC_UNAVAILABLE_REASONS: Final[frozenset[str]] = (
    _DATASET_UNAVAILABLE_REASONS | {"SPOT_FACTS_UNAVAILABLE"}
)


def _require_source_mode(value: object) -> str:
    if type(value) is not str or value not in _SOURCE_MODES:
        raise PortfolioAnalyticsError("INVALID_SOURCE_MODE")
    return value


def _require_reason(value: object) -> str:
    if type(value) is not str or value not in _DATASET_UNAVAILABLE_REASONS:
        raise PortfolioAnalyticsError("INVALID_UNAVAILABLE_REASON")
    return value


def _availability(
    status: object,
    reason_code: object,
    metadata: tuple[object, ...],
    *,
    complete: object,
    rows: object,
) -> tuple[str, str | None]:
    if status == "available" and type(status) is str:
        if reason_code is not None or complete is not True or not rows:
            raise PortfolioAnalyticsError("INVALID_AVAILABLE_DATASET")
        if any(value is None for value in metadata):
            raise PortfolioAnalyticsError("INVALID_AVAILABLE_DATASET")
        return "available", None
    if status == "unavailable" and type(status) is str:
        reason = _require_reason(reason_code)
        if complete is not None or rows or any(value is not None for value in metadata):
            raise PortfolioAnalyticsError("INVALID_UNAVAILABLE_DATASET")
        return "unavailable", reason
    raise PortfolioAnalyticsError("INVALID_DATASET_STATUS")


def _as_tuple_rows(value: object, item_type: type, *, minimum: int = 1) -> tuple[object, ...]:
    if type(value) not in (tuple, list):
        raise PortfolioAnalyticsError("INVALID_ROWS")
    if not minimum <= len(value) <= _MAX_ROWS:
        raise PortfolioAnalyticsError("INVALID_ROW_COUNT")
    if any(type(item) is not item_type for item in value):
        raise PortfolioAnalyticsError("UNSUPPORTED_ROW_TYPE")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class SpotFactsV2:
    """Spot rows at one explicit cut with their own source cursor."""

    status: str
    reason_code: str | None
    as_of_utc: datetime | None
    source_ref: str | None
    source_version: str | None
    source_generation: str | None
    source_cursor: str | None
    coverage_complete: bool | None
    positions: tuple[SpotPositionMetricInputV1, ...]

    def __post_init__(self) -> None:
        positions = _as_tuple_rows(
            self.positions,
            SpotPositionMetricInputV1,
            minimum=0 if self.status == "unavailable" else 1,
        )
        object.__setattr__(self, "positions", positions)
        metadata = (
            self.as_of_utc,
            self.source_ref,
            self.source_version,
            self.source_generation,
            self.source_cursor,
        )
        status, reason = _availability(
            self.status,
            self.reason_code,
            metadata,
            complete=self.coverage_complete,
            rows=positions,
        )
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "reason_code", reason)
        if status == "available":
            _require_utc(self.as_of_utc)
            _require_text(self.source_ref)
            _require_text(self.source_version, versioned=True)
            _require_text(self.source_generation)
            _require_text(self.source_cursor)
            if any(row.as_of_utc != self.as_of_utc for row in positions):
                raise PortfolioAnalyticsError("SPOT_CUT_MISMATCH")
        elif positions:
            raise PortfolioAnalyticsError("INVALID_UNAVAILABLE_DATASET")


@dataclass(frozen=True, slots=True)
class NavHistoryFactsV2:
    """A complete, ordered NAV history with bounded coverage metadata."""

    status: str
    reason_code: str | None
    source_ref: str | None
    source_version: str | None
    source_generation: str | None
    coverage_start_utc: datetime | None
    coverage_end_utc: datetime | None
    start_cursor: str | None
    end_cursor: str | None
    coverage_complete: bool | None
    observations: tuple[NavObservationV1, ...]

    def __post_init__(self) -> None:
        observations = _as_tuple_rows(
            self.observations,
            NavObservationV1,
            minimum=0 if self.status == "unavailable" else 2,
        )
        object.__setattr__(self, "observations", observations)
        metadata = (
            self.source_ref,
            self.source_version,
            self.source_generation,
            self.coverage_start_utc,
            self.coverage_end_utc,
            self.start_cursor,
            self.end_cursor,
        )
        status, reason = _availability(
            self.status,
            self.reason_code,
            metadata,
            complete=self.coverage_complete,
            rows=observations,
        )
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "reason_code", reason)
        if status == "available":
            _require_text(self.source_ref)
            _require_text(self.source_version, versioned=True)
            _require_text(self.source_generation)
            _require_text(self.start_cursor)
            _require_text(self.end_cursor)
            _require_utc(self.coverage_start_utc)
            _require_utc(self.coverage_end_utc)
            if (
                self.coverage_start_utc != observations[0].as_of_utc
                or self.coverage_end_utc != observations[-1].as_of_utc
            ):
                raise PortfolioAnalyticsError("NAV_COVERAGE_MISMATCH")
        elif observations:
            raise PortfolioAnalyticsError("INVALID_UNAVAILABLE_DATASET")


@dataclass(frozen=True, slots=True)
class LossHistoryFactsV2:
    """Complete ordered loss observations for one declared horizon."""

    status: str
    reason_code: str | None
    horizon_ref: str
    source_ref: str | None
    source_version: str | None
    source_generation: str | None
    coverage_start_utc: datetime | None
    coverage_end_utc: datetime | None
    start_cursor: str | None
    end_cursor: str | None
    coverage_complete: bool | None
    observations: tuple[HistoricalLossObservationV1, ...]

    def __post_init__(self) -> None:
        _require_ref(self.horizon_ref, versioned=True)
        observations = _as_tuple_rows(
            self.observations,
            HistoricalLossObservationV1,
            minimum=0 if self.status == "unavailable" else 2,
        )
        object.__setattr__(self, "observations", observations)
        metadata = (
            self.source_ref,
            self.source_version,
            self.source_generation,
            self.coverage_start_utc,
            self.coverage_end_utc,
            self.start_cursor,
            self.end_cursor,
        )
        status, reason = _availability(
            self.status,
            self.reason_code,
            metadata,
            complete=self.coverage_complete,
            rows=observations,
        )
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "reason_code", reason)
        if status == "available":
            _require_text(self.source_ref)
            _require_text(self.source_version, versioned=True)
            _require_text(self.source_generation)
            _require_text(self.start_cursor)
            _require_text(self.end_cursor)
            _require_utc(self.coverage_start_utc)
            _require_utc(self.coverage_end_utc)
            if (
                self.coverage_start_utc != observations[0].as_of_utc
                or self.coverage_end_utc != observations[-1].as_of_utc
            ):
                raise PortfolioAnalyticsError("LOSS_COVERAGE_MISMATCH")
        elif observations:
            raise PortfolioAnalyticsError("INVALID_UNAVAILABLE_DATASET")


@dataclass(frozen=True, slots=True)
class ScenarioFactsV2:
    """One named, versioned stress assumption and its complete shock rows."""

    status: str
    reason_code: str | None
    scenario_ref: str
    scenario_version: str
    source_ref: str | None
    source_version: str | None
    source_generation: str | None
    source_cursor: str | None
    coverage_complete: bool | None
    shocks: tuple[SpotPriceFxShockV1, ...]

    def __post_init__(self) -> None:
        _require_ref(self.scenario_ref)
        _require_ref(self.scenario_version, versioned=True)
        shocks = _as_tuple_rows(
            self.shocks,
            SpotPriceFxShockV1,
            minimum=0 if self.status == "unavailable" else 1,
        )
        object.__setattr__(self, "shocks", shocks)
        metadata = (
            self.source_ref,
            self.source_version,
            self.source_generation,
            self.source_cursor,
        )
        status, reason = _availability(
            self.status,
            self.reason_code,
            metadata,
            complete=self.coverage_complete,
            rows=shocks,
        )
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "reason_code", reason)
        if status == "available":
            _require_text(self.source_ref)
            _require_text(self.source_version, versioned=True)
            _require_text(self.source_generation)
            _require_text(self.source_cursor)
        elif shocks:
            raise PortfolioAnalyticsError("INVALID_UNAVAILABLE_DATASET")


@dataclass(frozen=True, slots=True)
class PortfolioAnalyticsFactsV2:
    """Immutable, offline task facts; no prices or histories are inferred."""

    portfolio_ref: str
    source_mode: str
    source_ref: str
    source_version: str
    source_generation: str
    facts_snapshot_ref: str
    spot: SpotFactsV2
    nav_history: NavHistoryFactsV2
    loss_history: LossHistoryFactsV2
    scenario: ScenarioFactsV2

    def __post_init__(self) -> None:
        _require_text(self.portfolio_ref)
        _require_source_mode(self.source_mode)
        _require_text(self.source_ref)
        _require_text(self.source_version, versioned=True)
        _require_text(self.source_generation)
        _require_text(self.facts_snapshot_ref)
        if type(self.spot) is not SpotFactsV2:
            raise PortfolioAnalyticsError("INVALID_SPOT_FACTS")
        if type(self.nav_history) is not NavHistoryFactsV2:
            raise PortfolioAnalyticsError("INVALID_NAV_FACTS")
        if type(self.loss_history) is not LossHistoryFactsV2:
            raise PortfolioAnalyticsError("INVALID_LOSS_FACTS")
        if type(self.scenario) is not ScenarioFactsV2:
            raise PortfolioAnalyticsError("INVALID_SCENARIO_FACTS")

    def to_payload(self) -> dict[str, object]:
        return {
            "facts_snapshot_ref": self.facts_snapshot_ref,
            "loss_history": _loss_history_payload(self.loss_history),
            "nav_history": _nav_history_payload(self.nav_history),
            "portfolio_ref": self.portfolio_ref,
            "scenario": _scenario_payload(self.scenario),
            "source_generation": self.source_generation,
            "source_mode": self.source_mode,
            "source_ref": self.source_ref,
            "source_version": self.source_version,
            "spot": _spot_payload(self.spot),
            "version": 2,
        }


@dataclass(frozen=True, slots=True)
class PortfolioAnalyticsRequestV2:
    """Selectors and method parameters; the request carries no facts."""

    portfolio_ref: str
    reporting_currency: str
    loss_horizon_ref: str
    confidence: Decimal
    scenario_ref: str
    scenario_version: str

    def __post_init__(self) -> None:
        _require_text(self.portfolio_ref)
        _require_currency(self.reporting_currency)
        _require_ref(self.loss_horizon_ref, versioned=True)
        _require_metric_decimal(self.confidence)
        if not Decimal("0") < self.confidence < Decimal("1"):
            raise PortfolioAnalyticsError("INVALID_CONFIDENCE")
        _require_ref(self.scenario_ref)
        _require_ref(self.scenario_version, versioned=True)

    def to_payload(self) -> dict[str, object]:
        return {
            "confidence": _canonical_decimal(self.confidence),
            "loss_horizon_ref": self.loss_horizon_ref,
            "portfolio_ref": self.portfolio_ref,
            "reporting_currency": self.reporting_currency,
            "scenario_ref": self.scenario_ref,
            "scenario_version": self.scenario_version,
            "version": 2,
        }


@dataclass(frozen=True, slots=True)
class MetricOutcomeV2:
    """A calculated metric or one explicit nonnumeric availability state."""

    status: str
    reason_code: str | None
    value: SpotExposureReportV1 | DrawdownReportV1 | HistoricalVarEsReportV1 | SpotStressReportV1 | None

    def __post_init__(self) -> None:
        valid_value_type = type(self.value) in {
            SpotExposureReportV1,
            DrawdownReportV1,
            HistoricalVarEsReportV1,
            SpotStressReportV1,
        }
        if (
            type(self.status) is str
            and self.status == "available"
            and self.reason_code is None
            and valid_value_type
        ):
            return
        if (
            type(self.status) is str
            and self.status == "unavailable"
            and type(self.reason_code) is str
            and self.reason_code in _METRIC_UNAVAILABLE_REASONS
            and self.value is None
        ):
            return
        raise PortfolioAnalyticsError("INVALID_METRIC_OUTCOME")

    def to_payload(self) -> dict[str, object]:
        if self.status == "unavailable":
            return {"reason_code": self.reason_code, "status": "unavailable", "value": None}
        return {
            "reason_code": None,
            "status": "available",
            "value": _metric_value_payload(self.value),
        }


@dataclass(frozen=True, slots=True)
class PortfolioAnalyticsReportV2:
    """Deterministic result and source-cut projection for one V2 task."""

    portfolio_ref: str
    reporting_currency: str
    source_mode: str
    source_ref: str
    source_version: str
    source_generation: str
    facts_snapshot_ref: str
    input_sha256: str
    request_sha256: str
    spot: SpotFactsV2
    nav_history: NavHistoryFactsV2
    loss_history: LossHistoryFactsV2
    scenario: ScenarioFactsV2
    spot_exposure: MetricOutcomeV2
    max_drawdown: MetricOutcomeV2
    historical_var_es: MetricOutcomeV2
    stress_scenario: MetricOutcomeV2

    def __post_init__(self) -> None:
        for value in (self.input_sha256, self.request_sha256):
            if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
                raise PortfolioAnalyticsError("INVALID_DIGEST")

    @property
    def status(self) -> str:
        return (
            "AVAILABLE"
            if any(
                item.status == "available"
                for item in (
                    self.spot_exposure,
                    self.max_drawdown,
                    self.historical_var_es,
                    self.stress_scenario,
                )
            )
            else "UNAVAILABLE"
        )

    def to_payload(self) -> dict[str, object]:
        base: dict[str, object] = {
            "calculation_ref": PORTFOLIO_ANALYTICS_V2_CALCULATION,
            "facts_snapshot_ref": self.facts_snapshot_ref,
            "input_sha256": self.input_sha256,
            "metrics": {
                "historical_var_es": self.historical_var_es.to_payload(),
                "max_drawdown": self.max_drawdown.to_payload(),
                "spot_exposure": self.spot_exposure.to_payload(),
                "stress_scenario": self.stress_scenario.to_payload(),
            },
            "portfolio_ref": self.portfolio_ref,
            "provenance": {
                "facts_source": {
                    "generation": self.source_generation,
                    "mode": self.source_mode,
                    "source_ref": self.source_ref,
                    "source_version": self.source_version,
                    "snapshot_ref": self.facts_snapshot_ref,
                },
                "loss_history": _loss_history_provenance(self.loss_history),
                "nav_history": _nav_history_provenance(self.nav_history),
                "scenario": _scenario_provenance(self.scenario),
                "spot": _spot_provenance(self.spot),
            },
            "reporting_currency": self.reporting_currency,
            "request_sha256": self.request_sha256,
            "schema_ref": PORTFOLIO_ANALYTICS_SCHEMA_V2,
            "serialization_ref": CANONICAL_SERIALIZATION_V2,
            "decimal_serialization_ref": DECIMAL_SERIALIZATION_V2,
            "status": self.status,
            "version": 2,
        }
        digest = hashlib.sha256(_canonical_json_v2(base)).hexdigest()
        return {**base, "report_sha256": digest}


class PortfolioAnalyticsServiceV2:
    """Run the four accepted pure metrics over one immutable V2 fact bundle."""

    def analyze_snapshot_v2(
        self,
        facts: PortfolioAnalyticsFactsV2,
        request: PortfolioAnalyticsRequestV2,
        *,
        input_sha256: str,
    ) -> PortfolioAnalyticsReportV2:
        if type(facts) is not PortfolioAnalyticsFactsV2:
            raise PortfolioAnalyticsError("INVALID_FACTS")
        if type(request) is not PortfolioAnalyticsRequestV2:
            raise PortfolioAnalyticsError("INVALID_REQUEST")
        if facts.portfolio_ref != request.portfolio_ref:
            raise PortfolioAnalyticsError("PORTFOLIO_MISMATCH")
        if facts.loss_history.horizon_ref != request.loss_horizon_ref:
            raise PortfolioAnalyticsError("LOSS_HORIZON_MISMATCH")
        if (
            facts.scenario.scenario_ref != request.scenario_ref
            or facts.scenario.scenario_version != request.scenario_version
        ):
            raise PortfolioAnalyticsError("SCENARIO_VERSION_MISMATCH")
        if type(input_sha256) is not str or _SHA256_RE.fullmatch(input_sha256) is None:
            raise PortfolioAnalyticsError("INVALID_DIGEST")

        exposure = self._unavailable(self._spot_unavailable_reason(facts.spot))
        drawdown = self._unavailable(
            self._dataset_reason(
                facts.nav_history.status, facts.nav_history.reason_code
            )
        )
        var_es = self._unavailable(
            self._dataset_reason(
                facts.loss_history.status, facts.loss_history.reason_code
            )
        )
        stress = self._unavailable(
            "SPOT_FACTS_UNAVAILABLE"
            if facts.spot.status == "unavailable"
            else self._dataset_reason(facts.scenario.status, facts.scenario.reason_code)
        )

        try:
            if facts.spot.status == "available":
                exposure = MetricOutcomeV2(
                    "available",
                    None,
                    calculate_spot_exposure_v1(
                        facts.spot.positions,
                        reporting_currency=request.reporting_currency,
                    ),
                )
            if facts.nav_history.status == "available":
                if (
                    facts.nav_history.observations[0].currency
                    != request.reporting_currency
                ):
                    raise PortfolioAnalyticsError("NAV_REPORTING_CURRENCY_MISMATCH")
                drawdown = MetricOutcomeV2(
                    "available",
                    None,
                    calculate_max_drawdown_v1(facts.nav_history.observations),
                )
            if facts.loss_history.status == "available":
                var_es = MetricOutcomeV2(
                    "available",
                    None,
                    calculate_historical_var_es_v1(
                        facts.loss_history.observations,
                        reporting_currency=request.reporting_currency,
                        horizon_ref=request.loss_horizon_ref,
                        confidence=request.confidence,
                    ),
                )
            if facts.spot.status == "available" and facts.scenario.status == "available":
                stress = MetricOutcomeV2(
                    "available",
                    None,
                    calculate_spot_scenario_pnl_v1(
                        facts.spot.positions,
                        facts.scenario.shocks,
                        reporting_currency=request.reporting_currency,
                        scenario_ref=request.scenario_ref,
                        scenario_version=request.scenario_version,
                    ),
                )
        except PortfolioMetricsError as exc:
            raise PortfolioAnalyticsError(exc.code) from exc

        return PortfolioAnalyticsReportV2(
            portfolio_ref=facts.portfolio_ref,
            reporting_currency=request.reporting_currency,
            source_mode=facts.source_mode,
            source_ref=facts.source_ref,
            source_version=facts.source_version,
            source_generation=facts.source_generation,
            facts_snapshot_ref=facts.facts_snapshot_ref,
            input_sha256=input_sha256,
            request_sha256=hashlib.sha256(
                _canonical_json_v2(request.to_payload())
            ).hexdigest(),
            spot=facts.spot,
            nav_history=facts.nav_history,
            loss_history=facts.loss_history,
            scenario=facts.scenario,
            spot_exposure=exposure,
            max_drawdown=drawdown,
            historical_var_es=var_es,
            stress_scenario=stress,
        )

    @staticmethod
    def _dataset_reason(status: str, reason: str | None) -> str:
        return reason if status == "unavailable" and reason is not None else "NO_SOURCE_DATA"

    @classmethod
    def _spot_unavailable_reason(cls, spot: SpotFactsV2) -> str:
        return cls._dataset_reason(spot.status, spot.reason_code)

    @staticmethod
    def _unavailable(reason: str) -> MetricOutcomeV2:
        return MetricOutcomeV2("unavailable", reason, None)


def parse_facts_v2(value: Mapping[str, object]) -> PortfolioAnalyticsFactsV2:
    """Strict V2 facts codec used by the task adapter after bounded copying."""

    obj = _exact_object(
        value,
        {
            "facts_snapshot_ref",
            "loss_history",
            "nav_history",
            "portfolio_ref",
            "scenario",
            "source_generation",
            "source_mode",
            "source_ref",
            "source_version",
            "spot",
            "version",
        },
    )
    if type(obj["version"]) is not int or obj["version"] != 2:
        raise PortfolioAnalyticsError("INVALID_SCHEMA_VERSION")
    return PortfolioAnalyticsFactsV2(
        portfolio_ref=obj["portfolio_ref"],
        source_mode=obj["source_mode"],
        source_ref=obj["source_ref"],
        source_version=obj["source_version"],
        source_generation=obj["source_generation"],
        facts_snapshot_ref=obj["facts_snapshot_ref"],
        spot=_parse_spot(obj["spot"]),
        nav_history=_parse_nav_history(obj["nav_history"]),
        loss_history=_parse_loss_history(obj["loss_history"]),
        scenario=_parse_scenario(obj["scenario"]),
    )


def parse_request_v2(value: Mapping[str, object]) -> PortfolioAnalyticsRequestV2:
    """Strict V2 request codec; financial facts are never request fields."""

    obj = _exact_object(
        value,
        {
            "confidence",
            "loss_horizon_ref",
            "portfolio_ref",
            "reporting_currency",
            "scenario_ref",
            "scenario_version",
            "version",
        },
    )
    if type(obj["version"]) is not int or obj["version"] != 2:
        raise PortfolioAnalyticsError("INVALID_SCHEMA_VERSION")
    return PortfolioAnalyticsRequestV2(
        portfolio_ref=obj["portfolio_ref"],
        reporting_currency=obj["reporting_currency"],
        loss_horizon_ref=obj["loss_horizon_ref"],
        confidence=_parse_decimal(obj["confidence"]),
        scenario_ref=obj["scenario_ref"],
        scenario_version=obj["scenario_version"],
    )


def _exact_object(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise PortfolioAnalyticsError("INVALID_INPUT")
    return value


def _parse_decimal(value: object) -> Decimal:
    if type(value) is not str:
        raise PortfolioAnalyticsError("INVALID_DECIMAL")
    try:
        return Decimal(value)
    except InvalidOperation as exc:
        raise PortfolioAnalyticsError("INVALID_DECIMAL") from exc


def _parse_datetime(value: object) -> datetime:
    if type(value) is not str:
        raise PortfolioAnalyticsError("INVALID_UTC_TIMESTAMP")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PortfolioAnalyticsError("INVALID_UTC_TIMESTAMP") from exc
    return _require_utc(parsed)


def _parse_spot(value: object) -> SpotFactsV2:
    obj = _exact_object(
        value,
        {
            "as_of_utc",
            "coverage_complete",
            "positions",
            "reason_code",
            "source_cursor",
            "source_generation",
            "source_ref",
            "source_version",
            "status",
        },
    )
    rows = _parse_array(obj["positions"], _parse_spot_position)
    return SpotFactsV2(
        status=obj["status"],
        reason_code=obj["reason_code"],
        as_of_utc=None if obj["as_of_utc"] is None else _parse_datetime(obj["as_of_utc"]),
        source_ref=obj["source_ref"],
        source_version=obj["source_version"],
        source_generation=obj["source_generation"],
        source_cursor=obj["source_cursor"],
        coverage_complete=obj["coverage_complete"],
        positions=rows,
    )


def _parse_nav_history(value: object) -> NavHistoryFactsV2:
    obj = _exact_object(
        value,
        {
            "coverage_complete",
            "coverage_end_utc",
            "coverage_start_utc",
            "end_cursor",
            "observations",
            "reason_code",
            "source_generation",
            "source_ref",
            "source_version",
            "start_cursor",
            "status",
        },
    )
    return NavHistoryFactsV2(
        status=obj["status"],
        reason_code=obj["reason_code"],
        source_ref=obj["source_ref"],
        source_version=obj["source_version"],
        source_generation=obj["source_generation"],
        coverage_start_utc=(
            None
            if obj["coverage_start_utc"] is None
            else _parse_datetime(obj["coverage_start_utc"])
        ),
        coverage_end_utc=(
            None
            if obj["coverage_end_utc"] is None
            else _parse_datetime(obj["coverage_end_utc"])
        ),
        start_cursor=obj["start_cursor"],
        end_cursor=obj["end_cursor"],
        coverage_complete=obj["coverage_complete"],
        observations=_parse_array(obj["observations"], _parse_nav_observation),
    )


def _parse_loss_history(value: object) -> LossHistoryFactsV2:
    obj = _exact_object(
        value,
        {
            "coverage_complete",
            "coverage_end_utc",
            "coverage_start_utc",
            "end_cursor",
            "horizon_ref",
            "observations",
            "reason_code",
            "source_generation",
            "source_ref",
            "source_version",
            "start_cursor",
            "status",
        },
    )
    return LossHistoryFactsV2(
        status=obj["status"],
        reason_code=obj["reason_code"],
        horizon_ref=obj["horizon_ref"],
        source_ref=obj["source_ref"],
        source_version=obj["source_version"],
        source_generation=obj["source_generation"],
        coverage_start_utc=(
            None
            if obj["coverage_start_utc"] is None
            else _parse_datetime(obj["coverage_start_utc"])
        ),
        coverage_end_utc=(
            None
            if obj["coverage_end_utc"] is None
            else _parse_datetime(obj["coverage_end_utc"])
        ),
        start_cursor=obj["start_cursor"],
        end_cursor=obj["end_cursor"],
        coverage_complete=obj["coverage_complete"],
        observations=_parse_array(obj["observations"], _parse_loss_observation),
    )


def _parse_scenario(value: object) -> ScenarioFactsV2:
    obj = _exact_object(
        value,
        {
            "coverage_complete",
            "reason_code",
            "scenario_ref",
            "scenario_version",
            "shocks",
            "source_cursor",
            "source_generation",
            "source_ref",
            "source_version",
            "status",
        },
    )
    return ScenarioFactsV2(
        status=obj["status"],
        reason_code=obj["reason_code"],
        scenario_ref=obj["scenario_ref"],
        scenario_version=obj["scenario_version"],
        source_ref=obj["source_ref"],
        source_version=obj["source_version"],
        source_generation=obj["source_generation"],
        source_cursor=obj["source_cursor"],
        coverage_complete=obj["coverage_complete"],
        shocks=_parse_array(obj["shocks"], _parse_shock),
    )


def _parse_array(value: object, parser) -> tuple:
    if type(value) is not list or len(value) > _MAX_ROWS:
        raise PortfolioAnalyticsError("INVALID_ROWS")
    return tuple(parser(item) for item in value)


def _parse_spot_position(value: object) -> SpotPositionMetricInputV1:
    obj = _exact_object(
        value,
        {
            "as_of_utc",
            "base_currency",
            "fx_unit",
            "position_ref",
            "quantity",
            "quantity_unit",
            "quote_currency",
            "reporting_per_quote",
            "price_unit",
            "unit_price",
        },
    )
    return SpotPositionMetricInputV1(
        position_ref=obj["position_ref"],
        as_of_utc=_parse_datetime(obj["as_of_utc"]),
        base_currency=obj["base_currency"],
        quote_currency=obj["quote_currency"],
        quantity=_parse_decimal(obj["quantity"]),
        quantity_unit=obj["quantity_unit"],
        unit_price=_parse_decimal(obj["unit_price"]),
        price_unit=obj["price_unit"],
        reporting_per_quote=_parse_decimal(obj["reporting_per_quote"]),
        fx_unit=obj["fx_unit"],
    )


def _parse_nav_observation(value: object) -> NavObservationV1:
    obj = _exact_object(value, {"as_of_utc", "currency", "nav"})
    return NavObservationV1(
        as_of_utc=_parse_datetime(obj["as_of_utc"]),
        nav=_parse_decimal(obj["nav"]),
        currency=obj["currency"],
    )


def _parse_loss_observation(value: object) -> HistoricalLossObservationV1:
    obj = _exact_object(value, {"as_of_utc", "currency", "loss", "loss_unit"})
    return HistoricalLossObservationV1(
        as_of_utc=_parse_datetime(obj["as_of_utc"]),
        loss=_parse_decimal(obj["loss"]),
        currency=obj["currency"],
        loss_unit=obj["loss_unit"],
    )


def _parse_shock(value: object) -> SpotPriceFxShockV1:
    obj = _exact_object(value, {"fx_return", "position_ref", "price_return", "shock_unit"})
    return SpotPriceFxShockV1(
        position_ref=obj["position_ref"],
        price_return=_parse_decimal(obj["price_return"]),
        fx_return=_parse_decimal(obj["fx_return"]),
        shock_unit=obj["shock_unit"],
    )


def _spot_payload(value: SpotFactsV2) -> dict[str, object]:
    return {
        "as_of_utc": None if value.as_of_utc is None else value.as_of_utc.isoformat(),
        "coverage_complete": value.coverage_complete,
        "positions": [
            {
                "as_of_utc": row.as_of_utc.isoformat(),
                "base_currency": row.base_currency,
                "fx_unit": row.fx_unit,
                "position_ref": row.position_ref,
                "quantity": _canonical_decimal(row.quantity),
                "quantity_unit": row.quantity_unit,
                "quote_currency": row.quote_currency,
                "reporting_per_quote": _canonical_decimal(row.reporting_per_quote),
                "price_unit": row.price_unit,
                "unit_price": _canonical_decimal(row.unit_price),
            }
            for row in value.positions
        ],
        "reason_code": value.reason_code,
        "source_cursor": value.source_cursor,
        "source_generation": value.source_generation,
        "source_ref": value.source_ref,
        "source_version": value.source_version,
        "status": value.status,
    }


def _nav_history_payload(value: NavHistoryFactsV2) -> dict[str, object]:
    return {
        "coverage_complete": value.coverage_complete,
        "coverage_end_utc": (
            None
            if value.coverage_end_utc is None
            else value.coverage_end_utc.isoformat()
        ),
        "coverage_start_utc": (
            None
            if value.coverage_start_utc is None
            else value.coverage_start_utc.isoformat()
        ),
        "end_cursor": value.end_cursor,
        "observations": [
            {
                "as_of_utc": row.as_of_utc.isoformat(),
                "currency": row.currency,
                "nav": _canonical_decimal(row.nav),
            }
            for row in value.observations
        ],
        "reason_code": value.reason_code,
        "source_generation": value.source_generation,
        "source_ref": value.source_ref,
        "source_version": value.source_version,
        "start_cursor": value.start_cursor,
        "status": value.status,
    }


def _loss_history_payload(value: LossHistoryFactsV2) -> dict[str, object]:
    return {
        "coverage_complete": value.coverage_complete,
        "coverage_end_utc": (
            None
            if value.coverage_end_utc is None
            else value.coverage_end_utc.isoformat()
        ),
        "coverage_start_utc": (
            None
            if value.coverage_start_utc is None
            else value.coverage_start_utc.isoformat()
        ),
        "end_cursor": value.end_cursor,
        "horizon_ref": value.horizon_ref,
        "observations": [
            {
                "as_of_utc": row.as_of_utc.isoformat(),
                "currency": row.currency,
                "loss": _canonical_decimal(row.loss),
                "loss_unit": row.loss_unit,
            }
            for row in value.observations
        ],
        "reason_code": value.reason_code,
        "source_generation": value.source_generation,
        "source_ref": value.source_ref,
        "source_version": value.source_version,
        "start_cursor": value.start_cursor,
        "status": value.status,
    }


def _scenario_payload(value: ScenarioFactsV2) -> dict[str, object]:
    return {
        "coverage_complete": value.coverage_complete,
        "reason_code": value.reason_code,
        "scenario_ref": value.scenario_ref,
        "scenario_version": value.scenario_version,
        "shocks": [
            {
                "fx_return": _canonical_decimal(row.fx_return),
                "position_ref": row.position_ref,
                "price_return": _canonical_decimal(row.price_return),
                "shock_unit": row.shock_unit,
            }
            for row in value.shocks
        ],
        "source_cursor": value.source_cursor,
        "source_generation": value.source_generation,
        "source_ref": value.source_ref,
        "source_version": value.source_version,
        "status": value.status,
    }


def _metric_value_payload(value: object) -> dict[str, object]:
    if type(value) is SpotExposureReportV1:
        return {
            "as_of_utc": value.as_of_utc.isoformat(),
            "contributions": [
                {
                    "gross_reporting_notional": _canonical_decimal(row.gross_reporting_notional),
                    "position_ref": row.position_ref,
                    "signed_reporting_notional": _canonical_decimal(row.signed_reporting_notional),
                }
                for row in value.contributions
            ],
            "gross_reporting_notional": _canonical_decimal(value.gross_reporting_notional),
            "method_ref": value.method_ref,
            "net_reporting_notional": _canonical_decimal(value.net_reporting_notional),
            "reporting_currency": value.reporting_currency,
            "schema_version": value.schema_version,
            "scope": value.scope,
        }
    if type(value) is DrawdownReportV1:
        return {
            "method_ref": value.method_ref,
            "max_drawdown_ratio": _canonical_decimal(value.max_drawdown_ratio),
            "observation_count": value.observation_count,
            "peak_as_of_utc": value.peak_as_of_utc.isoformat(),
            "peak_nav": _canonical_decimal(value.peak_nav),
            "reporting_currency": value.reporting_currency,
            "schema_version": value.schema_version,
            "trough_as_of_utc": value.trough_as_of_utc.isoformat(),
            "trough_nav": _canonical_decimal(value.trough_nav),
        }
    if type(value) is HistoricalVarEsReportV1:
        return {
            "confidence": _canonical_decimal(value.confidence),
            "expected_shortfall_loss": _canonical_decimal(value.expected_shortfall_loss),
            "first_as_of_utc": value.first_as_of_utc.isoformat(),
            "horizon_ref": value.horizon_ref,
            "last_as_of_utc": value.last_as_of_utc.isoformat(),
            "method_ref": value.method_ref,
            "observation_count": value.observation_count,
            "reporting_currency": value.reporting_currency,
            "schema_version": value.schema_version,
            "tail_observation_mass": _canonical_decimal(value.tail_observation_mass),
            "var_loss": _canonical_decimal(value.var_loss),
        }
    if type(value) is SpotStressReportV1:
        return {
            "as_of_utc": value.as_of_utc.isoformat(),
            "contributions": [
                {
                    "base_reporting_notional": _canonical_decimal(row.base_reporting_notional),
                    "pnl_reporting_amount": _canonical_decimal(row.pnl_reporting_amount),
                    "position_ref": row.position_ref,
                    "stressed_reporting_notional": _canonical_decimal(row.stressed_reporting_notional),
                }
                for row in value.contributions
            ],
            "method_ref": value.method_ref,
            "pnl_reporting_amount": _canonical_decimal(value.pnl_reporting_amount),
            "reporting_currency": value.reporting_currency,
            "scenario_ref": value.scenario_ref,
            "scenario_version": value.scenario_version,
            "schema_version": value.schema_version,
            "scope": value.scope,
        }
    raise PortfolioAnalyticsError("UNSUPPORTED_METRIC_REPORT")


def _spot_provenance(value: SpotFactsV2) -> dict[str, object]:
    return {
        "as_of_utc": None if value.as_of_utc is None else value.as_of_utc.isoformat(),
        "coverage_complete": value.coverage_complete,
        "reason_code": value.reason_code,
        "source_cursor": value.source_cursor,
        "source_generation": value.source_generation,
        "source_ref": value.source_ref,
        "source_version": value.source_version,
        "status": value.status,
    }


def _nav_history_provenance(value: NavHistoryFactsV2) -> dict[str, object]:
    return {
        "coverage_complete": value.coverage_complete,
        "coverage_end_utc": (
            None
            if value.coverage_end_utc is None
            else value.coverage_end_utc.isoformat()
        ),
        "coverage_start_utc": (
            None
            if value.coverage_start_utc is None
            else value.coverage_start_utc.isoformat()
        ),
        "end_cursor": value.end_cursor,
        "reason_code": value.reason_code,
        "source_generation": value.source_generation,
        "source_ref": value.source_ref,
        "source_version": value.source_version,
        "start_cursor": value.start_cursor,
        "status": value.status,
    }


def _loss_history_provenance(value: LossHistoryFactsV2) -> dict[str, object]:
    return {
        "coverage_complete": value.coverage_complete,
        "coverage_end_utc": (
            None
            if value.coverage_end_utc is None
            else value.coverage_end_utc.isoformat()
        ),
        "coverage_start_utc": (
            None
            if value.coverage_start_utc is None
            else value.coverage_start_utc.isoformat()
        ),
        "end_cursor": value.end_cursor,
        "horizon_ref": value.horizon_ref,
        "reason_code": value.reason_code,
        "source_generation": value.source_generation,
        "source_ref": value.source_ref,
        "source_version": value.source_version,
        "start_cursor": value.start_cursor,
        "status": value.status,
    }


def _scenario_provenance(value: ScenarioFactsV2) -> dict[str, object]:
    return {
        "coverage_complete": value.coverage_complete,
        "reason_code": value.reason_code,
        "scenario_ref": value.scenario_ref,
        "scenario_version": value.scenario_version,
        "source_cursor": value.source_cursor,
        "source_generation": value.source_generation,
        "source_ref": value.source_ref,
        "source_version": value.source_version,
        "status": value.status,
    }


def _canonical_json_v2(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


__all__ = [
    "CANONICAL_SERIALIZATION_V2",
    "DECIMAL_SERIALIZATION_V2",
    "LossHistoryFactsV2",
    "MetricOutcomeV2",
    "NavHistoryFactsV2",
    "PORTFOLIO_ANALYTICS_SCHEMA_V2",
    "PORTFOLIO_ANALYTICS_V2_CALCULATION",
    "PortfolioAnalyticsFactsV2",
    "PortfolioAnalyticsReportV2",
    "PortfolioAnalyticsRequestV2",
    "PortfolioAnalyticsServiceV2",
    "ScenarioFactsV2",
    "SpotFactsV2",
    "parse_facts_v2",
    "parse_request_v2",
]
