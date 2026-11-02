"""Decode Risk-owned position payloads without establishing their provenance.

The caller remains responsible for source receipts, journal authority and fences.
"""
from __future__ import annotations

from collections.abc import Mapping

from .core.admission import AccountScope
from .core.exposure import PositionSnapshotCoverage
from .core.instrument import (
    AccountPositionRiskFact,
    InstrumentRiskFxRate,
    InstrumentRiskGreeks,
    InstrumentRiskMetadata,
)


class RiskPositionPayloadError(RuntimeError):
    """Finite error code for an invalid position payload."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _position_metadata_from_payload(value: object) -> InstrumentRiskMetadata:
    if not isinstance(value, Mapping):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_METADATA_INVALID")
    data = dict(value)
    if data.pop("schema", None) != "bt_api_risk.instrument-admission.v1":
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_METADATA_INVALID")
    allowed = {
        "as_of_ns", "contract_multiplier", "expires_at_ns", "fixed_fee", "fixed_fee_unit",
        "fx_source_ref", "instrument", "max_gross_notional", "max_quantity",
        "max_slippage_bps", "metadata_version", "min_quantity", "quantity_step",
        "quantity_unit", "quote_currency", "taker_fee_bps", "tick_size",
        "underlying_ref", "valuation_unit",
    }
    required = {
        "as_of_ns", "contract_multiplier", "expires_at_ns", "fixed_fee", "instrument",
        "max_gross_notional", "max_slippage_bps", "metadata_version", "quantity_step",
        "taker_fee_bps", "tick_size",
    }
    if not required <= set(data) or not set(data) <= allowed:
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_METADATA_INVALID")
    try:
        return InstrumentRiskMetadata(**data)
    except (TypeError, ValueError):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_METADATA_INVALID") from None


def _position_fx_from_payload(value: object) -> InstrumentRiskFxRate:
    if not isinstance(value, Mapping):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_FX_INVALID")
    data = dict(value)
    if data.pop("schema", None) != "bt_api_risk.instrument-fx-rate.v1":
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_FX_INVALID")
    pair = data.pop("fx_pair", None)
    if set(data) != {
        "instrument", "observed_at_ns", "quote_currency", "rate", "source_record_sha256",
        "source_ref", "source_revision", "valid_until_ns", "valuation_unit",
    }:
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_FX_INVALID")
    try:
        result = InstrumentRiskFxRate(**data)
    except (TypeError, ValueError):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_FX_INVALID") from None
    if pair != result.fx_pair:
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_FX_INVALID")
    return result


def _position_greeks_from_payload(value: object) -> InstrumentRiskGreeks:
    if not isinstance(value, Mapping):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_GREEKS_INVALID")
    data = dict(value)
    if data.pop("schema", None) != "bt_api_risk.instrument-greeks.v1" or set(data) != {
        "delta_per_contract", "delta_unit", "gamma_per_contract", "gamma_unit", "instrument",
        "observed_at_ns", "source_record_sha256", "source_ref", "source_revision",
        "underlying_ref", "valid_until_ns", "vega_per_contract", "vega_unit",
    }:
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_GREEKS_INVALID")
    try:
        return InstrumentRiskGreeks(**data)
    except (TypeError, ValueError):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_GREEKS_INVALID") from None


def position_risk_fact_from_payload(value: object) -> AccountPositionRiskFact:
    if not isinstance(value, Mapping):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_FACT_INVALID")
    data = dict(value)
    if data.pop("schema", None) != "bt_api_risk.account-position-risk-fact.v1" or set(data) != {
        "fx_rate", "greeks", "instrument", "mark_observed_at_ns", "mark_price",
        "mark_source_record_sha256", "mark_source_ref", "mark_source_revision",
        "mark_valid_until_ns", "metadata", "position_id", "position_side",
        "position_source_record_sha256", "quantity", "quantity_unit", "strategy_id",
    }:
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_FACT_INVALID")
    try:
        result = AccountPositionRiskFact(
            position_id=data["position_id"],
            strategy_id=data["strategy_id"],
            instrument=data["instrument"],
            position_side=data["position_side"],
            quantity=data["quantity"],
            quantity_unit=data["quantity_unit"],
            mark_price=data["mark_price"],
            mark_observed_at_ns=data["mark_observed_at_ns"],
            mark_valid_until_ns=data["mark_valid_until_ns"],
            mark_source_ref=data["mark_source_ref"],
            mark_source_revision=data["mark_source_revision"],
            mark_source_record_sha256=data["mark_source_record_sha256"],
            position_source_record_sha256=data["position_source_record_sha256"],
            metadata=_position_metadata_from_payload(data["metadata"]),
            fx_rate=None if data["fx_rate"] is None else _position_fx_from_payload(data["fx_rate"]),
            greeks=None if data["greeks"] is None else _position_greeks_from_payload(data["greeks"]),
        )
    except RiskPositionPayloadError:
        raise
    except (TypeError, ValueError):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_FACT_INVALID") from None
    if dict(value) != result.to_payload():
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_FACT_INVALID")
    return result


def position_coverage_from_payload(
    value: object, *, scope: AccountScope
) -> PositionSnapshotCoverage:
    if not isinstance(value, Mapping):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_COVERAGE_INVALID")
    data = dict(value)
    if data.pop("schema", None) != "bt_api_risk.position-snapshot-coverage.v1":
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_COVERAGE_INVALID")
    expected = {
        "account_revision", "account_scope", "filters", "observed_at_ns", "page_count",
        "pagination_exhausted", "permission_revision", "permission_scope", "query_scope",
        "snapshot_version", "source_schema_version", "valid_until_ns",
    }
    if set(data) != expected or not isinstance(data.get("account_scope"), Mapping):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_COVERAGE_INVALID")
    if dict(data["account_scope"]) != {
        "account_id": scope.account_id,
        "environment": scope.environment,
        "provider": scope.provider,
    }:
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_COVERAGE_INVALID")
    filters = data.get("filters")
    if type(filters) is not list or any(type(item) is not str for item in filters):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_COVERAGE_INVALID")
    try:
        result = PositionSnapshotCoverage(
            scope=scope,
            account_revision=data["account_revision"],
            source_schema_version=data["source_schema_version"],
            query_scope=data["query_scope"],
            filters=tuple(filters),
            permission_scope=data["permission_scope"],
            permission_revision=data["permission_revision"],
            pagination_exhausted=data["pagination_exhausted"],
            page_count=data["page_count"],
            snapshot_version=data["snapshot_version"],
            observed_at_ns=data["observed_at_ns"],
            valid_until_ns=data["valid_until_ns"],
        )
    except (TypeError, ValueError):
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_COVERAGE_INVALID") from None
    if dict(value) != result.to_payload():
        raise RiskPositionPayloadError("GROSS_BASELINE_POSITION_COVERAGE_INVALID")
    return result




def position_dimensions_from_payload(payload: object) -> tuple[str, str]:
    """Read only the canonical optional position qualifiers, with v1 defaults."""

    if not isinstance(payload, Mapping):
        raise RiskPositionPayloadError("POSITION_DIMENSIONS_INVALID")
    position_side = payload.get("position_side", "NET")
    position_bucket = payload.get("position_bucket", "ALL")
    if (
        type(position_side) is not str
        or position_side not in {"NET", "LONG", "SHORT"}
        or type(position_bucket) is not str
        or position_bucket not in {"ALL", "TODAY", "YESTERDAY"}
    ):
        raise RiskPositionPayloadError("POSITION_DIMENSIONS_INVALID")
    return position_side, position_bucket


def position_dimensions_match(payload: object, expected: tuple[str, str]) -> bool:
    if not isinstance(payload, Mapping):
        return False
    return (
        payload.get("position_side", "NET") == expected[0]
        and payload.get("position_bucket", "ALL") == expected[1]
    )

