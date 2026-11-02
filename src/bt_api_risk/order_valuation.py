"""Risk order valuation projections; caller supplies trusted source facts.

These projections neither verify provider provenance nor own a journal fence.
"""
from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any

from .core.exposure import OrderExposureObservationProof, OrderFillFact
from .core.instrument import InstrumentRiskFxRate


def observation_fx_matches(
    observation: OrderExposureObservationProof,
    fx_rate: InstrumentRiskFxRate | None,
) -> bool:
    return all(
        (
            observation.fx_pair == (None if fx_rate is None else fx_rate.fx_pair),
            observation.fx_rate == (None if fx_rate is None else fx_rate.rate),
            observation.fx_observed_at_ns
            == (None if fx_rate is None else fx_rate.observed_at_ns),
            observation.fx_valid_until_ns
            == (None if fx_rate is None else fx_rate.valid_until_ns),
        )
    )


def valuation_facts_sha256(
    *,
    metadata: Mapping[str, Any],
    quote_currency: str,
    valuation_unit: str,
    fill_facts: tuple[OrderFillFact, ...],
    leaves_valuation_price: Decimal,
    fx_rate: InstrumentRiskFxRate | None,
    decimal_text, canonical_json, sha256_text,
) -> str:
    payload: dict[str, Any] = {
        "fill_fingerprints": [item.fingerprint for item in fill_facts],
        "instrument_metadata_sha256": metadata.get("metadata_sha256"),
        "instrument_multiplier": decimal_text(
            Decimal(str(metadata.get("contract_multiplier")))
        ),
        "leaves_valuation_price": decimal_text(leaves_valuation_price),
        "quote_currency": quote_currency,
        "valuation_unit": valuation_unit,
    }
    if fx_rate is not None:
        payload["fx_rate"] = fx_rate.to_payload()
        payload["fx_rate_sha256"] = fx_rate.digest
    return sha256_text(canonical_json(payload))


__all__ = ("observation_fx_matches", "valuation_facts_sha256")
