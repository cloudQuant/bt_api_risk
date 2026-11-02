"""Risk-owned valuation and aggregation of position baseline facts.

Callers retain responsibility for provenance, journal authority and fencing.
"""
from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from fractions import Fraction

from .core.exposure import StrategyGrossBaseline


class PositionBaselineError(RuntimeError):
    """Finite classification of an invalid risk baseline."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def revalue_position_facts(facts, *, notional_unit, observed_at_ns):
    """Revalue typed Risk facts by strategy using exact rational sums."""
    result = {}
    for fact in facts:
        if fact.metadata.valuation_unit != notional_unit:
            raise PositionBaselineError("GROSS_BASELINE_POSITION_UNIT_MISMATCH")
        try:
            gross_notional, _ = fact.exposure_dimensions(
                (), now_ns=observed_at_ns, max_age_ns=observed_at_ns
            )
        except (TypeError, ValueError, InvalidOperation):
            raise PositionBaselineError("GROSS_BASELINE_POSITION_FACT_INVALID") from None
        result[fact.strategy_id] = result.get(fact.strategy_id, Fraction(0)) + Fraction(gross_notional)
    return result


def summarize_position_rows(rows, *, notional_unit, require_sha256):
    """Validate and aggregate the producer's attributed position summaries."""
    by_strategy = {}
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {
            "active_increase_intent_count", "gross_notional", "notional_unit",
            "source_record_sha256", "strategy_id", "valuation_facts_sha256",
        }:
            raise PositionBaselineError("GROSS_BASELINE_POSITION_INVALID")
        strategy_id = row.get("strategy_id")
        unit = row.get("notional_unit")
        count = row.get("active_increase_intent_count")
        if (
            type(strategy_id) is not str or not strategy_id
            or strategy_id != strategy_id.strip()
            or type(unit) is not str or unit != notional_unit
            or type(count) is not int or count < 0
        ):
            raise PositionBaselineError("GROSS_BASELINE_POSITION_INVALID")
        require_sha256(row.get("source_record_sha256"), "baseline position source digest")
        require_sha256(row.get("valuation_facts_sha256"), "baseline position valuation digest")
        try:
            gross = Decimal(str(row.get("gross_notional")))
        except (InvalidOperation, ValueError):
            raise PositionBaselineError("GROSS_BASELINE_POSITION_INVALID") from None
        if not gross.is_finite() or gross < 0:
            raise PositionBaselineError("GROSS_BASELINE_POSITION_INVALID")
        prior_gross, prior_count = by_strategy.get(strategy_id, (Fraction(0), 0))
        by_strategy[strategy_id] = (prior_gross + Fraction(gross), prior_count + count)
    return by_strategy


def require_matching_revaluation(by_strategy, source_gross_by_strategy):
    if any(
        by_strategy.get(strategy_id, (Fraction(0), 0))[0]
        != source_gross_by_strategy.get(strategy_id, Fraction(0))
        for strategy_id in set(by_strategy) | set(source_gross_by_strategy)
    ):
        raise PositionBaselineError("GROSS_BASELINE_POSITION_REVALUATION_MISMATCH")


def _decimal_from_fraction_exact(value):
    """Convert a rational made from finite Decimals without context rounding."""
    numerator = value.numerator
    denominator = value.denominator
    twos = 0
    fives = 0
    while denominator % 2 == 0:
        twos += 1
        denominator //= 2
    while denominator % 5 == 0:
        fives += 1
        denominator //= 5
    if denominator != 1:
        raise PositionBaselineError("GROSS_BASELINE_POSITION_ARITHMETIC_INVALID")
    places = max(twos, fives)
    scaled = abs(numerator) * (2 ** (places - twos)) * (5 ** (places - fives))
    digits = tuple(int(character) for character in str(scaled))
    sign = 1 if numerator < 0 else 0
    return Decimal((sign, digits, -places))


def strategy_baseline_totals(by_strategy):
    """Create stable strategy rows and exact account totals."""
    strategies = tuple(
        StrategyGrossBaseline(strategy_id, _decimal_from_fraction_exact(gross), count)
        for strategy_id, (gross, count) in sorted(by_strategy.items())
    )
    account_gross = _decimal_from_fraction_exact(
        sum((gross for gross, _ in by_strategy.values()), Fraction(0))
    )
    account_count = sum(item.active_increase_intent_count for item in strategies)
    return strategies, account_gross, account_count
