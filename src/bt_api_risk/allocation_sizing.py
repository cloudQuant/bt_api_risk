"""Advisory sizing from local allocation and the existing instrument assessor.

This helper neither issues a permit nor reads provider account facts. A writer
must reserve against the current allocation revision before dispatch.
"""

from decimal import Decimal, localcontext
from fractions import Fraction

from .core.admission import RiskDeniedError, StrategyAllocationSnapshot
from .core.instrument import InstrumentRiskOrder, InstrumentRiskRegistry, _precision


def size_for_strategy_allocation(
    allocation: StrategyAllocationSnapshot,
    registry: InstrumentRiskRegistry,
    *,
    instrument: str,
    limit_price: Decimal,
    now_ns: int,
) -> Decimal:
    """Suggest a quantity on the reviewed lattice within local notional budget.

    The same registry assessment supplies adverse price, multiplier and fees
    used for admission. Fixed fees are paid once, not once per quantity step.
    Missing valuation facts reject. A complete budget below one permitted
    lot returns zero. Quantity-position allocations need a separate remaining
    quantity view and therefore reject here rather than pretending it is known.
    """

    if type(allocation) is not StrategyAllocationSnapshot:
        raise ValueError("an exact local strategy allocation snapshot is required")
    if type(registry) is not InstrumentRiskRegistry:
        raise ValueError("an exact instrument risk registry is required")
    if (
        type(limit_price) is not Decimal
        or not limit_price.is_finite()
        or limit_price <= 0
    ):
        raise ValueError("a positive finite Decimal limit price is required")
    if (
        allocation.source != "local_risk_reservation_ledger"
        or allocation.completeness != "LOCAL_LEDGER_COMPLETE"
        or allocation.reason is not None
    ):
        raise RiskDeniedError(
            "ALLOCATION_UNAVAILABLE", "complete local allocation is required"
        )
    for value in (
        allocation.allocated_notional,
        allocation.used_notional,
        allocation.reserved_notional,
        allocation.available_notional,
    ):
        if type(value) is not Decimal or not value.is_finite() or value < 0:
            raise ValueError("allocation amounts must be finite nonnegative Decimals")
        _precision(value)
    budget = allocation.available_notional
    remaining = (
        Fraction(allocation.allocated_notional)
        - Fraction(allocation.used_notional)
        - Fraction(allocation.reserved_notional)
    )
    if Fraction(budget) > max(Fraction(0), remaining):
        raise ValueError("allocation available exceeds its retained occupancy bound")
    if allocation.max_position is not None:
        raise RiskDeniedError(
            "ALLOCATION_QUANTITY_UNAVAILABLE",
            "remaining quantity reservation view is required",
        )
    metadata = registry.get(instrument)
    if metadata is None:
        raise RiskDeniedError(
            "INSTRUMENT_METADATA_MISSING", "reviewed instrument is unavailable"
        )
    if (
        not allocation.notional_unit
        or metadata.valuation_unit != allocation.notional_unit
    ):
        raise RiskDeniedError(
            "NOTIONAL_UNIT_MISMATCH", "allocation and metadata units differ"
        )

    def order(quantity):
        return InstrumentRiskOrder(
            instrument,
            quantity,
            limit_price,
            metadata.metadata_version,
            metadata.digest,
        )

    def assess(quantity):
        request = order(quantity)
        # The registry's result constructor verifies its fee identity after
        # leaving the calculation context. Keep that verification in the same
        # precision, independent of the caller's Decimal context.
        with localcontext() as context:
            context.prec = _precision(
                request.quantity,
                request.limit_price,
                metadata.contract_multiplier,
                metadata.taker_fee_bps,
                metadata.fixed_fee,
                metadata.max_slippage_bps,
            )
            return registry.assess(request, now_ns)

    probe_quantity = metadata.min_quantity or metadata.quantity_step
    try:
        assessment = assess(probe_quantity)
    except RiskDeniedError as error:
        if error.code == "INSTRUMENT_GROSS_NOTIONAL_LIMIT":
            return Decimal("0")
        raise
    if budget < assessment.gross_notional:
        return Decimal("0")
    # Fractions keep floor division exact even with a small ambient Decimal
    # precision. Reuse the assessor's computed costs instead of a second
    # price/fee formula that can drift from the writer's risk calculation.
    budget = min(budget, metadata.max_gross_notional)
    variable = Fraction(assessment.gross_notional) - Fraction(metadata.fixed_fee)
    if variable <= 0:
        raise ValueError("instrument assessment has no positive variable cost")
    lots = int(
        (Fraction(budget) - Fraction(metadata.fixed_fee))
        * Fraction(probe_quantity)
        / variable
        / Fraction(metadata.quantity_step)
    )
    if metadata.max_quantity is not None:
        lots = min(
            lots,
            int(Fraction(metadata.max_quantity) / Fraction(metadata.quantity_step)),
        )
    # Construct the exact Decimal lattice product without context rounding.
    sign, digits, exponent = metadata.quantity_step.as_tuple()
    coefficient = int("".join(str(digit) for digit in digits)) * lots
    quantity = Decimal((sign, tuple(int(char) for char in str(coefficient)), exponent))
    if quantity < probe_quantity:
        return Decimal("0")
    final = assess(quantity)
    if final.gross_notional > allocation.available_notional:
        raise ValueError("sizing result exceeds local allocation")
    return quantity


__all__ = ["size_for_strategy_allocation"]
