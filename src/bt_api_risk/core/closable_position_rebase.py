"""Typed proof values for execution-book-backed closable-position rebases.

These values are constructed by a trusted server-side source adapter after it
has verified one complete execution snapshot and the exact terminal close
receipts it absorbs.  They are not HTTP payloads or client-supplied account
balances.  ``DurableRiskGate`` independently checks the close references
against its own immutable ledger and applies the snapshot under the same
SQLite writer transaction used by close admission.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal

from .admission import AccountScope

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_INSTRUMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GENERATION = re.compile(r"^[0-9a-f]{32}$")


def _identifier(value: object, name: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("invalid " + name)
    return value


def _sha256(value: object, name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError("invalid " + name)
    return value


@dataclass(frozen=True)
class ClosablePositionCloseReceiptV1:
    """Identity and Risk-owned digest of one exact terminal CLOSE receipt."""

    permit_id: str
    intent_id: str
    close_receipt_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.permit_id, "permit_id")
        _identifier(self.intent_id, "intent_id")
        _sha256(self.close_receipt_sha256, "close_receipt_sha256")


@dataclass(frozen=True)
class ClosablePositionRebaseV1:
    """One complete execution snapshot applied to an attributed Risk slice.

    ``closable_quantity`` is the full current book quantity at
    ``(execution_generation, execution_cursor)``.  It already includes the
    economic effect of every ``absorbed_close_receipts`` member; Risk therefore
    excludes those exact terminal reservations from subsequent usage totals.
    A later cursor in the same generation may rebase again. This version
    supports only the NET/ALL book published by the managed-paper execution
    source; other position slices fail closed until they have an authoritative
    full-book producer. This type carries source identities only; the trusted
    adapter must verify the execution source and calculate ``snapshot_sha256``
    before constructing it.
    """

    scope: AccountScope
    instrument: str
    strategy_id: str
    closable_quantity: Decimal
    quantity_unit: str
    execution_generation: str
    execution_cursor: int
    snapshot_sha256: str
    absorbed_close_receipts: tuple[ClosablePositionCloseReceiptV1, ...]
    position_side: str = "NET"
    position_bucket: str = "ALL"

    def __post_init__(self) -> None:
        if type(self.scope) is not AccountScope:
            raise ValueError("scope must be an AccountScope")
        if type(self.instrument) is not str or _INSTRUMENT.fullmatch(self.instrument) is None:
            raise ValueError("invalid instrument")
        _identifier(self.strategy_id, "strategy_id")
        _identifier(self.quantity_unit, "quantity_unit")
        try:
            if isinstance(self.closable_quantity, bool):
                raise ValueError("boolean is not a quantity")
            quantity = (
                self.closable_quantity
                if isinstance(self.closable_quantity, Decimal)
                else Decimal(str(self.closable_quantity))
            )
        except Exception as error:
            raise ValueError("closable_quantity must be a non-negative finite decimal") from error
        if not quantity.is_finite() or quantity < 0:
            raise ValueError("closable_quantity must be a non-negative finite decimal")
        object.__setattr__(self, "closable_quantity", quantity)
        if type(self.execution_generation) is not str or _GENERATION.fullmatch(
            self.execution_generation
        ) is None:
            raise ValueError("invalid execution_generation")
        if type(self.execution_cursor) is not int or self.execution_cursor < 0:
            raise ValueError("execution_cursor must be a non-negative integer")
        _sha256(self.snapshot_sha256, "snapshot_sha256")
        if type(self.position_side) is not str or self.position_side not in {
            "NET",
            "LONG",
            "SHORT",
        }:
            raise ValueError("position_side must be NET, LONG, or SHORT")
        if type(self.position_bucket) is not str or self.position_bucket not in {
            "ALL",
            "TODAY",
            "YESTERDAY",
        }:
            raise ValueError("position_bucket must be ALL, TODAY, or YESTERDAY")
        if self.position_side != "NET" or self.position_bucket != "ALL":
            raise ValueError("closable position rebase currently supports NET/ALL only")
        if type(self.absorbed_close_receipts) is not tuple or any(
            type(item) is not ClosablePositionCloseReceiptV1
            for item in self.absorbed_close_receipts
        ):
            raise ValueError("absorbed_close_receipts must be a typed immutable tuple")
        ordered = tuple(
            sorted(
                self.absorbed_close_receipts,
                key=lambda item: (
                    item.permit_id,
                    item.intent_id,
                    item.close_receipt_sha256,
                ),
            )
        )
        if len({item.permit_id for item in ordered}) != len(ordered):
            raise ValueError("absorbed close permit references must be unique")
        object.__setattr__(self, "absorbed_close_receipts", ordered)


__all__ = [
    "ClosablePositionCloseReceiptV1",
    "ClosablePositionRebaseV1",
]
