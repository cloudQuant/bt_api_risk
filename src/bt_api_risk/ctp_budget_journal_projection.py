"""CTP risk-budget journal value projection, without custody or I/O.

The caller owns journal recovery, account binding, locks and reservation
capabilities. These functions project its existing serialized budget values;
they do not establish their provenance or authorize a reservation.
"""

from collections.abc import Mapping
from copy import deepcopy
from decimal import Decimal, InvalidOperation


def budget_decimal(value, field, *, signed=False):
    if isinstance(value, bool) or value is None:
        raise ValueError(f"invalid_budget_{field}")
    try:
        parsed = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError(f"invalid_budget_{field}") from None
    if not parsed.is_finite() or (not signed and parsed < 0):
        raise ValueError(f"invalid_budget_{field}")
    return parsed


def budget_stringify(value, *, recurse):
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, Mapping):
        return {key: recurse(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [recurse(item) for item in value]
    return value


def budget_row_state(row, *, status, decimal_parser=budget_decimal):
    context = row.get("context")
    if not isinstance(context, dict):
        raise ValueError("missing_budget_context")
    reservation_id = row.get("reservation_id")
    if not isinstance(reservation_id, str) or not reservation_id:
        raise ValueError("missing_budget_reservation_id")
    state = {
        "reservation_id": reservation_id,
        "mode": row.get("mode"),
        "amount_cny": decimal_parser(row.get("amount_cny"), "amount"),
        "candidate_budget_cny": decimal_parser(row.get("candidate_budget_cny"), "candidate_budget"),
        "ordinary_cap_cny": decimal_parser(row.get("ordinary_cap_cny"), "ordinary_cap"),
        "ordinary_peak_cny": decimal_parser(row.get("ordinary_peak_cny"), "ordinary_peak"),
        "recovery_increment_cny": decimal_parser(
            row.get("recovery_increment_cny"), "recovery_increment"
        ),
        "full_state_peak_cny": decimal_parser(row.get("full_state_peak_cny"), "full_state_peak"),
        "available_required_cny": decimal_parser(
            row.get("available_required_cny"), "available_required"
        ),
        "remaining_unabsorbed_cny": decimal_parser(
            row.get("remaining_unabsorbed_cny", row.get("amount_cny")), "remaining_unabsorbed"
        ),
        "source": row.get("source"),
        "synthetic": bool(row.get("synthetic")),
        "evidence_digest": str(row.get("evidence_digest") or ""),
        "context": deepcopy(context),
        "status": status,
        "action_ids": set(),
        "transition_ids": set(),
        "transitions": [],
        "expires_at": row.get("expires_at"),
        "registry_scope": row.get("registry_scope"),
    }
    if not isinstance(state["mode"], str) or state["mode"] not in {"ordinary", "recovery"}:
        raise ValueError("invalid_budget_mode")
    return state


def apply_budget_transition(state, transition, amount, row, *, on_uncertain):
    """Apply budget economics while delegating the owner's uncertainty fence."""
    if transition in {"unknown", "late_fill"}:
        state["status"] = "uncertain"
        on_uncertain(state["reservation_id"])
        return
    if transition in {"paid", "confirmed_paid", "margin_paid"}:
        state["paid_cny"] = state.get("paid_cny", Decimal("0")) + amount
        return
    if transition == "absorbed":
        state["remaining_unabsorbed_cny"] = max(
            Decimal("0"),
            state.get("remaining_unabsorbed_cny", Decimal("0")) - amount,
        )
        state["absorbed_cny"] = state.get("absorbed_cny", Decimal("0")) + amount
        state["reserved_amount_cny"] = max(
            Decimal("0"),
            state.get("reserved_amount_cny", state.get("amount_cny", Decimal("0"))) - amount,
        )
        if state["reserved_amount_cny"] == 0 and state.get("status") == "active":
            state["status"] = "absorbed"
        return
    if transition == "released":
        if row.get("terminated_unused") is not True:
            raise ValueError("budget_release_unproven")
        state["reserved_amount_cny"] = Decimal("0")
        state["remaining_unabsorbed_cny"] = Decimal("0")
        state["status"] = "released"
        return
    raise ValueError("unknown_budget_transition")
