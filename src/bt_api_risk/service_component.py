"""Pure service-option validation and a local risk-ledger read adapter.

This module imports only the neutral ``bt_api_base`` wire contract and the
local admission gate. It does not import SDK composition, transport, provider,
network, or analytical packages. ``RiskReadService`` borrows an already
configured ``DurableRiskGate`` and maps exact ``WireScope`` templates to
trusted ``AccountScope`` values. Its snapshot is the owner's local reservation
ledger; it is not an external account, position, or provider snapshot.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from decimal import Decimal
from types import MappingProxyType
from typing import Final

from bt_api_base.service_protocol import WireScope

from bt_api_risk.core.admission import AccountScope, DurableRiskGate

_REF_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VERSIONED_REF_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]*-v[1-9][0-9]*$"
)
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_MODES: Final[frozenset[str]] = frozenset({"research", "imported", "paper"})
_RISK_ROLE_PORTS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "account_admission": frozenset(
            {
                "service.order_admission",
                "service.risk_query",
                "service.group_reservations",
                "service.owner_control",
            }
        ),
        "group_policy": frozenset({"service.group_admission"}),
        "portfolio_analytics": frozenset({"service.risk_analysis"}),
        "policy_catalog": frozenset({"service.risk_policy"}),
    }
)
_WIRE_SCOPE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "execution_domain_ref",
        "account_ref",
        "account_refs",
        "strategy_ref",
        "run_id",
        "manual_book_ref",
        "portfolio_ref",
        "group_id",
        "leg_id",
    }
)


class RiskServiceError(ValueError):
    """Finite adapter/configuration error that does not include caller values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def validate_service_options(
    options: Mapping[str, object], bind_ports: tuple[str, ...]
) -> Mapping[str, object]:
    """Validate one risk component role using the parent SDK's exact contract.

    The returned mapping is detached and immutable. ``allowed_source_modes``
    is returned as a tuple so callers cannot mutate the validated projection.
    Validation performs no I/O and does not import optional analytics code.
    """

    if not isinstance(options, Mapping) or type(bind_ports) is not tuple:
        raise RiskServiceError("INVALID_OPTIONS")
    if not bind_ports or any(type(port) is not str for port in bind_ports):
        raise RiskServiceError("INVALID_BIND_PORTS")
    if len(set(bind_ports)) != len(bind_ports):
        raise RiskServiceError("DUPLICATE_BIND_PORT")

    role = options.get("role")
    if type(role) is not str or role not in _RISK_ROLE_PORTS:
        raise RiskServiceError("UNKNOWN_ROLE")
    if any(port not in _RISK_ROLE_PORTS[role] for port in bind_ports):
        raise RiskServiceError("PORT_ROLE_MISMATCH")

    if role == "account_admission":
        _check_option_keys(options, {"role", "account_policy_ref"})
        result: dict[str, object] = {
            "role": role,
            "account_policy_ref": _versioned_reference(options.get("account_policy_ref")),
        }
        return MappingProxyType(result)

    if role == "group_policy":
        _check_option_keys(options, {"role", "group_policy_ref"})
        result = {
            "role": role,
            "group_policy_ref": _versioned_reference(options.get("group_policy_ref")),
        }
        return MappingProxyType(result)

    if role == "portfolio_analytics":
        _check_option_subset(
            options,
            {
                "role",
                "model_profile_ref",
                "allowed_source_modes",
                "max_concurrent_tasks",
                "max_input_bytes",
            },
            {"role", "model_profile_ref", "allowed_source_modes"},
        )
        modes = _source_modes(options.get("allowed_source_modes"))
        result = {
            "role": role,
            "model_profile_ref": _versioned_reference(options.get("model_profile_ref")),
            "allowed_source_modes": modes,
        }
        if "max_concurrent_tasks" in options:
            result["max_concurrent_tasks"] = _bounded_int(options["max_concurrent_tasks"], 1, 64)
        if "max_input_bytes" in options:
            result["max_input_bytes"] = _bounded_int(options["max_input_bytes"], 1, 67_108_864)
        return MappingProxyType(result)

    _check_option_keys(options, {"role"})
    return MappingProxyType({"role": role})


def _check_option_keys(options: Mapping[str, object], expected: set[str]) -> None:
    if any(type(key) is not str for key in options) or set(options) != expected:
        raise RiskServiceError("INVALID_OPTIONS")


def _check_option_subset(
    options: Mapping[str, object], allowed: set[str], required: set[str]
) -> None:
    keys = set(options)
    if (
        any(type(key) is not str for key in options)
        or not required.issubset(keys)
        or not keys.issubset(allowed)
    ):
        raise RiskServiceError("INVALID_OPTIONS")


def _versioned_reference(value: object) -> str:
    if type(value) is not str or _VERSIONED_REF_PATTERN.fullmatch(value) is None:
        raise RiskServiceError("VERSIONED_REFERENCE_REQUIRED")
    if _REF_PATTERN.fullmatch(value) is None:
        raise RiskServiceError("INVALID_REFERENCE")
    return value


def _source_modes(value: object) -> tuple[str, ...]:
    if type(value) not in (list, tuple) or not value:
        raise RiskServiceError("INVALID_SOURCE_MODES")
    if any(type(mode) is not str or mode not in _SOURCE_MODES for mode in value):
        raise RiskServiceError("INVALID_SOURCE_MODES")
    modes = tuple(value)
    if len(set(modes)) != len(modes):
        raise RiskServiceError("DUPLICATE_SOURCE_MODE")
    return modes


def _bounded_int(value: object, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise RiskServiceError("INVALID_OPTION_VALUE")
    return value


class RiskReadService:
    """Serve only owner-maintained ``risk.snapshot`` views from a borrowed gate.

    Scope templates are exact SDK ``WireScope`` instances. A strategy template
    must leave ``run_id`` unset; a request may supply one run ID while every
    other scope field remains identical. Group-root scopes are rejected because
    this gate represents one account and cannot safely aggregate a group.

    Calling ``DurableRiskGate.snapshot`` has the gate's existing housekeeping
    behavior: it may expire eligible active reservations. The adapter adds no
    ledger writes, account lookups, replay window, or acknowledgement state.
    """

    SUPPORTED_OPERATIONS: Final[frozenset[str]] = frozenset({"risk.snapshot"})

    def __init__(
        self,
        gate: DurableRiskGate,
        targets: Mapping[WireScope, AccountScope],
    ) -> None:
        if type(gate) is not DurableRiskGate:
            raise RiskServiceError("INVALID_RISK_GATE")
        if not isinstance(targets, Mapping) or not targets:
            raise RiskServiceError("INVALID_SCOPE_TARGETS")

        first_template = next(iter(targets))
        if type(first_template) is not WireScope:
            raise RiskServiceError("INVALID_SCOPE_TEMPLATE")

        normalized: dict[tuple[object, ...], AccountScope] = {}
        for template, account_scope in targets.items():
            if type(template) is not WireScope:
                raise RiskServiceError("INVALID_SCOPE_TEMPLATE")
            values = _wire_scope_values(template)
            if values[4] is not None:
                raise RiskServiceError("RUN_BOUND_SCOPE_TEMPLATE")
            if values[1] is None or values[2]:
                raise RiskServiceError("SINGLE_ACCOUNT_SCOPE_REQUIRED")
            # A group parent is an aggregate over account_refs, not one account
            # ledger. A child leg is safe only because it names its own account.
            if values[7] is not None and values[8] is None:
                raise RiskServiceError("GROUP_SCOPE_NOT_SUPPORTED")
            if type(account_scope) is not AccountScope:
                raise RiskServiceError("INVALID_ACCOUNT_SCOPE")
            if values in normalized:
                raise RiskServiceError("DUPLICATE_SCOPE_TEMPLATE")
            normalized[values] = account_scope

        self._gate = gate
        self._targets = MappingProxyType(normalized)

    @property
    def order_admission(self) -> DurableRiskGate:
        """Expose the borrowed gate only as an internal composition dependency."""

        return self._gate

    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        scope: WireScope,
        arguments: Mapping[str, object],
    ) -> Mapping[str, object]:
        """Return one JSON-safe local ledger snapshot for an exact trusted scope.

        ``principal_ref`` and the requested scope must already be authenticated
        and authorized by the SDK's service registry. This adapter does not
        treat either value as independent authorization evidence.
        """

        if type(principal_ref) is not str or not _valid_wire_text(principal_ref):
            raise RiskServiceError("INVALID_PRINCIPAL")
        if type(operation) is not str or operation not in self.SUPPORTED_OPERATIONS:
            raise RiskServiceError("UNSUPPORTED_OPERATION")
        if not isinstance(arguments, Mapping) or arguments:
            # In particular, account/provider/environment fields cannot select
            # or widen the trusted WireScope-to-AccountScope mapping.
            raise RiskServiceError("INVALID_ARGUMENTS")

        requested = _wire_scope_values(scope)
        account_scope = self._resolve_target(requested)
        try:
            snapshot = self._gate.snapshot(account_scope)
        except Exception:
            raise RiskServiceError("RISK_SNAPSHOT_UNAVAILABLE") from None
        return _json_snapshot(snapshot)

    def _resolve_target(self, requested: tuple[object, ...]) -> AccountScope:
        for template, account_scope in self._targets.items():
            if template[3] is None:
                if requested == template:
                    return account_scope
                continue

            # This is the SDK's strategy-run template rule: template identity
            # remains exact while the trusted runtime may fill only run_id.
            requested_without_run = requested[:4] + (None,) + requested[5:]
            if requested[4] is not None and requested_without_run == template:
                return account_scope
        raise RiskServiceError("SCOPE_DENIED")


def _json_snapshot(snapshot: object) -> Mapping[str, object]:
    expected = {
        "active_freeze_reasons",
        "increase_count",
        "increase_notional",
        "policy_fingerprint",
    }
    if type(snapshot) is not dict or set(snapshot) != expected:
        raise RiskServiceError("INVALID_RISK_SNAPSHOT")
    reasons = snapshot["active_freeze_reasons"]
    count = snapshot["increase_count"]
    notional = snapshot["increase_notional"]
    fingerprint = snapshot["policy_fingerprint"]
    if (
        type(reasons) is not list
        or any(type(reason) is not str for reason in reasons)
        or type(count) is not int
        or type(notional) is not Decimal
        or notional.is_finite() is not True
        or type(fingerprint) is not str
        or _SHA256_PATTERN.fullmatch(fingerprint) is None
    ):
        raise RiskServiceError("INVALID_RISK_SNAPSHOT")
    return MappingProxyType(
        {
            "source": "local_risk_reservation_ledger",
            "active_freeze_reasons": tuple(reasons),
            "increase_count": count,
            "increase_notional": format(notional, "f"),
            "policy_fingerprint": fingerprint,
        }
    )


def _wire_scope_values(value: object) -> tuple[object, ...]:
    if type(value) is not WireScope:
        raise RiskServiceError("INVALID_SCOPE")
    try:
        fields = vars(value)
    except TypeError:
        raise RiskServiceError("INVALID_SCOPE") from None
    if type(fields) is not dict or set(fields) != _WIRE_SCOPE_FIELDS:
        raise RiskServiceError("INVALID_SCOPE")

    ordered = (
        fields["execution_domain_ref"],
        fields["account_ref"],
        fields["account_refs"],
        fields["strategy_ref"],
        fields["run_id"],
        fields["manual_book_ref"],
        fields["portfolio_ref"],
        fields["group_id"],
        fields["leg_id"],
    )
    if not _valid_wire_text(ordered[0]):
        raise RiskServiceError("INVALID_SCOPE")
    for optional in (
        ordered[1],
        ordered[3],
        ordered[4],
        ordered[5],
        ordered[6],
        ordered[7],
        ordered[8],
    ):
        if optional is not None and not _valid_wire_text(optional):
            raise RiskServiceError("INVALID_SCOPE")
    account_refs = ordered[2]
    if (
        type(account_refs) is not tuple
        or any(not _valid_wire_text(account_ref) for account_ref in account_refs)
        or len(set(account_refs)) != len(account_refs)
    ):
        raise RiskServiceError("INVALID_SCOPE")

    if ordered[4] is not None and ordered[3] is None:
        raise RiskServiceError("INVALID_SCOPE")
    if ordered[5] is not None and ordered[3] is not None:
        raise RiskServiceError("INVALID_SCOPE")
    if ordered[7] is None:
        if ordered[8] is not None or (ordered[1] is not None and account_refs):
            raise RiskServiceError("INVALID_SCOPE")
    elif ordered[8] is None:
        if ordered[6] is None or ordered[1] is not None or not account_refs:
            raise RiskServiceError("INVALID_SCOPE")
    elif ordered[6] is None or ordered[1] is None or account_refs:
        raise RiskServiceError("INVALID_SCOPE")
    return ordered


def _valid_wire_text(value: object) -> bool:
    if type(value) is not str or value != value.strip():
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return (
        bool(encoded)
        and len(encoded) <= 256
        and not any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in value)
    )


__all__ = [
    "RiskReadService",
    "RiskServiceError",
    "validate_service_options",
]
