"""Pure service-option validation and local risk read/policy adapters.

This module imports only the neutral ``bt_api_base`` wire contract and the
local admission gate. It does not import SDK composition, transport, provider,
network, or analytical packages. ``RiskReadService`` borrows an already
configured ``DurableRiskGate`` and maps exact ``WireScope`` templates to
trusted ``AccountScope`` values. Its snapshot is the owner's local reservation
ledger; it is not an external account, position, or provider snapshot.

``PolicyCatalogService`` is the R control-plane adapter for the fixed
``policy_catalog`` role. It stores immutable, version-keyed policy versions in
an operator-supplied durable ``PolicyCatalogStore`` and serves the
``service.risk_policy`` control-plane operations, including static-budget
proposal and confirmation. Budget readiness is not an every-order admission
decision. ``ConfirmedPolicyStore`` is the owner-side durable pin of the exact
version/digest the catalog confirmed; it never re-reads a mutable latest and
never contacts the catalog at resolution time.

``GroupPolicyService`` is the internal-only admission gate for the fixed
``group_policy`` role. It is never served on a public port: the trusted
resource provider pins one immutable version in a ``GroupPolicyStore``,
constructs the gate against that exact version, and hands the same object to
the group coordinator. ``evaluate`` fails closed on version drift, scope, or
document denial and returns constant rejection codes only.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Final, Iterator

from bt_api_base.service_protocol import WireScope

from bt_api_risk.core.admission import AccountScope, DurableRiskGate

_REF_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VERSIONED_REF_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]*-v[1-9][0-9]*$"
)
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_MODES: Final[frozenset[str]] = frozenset({"research", "imported", "paper"})
_MAX_POLICY_CONTENT_BYTES: Final[int] = 64 * 1024
_MAX_POLICY_CONTENT_DEPTH: Final[int] = 24
_BUDGET_METRIC: Final[str] = "max_increase_notional"
_BUDGET_KIND: Final[str] = "afi.static_account_budget"
_BUDGET_SCHEMA_VERSION: Final[int] = 1
_MAX_BUDGET_MEMBERS: Final[int] = 256
_MAX_BUDGET_SCALE: Final[int] = 18
_MAX_BUDGET_UNITS: Final[int] = 9_223_372_036_854_775_807
_BUDGET_HELD_STATES: Final[tuple[str, ...]] = (
    "proposed",
    "approved",
    "publishing",
    "partial_hold",
    "unknown_hold",
    "authority_ready",
)
_BUDGET_AMOUNT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?$"
)
_BUDGET_CURRENCY_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")
_POLICY_SCOPE_FIELDS: Final[tuple[str, ...]] = (
    "execution_domain_ref",
    "account_ref",
    "account_refs",
    "strategy_ref",
    "run_id",
    "manual_book_ref",
    "portfolio_ref",
    "group_id",
    "leg_id",
)
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


# ---------------------------------------------------------------------------
# R policy_catalog control plane (fixed ``policy_catalog`` role).
# ---------------------------------------------------------------------------


class PolicyCatalogError(ValueError):
    """Finite control-plane/store error that does not include caller values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _canonical_json(value: object, *, path: str, depth: int = 0) -> str:
    """Return one canonical JSON encoding of bounded plain content."""

    if depth > _MAX_POLICY_CONTENT_DEPTH:
        raise PolicyCatalogError("INVALID_CONTENT")
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise PolicyCatalogError("INVALID_CONTENT") from None
    if not encoded or len(encoded) > _MAX_POLICY_CONTENT_BYTES:
        raise PolicyCatalogError("INVALID_CONTENT")
    return encoded.decode("utf-8")


def _policy_reference(value: object) -> str:
    if type(value) is not str or _REF_PATTERN.fullmatch(value) is None:
        raise PolicyCatalogError("INVALID_REFERENCE")
    if _VERSIONED_REF_PATTERN.fullmatch(value) is None:
        # Version-keyed addressing only: a mutable ``latest`` alias is never
        # a valid catalog reference.
        raise PolicyCatalogError("VERSIONED_REFERENCE_REQUIRED")
    return value


def _policy_digest(value: object) -> str:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise PolicyCatalogError("INVALID_POLICY_VERSION")
    return value


def _plain_wire_value(value: object, *, depth: int = 0) -> object:
    """Copy one wire-frozen value into plain JSON containers.

    The wire protocol freezes decoded payloads: every object becomes an
    immutable ``MappingProxyType`` and every array a ``tuple``. The policy
    store and the owner-side pin persist plain, canonical JSON, so this
    adapter boundary normalizes both wire-frozen and plain values into the
    same bounded ``dict``/``list`` shape before any digest is computed.
    """

    if depth > _MAX_POLICY_CONTENT_DEPTH:
        raise PolicyCatalogError("INVALID_CONTENT")
    if isinstance(value, Mapping):
        return {
            key: _plain_wire_value(item, depth=depth + 1) for key, item in value.items()
        }
    if type(value) in (list, tuple):
        return [_plain_wire_value(item, depth=depth + 1) for item in value]
    return value


def _management_scope(scope: object) -> tuple[dict[str, object], str]:
    """Validate one exact management/owner ``WireScope`` template.

    Policy management is not an order route: the scope must be run-free and
    every non-empty field is a validated plain string. The canonical JSON form
    is what the catalog stores and returns as the effective-receipt owner.
    """

    if type(scope) is not WireScope:
        raise PolicyCatalogError("INVALID_SCOPE")
    try:
        fields = vars(scope)
    except TypeError:
        raise PolicyCatalogError("INVALID_SCOPE") from None
    if type(fields) is not dict or set(fields) != set(_POLICY_SCOPE_FIELDS):
        raise PolicyCatalogError("INVALID_SCOPE")
    canonical: dict[str, object] = {}
    for name in _POLICY_SCOPE_FIELDS:
        value = fields[name]
        if name == "account_refs":
            if type(value) is not tuple or any(
                not _valid_wire_text(account) for account in value
            ):
                raise PolicyCatalogError("INVALID_SCOPE")
            canonical[name] = list(value)
        elif value is None:
            canonical[name] = None
        elif _valid_wire_text(value):
            canonical[name] = value
        else:
            raise PolicyCatalogError("INVALID_SCOPE")
    if canonical["run_id"] is not None:
        raise PolicyCatalogError("INVALID_SCOPE")
    return canonical, json.dumps(canonical, sort_keys=True, separators=(",", ":"))


def _plain_scope(value: object) -> dict[str, object]:
    try:
        value = _plain_wire_value(value)
    except PolicyCatalogError:
        raise PolicyCatalogError("INVALID_SCOPE") from None
    if type(value) is not dict or set(value) != set(_POLICY_SCOPE_FIELDS):
        raise PolicyCatalogError("INVALID_SCOPE")
    canonical: dict[str, object] = {}
    for name in _POLICY_SCOPE_FIELDS:
        item = value[name]
        if name == "account_refs":
            if type(item) is not list or any(not _valid_wire_text(a) for a in item):
                raise PolicyCatalogError("INVALID_SCOPE")
            canonical[name] = list(item)
        elif item is None:
            canonical[name] = None
        elif _valid_wire_text(item):
            canonical[name] = item
        else:
            raise PolicyCatalogError("INVALID_SCOPE")
    if canonical["run_id"] is not None:
        raise PolicyCatalogError("INVALID_SCOPE")
    return canonical


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _budget_amount_units(value: object, scale: int, *, allow_zero: bool) -> int:
    """Parse a canonical base-10 amount into the pool's exact integer unit."""

    if (
        type(value) is not str
        or len(value) > 64
        or _BUDGET_AMOUNT_PATTERN.fullmatch(value) is None
        or type(scale) is not int
        or not 0 <= scale <= _MAX_BUDGET_SCALE
    ):
        raise PolicyCatalogError("INVALID_BUDGET_AMOUNT")
    try:
        amount = Decimal(value)
    except InvalidOperation:
        raise PolicyCatalogError("INVALID_BUDGET_AMOUNT") from None
    sign, digits, exponent = amount.as_tuple()
    if sign or len(digits) > 38 or exponent < -scale or amount.adjusted() > 63:
        raise PolicyCatalogError("INVALID_BUDGET_AMOUNT")
    coefficient = int("".join(str(digit) for digit in digits) or "0")
    units = coefficient * (10 ** (exponent + scale))
    if units < 0 or units > _MAX_BUDGET_UNITS or (units == 0 and not allow_zero):
        raise PolicyCatalogError("INVALID_BUDGET_AMOUNT")
    return units


def _budget_units_text(units: int, scale: int) -> str:
    """Return the canonical decimal text represented by integer pool units."""

    if type(units) is not int or units < 0 or type(scale) is not int:
        raise PolicyCatalogError("INVALID_BUDGET_AMOUNT")
    if scale == 0:
        return str(units)
    whole, fraction = divmod(units, 10**scale)
    tail = f"{fraction:0{scale}d}".rstrip("0")
    return str(whole) if not tail else f"{whole}.{tail}"


class PolicyCatalogStore:
    """Durable immutable policy versions for the ``policy_catalog`` role.

    The store is operator-owned: it is opened by the trusted resource provider
    and borrowed by the service adapter. Lifecycle is
    ``draft`` -> ``approved`` -> ``published``; a reference is a version-keyed
    policy identifier (``...-vN``) and is deduplicated by exact reference.
    Published rows are immutable: a same-content re-draft or re-publish is
    rejected with ``POLICY_ALREADY_PUBLISHED`` and an already-published
    reference can never be replaced with different content. Reads and
    effective receipts resolve only exact published versions; there is no
    mutable ``latest`` pointer.
    """

    _STATES: Final[frozenset[str]] = frozenset({"draft", "approved", "published"})

    def __init__(
        self,
        path: str,
        *,
        clock: Callable[[], str] = _now_utc,
        trusted_approver_principals: tuple[str, ...] | frozenset[str] = (),
    ) -> None:
        if type(path) is not str or not path:
            raise PolicyCatalogError("INVALID_STORE_PATH")
        if not callable(clock):
            raise PolicyCatalogError("INVALID_CLOCK")
        if type(trusted_approver_principals) not in (tuple, frozenset):
            raise PolicyCatalogError("INVALID_APPROVER_CAPABILITY")
        if any(not _valid_wire_text(value) for value in trusted_approver_principals):
            raise PolicyCatalogError("INVALID_APPROVER_CAPABILITY")
        self._clock = clock
        self._trusted_approver_principals = frozenset(trusted_approver_principals)
        self._write_lock = threading.RLock()
        self._db = sqlite3.connect(path, timeout=10.0, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._db:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS policy_catalog_versions ("
                "reference TEXT PRIMARY KEY, "
                "state TEXT NOT NULL, "
                "digest TEXT NOT NULL, "
                "content_json TEXT NOT NULL, "
                "owner_principal TEXT NOT NULL, "
                "owner_scope_json TEXT NOT NULL, "
                "created_utc TEXT NOT NULL, "
                "published_utc TEXT)"
            )
            columns = {
                row["name"]
                for row in self._db.execute("PRAGMA table_info(policy_catalog_versions)")
            }
            for name, declaration in (
                ("approved_by", "TEXT"),
                ("approved_scope_json", "TEXT"),
                ("approved_utc", "TEXT"),
            ):
                if name not in columns:
                    self._db.execute(
                        f"ALTER TABLE policy_catalog_versions ADD COLUMN {name} {declaration}"
                    )
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS policy_budget_pools ("
                "pool_ref TEXT PRIMARY KEY, "
                "capacity_units INTEGER NOT NULL, "
                "currency TEXT NOT NULL, "
                "metric TEXT NOT NULL, "
                "scale INTEGER NOT NULL, "
                "portfolio_ref TEXT NOT NULL, "
                "membership_version INTEGER NOT NULL, "
                "membership_sha256 TEXT NOT NULL, "
                "account_refs_json TEXT NOT NULL, "
                "authority_generation_ref TEXT, "
                "created_utc TEXT NOT NULL)"
            )
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS policy_budget_generations ("
                "generation_ref TEXT PRIMARY KEY, "
                "pool_ref TEXT NOT NULL, "
                "portfolio_ref TEXT NOT NULL, "
                "membership_version INTEGER NOT NULL, "
                "membership_sha256 TEXT NOT NULL, "
                "allocation_set_sha256 TEXT NOT NULL, "
                "currency TEXT NOT NULL, "
                "metric TEXT NOT NULL, "
                "total_units INTEGER NOT NULL, "
                "unallocated_units INTEGER NOT NULL, "
                "state TEXT NOT NULL, "
                "proposer_principal TEXT NOT NULL, "
                "proposer_scope_json TEXT NOT NULL, "
                "request_digest TEXT NOT NULL, "
                "approved_by TEXT, "
                "approved_scope_json TEXT, "
                "approved_utc TEXT, "
                "created_utc TEXT NOT NULL, "
                "updated_utc TEXT NOT NULL)"
            )
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS policy_budget_generations_pool_state "
                "ON policy_budget_generations(pool_ref, state)"
            )
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS policy_budget_members ("
                "generation_ref TEXT NOT NULL, "
                "account_ref TEXT NOT NULL, "
                "policy_ref TEXT NOT NULL UNIQUE, "
                "amount_units INTEGER NOT NULL, "
                "amount_text TEXT NOT NULL, "
                "max_increase_count INTEGER NOT NULL, "
                "policy_digest TEXT NOT NULL, "
                "owner_principal TEXT NOT NULL, "
                "owner_scope_json TEXT NOT NULL, "
                "state TEXT NOT NULL, "
                "receipt_json TEXT, "
                "PRIMARY KEY(generation_ref, account_ref))"
            )

    def close(self) -> None:
        with self._write_lock:
            self._db.close()

    @contextmanager
    def _immediate(self) -> Iterator[None]:
        """Serialize writes both per connection and across SQLite connections."""

        with self._write_lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._db.rollback()
                raise
            else:
                self._db.commit()

    def _stamp(self) -> str:
        value = self._clock()
        if not _valid_wire_text(value) or len(value) > 64:
            raise PolicyCatalogError("INVALID_CLOCK")
        return value

    def _row(self, reference: str) -> sqlite3.Row | None:
        with self._write_lock:
            return self._db.execute(
                "SELECT * FROM policy_catalog_versions WHERE reference=?", (reference,)
            ).fetchone()

    def draft(
        self,
        reference: str,
        content: object,
        *,
        principal_ref: str,
        scope: object,
    ) -> Mapping[str, object]:
        reference = _policy_reference(reference)
        if not _valid_wire_text(principal_ref):
            raise PolicyCatalogError("INVALID_PRINCIPAL")
        _, scope_json = _management_scope(scope)
        content = _plain_wire_value(content)
        if type(content) is not dict or not content:
            raise PolicyCatalogError("INVALID_CONTENT")
        content_json = _canonical_json(content, path="$.content")
        digest = hashlib.sha256(content_json.encode("utf-8")).hexdigest()
        with self._immediate():
            if self._row(reference) is not None:
                raise PolicyCatalogError("POLICY_ALREADY_PUBLISHED")
            self._db.execute(
                "INSERT INTO policy_catalog_versions "
                "(reference, state, digest, content_json, owner_principal, "
                "owner_scope_json, created_utc, published_utc) "
                "VALUES (?, 'draft', ?, ?, ?, ?, ?, NULL)",
                (reference, digest, content_json, principal_ref, scope_json, self._stamp()),
            )
        return {"policy_ref": reference, "policy_version": digest, "state": "draft"}

    def _require_approver(self, principal_ref: str) -> None:
        if not _valid_wire_text(principal_ref):
            raise PolicyCatalogError("INVALID_PRINCIPAL")
        if principal_ref not in self._trusted_approver_principals:
            raise PolicyCatalogError("APPROVER_NOT_AUTHORIZED")

    def _approve_policy_row(
        self,
        row: sqlite3.Row,
        *,
        principal_ref: str,
        scope_json: str,
    ) -> None:
        if row["state"] != "draft":
            raise PolicyCatalogError("INVALID_STATE")
        self._db.execute(
            "UPDATE policy_catalog_versions SET state='approved', approved_by=?, "
            "approved_scope_json=?, approved_utc=? WHERE reference=?",
            (principal_ref, scope_json, self._stamp(), row["reference"]),
        )

    def approve(
        self,
        reference: str,
        *,
        principal_ref: str,
        scope: object,
    ) -> Mapping[str, object]:
        reference = _policy_reference(reference)
        if not _valid_wire_text(principal_ref):
            raise PolicyCatalogError("INVALID_PRINCIPAL")
        _, scope_json = _management_scope(scope)
        with self._immediate():
            row = self._row(reference)
            if row is None:
                raise PolicyCatalogError("POLICY_NOT_FOUND")
            if "afi_budget" in json.loads(row["content_json"]):
                raise PolicyCatalogError("BUDGET_GENERATION_REQUIRED")
            if row["owner_scope_json"] != scope_json:
                raise PolicyCatalogError("SCOPE_NOT_OWNER")
            self._approve_policy_row(
                row, principal_ref=principal_ref, scope_json=scope_json
            )
        return {"policy_ref": reference, "policy_version": row["digest"], "state": "approved"}

    def _publish_policy_row(self, row: sqlite3.Row) -> Mapping[str, object]:
        reference = row["reference"]
        if row["state"] == "published":
            raise PolicyCatalogError("POLICY_ALREADY_PUBLISHED")
        if row["state"] != "approved":
            raise PolicyCatalogError("POLICY_NOT_APPROVED")
        stamp = self._stamp()
        self._db.execute(
            "UPDATE policy_catalog_versions SET state='published', published_utc=? "
            "WHERE reference=?",
            (stamp, reference),
        )
        return self._receipt_payload(reference, row, stamp)

    def publish(
        self,
        reference: str,
        *,
        principal_ref: str,
        scope: object,
    ) -> Mapping[str, object]:
        reference = _policy_reference(reference)
        if not _valid_wire_text(principal_ref):
            raise PolicyCatalogError("INVALID_PRINCIPAL")
        _, scope_json = _management_scope(scope)
        with self._immediate():
            row = self._row(reference)
            if row is None:
                raise PolicyCatalogError("POLICY_NOT_FOUND")
            if "afi_budget" in json.loads(row["content_json"]):
                raise PolicyCatalogError("BUDGET_GENERATION_REQUIRED")
            if row["approved_by"] != principal_ref:
                raise PolicyCatalogError("APPROVER_MISMATCH")
            if row["approved_scope_json"] != scope_json:
                raise PolicyCatalogError("SCOPE_NOT_OWNER")
            return self._publish_policy_row(row)

    def read(self, reference: str) -> Mapping[str, object]:
        reference = _policy_reference(reference)
        row = self._row(reference)
        if row is None:
            raise PolicyCatalogError("POLICY_NOT_FOUND")
        if row["state"] != "published":
            raise PolicyCatalogError("POLICY_NOT_PUBLISHED")
        content = json.loads(row["content_json"])
        return {
            "policy_ref": reference,
            "policy_version": row["digest"],
            "published_utc": row["published_utc"],
            "content": content,
        }

    def receipt(self, reference: str, *, scope: object) -> Mapping[str, object]:
        reference = _policy_reference(reference)
        _, scope_json = _management_scope(scope)
        row = self._row(reference)
        if row is None:
            raise PolicyCatalogError("POLICY_NOT_FOUND")
        if row["state"] != "published":
            raise PolicyCatalogError("POLICY_NOT_PUBLISHED")
        if row["owner_scope_json"] != scope_json:
            # The effective receipt belongs to the exact owner scope that
            # published the version; other scopes cannot claim it.
            raise PolicyCatalogError("SCOPE_NOT_OWNER")
        return self._receipt_payload(reference, row, row["published_utc"])

    def configure_budget_pool(
        self,
        pool_ref: str,
        *,
        capacity_amount: str,
        currency: str,
        metric: str,
        scale: int,
        portfolio_ref: str,
        membership_version: int,
        membership_sha256: str,
        account_refs: tuple[str, ...],
    ) -> Mapping[str, object]:
        """Install immutable owner-side capacity and its current roster snapshot.

        This setup method is intentionally absent from the public service
        operation set. The trusted Risk resource provider calls it from
        operator configuration; AFI proposal clients cannot raise capacity or
        redefine pool membership.
        """

        pool_ref = _policy_reference(pool_ref)
        capacity_units = _budget_amount_units(capacity_amount, scale, allow_zero=False)
        if (
            type(currency) is not str
            or _BUDGET_CURRENCY_PATTERN.fullmatch(currency) is None
            or metric != _BUDGET_METRIC
            or type(portfolio_ref) is not str
            or _REF_PATTERN.fullmatch(portfolio_ref) is None
            or type(membership_version) is not int
            or membership_version < 1
            or type(membership_sha256) is not str
            or _SHA256_PATTERN.fullmatch(membership_sha256) is None
            or type(account_refs) is not tuple
            or not account_refs
            or len(account_refs) > _MAX_BUDGET_MEMBERS
            or any(not _valid_wire_text(account) for account in account_refs)
            or len(set(account_refs)) != len(account_refs)
        ):
            raise PolicyCatalogError("INVALID_BUDGET_POOL")
        canonical_accounts = tuple(sorted(account_refs))
        accounts_json = json.dumps(canonical_accounts, separators=(",", ":"))
        with self._immediate():
            row = self._db.execute(
                "SELECT * FROM policy_budget_pools WHERE pool_ref=?", (pool_ref,)
            ).fetchone()
            requested = (
                capacity_units,
                currency,
                metric,
                scale,
                portfolio_ref,
                membership_version,
                membership_sha256,
                accounts_json,
            )
            if row is not None:
                existing = (
                    row["capacity_units"],
                    row["currency"],
                    row["metric"],
                    row["scale"],
                    row["portfolio_ref"],
                    row["membership_version"],
                    row["membership_sha256"],
                    row["account_refs_json"],
                )
                if existing != requested:
                    raise PolicyCatalogError("BUDGET_POOL_IMMUTABLE")
                return self._budget_pool_summary(row)
            self._db.execute(
                "INSERT INTO policy_budget_pools "
                "(pool_ref, capacity_units, currency, metric, scale, portfolio_ref, "
                "membership_version, membership_sha256, account_refs_json, "
                "authority_generation_ref, created_utc) VALUES (?,?,?,?,?,?,?,?,?,NULL,?)",
                (
                    pool_ref,
                    capacity_units,
                    currency,
                    metric,
                    scale,
                    portfolio_ref,
                    membership_version,
                    membership_sha256,
                    accounts_json,
                    self._stamp(),
                ),
            )
        return {
            "pool_ref": pool_ref,
            "capacity_amount": _budget_units_text(capacity_units, scale),
            "currency": currency,
            "metric": metric,
            "scale": scale,
            "portfolio_ref": portfolio_ref,
            "membership_version": membership_version,
            "membership_sha256": membership_sha256,
            "account_refs": canonical_accounts,
            "authority_generation_ref": None,
            "consumer_effective": False,
        }

    def update_budget_pool_membership(
        self,
        pool_ref: str,
        *,
        membership_version: int,
        membership_sha256: str,
        account_refs: tuple[str, ...],
    ) -> Mapping[str, object]:
        """Pin a newer trusted roster without releasing any existing claims."""

        pool_ref = _policy_reference(pool_ref)
        if (
            type(membership_version) is not int
            or membership_version < 1
            or type(membership_sha256) is not str
            or _SHA256_PATTERN.fullmatch(membership_sha256) is None
            or type(account_refs) is not tuple
            or not account_refs
            or len(account_refs) > _MAX_BUDGET_MEMBERS
            or any(not _valid_wire_text(account) for account in account_refs)
            or len(set(account_refs)) != len(account_refs)
        ):
            raise PolicyCatalogError("INVALID_BUDGET_MEMBERSHIP")
        canonical_accounts = tuple(sorted(account_refs))
        accounts_json = json.dumps(canonical_accounts, separators=(",", ":"))
        with self._immediate():
            pool = self._db.execute(
                "SELECT * FROM policy_budget_pools WHERE pool_ref=?", (pool_ref,)
            ).fetchone()
            if pool is None:
                raise PolicyCatalogError("BUDGET_POOL_NOT_FOUND")
            if membership_version == pool["membership_version"]:
                if (
                    membership_sha256 == pool["membership_sha256"]
                    and accounts_json == pool["account_refs_json"]
                ):
                    return self._budget_pool_summary(pool)
                raise PolicyCatalogError("BUDGET_MEMBERSHIP_CONFLICT")
            if membership_version <= pool["membership_version"]:
                raise PolicyCatalogError("STALE_BUDGET_MEMBERSHIP")
            if pool["authority_generation_ref"] is not None:
                # There is no consumer-side revocation or replacement protocol
                # in this component yet. Keep the exact roster pinned while a
                # generation is projected as authority-ready.
                raise PolicyCatalogError("BUDGET_AUTHORITY_ALREADY_READY")
            pending = self._db.execute(
                "SELECT 1 FROM policy_budget_generations WHERE pool_ref=? "
                "AND state IN ('proposed','approved','publishing','partial_hold','unknown_hold') "
                "LIMIT 1",
                (pool_ref,),
            ).fetchone()
            if pending is not None:
                raise PolicyCatalogError("BUDGET_MEMBERSHIP_CHANGE_PENDING")
            self._db.execute(
                "UPDATE policy_budget_pools SET membership_version=?, membership_sha256=?, "
                "account_refs_json=? WHERE pool_ref=?",
                (membership_version, membership_sha256, accounts_json, pool_ref),
            )
            updated = self._db.execute(
                "SELECT * FROM policy_budget_pools WHERE pool_ref=?", (pool_ref,)
            ).fetchone()
        return self._budget_pool_summary(updated)

    def propose_budget_generation(
        self,
        proposal: object,
        *,
        principal_ref: str,
        scope: object,
    ) -> Mapping[str, object]:
        """Reserve one complete static allocation set in a single DB write."""

        if not _valid_wire_text(principal_ref):
            raise PolicyCatalogError("INVALID_PRINCIPAL")
        plain = _plain_wire_value(proposal)
        expected_fields = {
            "pool_ref",
            "generation_ref",
            "portfolio_ref",
            "membership_version",
            "membership_sha256",
            "allocation_set_sha256",
            "currency",
            "metric",
            "total_amount",
            "unallocated_amount",
            "allocations",
        }
        if type(plain) is not dict or set(plain) != expected_fields:
            raise PolicyCatalogError("INVALID_BUDGET_PROPOSAL")
        pool_ref = _policy_reference(plain["pool_ref"])
        generation_ref = _policy_reference(plain["generation_ref"])
        portfolio_ref = plain["portfolio_ref"]
        membership_version = plain["membership_version"]
        membership_sha256 = plain["membership_sha256"]
        allocation_set_sha256 = plain["allocation_set_sha256"]
        currency = plain["currency"]
        metric = plain["metric"]
        if (
            type(portfolio_ref) is not str
            or _REF_PATTERN.fullmatch(portfolio_ref) is None
            or type(membership_version) is not int
            or membership_version < 1
            or type(membership_sha256) is not str
            or _SHA256_PATTERN.fullmatch(membership_sha256) is None
            or type(allocation_set_sha256) is not str
            or _SHA256_PATTERN.fullmatch(allocation_set_sha256) is None
            or type(currency) is not str
            or _BUDGET_CURRENCY_PATTERN.fullmatch(currency) is None
            or metric != _BUDGET_METRIC
            or type(plain["allocations"]) is not list
            or not plain["allocations"]
            or len(plain["allocations"]) > _MAX_BUDGET_MEMBERS
        ):
            raise PolicyCatalogError("INVALID_BUDGET_PROPOSAL")
        canonical_scope, scope_json = _management_scope(scope)
        if canonical_scope["portfolio_ref"] != portfolio_ref:
            raise PolicyCatalogError("SCOPE_NOT_OWNER")

        accounts: set[str] = set()
        policy_refs: set[str] = set()
        normalized_allocations: list[dict[str, object]] = []
        total_text = plain["total_amount"]
        unallocated_text = plain["unallocated_amount"]
        if type(total_text) is not str or type(unallocated_text) is not str:
            raise PolicyCatalogError("INVALID_BUDGET_AMOUNT")

        # Scale is fixed by trusted pool configuration; it is read under the
        # same immediate transaction as capacity/overlap checks below.
        with self._immediate():
            pool = self._db.execute(
                "SELECT * FROM policy_budget_pools WHERE pool_ref=?", (pool_ref,)
            ).fetchone()
            if pool is None:
                raise PolicyCatalogError("BUDGET_POOL_NOT_FOUND")
            scale = pool["scale"]
            total_units = _budget_amount_units(total_text, scale, allow_zero=False)
            unallocated_units = _budget_amount_units(
                unallocated_text, scale, allow_zero=True
            )
            if (
                _budget_units_text(total_units, scale) != total_text
                or _budget_units_text(unallocated_units, scale) != unallocated_text
            ):
                raise PolicyCatalogError("INVALID_BUDGET_AMOUNT")
            allocation_units = 0
            for item in plain["allocations"]:
                if type(item) is not dict or set(item) != {
                    "account_ref",
                    "policy_ref",
                    "amount",
                    "max_increase_count",
                    "metric",
                    "currency",
                }:
                    raise PolicyCatalogError("INVALID_BUDGET_ALLOCATION")
                account_ref = item["account_ref"]
                if not _valid_wire_text(account_ref):
                    raise PolicyCatalogError("INVALID_BUDGET_ALLOCATION")
                policy_ref = _policy_reference(item["policy_ref"])
                amount_text = item["amount"]
                amount_units = _budget_amount_units(amount_text, scale, allow_zero=False)
                if (
                    _budget_units_text(amount_units, scale) != amount_text
                    or type(item["max_increase_count"]) is not int
                    or item["max_increase_count"] < 0
                    or item["metric"] != metric
                    or item["currency"] != currency
                    or account_ref in accounts
                    or policy_ref in policy_refs
                ):
                    raise PolicyCatalogError("INVALID_BUDGET_ALLOCATION")
                accounts.add(account_ref)
                policy_refs.add(policy_ref)
                allocation_units += amount_units
                normalized_allocations.append(
                    {
                        "account_ref": account_ref,
                        "policy_ref": policy_ref,
                        "amount": amount_text,
                        "max_increase_count": item["max_increase_count"],
                        "metric": metric,
                        "currency": currency,
                        "amount_units": amount_units,
                    }
                )
            if allocation_units + unallocated_units != total_units:
                raise PolicyCatalogError("BUDGET_NOT_CONSERVED")
            if tuple(sorted(canonical_scope["account_refs"])) != tuple(sorted(accounts)):
                raise PolicyCatalogError("SCOPE_NOT_OWNER")

            manifest = {
                "kind": _BUDGET_KIND,
                "schema_version": _BUDGET_SCHEMA_VERSION,
                "portfolio_ref": portfolio_ref,
                "membership_version": membership_version,
                "membership_sha256": membership_sha256,
                "metric": metric,
                "currency": currency,
                "total_amount": total_text,
                "unallocated_amount": unallocated_text,
                "allocations": [
                    {
                        key: allocation[key]
                        for key in (
                            "account_ref",
                            "policy_ref",
                            "amount",
                            "max_increase_count",
                            "metric",
                            "currency",
                        )
                    }
                    for allocation in sorted(
                        normalized_allocations, key=lambda row: row["account_ref"]
                    )
                ],
            }
            actual_allocation_digest = hashlib.sha256(
                _canonical_json(manifest, path="$.budget").encode("utf-8")
            ).hexdigest()
            if actual_allocation_digest != allocation_set_sha256:
                raise PolicyCatalogError("ALLOCATION_SET_DIGEST_MISMATCH")

            # The trusted roster digest and exact member list are installed by
            # the Risk resource owner; caller-provided membership is only a pin.
            if (
                pool["portfolio_ref"] != portfolio_ref
                or pool["membership_version"] != membership_version
                or pool["membership_sha256"] != membership_sha256
                or pool["currency"] != currency
                or pool["metric"] != metric
            ):
                raise PolicyCatalogError("STALE_OR_MIXED_BUDGET_SCOPE")
            pool_accounts = set(json.loads(pool["account_refs_json"]))
            if not accounts.issubset(pool_accounts):
                raise PolicyCatalogError("MEMBER_OUTSIDE_TRUSTED_ROSTER")

            request_value = {
                "proposal": plain,
                "principal_ref": principal_ref,
                "scope": canonical_scope,
            }
            request_digest = hashlib.sha256(
                _canonical_json(request_value, path="$.proposal").encode("utf-8")
            ).hexdigest()
            existing = self._db.execute(
                "SELECT * FROM policy_budget_generations WHERE generation_ref=?",
                (generation_ref,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["request_digest"] != request_digest
                    or existing["proposer_principal"] != principal_ref
                    or existing["proposer_scope_json"] != scope_json
                ):
                    raise PolicyCatalogError("BUDGET_GENERATION_CONFLICT")
                return self._budget_generation_summary(existing)

            if pool["authority_generation_ref"] is not None:
                # One pool has one prepared authority generation. Replacing it
                # requires a later consumer revocation/rollover contract.
                raise PolicyCatalogError("BUDGET_AUTHORITY_ALREADY_READY")

            held_states = ",".join("?" for _ in _BUDGET_HELD_STATES)
            used = self._db.execute(
                "SELECT COALESCE(SUM(total_units), 0) AS used_units "
                "FROM policy_budget_generations WHERE pool_ref=? "
                f"AND state IN ({held_states})",
                (pool_ref, *_BUDGET_HELD_STATES),
            ).fetchone()["used_units"]
            if used + total_units > pool["capacity_units"]:
                raise PolicyCatalogError("BUDGET_CAPACITY_EXCEEDED")
            if accounts:
                member_marks = ",".join("?" for _ in accounts)
                overlap = self._db.execute(
                    "SELECT 1 FROM policy_budget_members m "
                    "JOIN policy_budget_generations g USING(generation_ref) "
                    "WHERE g.pool_ref=? AND g.state IN ("
                    f"{held_states}) AND m.account_ref IN ({member_marks}) LIMIT 1",
                    (pool_ref, *_BUDGET_HELD_STATES, *sorted(accounts)),
                ).fetchone()
                if overlap is not None:
                    raise PolicyCatalogError("ACCOUNT_ALREADY_CLAIMED")
            for allocation in normalized_allocations:
                if self._db.execute(
                    "SELECT 1 FROM policy_budget_members WHERE policy_ref=?",
                    (allocation["policy_ref"],),
                ).fetchone() is not None:
                    raise PolicyCatalogError("POLICY_ALREADY_BOUND")
                policy = self._row(allocation["policy_ref"])
                if policy is None or policy["state"] != "draft":
                    raise PolicyCatalogError("BUDGET_POLICY_DRAFT_REQUIRED")
                if policy["owner_principal"] != principal_ref:
                    raise PolicyCatalogError("BUDGET_POLICY_OWNER_MISMATCH")
                owner_scope = json.loads(policy["owner_scope_json"])
                if (
                    owner_scope.get("account_ref") != allocation["account_ref"]
                    or owner_scope.get("portfolio_ref") != portfolio_ref
                    or owner_scope.get("execution_domain_ref")
                    != canonical_scope["execution_domain_ref"]
                ):
                    raise PolicyCatalogError("BUDGET_POLICY_SCOPE_MISMATCH")
                content = json.loads(policy["content_json"])
                afi_budget = content.get("afi_budget")
                risk_policy = content.get("risk_policy")
                expected_budget = {
                    "kind": _BUDGET_KIND,
                    "schema_version": _BUDGET_SCHEMA_VERSION,
                    "portfolio_ref": portfolio_ref,
                    "membership_version": membership_version,
                    "membership_sha256": membership_sha256,
                    "allocation_set_sha256": allocation_set_sha256,
                    "metric": metric,
                    "currency": currency,
                    "total_amount": total_text,
                    "unallocated_amount": unallocated_text,
                    "account_ref": allocation["account_ref"],
                    "allocated_amount": allocation["amount"],
                }
                if (
                    afi_budget != expected_budget
                    or type(risk_policy) is not dict
                    or risk_policy.get("policy_id") != allocation["policy_ref"]
                    or risk_policy.get("max_increase_notional") != allocation["amount"]
                    or risk_policy.get("max_increase_count")
                    != allocation["max_increase_count"]
                    or risk_policy.get("notional_unit") != currency
                ):
                    raise PolicyCatalogError("BUDGET_POLICY_CONTENT_MISMATCH")

            stamp = self._stamp()
            self._db.execute(
                "INSERT INTO policy_budget_generations "
                "(generation_ref, pool_ref, portfolio_ref, membership_version, "
                "membership_sha256, allocation_set_sha256, currency, metric, total_units, "
                "unallocated_units, state, proposer_principal, proposer_scope_json, "
                "request_digest, approved_by, approved_scope_json, approved_utc, "
                "created_utc, updated_utc) VALUES (?,?,?,?,?,?,?,?,?,?,'proposed',?,?,?,"
                "NULL,NULL,NULL,?,?)",
                (
                    generation_ref,
                    pool_ref,
                    portfolio_ref,
                    membership_version,
                    membership_sha256,
                    allocation_set_sha256,
                    currency,
                    metric,
                    total_units,
                    unallocated_units,
                    principal_ref,
                    scope_json,
                    request_digest,
                    stamp,
                    stamp,
                ),
            )
            for allocation in normalized_allocations:
                policy = self._row(allocation["policy_ref"])
                self._db.execute(
                    "INSERT INTO policy_budget_members "
                    "(generation_ref, account_ref, policy_ref, amount_units, amount_text, "
                    "max_increase_count, policy_digest, owner_principal, owner_scope_json, "
                    "state, receipt_json) VALUES (?,?,?,?,?,?,?,?,?,'pending',NULL)",
                    (
                        generation_ref,
                        allocation["account_ref"],
                        allocation["policy_ref"],
                        allocation["amount_units"],
                        allocation["amount"],
                        allocation["max_increase_count"],
                        policy["digest"],
                        policy["owner_principal"],
                        policy["owner_scope_json"],
                    ),
                )
            created = self._db.execute(
                "SELECT * FROM policy_budget_generations WHERE generation_ref=?",
                (generation_ref,),
            ).fetchone()
            return self._budget_generation_summary(created)

    def approve_budget_generation(
        self,
        generation_ref: str,
        *,
        principal_ref: str,
        scope: object,
    ) -> Mapping[str, object]:
        generation_ref = _policy_reference(generation_ref)
        self._require_approver(principal_ref)
        _, scope_json = _management_scope(scope)
        with self._immediate():
            generation = self._budget_generation_row(generation_ref)
            if generation is None:
                raise PolicyCatalogError("BUDGET_GENERATION_NOT_FOUND")
            if generation["proposer_principal"] == principal_ref:
                raise PolicyCatalogError("MAKER_CHECKER_REQUIRED")
            if generation["proposer_scope_json"] != scope_json:
                raise PolicyCatalogError("SCOPE_NOT_OWNER")
            if generation["state"] == "approved":
                if (
                    generation["approved_by"] == principal_ref
                    and generation["approved_scope_json"] == scope_json
                ):
                    return self._budget_generation_summary(generation)
                raise PolicyCatalogError("BUDGET_APPROVAL_CONFLICT")
            if generation["state"] != "proposed":
                raise PolicyCatalogError("INVALID_BUDGET_STATE")
            pool = self._db.execute(
                "SELECT * FROM policy_budget_pools WHERE pool_ref=?",
                (generation["pool_ref"],),
            ).fetchone()
            if pool is None or (
                pool["membership_version"] != generation["membership_version"]
                or pool["membership_sha256"] != generation["membership_sha256"]
            ):
                raise PolicyCatalogError("STALE_BUDGET_MEMBERSHIP")
            if pool["authority_generation_ref"] not in (None, generation_ref):
                raise PolicyCatalogError("BUDGET_AUTHORITY_ALREADY_READY")
            members = self._budget_members(generation_ref)
            stamp = self._stamp()
            for member in members:
                policy = self._row(member["policy_ref"])
                if (
                    policy is None
                    or policy["state"] != "draft"
                    or policy["digest"] != member["policy_digest"]
                    or policy["owner_principal"] != generation["proposer_principal"]
                ):
                    raise PolicyCatalogError("BUDGET_POLICY_STATE_CONFLICT")
                if "afi_budget" not in json.loads(policy["content_json"]):
                    raise PolicyCatalogError("BUDGET_POLICY_CONTENT_MISMATCH")
                self._db.execute(
                    "UPDATE policy_catalog_versions SET state='approved', approved_by=?, "
                    "approved_scope_json=?, approved_utc=? WHERE reference=?",
                    (principal_ref, scope_json, stamp, member["policy_ref"]),
                )
            self._db.execute(
                "UPDATE policy_budget_generations SET state='approved', approved_by=?, "
                "approved_scope_json=?, approved_utc=?, updated_utc=? "
                "WHERE generation_ref=?",
                (principal_ref, scope_json, stamp, stamp, generation_ref),
            )
            updated = self._budget_generation_row(generation_ref)
            return self._budget_generation_summary(updated)

    def publish_budget_member(
        self,
        generation_ref: str,
        account_ref: str,
        *,
        principal_ref: str,
        scope: object,
    ) -> Mapping[str, object]:
        generation_ref = _policy_reference(generation_ref)
        if not _valid_wire_text(principal_ref) or not _valid_wire_text(account_ref):
            raise PolicyCatalogError("INVALID_BUDGET_MEMBER")
        _, scope_json = _management_scope(scope)
        with self._immediate():
            generation = self._budget_generation_row(generation_ref)
            if generation is None:
                raise PolicyCatalogError("BUDGET_GENERATION_NOT_FOUND")
            if (
                generation["approved_by"] != principal_ref
                or generation["approved_scope_json"] != scope_json
                or principal_ref not in self._trusted_approver_principals
            ):
                raise PolicyCatalogError("BUDGET_PUBLISH_NOT_AUTHORIZED")
            member = self._budget_member_row(generation_ref, account_ref)
            if member is None:
                raise PolicyCatalogError("BUDGET_MEMBER_NOT_FOUND")
            if member["state"] in ("published", "confirmed"):
                receipt = json.loads(member["receipt_json"])
                return {
                    "generation_ref": generation_ref,
                    "state": generation["state"],
                    "member": receipt,
                    "consumer_effective": False,
                }
            if generation["state"] not in ("approved", "publishing"):
                raise PolicyCatalogError("BUDGET_GENERATION_HELD")
            pool = self._db.execute(
                "SELECT * FROM policy_budget_pools WHERE pool_ref=?",
                (generation["pool_ref"],),
            ).fetchone()
            if pool is None or (
                pool["membership_version"] != generation["membership_version"]
                or pool["membership_sha256"] != generation["membership_sha256"]
            ):
                raise PolicyCatalogError("STALE_BUDGET_MEMBERSHIP")
            if pool["authority_generation_ref"] not in (None, generation_ref):
                raise PolicyCatalogError("BUDGET_AUTHORITY_ALREADY_READY")
            policy = self._row(member["policy_ref"])
            if (
                policy is None
                or policy["state"] != "approved"
                or policy["digest"] != member["policy_digest"]
                or policy["approved_by"] != principal_ref
                or policy["approved_scope_json"] != scope_json
            ):
                raise PolicyCatalogError("BUDGET_POLICY_STATE_CONFLICT")
            receipt = self._publish_policy_row(policy)
            receipt_json = _canonical_json(receipt, path="$.budget_receipt")
            stamp = self._stamp()
            self._db.execute(
                "UPDATE policy_budget_members SET state='published', receipt_json=? "
                "WHERE generation_ref=? AND account_ref=?",
                (receipt_json, generation_ref, account_ref),
            )
            self._db.execute(
                "UPDATE policy_budget_generations SET state='publishing', updated_utc=? "
                "WHERE generation_ref=?",
                (stamp, generation_ref),
            )
            updated = self._budget_generation_row(generation_ref)
            return {
                "generation_ref": generation_ref,
                "state": updated["state"],
                "member": dict(receipt),
                "consumer_effective": False,
            }

    def confirm_budget_member(
        self,
        generation_ref: str,
        account_ref: str,
        *,
        principal_ref: str,
        scope: object,
        confirmation_store: ConfirmedPolicyStore | None,
    ) -> Mapping[str, object]:
        generation_ref = _policy_reference(generation_ref)
        if not _valid_wire_text(principal_ref) or not _valid_wire_text(account_ref):
            raise PolicyCatalogError("INVALID_BUDGET_MEMBER")
        if confirmation_store is not None and type(confirmation_store) is not ConfirmedPolicyStore:
            raise PolicyCatalogError("INVALID_CONFIRMATION_STORE")
        _, scope_json = _management_scope(scope)
        failure: str | None = None
        with self._immediate():
            generation = self._budget_generation_row(generation_ref)
            if generation is None:
                raise PolicyCatalogError("BUDGET_GENERATION_NOT_FOUND")
            member = self._budget_member_row(generation_ref, account_ref)
            if member is None:
                raise PolicyCatalogError("BUDGET_MEMBER_NOT_FOUND")
            if (
                principal_ref != member["owner_principal"]
                or scope_json != member["owner_scope_json"]
            ):
                raise PolicyCatalogError("BUDGET_MEMBER_OWNER_REQUIRED")
            if member["state"] == "rejected":
                raise PolicyCatalogError("BUDGET_MEMBER_REJECTED")
            if member["state"] == "confirmed" and generation["state"] == "authority_ready":
                return self._budget_generation_summary(generation)
            if generation["state"] not in (
                "publishing",
                "partial_hold",
                "unknown_hold",
            ):
                raise PolicyCatalogError("INVALID_BUDGET_STATE")
            if confirmation_store is None:
                failure = "CONFIRMATION_STORE_UNAVAILABLE"
            elif member["receipt_json"] is None:
                failure = "BUDGET_MEMBER_NOT_PUBLISHED"
            else:
                expected = json.loads(member["receipt_json"])
                try:
                    confirmed = confirmation_store.resolve(member["policy_ref"])
                except PolicyCatalogError as error:
                    failure = error.code
                except sqlite3.Error:
                    failure = "CONFIRMATION_STORE_UNAVAILABLE"
                else:
                    if any(confirmed.get(key) != value for key, value in expected.items()):
                        failure = "CONFIRMED_RECEIPT_MISMATCH"
            if failure is not None:
                self._db.execute(
                    "UPDATE policy_budget_members SET state='unknown' "
                    "WHERE generation_ref=? AND account_ref=?",
                    (generation_ref, account_ref),
                )
                self._db.execute(
                    "UPDATE policy_budget_generations SET state='unknown_hold', updated_utc=? "
                    "WHERE generation_ref=?",
                    (self._stamp(), generation_ref),
                )
            else:
                self._db.execute(
                    "UPDATE policy_budget_members SET state='confirmed' "
                    "WHERE generation_ref=? AND account_ref=?",
                    (generation_ref, account_ref),
                )
                remaining = self._db.execute(
                    "SELECT 1 FROM policy_budget_members WHERE generation_ref=? "
                    "AND state!='confirmed' LIMIT 1",
                    (generation_ref,),
                ).fetchone()
                if remaining is None:
                    pool = self._db.execute(
                        "SELECT authority_generation_ref FROM policy_budget_pools "
                        "WHERE pool_ref=?",
                        (generation["pool_ref"],),
                    ).fetchone()
                    if pool is None or pool["authority_generation_ref"] not in (
                        None,
                        generation_ref,
                    ):
                        failure = "BUDGET_AUTHORITY_ALREADY_READY"
                        self._db.execute(
                            "UPDATE policy_budget_generations SET state='unknown_hold', "
                            "updated_utc=? WHERE generation_ref=?",
                            (self._stamp(), generation_ref),
                        )
                    else:
                        stamp = self._stamp()
                        self._db.execute(
                            "UPDATE policy_budget_generations SET state='authority_ready', "
                            "updated_utc=? WHERE generation_ref=?",
                            (stamp, generation_ref),
                        )
                        self._db.execute(
                            "UPDATE policy_budget_pools SET authority_generation_ref=? "
                            "WHERE pool_ref=? AND authority_generation_ref IS NULL",
                            (generation_ref, generation["pool_ref"]),
                        )
                elif generation["state"] in ("partial_hold", "unknown_hold"):
                    # A partial publish or an operational UNKNOWN is sticky.
                    # Confirming one member cannot release or split the whole
                    # pool claim, or reopen publication for other members.
                    self._db.execute(
                        "UPDATE policy_budget_generations SET state=?, updated_utc=? "
                        "WHERE generation_ref=?",
                        (generation["state"], self._stamp(), generation_ref),
                    )
                else:
                    self._db.execute(
                        "UPDATE policy_budget_generations SET state='publishing', updated_utc=? "
                        "WHERE generation_ref=?",
                        (self._stamp(), generation_ref),
                    )
            updated = self._budget_generation_row(generation_ref)
            result = self._budget_generation_summary(updated)
        if failure is not None:
            raise PolicyCatalogError(failure)
        return result

    def reject_budget_member(
        self,
        generation_ref: str,
        account_ref: str,
        *,
        principal_ref: str,
        scope: object,
    ) -> Mapping[str, object]:
        generation_ref = _policy_reference(generation_ref)
        if not _valid_wire_text(principal_ref) or not _valid_wire_text(account_ref):
            raise PolicyCatalogError("INVALID_BUDGET_MEMBER")
        _, scope_json = _management_scope(scope)
        with self._immediate():
            generation = self._budget_generation_row(generation_ref)
            if generation is None:
                raise PolicyCatalogError("BUDGET_GENERATION_NOT_FOUND")
            member = self._budget_member_row(generation_ref, account_ref)
            if member is None:
                raise PolicyCatalogError("BUDGET_MEMBER_NOT_FOUND")
            if (
                principal_ref != member["owner_principal"]
                or scope_json != member["owner_scope_json"]
            ):
                raise PolicyCatalogError("BUDGET_MEMBER_OWNER_REQUIRED")
            if member["state"] == "confirmed":
                raise PolicyCatalogError("CONFIRMED_BUDGET_MEMBER_IMMUTABLE")
            if generation["state"] in ("retracted", "rejected"):
                return self._budget_generation_summary(generation)
            self._db.execute(
                "UPDATE policy_budget_members SET state='rejected' "
                "WHERE generation_ref=? AND account_ref=?",
                (generation_ref, account_ref),
            )
            published = self._db.execute(
                "SELECT 1 FROM policy_budget_members WHERE generation_ref=? "
                "AND receipt_json IS NOT NULL LIMIT 1",
                (generation_ref,),
            ).fetchone()
            if generation["state"] == "unknown_hold":
                new_state = "unknown_hold"
            else:
                new_state = "partial_hold" if published is not None else "rejected"
            self._db.execute(
                "UPDATE policy_budget_generations SET state=?, updated_utc=? "
                "WHERE generation_ref=?",
                (new_state, self._stamp(), generation_ref),
            )
            updated = self._budget_generation_row(generation_ref)
            return self._budget_generation_summary(updated)

    def mark_budget_unknown(
        self,
        generation_ref: str,
        *,
        principal_ref: str,
        scope: object,
    ) -> Mapping[str, object]:
        generation_ref = _policy_reference(generation_ref)
        if not _valid_wire_text(principal_ref):
            raise PolicyCatalogError("INVALID_PRINCIPAL")
        _, scope_json = _management_scope(scope)
        with self._immediate():
            generation = self._budget_generation_row(generation_ref)
            if generation is None:
                raise PolicyCatalogError("BUDGET_GENERATION_NOT_FOUND")
            if (
                scope_json != generation["proposer_scope_json"]
                or principal_ref
                not in (generation["proposer_principal"], generation["approved_by"])
            ):
                raise PolicyCatalogError("BUDGET_PROPOSAL_OWNER_REQUIRED")
            if generation["state"] == "authority_ready":
                raise PolicyCatalogError("AUTHORITY_READY_BUDGET_IMMUTABLE")
            if generation["state"] in ("retracted", "rejected"):
                raise PolicyCatalogError("INVALID_BUDGET_STATE")
            self._db.execute(
                "UPDATE policy_budget_generations SET state='unknown_hold', updated_utc=? "
                "WHERE generation_ref=?",
                (self._stamp(), generation_ref),
            )
            updated = self._budget_generation_row(generation_ref)
            return self._budget_generation_summary(updated)

    def retract_budget_generation(
        self,
        generation_ref: str,
        *,
        principal_ref: str,
        scope: object,
    ) -> Mapping[str, object]:
        generation_ref = _policy_reference(generation_ref)
        _, scope_json = _management_scope(scope)
        with self._immediate():
            generation = self._budget_generation_row(generation_ref)
            if generation is None:
                raise PolicyCatalogError("BUDGET_GENERATION_NOT_FOUND")
            if (
                principal_ref != generation["proposer_principal"]
                or scope_json != generation["proposer_scope_json"]
            ):
                raise PolicyCatalogError("BUDGET_PROPOSAL_OWNER_REQUIRED")
            if generation["state"] == "retracted":
                return self._budget_generation_summary(generation)
            if generation["state"] not in ("proposed", "approved"):
                raise PolicyCatalogError("BUDGET_RETRACTION_UNSAFE")
            published = self._db.execute(
                "SELECT 1 FROM policy_budget_members WHERE generation_ref=? "
                "AND receipt_json IS NOT NULL LIMIT 1",
                (generation_ref,),
            ).fetchone()
            if published is not None:
                raise PolicyCatalogError("BUDGET_RETRACTION_UNSAFE")
            self._db.execute(
                "UPDATE policy_budget_generations SET state='retracted', updated_utc=? "
                "WHERE generation_ref=?",
                (self._stamp(), generation_ref),
            )
            updated = self._budget_generation_row(generation_ref)
            return self._budget_generation_summary(updated)

    def read_budget_generation(
        self, generation_ref: str, *, scope: object
    ) -> Mapping[str, object]:
        generation_ref = _policy_reference(generation_ref)
        _, scope_json = _management_scope(scope)
        generation = self._budget_generation_row(generation_ref)
        if generation is None:
            raise PolicyCatalogError("BUDGET_GENERATION_NOT_FOUND")
        if scope_json != generation["proposer_scope_json"]:
            raise PolicyCatalogError("SCOPE_NOT_OWNER")
        return self._budget_generation_summary(generation)

    def read_authority_ready_budget_member(
        self,
        pool_ref: str,
        account_ref: str,
        *,
        scope: object,
    ) -> Mapping[str, object]:
        """Read one exact member from the pool's persisted ready generation.

        This owner-local snapshot is intentionally not a service operation.
        It resolves through the pool's durable authority pointer, rather than
        trusting a generation reference supplied by a caller, and verifies
        the complete generation/member state in one SQLite read transaction.
        Confirmation-store readback is performed by the admission resolver.
        """

        pool_ref = _policy_reference(pool_ref)
        if not _valid_wire_text(account_ref):
            raise PolicyCatalogError("INVALID_BUDGET_MEMBER")
        canonical_scope, scope_json = _management_scope(scope)
        if canonical_scope["account_ref"] != account_ref:
            raise PolicyCatalogError("BUDGET_MEMBER_SCOPE_MISMATCH")

        with self._write_lock:
            self._db.execute("BEGIN")
            try:
                pool = self._db.execute(
                    "SELECT * FROM policy_budget_pools WHERE pool_ref=?", (pool_ref,)
                ).fetchone()
                if pool is None:
                    raise PolicyCatalogError("BUDGET_POOL_NOT_FOUND")
                if (
                    canonical_scope["portfolio_ref"] != pool["portfolio_ref"]
                    or account_ref not in json.loads(pool["account_refs_json"])
                ):
                    raise PolicyCatalogError("BUDGET_MEMBER_SCOPE_MISMATCH")

                generation_ref = pool["authority_generation_ref"]
                if generation_ref is None:
                    raise PolicyCatalogError("BUDGET_AUTHORITY_NOT_READY")
                generation = self._db.execute(
                    "SELECT * FROM policy_budget_generations WHERE generation_ref=?",
                    (generation_ref,),
                ).fetchone()
                if (
                    generation is None
                    or generation["pool_ref"] != pool_ref
                    or generation["state"] != "authority_ready"
                    or generation["portfolio_ref"] != pool["portfolio_ref"]
                    or generation["membership_version"] != pool["membership_version"]
                    or generation["membership_sha256"] != pool["membership_sha256"]
                    or generation["currency"] != pool["currency"]
                    or generation["metric"] != pool["metric"]
                    or generation["metric"] != _BUDGET_METRIC
                ):
                    raise PolicyCatalogError("BUDGET_AUTHORITY_NOT_READY")

                members = list(
                    self._db.execute(
                        "SELECT * FROM policy_budget_members WHERE generation_ref=? "
                        "ORDER BY account_ref",
                        (generation_ref,),
                    ).fetchall()
                )
                if (
                    not members
                    or any(
                        member["state"] != "confirmed" or member["receipt_json"] is None
                        for member in members
                    )
                    or sum(member["amount_units"] for member in members)
                    + generation["unallocated_units"]
                    != generation["total_units"]
                    or generation["total_units"] > pool["capacity_units"]
                    or any(
                        member["account_ref"]
                        not in json.loads(pool["account_refs_json"])
                        for member in members
                    )
                ):
                    raise PolicyCatalogError("BUDGET_AUTHORITY_NOT_READY")

                member = next(
                    (item for item in members if item["account_ref"] == account_ref),
                    None,
                )
                if member is None:
                    raise PolicyCatalogError("BUDGET_MEMBER_NOT_FOUND")
                if member["owner_scope_json"] != scope_json:
                    raise PolicyCatalogError("BUDGET_MEMBER_SCOPE_MISMATCH")

                policy = self._db.execute(
                    "SELECT * FROM policy_catalog_versions WHERE reference=?",
                    (member["policy_ref"],),
                ).fetchone()
                if (
                    policy is None
                    or policy["state"] != "published"
                    or policy["digest"] != member["policy_digest"]
                    or policy["owner_principal"] != member["owner_principal"]
                    or policy["owner_scope_json"] != member["owner_scope_json"]
                ):
                    raise PolicyCatalogError("BUDGET_POLICY_STATE_CONFLICT")

                content = json.loads(policy["content_json"])
                if (
                    type(content) is not dict
                    or _canonical_json(content, path="$.content")
                    != policy["content_json"]
                    or hashlib.sha256(policy["content_json"].encode("utf-8")).hexdigest()
                    != policy["digest"]
                ):
                    raise PolicyCatalogError("BUDGET_POLICY_CONTENT_MISMATCH")
                receipt = json.loads(member["receipt_json"])
                expected_receipt = dict(
                    self._receipt_payload(
                        member["policy_ref"], policy, policy["published_utc"]
                    )
                )
                if (
                    type(receipt) is not dict
                    or set(receipt) != set(expected_receipt)
                    or receipt != expected_receipt
                ):
                    raise PolicyCatalogError("BUDGET_MEMBER_RECEIPT_MISMATCH")

                result = MappingProxyType(
                    {
                        "pool_ref": pool_ref,
                        "generation_ref": generation_ref,
                        "portfolio_ref": generation["portfolio_ref"],
                        "membership_version": generation["membership_version"],
                        "membership_sha256": generation["membership_sha256"],
                        "allocation_set_sha256": generation["allocation_set_sha256"],
                        "currency": generation["currency"],
                        "metric": generation["metric"],
                        "total_amount": _budget_units_text(
                            generation["total_units"], pool["scale"]
                        ),
                        "unallocated_amount": _budget_units_text(
                            generation["unallocated_units"], pool["scale"]
                        ),
                        "account_ref": member["account_ref"],
                        "allocated_amount": member["amount_text"],
                        "max_increase_count": member["max_increase_count"],
                        "policy_ref": member["policy_ref"],
                        "policy_version": member["policy_digest"],
                        "owner_principal": member["owner_principal"],
                        "owner_scope": MappingProxyType(
                            json.loads(member["owner_scope_json"])
                        ),
                        "receipt": MappingProxyType(expected_receipt),
                        "content": MappingProxyType(
                            {
                                key: MappingProxyType(value)
                                for key, value in content.items()
                                if type(value) is dict
                            }
                        ),
                    }
                )
            except BaseException:
                self._db.rollback()
                raise
            else:
                self._db.commit()
                return result

    def _budget_pool_summary(self, pool: sqlite3.Row) -> Mapping[str, object]:
        marks = ",".join("?" for _ in _BUDGET_HELD_STATES)
        with self._write_lock:
            used = self._db.execute(
                "SELECT COALESCE(SUM(total_units),0) AS used_units "
                "FROM policy_budget_generations WHERE pool_ref=? "
                f"AND state IN ({marks})",
                (pool["pool_ref"], *_BUDGET_HELD_STATES),
            ).fetchone()["used_units"]
        return {
            "pool_ref": pool["pool_ref"],
            "capacity_amount": _budget_units_text(pool["capacity_units"], pool["scale"]),
            "used_amount": _budget_units_text(used, pool["scale"]),
            "available_amount": _budget_units_text(
                pool["capacity_units"] - used, pool["scale"]
            ),
            "currency": pool["currency"],
            "metric": pool["metric"],
            "scale": pool["scale"],
            "portfolio_ref": pool["portfolio_ref"],
            "membership_version": pool["membership_version"],
            "membership_sha256": pool["membership_sha256"],
            "account_refs": tuple(json.loads(pool["account_refs_json"])),
            "authority_generation_ref": pool["authority_generation_ref"],
            "consumer_effective": False,
        }

    def _budget_generation_row(self, generation_ref: str) -> sqlite3.Row | None:
        with self._write_lock:
            return self._db.execute(
                "SELECT * FROM policy_budget_generations WHERE generation_ref=?",
                (generation_ref,),
            ).fetchone()

    def _budget_member_row(
        self, generation_ref: str, account_ref: str
    ) -> sqlite3.Row | None:
        with self._write_lock:
            return self._db.execute(
                "SELECT * FROM policy_budget_members WHERE generation_ref=? AND account_ref=?",
                (generation_ref, account_ref),
            ).fetchone()

    def _budget_members(self, generation_ref: str) -> list[sqlite3.Row]:
        with self._write_lock:
            return list(
                self._db.execute(
                    "SELECT * FROM policy_budget_members WHERE generation_ref=? "
                    "ORDER BY account_ref",
                    (generation_ref,),
                ).fetchall()
            )

    def _budget_generation_summary(
        self, generation: sqlite3.Row
    ) -> Mapping[str, object]:
        with self._write_lock:
            pool = self._db.execute(
                "SELECT scale FROM policy_budget_pools WHERE pool_ref=?",
                (generation["pool_ref"],),
            ).fetchone()
        members = tuple(
            {
                "account_ref": member["account_ref"],
                "policy_ref": member["policy_ref"],
                "amount": member["amount_text"],
                "policy_version": member["policy_digest"],
                "state": member["state"],
            }
            for member in self._budget_members(generation["generation_ref"])
        )
        return {
            "generation_ref": generation["generation_ref"],
            "pool_ref": generation["pool_ref"],
            "portfolio_ref": generation["portfolio_ref"],
            "membership_version": generation["membership_version"],
            "membership_sha256": generation["membership_sha256"],
            "allocation_set_sha256": generation["allocation_set_sha256"],
            "currency": generation["currency"],
            "metric": generation["metric"],
            "total_amount": _budget_units_text(generation["total_units"], pool["scale"]),
            "unallocated_amount": _budget_units_text(
                generation["unallocated_units"], pool["scale"]
            ),
            "state": generation["state"],
            "proposed_by": generation["proposer_principal"],
            "approved_by": generation["approved_by"],
            "members": members,
            "consumer_effective": False,
        }

    @staticmethod
    def _receipt_payload(
        reference: str, row: sqlite3.Row | Mapping[str, object], published_utc: object
    ) -> Mapping[str, object]:
        return {
            "policy_ref": reference,
            "policy_version": row["digest"],
            "owner_principal": row["owner_principal"],
            "owner_scope": json.loads(row["owner_scope_json"]),
            "published_utc": published_utc,
        }


class PolicyCatalogService:
    """Serve catalog and single-owner static-budget control-plane actions.

    This is a versioned policy directory, not an every-order admission
    service. Each action receives the already-authenticated principal and the
    exact registered scope from the SDK registry; the adapter adds immutable
    version semantics and owner-scoped effective receipts and does not treat
    caller-supplied values as authorization evidence. Business rejections are
    returned in-band as ``ok: false`` codes so no side effect is implied.
    """

    SUPPORTED_OPERATIONS: Final[frozenset[str]] = frozenset(
        {
            "policy.read",
            "policy.draft",
            "policy.approve",
            "policy.publish",
            "policy.receipt",
            "policy.budget.propose",
            "policy.budget.approve",
            "policy.budget.publish_member",
            "policy.budget.confirm_member",
            "policy.budget.reject_member",
            "policy.budget.mark_unknown",
            "policy.budget.retract",
            "policy.budget.read",
        }
    )

    _READ_ARGUMENTS: Final[frozenset[str]] = frozenset({"policy_ref"})
    _DRAFT_ARGUMENTS: Final[frozenset[str]] = frozenset({"policy_ref", "content"})
    _BUDGET_GENERATION_ARGUMENTS: Final[frozenset[str]] = frozenset({"generation_ref"})
    _BUDGET_MEMBER_ARGUMENTS: Final[frozenset[str]] = frozenset(
        {"generation_ref", "account_ref"}
    )

    def __init__(
        self,
        store: PolicyCatalogStore,
        *,
        confirmation_store: ConfirmedPolicyStore | None = None,
    ) -> None:
        if type(store) is not PolicyCatalogStore:
            raise RiskServiceError("INVALID_POLICY_CATALOG_STORE")
        if confirmation_store is not None and type(confirmation_store) is not ConfirmedPolicyStore:
            raise RiskServiceError("INVALID_CONFIRMED_POLICY_STORE")
        self._store = store
        self._confirmation_store = confirmation_store
        self._closed = False

    @property
    def supported_operations(self) -> frozenset[str]:
        return PolicyCatalogService.SUPPORTED_OPERATIONS

    def close(self) -> None:
        self._closed = True

    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        scope: WireScope,
        arguments: Mapping[str, object],
    ) -> Mapping[str, object]:
        try:
            if self._closed:
                raise PolicyCatalogError("CLOSED")
            if operation not in self.SUPPORTED_OPERATIONS:
                raise PolicyCatalogError("UNKNOWN_OPERATION")
            if not _valid_wire_text(principal_ref) or type(scope) is not WireScope:
                raise PolicyCatalogError("INVALID_REQUEST")
            if not isinstance(arguments, Mapping):
                raise PolicyCatalogError("INVALID_REQUEST")
            keys = set(arguments)
            if operation == "policy.draft":
                if keys != self._DRAFT_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.draft(
                    arguments["policy_ref"],
                    arguments["content"],
                    principal_ref=principal_ref,
                    scope=scope,
                )
            elif operation == "policy.approve":
                if keys != self._READ_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.approve(
                    arguments["policy_ref"], principal_ref=principal_ref, scope=scope
                )
            elif operation == "policy.publish":
                if keys != self._READ_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.publish(
                    arguments["policy_ref"], principal_ref=principal_ref, scope=scope
                )
            elif operation == "policy.read":
                if keys != self._READ_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.read(arguments["policy_ref"])
            elif operation == "policy.receipt":
                if keys != self._READ_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.receipt(arguments["policy_ref"], scope=scope)
            elif operation == "policy.budget.propose":
                result = self._store.propose_budget_generation(
                    arguments, principal_ref=principal_ref, scope=scope
                )
            elif operation == "policy.budget.approve":
                if keys != self._BUDGET_GENERATION_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.approve_budget_generation(
                    arguments["generation_ref"], principal_ref=principal_ref, scope=scope
                )
            elif operation == "policy.budget.publish_member":
                if keys != self._BUDGET_MEMBER_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.publish_budget_member(
                    arguments["generation_ref"],
                    arguments["account_ref"],
                    principal_ref=principal_ref,
                    scope=scope,
                )
            elif operation == "policy.budget.confirm_member":
                if keys != self._BUDGET_MEMBER_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.confirm_budget_member(
                    arguments["generation_ref"],
                    arguments["account_ref"],
                    principal_ref=principal_ref,
                    scope=scope,
                    confirmation_store=self._confirmation_store,
                )
            elif operation == "policy.budget.reject_member":
                if keys != self._BUDGET_MEMBER_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.reject_budget_member(
                    arguments["generation_ref"],
                    arguments["account_ref"],
                    principal_ref=principal_ref,
                    scope=scope,
                )
            elif operation == "policy.budget.mark_unknown":
                if keys != self._BUDGET_GENERATION_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.mark_budget_unknown(
                    arguments["generation_ref"], principal_ref=principal_ref, scope=scope
                )
            elif operation == "policy.budget.retract":
                if keys != self._BUDGET_GENERATION_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.retract_budget_generation(
                    arguments["generation_ref"], principal_ref=principal_ref, scope=scope
                )
            else:
                if keys != self._BUDGET_GENERATION_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.read_budget_generation(
                    arguments["generation_ref"], scope=scope
                )
        except PolicyCatalogError as error:
            return {"ok": False, "code": error.code, "result": {}}
        except sqlite3.Error:
            return {"ok": False, "code": "CATALOG_STORAGE_UNAVAILABLE", "result": {}}
        return {"ok": True, "code": "OK", "result": dict(result)}


SUPPORTED_OPERATIONS: Final[frozenset[str]] = PolicyCatalogService.SUPPORTED_OPERATIONS


class ConfirmedPolicyStore:
    """Owner-side durable pin of catalog-confirmed policy versions.

    ``confirm`` persists exactly the version/digest the catalog returned in an
    effective receipt; the first confirmation for a reference is final, and a
    later receipt for the same reference with a different version is rejected
    instead of silently replacing the confirmed policy. ``resolve`` never
    contacts the catalog and never reads a mutable ``latest``: a short catalog
    outage does not change an already-confirmed valid policy, while an
    unconfirmed reference fails explicitly.
    """

    _RECEIPT_FIELDS: Final[frozenset[str]] = frozenset(
        {"policy_ref", "policy_version", "owner_principal", "owner_scope", "published_utc"}
    )

    def __init__(self, path: str) -> None:
        if type(path) is not str or not path:
            raise PolicyCatalogError("INVALID_STORE_PATH")
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._db:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS confirmed_policies ("
                "reference TEXT PRIMARY KEY, "
                "policy_version TEXT NOT NULL, "
                "owner_principal TEXT NOT NULL, "
                "owner_scope_json TEXT NOT NULL, "
                "published_utc TEXT NOT NULL, "
                "confirmed_utc TEXT NOT NULL)"
            )

    def close(self) -> None:
        self._db.close()

    def confirm(self, receipt: Mapping[str, object]) -> Mapping[str, object]:
        if not isinstance(receipt, Mapping) or set(receipt) != self._RECEIPT_FIELDS:
            raise PolicyCatalogError("INVALID_RECEIPT")
        reference = _policy_reference(receipt["policy_ref"])
        digest = _policy_digest(receipt["policy_version"])
        principal = receipt["owner_principal"]
        if not _valid_wire_text(principal):
            raise PolicyCatalogError("INVALID_RECEIPT")
        scope = _plain_scope(receipt["owner_scope"])
        stamp = receipt["published_utc"]
        if not _valid_wire_text(stamp) or len(stamp) > 64:
            raise PolicyCatalogError("INVALID_RECEIPT")
        scope_json = json.dumps(scope, sort_keys=True, separators=(",", ":"))
        with self._db:
            row = self._db.execute(
                "SELECT * FROM confirmed_policies WHERE reference=?", (reference,)
            ).fetchone()
            if row is not None:
                if (
                    row["policy_version"] != digest
                    or row["owner_principal"] != principal
                    or row["owner_scope_json"] != scope_json
                    or row["published_utc"] != stamp
                ):
                    # A new confirmed version never silently replaces the
                    # pinned one; that would require an explicit migration.
                    raise PolicyCatalogError("POLICY_VERSION_CONFLICT")
                return self._record(row)
            self._db.execute(
                "INSERT INTO confirmed_policies "
                "(reference, policy_version, owner_principal, owner_scope_json, "
                "published_utc, confirmed_utc) VALUES (?,?,?,?,?,?)",
                (reference, digest, principal, scope_json, stamp, _now_utc()),
            )
        return self._record(
            self._db.execute(
                "SELECT * FROM confirmed_policies WHERE reference=?", (reference,)
            ).fetchone()
        )

    def resolve(self, reference: object) -> Mapping[str, object]:
        reference = _policy_reference(reference)
        row = self._db.execute(
            "SELECT * FROM confirmed_policies WHERE reference=?", (reference,)
        ).fetchone()
        if row is None:
            raise PolicyCatalogError("POLICY_NOT_CONFIRMED")
        return self._record(row)

    @staticmethod
    def _record(row: sqlite3.Row) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "policy_ref": row["reference"],
                "policy_version": row["policy_version"],
                "owner_principal": row["owner_principal"],
                "owner_scope": json.loads(row["owner_scope_json"]),
                "published_utc": row["published_utc"],
                "confirmed_utc": row["confirmed_utc"],
            }
        )


# ---------------------------------------------------------------------------
# R group_policy control plane (fixed ``group_policy`` role, internal only).
# ---------------------------------------------------------------------------


class GroupPolicyError(ValueError):
    """Finite group-policy/store error that does not include caller values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_GROUP_POLICY_DOCUMENT_FIELDS: Final[frozenset[str]] = frozenset(
    {"admitted_portfolios", "denied_group_ids"}
)


def _group_policy_reference(value: object) -> str:
    if type(value) is not str or _REF_PATTERN.fullmatch(value) is None:
        raise GroupPolicyError("INVALID_REFERENCE")
    if _VERSIONED_REF_PATTERN.fullmatch(value) is None:
        # Version-keyed addressing only: a mutable ``latest`` alias is never
        # a valid group-policy reference.
        raise GroupPolicyError("VERSIONED_REFERENCE_REQUIRED")
    return value


def _group_policy_digest(value: object) -> str:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise GroupPolicyError("INVALID_POLICY_VERSION")
    return value


def _group_policy_document(value: object) -> dict[str, list[str]]:
    """Validate one bounded plain group-policy document.

    The document is a JSON object with exactly two string arrays:
    ``admitted_portfolios`` (the only portfolio scopes this version admits)
    and ``denied_group_ids`` (groups denied inside an admitted portfolio).
    Unknown keys, duplicate or non-text entries, and wire-frozen tuples are
    normalized away so a stored version can never silently widen its scope.
    """

    if not isinstance(value, Mapping) or set(value) != _GROUP_POLICY_DOCUMENT_FIELDS:
        raise GroupPolicyError("INVALID_DOCUMENT")
    normalized: dict[str, list[str]] = {}
    for field_name in ("admitted_portfolios", "denied_group_ids"):
        entries = value[field_name]
        if (
            type(entries) not in (list, tuple)
            or any(not _valid_wire_text(entry) for entry in entries)
            or len(set(entries)) != len(entries)
        ):
            raise GroupPolicyError("INVALID_DOCUMENT")
        normalized[field_name] = list(entries)
    return normalized


def _group_policy_document_json(value: object) -> tuple[dict[str, list[str]], str]:
    normalized = _group_policy_document(value)
    try:
        document_json = _canonical_json(normalized, path="$.document")
    except PolicyCatalogError:
        raise GroupPolicyError("INVALID_DOCUMENT") from None
    return normalized, document_json


class GroupPolicyStore:
    """Durable immutable group-policy versions for the ``group_policy`` role.

    The store is operator-owned: it is opened by the trusted resource provider
    and borrowed by the service gate. A reference is a version-keyed policy
    identifier (``...-vN``) and a version is the sha256 digest of the
    canonical document, so an activated version is self-certifying. The first
    pin for a reference is final; an identical re-pin is idempotent, and a
    conflicting version or document is rejected with
    ``GROUP_POLICY_VERSION_CONFLICT``. There is no mutable ``latest`` pointer.
    """

    def __init__(self, path: str) -> None:
        if type(path) is not str or not path:
            raise GroupPolicyError("INVALID_STORE_PATH")
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._db:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS group_policy_versions ("
                "group_policy_ref TEXT PRIMARY KEY, "
                "policy_version TEXT NOT NULL, "
                "document_json TEXT NOT NULL, "
                "pinned_utc TEXT NOT NULL)"
            )

    def close(self) -> None:
        self._db.close()

    def _row(self, reference: str) -> sqlite3.Row | None:
        return self._db.execute(
            "SELECT * FROM group_policy_versions WHERE group_policy_ref=?",
            (reference,),
        ).fetchone()

    def pin(
        self, group_policy_ref: str, policy_version: str, document: object
    ) -> Mapping[str, object]:
        reference = _group_policy_reference(group_policy_ref)
        version = _group_policy_digest(policy_version)
        _, document_json = _group_policy_document_json(document)
        digest = hashlib.sha256(document_json.encode("utf-8")).hexdigest()
        if digest != version:
            raise GroupPolicyError("INVALID_POLICY_VERSION")
        with self._db:
            row = self._row(reference)
            if row is not None:
                if row["policy_version"] != version or row["document_json"] != document_json:
                    # A new version never silently replaces the pinned one;
                    # that would require an explicit migration.
                    raise GroupPolicyError("GROUP_POLICY_VERSION_CONFLICT")
                return self._record(row)
            self._db.execute(
                "INSERT INTO group_policy_versions "
                "(group_policy_ref, policy_version, document_json, pinned_utc) "
                "VALUES (?,?,?,?)",
                (reference, version, document_json, _now_utc()),
            )
        row = self._row(reference)
        if row is None:  # pragma: no cover - the insert above must win.
            raise GroupPolicyError("GROUP_POLICY_NOT_FOUND")
        return self._record(row)

    def resolve(self, group_policy_ref: object) -> Mapping[str, object]:
        reference = _group_policy_reference(group_policy_ref)
        row = self._row(reference)
        if row is None:
            raise GroupPolicyError("GROUP_POLICY_NOT_FOUND")
        return self._record(row)

    @staticmethod
    def _record(row: sqlite3.Row) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "group_policy_ref": row["group_policy_ref"],
                "policy_version": row["policy_version"],
                "document": json.loads(row["document_json"]),
                "pinned_utc": row["pinned_utc"],
            }
        )


@dataclass(frozen=True, slots=True)
class GroupAdmissionDecision:
    """Finite decision of one group-admission evaluation.

    ``admitted`` is the only success signal; every refusal carries a constant
    rejection code and the exact ref/version the gate was activated with, so
    a coordinator refusal stays attributable without caller values.
    """

    admitted: bool
    code: str
    group_policy_ref: str
    policy_version: str


class GroupPolicyService:
    """Internal-only group admission gate handed in-process to the coordinator.

    This adapter is never registered on a public port: the trusted resource
    provider constructs it from a version pinned in a ``GroupPolicyStore`` and
    passes the same object both as the risk ``group_policy`` component's
    internal ``service.group_admission`` port and to the group coordinator.
    ``evaluate`` resolves the exact activated version once per group
    submission and fails closed on version drift, scope, or document denial.
    It treats no caller value as authorization evidence.
    """

    SUPPORTED_OPERATIONS: Final[frozenset[str]] = frozenset({"group.admission.evaluate"})

    def __init__(
        self,
        store: GroupPolicyStore,
        group_policy_ref: str,
        policy_version: str,
    ) -> None:
        if type(store) is not GroupPolicyStore:
            raise GroupPolicyError("INVALID_GROUP_POLICY_STORE")
        self._store = store
        self._group_policy_ref = _group_policy_reference(group_policy_ref)
        self._policy_version = _group_policy_digest(policy_version)
        self._closed = False

    @property
    def group_policy_ref(self) -> str:
        return self._group_policy_ref

    @property
    def policy_version(self) -> str:
        return self._policy_version

    @property
    def ready(self) -> bool:
        """True only while the store still serves the exact activated version."""

        if self._closed:
            return False
        try:
            row = self._store._row(self._group_policy_ref)
        except sqlite3.Error:
            return False
        return row is not None and row["policy_version"] == self._policy_version

    def close(self) -> None:
        self._closed = True

    def evaluate(self, *, portfolio_ref: str, group_id: str) -> GroupAdmissionDecision:
        """Admit or refuse one group submission for the exact pinned version.

        The group coordinator has already authenticated the principal and
        authorized the registration before calling this gate; the gate adds
        only the activated group-policy decision.
        """

        if self._closed:
            raise GroupPolicyError("CLOSED")
        if not _valid_wire_text(portfolio_ref) or not _valid_wire_text(group_id):
            raise GroupPolicyError("INVALID_ADMISSION_CONTEXT")
        try:
            row = self._store._row(self._group_policy_ref)
        except sqlite3.Error:
            raise GroupPolicyError("GROUP_POLICY_STORAGE_UNAVAILABLE") from None
        if row is None:
            raise GroupPolicyError("GROUP_POLICY_NOT_FOUND")
        if row["policy_version"] != self._policy_version:
            # Version drift is checked before any scope decision so a stale
            # activation can never admit under a policy it did not pin.
            return self._decision(False, "GROUP_POLICY_VERSION_REJECTED")
        try:
            document = _group_policy_document(json.loads(row["document_json"]))
        except (json.JSONDecodeError, GroupPolicyError):
            raise GroupPolicyError("INVALID_DOCUMENT") from None
        if portfolio_ref not in document["admitted_portfolios"]:
            return self._decision(False, "GROUP_POLICY_SCOPE_DENIED")
        if group_id in document["denied_group_ids"]:
            return self._decision(False, "GROUP_POLICY_DENIED")
        return self._decision(True, "OK")

    def _decision(self, admitted: bool, code: str) -> GroupAdmissionDecision:
        return GroupAdmissionDecision(admitted, code, self._group_policy_ref, self._policy_version)


GROUP_POLICY_OPERATIONS: Final[frozenset[str]] = GroupPolicyService.SUPPORTED_OPERATIONS


__all__ = [
    "ConfirmedPolicyStore",
    "GroupAdmissionDecision",
    "GroupPolicyError",
    "GroupPolicyService",
    "GroupPolicyStore",
    "PolicyCatalogError",
    "PolicyCatalogService",
    "PolicyCatalogStore",
    "RiskReadService",
    "RiskServiceError",
    "SUPPORTED_OPERATIONS",
    "validate_service_options",
]
