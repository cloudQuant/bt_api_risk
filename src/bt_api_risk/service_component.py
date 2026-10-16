"""Pure service-option validation and local risk read/policy adapters.

This module imports only the neutral ``bt_api_base`` wire contract and the
local admission gate. It does not import SDK composition, transport, provider,
network, or analytical packages. ``RiskReadService`` borrows an already
configured ``DurableRiskGate`` and maps exact ``WireScope`` templates to
trusted ``AccountScope`` values. Its snapshot is the owner's local reservation
ledger; it is not an external account, position, or provider snapshot.

``PolicyCatalogService`` is the R control-plane adapter for the fixed
``policy_catalog`` role. It stores immutable, version-keyed policy versions in
an operator-supplied durable ``PolicyCatalogStore`` and serves only the five
``service.risk_policy`` operations. It is not an every-order admission
service. ``ConfirmedPolicyStore`` is the owner-side durable pin of the exact
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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
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
_MAX_POLICY_CONTENT_BYTES: Final[int] = 64 * 1024
_MAX_POLICY_CONTENT_DEPTH: Final[int] = 24
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
    ) -> None:
        if type(path) is not str or not path:
            raise PolicyCatalogError("INVALID_STORE_PATH")
        if not callable(clock):
            raise PolicyCatalogError("INVALID_CLOCK")
        self._clock = clock
        self._db = sqlite3.connect(path, check_same_thread=False)
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

    def close(self) -> None:
        self._db.close()

    def _stamp(self) -> str:
        value = self._clock()
        if not _valid_wire_text(value) or len(value) > 64:
            raise PolicyCatalogError("INVALID_CLOCK")
        return value

    def _row(self, reference: str) -> sqlite3.Row | None:
        row = self._db.execute(
            "SELECT * FROM policy_catalog_versions WHERE reference=?", (reference,)
        ).fetchone()
        return row

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
        with self._db:
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

    def approve(self, reference: str) -> Mapping[str, object]:
        reference = _policy_reference(reference)
        with self._db:
            row = self._row(reference)
            if row is None:
                raise PolicyCatalogError("POLICY_NOT_FOUND")
            if row["state"] != "draft":
                raise PolicyCatalogError("INVALID_STATE")
            self._db.execute(
                "UPDATE policy_catalog_versions SET state='approved' WHERE reference=?",
                (reference,),
            )
        return {"policy_ref": reference, "policy_version": row["digest"], "state": "approved"}

    def publish(self, reference: str) -> Mapping[str, object]:
        reference = _policy_reference(reference)
        with self._db:
            row = self._row(reference)
            if row is None:
                raise PolicyCatalogError("POLICY_NOT_FOUND")
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
    """Serve exactly the five ``service.risk_policy`` control-plane actions.

    This is a versioned policy directory, not an every-order admission
    service. Each action receives the already-authenticated principal and the
    exact registered scope from the SDK registry; the adapter adds immutable
    version semantics and owner-scoped effective receipts and does not treat
    caller-supplied values as authorization evidence. Business rejections are
    returned in-band as ``ok: false`` codes so no side effect is implied.
    """

    SUPPORTED_OPERATIONS: Final[frozenset[str]] = frozenset(
        {"policy.read", "policy.draft", "policy.approve", "policy.publish", "policy.receipt"}
    )

    _READ_ARGUMENTS: Final[frozenset[str]] = frozenset({"policy_ref"})
    _DRAFT_ARGUMENTS: Final[frozenset[str]] = frozenset({"policy_ref", "content"})

    def __init__(self, store: PolicyCatalogStore) -> None:
        if type(store) is not PolicyCatalogStore:
            raise RiskServiceError("INVALID_POLICY_CATALOG_STORE")
        self._store = store
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
                result = self._store.approve(arguments["policy_ref"])
            elif operation == "policy.publish":
                if keys != self._READ_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.publish(arguments["policy_ref"])
            elif operation == "policy.read":
                if keys != self._READ_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.read(arguments["policy_ref"])
            else:
                if keys != self._READ_ARGUMENTS:
                    raise PolicyCatalogError("INVALID_REQUEST")
                result = self._store.receipt(arguments["policy_ref"], scope=scope)
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
