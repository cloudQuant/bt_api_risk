"""Resolve and bind confirmed ordinary account policies without a latest pointer.

This module is a trusted account-owner composition seam. It consumes exact
published catalog versions for first confirmation, then relies only on the
owner-side durable confirmed document and receipt during restart. It never
handles static AFI budget documents; those retain the stricter whole-generation
resolver and all-member readiness contract.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Final

from bt_api_base.service_protocol import WireScope

from bt_api_risk.core.admission import (
    AccountScope,
    DurableRiskGate,
    DurableRiskPolicyBinding,
    RiskDeniedError,
    RiskPolicy,
)

from .service_component import (
    ConfirmedPolicyStore,
    PolicyCatalogError,
    PolicyCatalogStore,
)

_DOCUMENT_FIELDS: Final[frozenset[str]] = frozenset({"risk_policy"})
_RISK_POLICY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "policy_id",
        "max_increase_notional",
        "max_increase_count",
        "permit_ttl_seconds",
        "require_strategy_allocation",
        "notional_unit",
    }
)
_DECIMAL_TEXT: Final[re.Pattern[str]] = re.compile(
    r"^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?$"
)
_SHA256_TEXT: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_FIELDS: Final[frozenset[str]] = frozenset(
    {"policy_ref", "policy_version", "owner_principal", "owner_scope", "published_utc"}
)
_CONFIRMED_FIELDS: Final[frozenset[str]] = _RECEIPT_FIELDS | {
    "confirmed_utc",
    "content",
}


class PolicyAdmissionResolutionError(ValueError):
    """Finite error raised when an immutable account policy cannot be trusted."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ResolvedAccountPolicy:
    """One exact published/confirmed ordinary account policy."""

    policy_ref: str
    policy_version: str
    account_ref: str
    owner_principal: str
    confirmed_utc: str | None
    risk_policy: RiskPolicy


@dataclass(frozen=True)
class BoundAccountPolicy:
    """A resolved policy read back from the exact durable account ledger."""

    resolved: ResolvedAccountPolicy
    binding: DurableRiskPolicyBinding


class PolicyCatalogAccountAdmissionResolver:
    """Resolve a published policy or restart only from a confirmed exact version.

    ``catalog_store`` may be ``None`` during offline restart. In that mode only
    :meth:`resolve_confirmed` and :meth:`resolve_confirmed_and_bind` are
    available; no catalog or latest lookup is attempted.
    """

    def __init__(
        self,
        catalog_store: PolicyCatalogStore | None,
        confirmation_store: ConfirmedPolicyStore,
    ) -> None:
        if catalog_store is not None and type(catalog_store) is not PolicyCatalogStore:
            raise PolicyAdmissionResolutionError("INVALID_POLICY_CATALOG_STORE")
        if type(confirmation_store) is not ConfirmedPolicyStore:
            raise PolicyAdmissionResolutionError("INVALID_CONFIRMATION_STORE")
        self._catalog_store = catalog_store
        self._confirmation_store = confirmation_store

    def resolve_published(
        self,
        policy_ref: str,
        account_ref: str,
        *,
        scope: WireScope,
    ) -> ResolvedAccountPolicy:
        """Read and validate one exact immutable published catalog document."""

        receipt, content, policy = self._published(policy_ref, account_ref, scope)
        return ResolvedAccountPolicy(
            policy_ref=policy_ref,
            policy_version=str(receipt["policy_version"]),
            account_ref=account_ref,
            owner_principal=str(receipt["owner_principal"]),
            confirmed_utc=None,
            risk_policy=policy,
        )

    def confirm_after_gate_binding(
        self,
        policy_ref: str,
        account_ref: str,
        *,
        principal_ref: str,
        scope: WireScope,
        account_scope: AccountScope,
        gate: DurableRiskGate,
    ) -> BoundAccountPolicy:
        """Confirm only after this account gate persists and reads back the policy.

        The published receipt and document are read internally from the
        catalog. No caller-supplied receipt, policy mapping, or client flag is
    accepted as confirmation evidence. The trusted composition must not expose
    the gate to its dispatch path until this method returns successfully; a
    confirmation-store failure leaves the ledger binding pinned but does not
    authorize the caller to serve from this incomplete startup.
        """

        receipt, content, policy = self._published(policy_ref, account_ref, scope)
        if type(principal_ref) is not str or principal_ref != receipt["owner_principal"]:
            raise PolicyAdmissionResolutionError("POLICY_OWNER_PRINCIPAL_MISMATCH")
        self._require_gate_policy(gate, account_scope, policy)
        binding = self._bind_gate(gate, account_scope, policy)
        try:
            persisted = self._confirmation_store.confirm_document(receipt, content)
            verified = self._confirmation_store.resolve_document(policy_ref)
        except PolicyCatalogError as error:
            raise PolicyAdmissionResolutionError(error.code) from None
        except sqlite3.Error:
            raise PolicyAdmissionResolutionError("CONFIRMATION_STORE_UNAVAILABLE") from None
        if not _same_confirmed_document(persisted, verified, receipt, content):
            raise PolicyAdmissionResolutionError("CONFIRMED_POLICY_READBACK_MISMATCH")
        resolved = ResolvedAccountPolicy(
            policy_ref=policy_ref,
            policy_version=str(receipt["policy_version"]),
            account_ref=account_ref,
            owner_principal=str(receipt["owner_principal"]),
            confirmed_utc=str(verified["confirmed_utc"]),
            risk_policy=policy,
        )
        return BoundAccountPolicy(resolved=resolved, binding=binding)

    def resolve_confirmed(
        self,
        policy_ref: str,
        account_ref: str,
        *,
        scope: WireScope,
    ) -> ResolvedAccountPolicy:
        """Load only the owner-confirmed document and receipt, without catalog I/O."""

        _validate_account_wire_scope(scope, account_ref)
        try:
            record = self._confirmation_store.resolve_document(policy_ref)
        except PolicyCatalogError as error:
            raise PolicyAdmissionResolutionError(error.code) from None
        except sqlite3.Error:
            raise PolicyAdmissionResolutionError("CONFIRMATION_STORE_UNAVAILABLE") from None
        if (
            not isinstance(record, Mapping)
            or set(record) != _CONFIRMED_FIELDS
            or record.get("policy_ref") != policy_ref
            or type(record.get("policy_version")) is not str
            or _SHA256_TEXT.fullmatch(record["policy_version"]) is None
            or type(record.get("owner_principal")) is not str
            or not record["owner_principal"]
            or type(record.get("confirmed_utc")) is not str
            or not record["confirmed_utc"]
            or not _receipt_scope_matches(record.get("owner_scope"), scope)
        ):
            raise PolicyAdmissionResolutionError("CONFIRMED_POLICY_SCOPE_MISMATCH")
        policy = _parse_risk_policy(
            policy_ref=policy_ref,
            policy_version=record["policy_version"],
            content=record["content"],
        )
        return ResolvedAccountPolicy(
            policy_ref=policy_ref,
            policy_version=record["policy_version"],
            account_ref=account_ref,
            owner_principal=record["owner_principal"],
            confirmed_utc=record["confirmed_utc"],
            risk_policy=policy,
        )

    def resolve_confirmed_and_bind(
        self,
        policy_ref: str,
        account_ref: str,
        *,
        scope: WireScope,
        account_scope: AccountScope,
        gate: DurableRiskGate,
    ) -> BoundAccountPolicy:
        """Restore one confirmed version and verify its actual account ledger binding."""

        resolved = self.resolve_confirmed(policy_ref, account_ref, scope=scope)
        self._require_gate_policy(gate, account_scope, resolved.risk_policy)
        binding = self._bind_gate(gate, account_scope, resolved.risk_policy)
        return BoundAccountPolicy(resolved=resolved, binding=binding)

    def _published(
        self, policy_ref: str, account_ref: str, scope: WireScope
    ) -> tuple[Mapping[str, object], Mapping[str, object], RiskPolicy]:
        _validate_account_wire_scope(scope, account_ref)
        store = self._catalog_store
        if store is None:
            raise PolicyAdmissionResolutionError("POLICY_CATALOG_UNAVAILABLE")
        try:
            receipt = store.receipt(policy_ref, scope=scope)
            published = store.read(policy_ref)
        except PolicyCatalogError as error:
            raise PolicyAdmissionResolutionError(error.code) from None
        except sqlite3.Error:
            raise PolicyAdmissionResolutionError("POLICY_CATALOG_UNAVAILABLE") from None
        if (
            not isinstance(receipt, Mapping)
            or set(receipt) != _RECEIPT_FIELDS
            or receipt.get("policy_ref") != policy_ref
            or not isinstance(published, Mapping)
            or set(published) != {"policy_ref", "policy_version", "published_utc", "content"}
            or published.get("policy_ref") != policy_ref
            or published.get("policy_version") != receipt.get("policy_version")
            or published.get("published_utc") != receipt.get("published_utc")
            or not _receipt_scope_matches(receipt.get("owner_scope"), scope)
            or type(receipt.get("owner_principal")) is not str
            or not receipt["owner_principal"]
        ):
            raise PolicyAdmissionResolutionError("PUBLISHED_POLICY_RECEIPT_MISMATCH")
        policy = _parse_risk_policy(
            policy_ref=policy_ref,
            policy_version=receipt["policy_version"],
            content=published["content"],
        )
        return receipt, published["content"], policy

    @staticmethod
    def _require_gate_policy(
        gate: DurableRiskGate, account_scope: AccountScope, policy: RiskPolicy
    ) -> None:
        if type(gate) is not DurableRiskGate or type(account_scope) is not AccountScope:
            raise PolicyAdmissionResolutionError("RISK_GATE_BINDING_UNAVAILABLE")
        if (
            gate.policy.policy_id != policy.policy_id
            or gate.policy.fingerprint != policy.fingerprint
        ):
            raise PolicyAdmissionResolutionError("RISK_GATE_POLICY_MISMATCH")

    @staticmethod
    def _bind_gate(
        gate: DurableRiskGate, account_scope: AccountScope, policy: RiskPolicy
    ) -> DurableRiskPolicyBinding:
        try:
            binding = gate.bind_policy(account_scope)
        except RiskDeniedError as error:
            raise PolicyAdmissionResolutionError(error.code) from None
        except Exception:
            raise PolicyAdmissionResolutionError("RISK_GATE_BINDING_UNAVAILABLE") from None
        if (
            type(binding) is not DurableRiskPolicyBinding
            or binding.scope != account_scope
            or binding.policy_id != policy.policy_id
            or binding.policy_fingerprint != policy.fingerprint
            or binding.ledger_identity_ref != gate.ledger_identity_ref
        ):
            raise PolicyAdmissionResolutionError("RISK_GATE_BINDING_READBACK_MISMATCH")
        return binding


def _validate_account_wire_scope(scope: WireScope, account_ref: str) -> None:
    if (
        type(scope) is not WireScope
        or type(account_ref) is not str
        or not account_ref
        or scope.account_ref != account_ref
        or scope.account_refs != ()
        or scope.strategy_ref is not None
        or scope.run_id is not None
        or scope.group_id is not None
        or scope.leg_id is not None
        or (
            scope.manual_book_ref is not None and scope.portfolio_ref is not None
        )
    ):
        raise PolicyAdmissionResolutionError("ACCOUNT_POLICY_SCOPE_REQUIRED")


def _receipt_scope_matches(owner_scope: object, scope: WireScope) -> bool:
    if not isinstance(owner_scope, Mapping):
        return False
    expected = {
        "execution_domain_ref": scope.execution_domain_ref,
        "account_ref": scope.account_ref,
        "account_refs": [],
        "strategy_ref": scope.strategy_ref,
        "run_id": scope.run_id,
        "manual_book_ref": scope.manual_book_ref,
        "portfolio_ref": scope.portfolio_ref,
        "group_id": scope.group_id,
        "leg_id": scope.leg_id,
    }
    return type(owner_scope) is dict and owner_scope == expected


def _canonical_document(content: object) -> tuple[dict[str, object], str]:
    if not isinstance(content, Mapping) or set(content) != _DOCUMENT_FIELDS:
        raise PolicyAdmissionResolutionError("POLICY_DOCUMENT_INVALID")
    try:
        plain = _plain_json_value(content)
        if type(plain) is not dict:
            raise ValueError
        encoded = json.dumps(
            plain,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise PolicyAdmissionResolutionError("POLICY_DOCUMENT_INVALID") from None
    if not encoded or len(encoded) > 64 * 1024:
        raise PolicyAdmissionResolutionError("POLICY_DOCUMENT_INVALID")
    return plain, encoded.decode("utf-8")


def _plain_json_value(value: object) -> object:
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError
            result[key] = _plain_json_value(item)
        return result
    if type(value) in (tuple, list):
        return [_plain_json_value(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise ValueError


def _parse_risk_policy(
    *, policy_ref: str, policy_version: object, content: object
) -> RiskPolicy:
    document, content_json = _canonical_document(content)
    if (
        type(policy_version) is not str
        or _SHA256_TEXT.fullmatch(policy_version) is None
        or hashlib.sha256(content_json.encode("utf-8")).hexdigest() != policy_version
    ):
        raise PolicyAdmissionResolutionError("POLICY_DOCUMENT_DIGEST_MISMATCH")
    raw = document["risk_policy"]
    if not isinstance(raw, Mapping) or set(raw) != _RISK_POLICY_FIELDS:
        raise PolicyAdmissionResolutionError("POLICY_DOCUMENT_UNSUPPORTED")
    if (
        type(raw.get("policy_id")) is not str
        or raw["policy_id"] != policy_ref
        or type(raw.get("max_increase_notional")) is not str
        or _DECIMAL_TEXT.fullmatch(raw["max_increase_notional"]) is None
        or type(raw.get("max_increase_count")) is not int
        or raw["max_increase_count"] < 0
        or type(raw.get("permit_ttl_seconds")) is not float
        or not math.isfinite(raw["permit_ttl_seconds"])
        or raw["permit_ttl_seconds"] <= 0
        or type(raw.get("require_strategy_allocation")) is not bool
        or (
            raw.get("notional_unit") is not None
            and type(raw.get("notional_unit")) is not str
        )
    ):
        raise PolicyAdmissionResolutionError("POLICY_DOCUMENT_UNSUPPORTED")
    try:
        notional = Decimal(raw["max_increase_notional"])
        if not notional.is_finite() or notional.is_signed():
            raise ValueError
        return RiskPolicy(
            policy_id=policy_ref,
            max_increase_notional=notional,
            max_increase_count=raw["max_increase_count"],
            permit_ttl_seconds=raw["permit_ttl_seconds"],
            require_strategy_allocation=raw["require_strategy_allocation"],
            notional_unit=raw["notional_unit"],
        )
    except (InvalidOperation, TypeError, ValueError):
        raise PolicyAdmissionResolutionError("POLICY_DOCUMENT_UNSUPPORTED") from None


def _same_confirmed_document(
    persisted: object,
    verified: object,
    receipt: Mapping[str, object],
    content: Mapping[str, object],
) -> bool:
    if not isinstance(persisted, Mapping) or not isinstance(verified, Mapping):
        return False
    return all(
        persisted.get(key) == receipt.get(key) == verified.get(key)
        for key in _RECEIPT_FIELDS
    ) and persisted.get("content") == verified.get("content") == content and bool(
        verified.get("confirmed_utc")
    )


__all__ = [
    "BoundAccountPolicy",
    "PolicyAdmissionResolutionError",
    "PolicyCatalogAccountAdmissionResolver",
    "ResolvedAccountPolicy",
]
