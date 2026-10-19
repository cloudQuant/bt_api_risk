"""Resolve an AFI static budget member for trusted Risk composition.

The policy catalog remains the single owner of pool reservations and
per-account generations. This resolver consumes only its persisted
``authority_ready`` pointer and an owner-side confirmation readback. It does
not accept a generation, policy receipt, or policy document from a service
caller, and it does not make a gate effective until trusted account-admission
composition installs the returned immutable policy.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from typing import Final

from bt_api_base.service_protocol import WireScope
from bt_api_risk.core.admission import RiskPolicy

from .service_component import (
    ConfirmedPolicyStore,
    PolicyCatalogError,
    PolicyCatalogStore,
)

_RECEIPT_FIELDS: Final[frozenset[str]] = frozenset(
    {"policy_ref", "policy_version", "owner_principal", "owner_scope", "published_utc"}
)
_CONFIRMED_RECEIPT_FIELDS: Final[frozenset[str]] = _RECEIPT_FIELDS | {"confirmed_utc"}
_CONTENT_FIELDS: Final[frozenset[str]] = frozenset({"afi_budget", "risk_policy"})
_AFI_BUDGET_BASE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "kind",
        "schema_version",
        "portfolio_ref",
        "membership_version",
        "membership_sha256",
        "allocation_set_sha256",
        "metric",
        "currency",
        "total_amount",
        "unallocated_amount",
        "account_ref",
        "allocated_amount",
    }
)
_AFI_BUDGET_FX_FIELDS: Final[frozenset[str]] = _AFI_BUDGET_BASE_FIELDS | {
    "source_amount",
    "source_currency",
    "fx_observation",
}
_BUDGET_FX_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "observation_ref",
        "base_currency",
        "quote_currency",
        "direction",
        "rate_unit",
        "rate",
        "as_of_ns",
        "valid_until_ns",
        "source_ref",
        "source_version",
        "source_generation",
        "source_cursor",
    }
)
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


class BudgetAdmissionResolutionError(ValueError):
    """Finite, fail-closed error raised while resolving a ready budget member."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ResolvedBudgetAdmission:
    """One catalog-backed immutable Risk policy and its audit references."""

    pool_ref: str
    generation_ref: str
    portfolio_ref: str
    account_ref: str
    policy_ref: str
    policy_version: str
    risk_policy: RiskPolicy
    fx_observations: tuple[Mapping[str, object], ...] = ()


class PolicyCatalogBudgetAdmissionResolver:
    """Resolve ready per-account policies from the Risk-owned SQLite stores.

    The caller is trusted account-admission composition. ``scope`` must be
    that account's exact registered ``WireScope`` template. The resolver
    reads the current generation through the pool's durable pointer and checks
    the owner-side confirmation store; caller-supplied receipt fields are
    never inputs to the decision.
    """

    def __init__(
        self,
        catalog_store: PolicyCatalogStore,
        confirmation_store: ConfirmedPolicyStore,
    ) -> None:
        if type(catalog_store) is not PolicyCatalogStore:
            raise BudgetAdmissionResolutionError("INVALID_POLICY_CATALOG_STORE")
        if type(confirmation_store) is not ConfirmedPolicyStore:
            raise BudgetAdmissionResolutionError("INVALID_CONFIRMATION_STORE")
        self._catalog_store = catalog_store
        self._confirmation_store = confirmation_store

    def resolve(
        self,
        pool_ref: str,
        account_ref: str,
        *,
        scope: WireScope,
    ) -> ResolvedBudgetAdmission:
        """Return the exact member policy only after durable authority readiness."""

        try:
            snapshot = self._catalog_store.read_authority_ready_budget_member(
                pool_ref, account_ref, scope=scope
            )
        except PolicyCatalogError as error:
            raise BudgetAdmissionResolutionError(error.code) from None
        except sqlite3.Error:
            raise BudgetAdmissionResolutionError("POLICY_CATALOG_UNAVAILABLE") from None

        try:
            confirmed = self._confirmation_store.resolve(snapshot["policy_ref"])
        except PolicyCatalogError as error:
            raise BudgetAdmissionResolutionError(error.code) from None
        except sqlite3.Error:
            raise BudgetAdmissionResolutionError("CONFIRMATION_STORE_UNAVAILABLE") from None

        expected_receipt = snapshot["receipt"]
        if (
            not isinstance(confirmed, Mapping)
            or set(confirmed) != _CONFIRMED_RECEIPT_FIELDS
            or type(confirmed.get("confirmed_utc")) is not str
            or not confirmed["confirmed_utc"]
            or any(
                confirmed.get(key) != expected_receipt.get(key)
                for key in _RECEIPT_FIELDS
            )
        ):
            raise BudgetAdmissionResolutionError("CONFIRMED_RECEIPT_MISMATCH")

        content = snapshot["content"]
        if not isinstance(content, Mapping) or set(content) != _CONTENT_FIELDS:
            raise BudgetAdmissionResolutionError("BUDGET_POLICY_CONTENT_MISMATCH")
        afi_budget = content["afi_budget"]
        risk_policy = content["risk_policy"]
        if (
            not isinstance(afi_budget, Mapping)
            or set(afi_budget) not in (_AFI_BUDGET_BASE_FIELDS, _AFI_BUDGET_FX_FIELDS)
            or not isinstance(risk_policy, Mapping)
            or set(risk_policy) != _RISK_POLICY_FIELDS
        ):
            raise BudgetAdmissionResolutionError("BUDGET_POLICY_CONTENT_MISMATCH")

        expected_budget = {
            "kind": "afi.static_account_budget",
            "schema_version": 1,
            "portfolio_ref": snapshot["portfolio_ref"],
            "membership_version": snapshot["membership_version"],
            "membership_sha256": snapshot["membership_sha256"],
            "allocation_set_sha256": snapshot["allocation_set_sha256"],
            "metric": snapshot["metric"],
            "currency": snapshot["currency"],
            "total_amount": snapshot["total_amount"],
            "unallocated_amount": snapshot["unallocated_amount"],
            "account_ref": snapshot["account_ref"],
            "allocated_amount": snapshot["allocated_amount"],
        }
        if any(
            type(afi_budget[key]) is not type(value) or afi_budget[key] != value
            for key, value in expected_budget.items()
        ):
            raise BudgetAdmissionResolutionError("BUDGET_POLICY_CONTENT_MISMATCH")

        generation_fx = snapshot.get("fx_observations")
        if type(generation_fx) not in (tuple, list):
            raise BudgetAdmissionResolutionError("BUDGET_POLICY_CONTENT_MISMATCH")
        if set(afi_budget) == _AFI_BUDGET_FX_FIELDS:
            source_amount = afi_budget["source_amount"]
            source_currency = afi_budget["source_currency"]
            fx_observation = afi_budget["fx_observation"]
            if (
                type(source_amount) is not str
                or type(source_currency) is not str
                or source_currency == ""
            ):
                raise BudgetAdmissionResolutionError("BUDGET_POLICY_CONTENT_MISMATCH")
            try:
                source_value = Decimal(source_amount)
                allocated_value = Decimal(snapshot["allocated_amount"])
            except (InvalidOperation, TypeError, ValueError):
                raise BudgetAdmissionResolutionError(
                    "BUDGET_POLICY_CONTENT_MISMATCH"
                ) from None
            if (
                not source_value.is_finite()
                or source_value <= 0
                or source_currency == snapshot["currency"]
                and (fx_observation is not None or source_value != allocated_value)
            ):
                raise BudgetAdmissionResolutionError("BUDGET_POLICY_CONTENT_MISMATCH")
            if source_currency != snapshot["currency"]:
                if (
                    not isinstance(fx_observation, Mapping)
                    or set(fx_observation) != _BUDGET_FX_FIELDS
                    or fx_observation.get("base_currency") != source_currency
                    or fx_observation.get("quote_currency") != snapshot["currency"]
                    or fx_observation.get("direction") != "BASE_TO_QUOTE"
                    or fx_observation.get("rate_unit") != "QUOTE_PER_BASE"
                    or not any(item == fx_observation for item in generation_fx)
                ):
                    raise BudgetAdmissionResolutionError(
                        "BUDGET_POLICY_CONTENT_MISMATCH"
                    )
                try:
                    rate = Decimal(fx_observation["rate"])
                    converted = Fraction(source_value) * Fraction(rate)
                    if (
                        not rate.is_finite()
                        or rate <= 0
                        or converted != Fraction(allocated_value)
                    ):
                        raise BudgetAdmissionResolutionError(
                            "BUDGET_POLICY_CONTENT_MISMATCH"
                        )
                except (InvalidOperation, TypeError, ValueError):
                    raise BudgetAdmissionResolutionError(
                        "BUDGET_POLICY_CONTENT_MISMATCH"
                    ) from None
        elif generation_fx:
            raise BudgetAdmissionResolutionError("BUDGET_POLICY_CONTENT_MISMATCH")

        amount = snapshot["allocated_amount"]
        max_count = snapshot["max_increase_count"]
        if (
            type(amount) is not str
            or type(risk_policy.get("policy_id")) is not str
            or risk_policy.get("policy_id") != snapshot["policy_ref"]
            or type(risk_policy.get("max_increase_notional")) is not str
            or risk_policy.get("max_increase_notional") != amount
            or type(max_count) is not int
            or type(risk_policy.get("max_increase_count")) is not int
            or risk_policy.get("max_increase_count") != max_count
            or type(risk_policy.get("permit_ttl_seconds")) is not float
            or risk_policy.get("permit_ttl_seconds") != 30.0
            or type(risk_policy.get("require_strategy_allocation")) is not bool
            or risk_policy.get("require_strategy_allocation") is not False
            or type(risk_policy.get("notional_unit")) is not str
            or risk_policy.get("notional_unit") != snapshot["currency"]
            or snapshot["metric"] != "max_increase_notional"
        ):
            raise BudgetAdmissionResolutionError("BUDGET_POLICY_CONTENT_MISMATCH")
        try:
            limit = Decimal(amount)
            policy = RiskPolicy(
                policy_id=snapshot["policy_ref"],
                max_increase_notional=limit,
                max_increase_count=max_count,
                permit_ttl_seconds=risk_policy["permit_ttl_seconds"],
                require_strategy_allocation=risk_policy["require_strategy_allocation"],
                notional_unit=snapshot["currency"],
            )
        except (InvalidOperation, TypeError, ValueError):
            raise BudgetAdmissionResolutionError("BUDGET_POLICY_CONTENT_MISMATCH") from None

        return ResolvedBudgetAdmission(
            pool_ref=snapshot["pool_ref"],
            generation_ref=snapshot["generation_ref"],
            portfolio_ref=snapshot["portfolio_ref"],
            account_ref=snapshot["account_ref"],
            policy_ref=snapshot["policy_ref"],
            policy_version=snapshot["policy_version"],
            risk_policy=policy,
            fx_observations=tuple(generation_fx),
        )


__all__ = [
    "BudgetAdmissionResolutionError",
    "PolicyCatalogBudgetAdmissionResolver",
    "ResolvedBudgetAdmission",
]
