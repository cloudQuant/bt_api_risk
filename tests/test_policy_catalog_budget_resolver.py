"""Focused tests for resolving persisted AFI budgets into Risk policies."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path

import pytest
from bt_api_base.service_protocol import WireScope
from bt_api_risk.budget_admission import (
    BudgetAdmissionResolutionError,
    PolicyCatalogBudgetAdmissionResolver,
)
from bt_api_risk.core.admission import RiskPolicy
from bt_api_risk.service_component import (
    ConfirmedPolicyStore,
    PolicyCatalogService,
    PolicyCatalogStore,
)

_DOMAIN = "paper:budget"
_PORTFOLIO = "portfolio-a"
_CURRENCY = "USD"
_METRIC = "max_increase_notional"
_MEMBERSHIP_DIGEST = "1" * 64
_MEMBERSHIP_VERSION = 1
_GENERATION = "resolver-generation-v1"
_POOL = "resolver-pool-v1"
_ALLOCATIONS = (
    {
        "account_ref": "acct-a",
        "policy_ref": "resolver-a-v1",
        "amount": "25",
        "max_increase_count": 7,
    },
    {
        "account_ref": "acct-b",
        "policy_ref": "resolver-b-v1",
        "amount": "15",
        "max_increase_count": 4,
    },
)


def _scope(account_ref: str | None = None) -> WireScope:
    if account_ref is None:
        return WireScope(
            execution_domain_ref=_DOMAIN,
            account_refs=("acct-a", "acct-b"),
            portfolio_ref=_PORTFOLIO,
            group_id="budget-group",
        )
    return WireScope(
        execution_domain_ref=_DOMAIN,
        account_ref=account_ref,
        portfolio_ref=_PORTFOLIO,
    )


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _call(
    service: PolicyCatalogService,
    operation: str,
    *,
    principal: str,
    scope: WireScope,
    arguments: dict[str, object],
) -> dict[str, object]:
    reply = service.handle(
        operation,
        principal_ref=principal,
        scope=scope,
        arguments=arguments,
    )
    assert reply["ok"] is True, reply
    assert reply["code"] == "OK", reply
    assert type(reply["result"]) is dict, reply
    return reply["result"]


def _draft_and_propose(service: PolicyCatalogService) -> dict[str, object]:
    allocations = [dict(row, metric=_METRIC, currency=_CURRENCY) for row in _ALLOCATIONS]
    total_amount = "50"
    unallocated_amount = "10"
    manifest = {
        "kind": "afi.static_account_budget",
        "schema_version": 1,
        "portfolio_ref": _PORTFOLIO,
        "membership_version": _MEMBERSHIP_VERSION,
        "membership_sha256": _MEMBERSHIP_DIGEST,
        "metric": _METRIC,
        "currency": _CURRENCY,
        "total_amount": total_amount,
        "unallocated_amount": unallocated_amount,
        "allocations": sorted(allocations, key=lambda row: row["account_ref"]),
    }
    allocation_digest = _digest(manifest)
    for allocation in allocations:
        account_ref = str(allocation["account_ref"])
        policy_ref = str(allocation["policy_ref"])
        amount = str(allocation["amount"])
        content = {
            "afi_budget": {
                "kind": "afi.static_account_budget",
                "schema_version": 1,
                "portfolio_ref": _PORTFOLIO,
                "membership_version": _MEMBERSHIP_VERSION,
                "membership_sha256": _MEMBERSHIP_DIGEST,
                "allocation_set_sha256": allocation_digest,
                "metric": _METRIC,
                "currency": _CURRENCY,
                "total_amount": total_amount,
                "unallocated_amount": unallocated_amount,
                "account_ref": account_ref,
                "allocated_amount": amount,
            },
            "risk_policy": {
                "policy_id": policy_ref,
                "max_increase_notional": amount,
                "max_increase_count": allocation["max_increase_count"],
                "permit_ttl_seconds": 30.0,
                "require_strategy_allocation": False,
                "notional_unit": _CURRENCY,
            },
        }
        _call(
            service,
            "policy.draft",
            principal="maker",
            scope=_scope(account_ref),
            arguments={"policy_ref": policy_ref, "content": content},
        )

    proposal: dict[str, object] = {
        "pool_ref": _POOL,
        "generation_ref": _GENERATION,
        "portfolio_ref": _PORTFOLIO,
        "membership_version": _MEMBERSHIP_VERSION,
        "membership_sha256": _MEMBERSHIP_DIGEST,
        "allocation_set_sha256": allocation_digest,
        "currency": _CURRENCY,
        "metric": _METRIC,
        "total_amount": total_amount,
        "unallocated_amount": unallocated_amount,
        "allocations": allocations,
    }
    return _call(
        service,
        "policy.budget.propose",
        principal="maker",
        scope=_scope(),
        arguments=proposal,
    )


def test_resolver_waits_for_whole_authority_and_reopens_persisted_stores(
    tmp_path: Path,
) -> None:
    catalog_path = tmp_path / "catalog.sqlite3"
    confirmation_path = tmp_path / "confirmed.sqlite3"
    store = PolicyCatalogStore(
        str(catalog_path), trusted_approver_principals=("checker",)
    )
    confirmations = ConfirmedPolicyStore(str(confirmation_path))
    service = PolicyCatalogService(store, confirmation_store=confirmations)
    store.configure_budget_pool(
        _POOL,
        capacity_amount="100",
        currency=_CURRENCY,
        metric=_METRIC,
        scale=2,
        portfolio_ref=_PORTFOLIO,
        membership_version=_MEMBERSHIP_VERSION,
        membership_sha256=_MEMBERSHIP_DIGEST,
        account_refs=("acct-a", "acct-b"),
    )
    resolver = PolicyCatalogBudgetAdmissionResolver(store, confirmations)

    try:
        _draft_and_propose(service)
        with pytest.raises(BudgetAdmissionResolutionError) as not_ready:
            resolver.resolve(_POOL, "acct-a", scope=_scope("acct-a"))
        assert not_ready.value.code == "BUDGET_AUTHORITY_NOT_READY"

        _call(
            service,
            "policy.budget.approve",
            principal="checker",
            scope=_scope(),
            arguments={"generation_ref": _GENERATION},
        )
        receipts: dict[str, dict[str, object]] = {}
        for allocation in _ALLOCATIONS:
            account_ref = str(allocation["account_ref"])
            publication = _call(
                service,
                "policy.budget.publish_member",
                principal="checker",
                scope=_scope(),
                arguments={
                    "generation_ref": _GENERATION,
                    "account_ref": account_ref,
                },
            )
            assert publication["consumer_effective"] is False
            receipts[account_ref] = publication["member"]

        confirmations.confirm(receipts["acct-a"])
        _call(
            service,
            "policy.budget.confirm_member",
            principal="maker",
            scope=_scope("acct-a"),
            arguments={"generation_ref": _GENERATION, "account_ref": "acct-a"},
        )
        with pytest.raises(BudgetAdmissionResolutionError) as partial:
            resolver.resolve(_POOL, "acct-a", scope=_scope("acct-a"))
        assert partial.value.code == "BUDGET_AUTHORITY_NOT_READY"

        confirmations.confirm(receipts["acct-b"])
        final = _call(
            service,
            "policy.budget.confirm_member",
            principal="maker",
            scope=_scope("acct-b"),
            arguments={"generation_ref": _GENERATION, "account_ref": "acct-b"},
        )
        assert final["state"] == "authority_ready"
        assert final["consumer_effective"] is False
    finally:
        service.close()
        store.close()
        confirmations.close()

    reopened_store = PolicyCatalogStore(
        str(catalog_path), trusted_approver_principals=("checker",)
    )
    reopened_confirmations = ConfirmedPolicyStore(str(confirmation_path))
    try:
        resolved = PolicyCatalogBudgetAdmissionResolver(
            reopened_store, reopened_confirmations
        ).resolve(_POOL, "acct-a", scope=_scope("acct-a"))
        assert resolved.pool_ref == _POOL
        assert resolved.generation_ref == _GENERATION
        assert resolved.account_ref == "acct-a"
        assert resolved.policy_ref == "resolver-a-v1"
        assert resolved.policy_version == receipts["acct-a"]["policy_version"]
        assert type(resolved.risk_policy) is RiskPolicy
        assert resolved.risk_policy.max_increase_notional == Decimal("25")
        assert resolved.risk_policy.max_increase_count == 7
        assert resolved.risk_policy.permit_ttl_seconds == 30.0
        assert resolved.risk_policy.require_strategy_allocation is False
        assert resolved.risk_policy.notional_unit == "USD"
        assert resolved.risk_policy.policy_id == "resolver-a-v1"

        unconfirmed_store = ConfirmedPolicyStore(
            str(tmp_path / "unconfirmed.sqlite3")
        )
        try:
            unconfirmed_resolver = PolicyCatalogBudgetAdmissionResolver(
                reopened_store, unconfirmed_store
            )
            with pytest.raises(BudgetAdmissionResolutionError) as missing_confirmation:
                unconfirmed_resolver.resolve(
                    _POOL, "acct-a", scope=_scope("acct-a")
                )
            assert missing_confirmation.value.code == "POLICY_NOT_CONFIRMED"
        finally:
            unconfirmed_store.close()
    finally:
        reopened_store.close()
        reopened_confirmations.close()


def test_resolver_binds_requested_account_and_confirmation_store(
    tmp_path: Path,
) -> None:
    catalog_path = tmp_path / "catalog.sqlite3"
    confirmation_path = tmp_path / "confirmed.sqlite3"
    store = PolicyCatalogStore(
        str(catalog_path), trusted_approver_principals=("checker",)
    )
    confirmations = ConfirmedPolicyStore(str(confirmation_path))
    service = PolicyCatalogService(store, confirmation_store=confirmations)
    store.configure_budget_pool(
        _POOL,
        capacity_amount="100",
        currency=_CURRENCY,
        metric=_METRIC,
        scale=2,
        portfolio_ref=_PORTFOLIO,
        membership_version=_MEMBERSHIP_VERSION,
        membership_sha256=_MEMBERSHIP_DIGEST,
        account_refs=("acct-a", "acct-b"),
    )
    try:
        _draft_and_propose(service)
        resolver = PolicyCatalogBudgetAdmissionResolver(store, confirmations)
        with pytest.raises(BudgetAdmissionResolutionError) as wrong_scope:
            resolver.resolve(_POOL, "acct-a", scope=_scope("acct-b"))
        assert wrong_scope.value.code == "BUDGET_MEMBER_SCOPE_MISMATCH"
    finally:
        service.close()
        store.close()
        confirmations.close()

