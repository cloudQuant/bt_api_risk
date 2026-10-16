"""Focused tests for the Risk-owned AFI static-budget authority path."""

from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
import traceback
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from queue import Empty, Queue
from threading import Barrier

import zmq
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from bt_api_py.service_components import ComponentResources
from bt_api_py.service_config import parse_client_config, parse_service_config
from bt_api_py.service_host import ServiceHost, TrustedServiceAuthority
from bt_api_py.service_registry import PrincipalGrant, ResourceGrant
from bt_api_py.service_runtime import (
    ClientCurveKeys,
    ServiceClientRuntime,
    ZmqTransportFactory,
)
from bt_api_risk.service_component import (
    ConfirmedPolicyStore,
    PolicyCatalogService,
    PolicyCatalogStore,
)

_METRIC = "max_increase_notional"
_CURRENCY = "USD"
_PORTFOLIO = "portfolio-a"
_DOMAIN = "paper:budget"
_MEMBERSHIP_VERSION = 1
_MEMBERSHIP_DIGEST = "1" * 64
_APPROVERS = ("maker", "checker")
_SDK_REPLY_FIELDS = frozenset({"ok", "code", "result"})
_BUDGET_SUMMARY_FIELDS = frozenset(
    {
        "generation_ref",
        "pool_ref",
        "portfolio_ref",
        "membership_version",
        "membership_sha256",
        "allocation_set_sha256",
        "currency",
        "metric",
        "total_amount",
        "unallocated_amount",
        "state",
        "proposed_by",
        "approved_by",
        "members",
        "consumer_effective",
    }
)
_BUDGET_MEMBER_SUMMARY_FIELDS = frozenset(
    {"account_ref", "policy_ref", "amount", "policy_version", "state"}
)
_BUDGET_PUBLICATION_FIELDS = frozenset(
    {"generation_ref", "state", "member", "consumer_effective"}
)
_POLICY_RECEIPT_FIELDS = frozenset(
    {"policy_ref", "policy_version", "owner_principal", "owner_scope", "published_utc"}
)
_POLICY_SCOPE_FIELDS = frozenset(
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


def _mapping_with_fields(
    value: object, expected_fields: frozenset[str], *, label: str
) -> Mapping[str, object]:
    assert isinstance(value, Mapping), (label, type(value).__name__)
    assert set(value) == expected_fields, (label, set(value))
    return value


def _budget_summary(
    value: object,
    *,
    expected_state: str,
    expected_approved_by: str | None,
    expected_member_states: tuple[str, str],
    expected_policy_versions: Mapping[str, str] | None = None,
) -> Mapping[str, object]:
    summary = _mapping_with_fields(
        value, _BUDGET_SUMMARY_FIELDS, label="budget generation summary"
    )
    assert summary["generation_ref"] == "afi-budget-generation-v1", summary
    assert summary["pool_ref"] == "pool-a-v1", summary
    assert summary["portfolio_ref"] == _PORTFOLIO, summary
    assert type(summary["membership_version"]) is int
    assert summary["membership_version"] == _MEMBERSHIP_VERSION, summary
    assert summary["membership_sha256"] == _MEMBERSHIP_DIGEST, summary
    assert type(summary["allocation_set_sha256"]) is str
    assert len(summary["allocation_set_sha256"]) == 64
    assert all(character in "0123456789abcdef" for character in summary["allocation_set_sha256"])
    assert summary["currency"] == _CURRENCY, summary
    assert summary["metric"] == _METRIC, summary
    assert summary["total_amount"] == "60", summary
    assert summary["unallocated_amount"] == "10", summary
    assert summary["state"] == expected_state, summary
    assert summary["proposed_by"] == "maker", summary
    assert summary["approved_by"] == expected_approved_by, summary
    assert summary["consumer_effective"] is False, summary

    members = summary["members"]
    assert type(members) is tuple, ("wire arrays decode as tuples", members)
    assert len(members) == 2, members
    expected_members = (
        ("acct-a", "afi-budget-acct-a-v1", "25"),
        ("acct-b", "afi-budget-acct-b-v1", "25"),
    )
    for member, (account_ref, policy_ref, amount), state in zip(
        members, expected_members, expected_member_states, strict=True
    ):
        row = _mapping_with_fields(
            member, _BUDGET_MEMBER_SUMMARY_FIELDS, label="budget member summary"
        )
        assert row["account_ref"] == account_ref, row
        assert row["policy_ref"] == policy_ref, row
        assert row["amount"] == amount, row
        assert type(row["policy_version"]) is str
        assert len(row["policy_version"]) == 64
        assert all(character in "0123456789abcdef" for character in row["policy_version"])
        if expected_policy_versions is not None:
            assert row["policy_version"] == expected_policy_versions[account_ref], row
        assert row["state"] == state, row
    return summary


def _thaw_rpc_value(value: object) -> object:
    """Convert one SDK-frozen reply into JSON containers for a later RPC request."""

    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise AssertionError("SDK-frozen object contains a non-text key")
        return {key: _thaw_rpc_value(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw_rpc_value(item) for item in value]
    if value is None or type(value) in (str, bool, int, float):
        return value
    raise AssertionError(f"SDK reply contains a non-JSON value: {type(value).__name__}")


def _group_scope(account_refs: tuple[str, ...]) -> WireScope:
    return WireScope(
        execution_domain_ref=_DOMAIN,
        account_refs=account_refs,
        portfolio_ref=_PORTFOLIO,
        group_id="budget-group",
    )


def _member_scope(account_ref: str) -> WireScope:
    return WireScope(
        execution_domain_ref=_DOMAIN,
        account_ref=account_ref,
        portfolio_ref=_PORTFOLIO,
    )


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _refresh_allocation_digest(proposal: dict[str, object]) -> None:
    proposal["allocation_set_sha256"] = _digest(
        {
            "kind": "afi.static_account_budget",
            "schema_version": 1,
            "portfolio_ref": proposal["portfolio_ref"],
            "membership_version": proposal["membership_version"],
            "membership_sha256": proposal["membership_sha256"],
            "metric": proposal["metric"],
            "currency": proposal["currency"],
            "total_amount": proposal["total_amount"],
            "unallocated_amount": proposal["unallocated_amount"],
            "allocations": sorted(
                proposal["allocations"], key=lambda item: item["account_ref"]
            ),
        }
    )


def _success(
    service: PolicyCatalogService,
    operation: str,
    *,
    principal_ref: str,
    scope: WireScope,
    arguments: dict[str, object],
) -> dict[str, object]:
    result = service.handle(
        operation,
        principal_ref=principal_ref,
        scope=scope,
        arguments=arguments,
    )
    assert result["ok"] is True
    assert result["code"] == "OK"
    assert type(result["result"]) is dict
    return result["result"]


def _failure(
    service: PolicyCatalogService,
    operation: str,
    expected_code: str,
    *,
    principal_ref: str,
    scope: WireScope,
    arguments: dict[str, object],
) -> None:
    result = service.handle(
        operation,
        principal_ref=principal_ref,
        scope=scope,
        arguments=arguments,
    )
    assert result == {"ok": False, "code": expected_code, "result": {}}


def _configure_pool(store: PolicyCatalogStore, account_refs: tuple[str, ...]) -> None:
    store.configure_budget_pool(
        "pool-a-v1",
        capacity_amount="100",
        currency=_CURRENCY,
        metric=_METRIC,
        scale=2,
        portfolio_ref=_PORTFOLIO,
        membership_version=_MEMBERSHIP_VERSION,
        membership_sha256=_MEMBERSHIP_DIGEST,
        account_refs=account_refs,
    )


def _prepare_generation(
    service: PolicyCatalogService,
    generation_ref: str,
    allocations: tuple[tuple[str, str], ...],
    *,
    total_amount: str,
    unallocated_amount: str,
) -> tuple[dict[str, object], WireScope, dict[str, WireScope]]:
    normalized = [
        {
            "account_ref": account_ref,
            "policy_ref": f"policy-{generation_ref}-{index}-v1",
            "amount": amount,
            "max_increase_count": 10 + index,
            "metric": _METRIC,
            "currency": _CURRENCY,
        }
        for index, (account_ref, amount) in enumerate(allocations)
    ]
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
        "allocations": sorted(normalized, key=lambda item: item["account_ref"]),
    }
    allocation_set_sha256 = _digest(manifest)
    proposal: dict[str, object] = {
        "pool_ref": "pool-a-v1",
        "generation_ref": generation_ref,
        "portfolio_ref": _PORTFOLIO,
        "membership_version": _MEMBERSHIP_VERSION,
        "membership_sha256": _MEMBERSHIP_DIGEST,
        "allocation_set_sha256": allocation_set_sha256,
        "currency": _CURRENCY,
        "metric": _METRIC,
        "total_amount": total_amount,
        "unallocated_amount": unallocated_amount,
        "allocations": normalized,
    }
    member_scopes: dict[str, WireScope] = {}
    for allocation in normalized:
        account_ref = str(allocation["account_ref"])
        policy_ref = str(allocation["policy_ref"])
        amount = str(allocation["amount"])
        member_scope = _member_scope(account_ref)
        member_scopes[account_ref] = member_scope
        content = {
            "afi_budget": {
                "kind": "afi.static_account_budget",
                "schema_version": 1,
                "portfolio_ref": _PORTFOLIO,
                "membership_version": _MEMBERSHIP_VERSION,
                "membership_sha256": _MEMBERSHIP_DIGEST,
                "allocation_set_sha256": allocation_set_sha256,
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
                "notional_unit": _CURRENCY,
            },
        }
        _success(
            service,
            "policy.draft",
            principal_ref="maker",
            scope=member_scope,
            arguments={"policy_ref": policy_ref, "content": content},
        )
    return proposal, _group_scope(tuple(sorted(member_scopes))), member_scopes


def _prepare_and_propose(
    service: PolicyCatalogService,
    generation_ref: str,
    allocations: tuple[tuple[str, str], ...],
    *,
    total_amount: str,
    unallocated_amount: str,
) -> tuple[dict[str, object], WireScope, dict[str, WireScope]]:
    proposal, scope, member_scopes = _prepare_generation(
        service,
        generation_ref,
        allocations,
        total_amount=total_amount,
        unallocated_amount=unallocated_amount,
    )
    _success(
        service,
        "policy.budget.propose",
        principal_ref="maker",
        scope=scope,
        arguments=proposal,
    )
    return proposal, scope, member_scopes


def test_budget_generation_uses_catalog_and_exact_confirmed_member_receipts(
    tmp_path: Path,
) -> None:
    catalog_path = tmp_path / "policy-catalog.sqlite3"
    confirmation_path = tmp_path / "confirmed-policies.sqlite3"
    store = PolicyCatalogStore(
        str(catalog_path), trusted_approver_principals=_APPROVERS
    )
    confirmation_store = ConfirmedPolicyStore(str(confirmation_path))
    service = PolicyCatalogService(store, confirmation_store=confirmation_store)
    _configure_pool(store, ("acct-a", "acct-b"))
    proposal, group_scope, member_scopes = _prepare_and_propose(
        service,
        "generation-a-v1",
        (("acct-a", "25"), ("acct-b", "25")),
        total_amount="60",
        unallocated_amount="10",
    )

    try:
        _failure(
            service,
            "policy.budget.approve",
            "MAKER_CHECKER_REQUIRED",
            principal_ref="maker",
            scope=group_scope,
            arguments={"generation_ref": proposal["generation_ref"]},
        )
        _failure(
            service,
            "policy.budget.approve",
            "APPROVER_NOT_AUTHORIZED",
            principal_ref="untrusted-checker",
            scope=group_scope,
            arguments={"generation_ref": proposal["generation_ref"]},
        )
        _success(
            service,
            "policy.budget.approve",
            principal_ref="checker",
            scope=group_scope,
            arguments={"generation_ref": proposal["generation_ref"]},
        )

        policy_ref = str(proposal["allocations"][0]["policy_ref"])
        _failure(
            service,
            "policy.approve",
            "BUDGET_GENERATION_REQUIRED",
            principal_ref="checker",
            scope=group_scope,
            arguments={"policy_ref": policy_ref},
        )
        _failure(
            service,
            "policy.publish",
            "BUDGET_GENERATION_REQUIRED",
            principal_ref="checker",
            scope=group_scope,
            arguments={"policy_ref": policy_ref},
        )

        receipts: dict[str, dict[str, object]] = {}
        for account_ref in ("acct-a", "acct-b"):
            publication = _success(
                service,
                "policy.budget.publish_member",
                principal_ref="checker",
                scope=group_scope,
                arguments={
                    "generation_ref": proposal["generation_ref"],
                    "account_ref": account_ref,
                },
            )
            assert publication["consumer_effective"] is False
            assert publication["state"] == "publishing"
            receipts[account_ref] = publication["member"]

        _failure(
            service,
            "policy.budget.confirm_member",
            "BUDGET_MEMBER_OWNER_REQUIRED",
            principal_ref="wrong-principal",
            scope=member_scopes["acct-a"],
            arguments={
                "generation_ref": proposal["generation_ref"],
                "account_ref": "acct-a",
            },
        )
        for account_ref in ("acct-a", "acct-b"):
            confirmation_store.confirm(receipts[account_ref])
            confirmed = _success(
                service,
                "policy.budget.confirm_member",
                principal_ref="maker",
                scope=member_scopes[account_ref],
                arguments={
                    "generation_ref": proposal["generation_ref"],
                    "account_ref": account_ref,
                },
            )

        assert confirmed["state"] == "authority_ready"
        assert confirmed["consumer_effective"] is False
        pool = store.configure_budget_pool(
            "pool-a-v1",
            capacity_amount="100",
            currency=_CURRENCY,
            metric=_METRIC,
            scale=2,
            portfolio_ref=_PORTFOLIO,
            membership_version=_MEMBERSHIP_VERSION,
            membership_sha256=_MEMBERSHIP_DIGEST,
            account_refs=("acct-a", "acct-b"),
        )
        assert pool["authority_generation_ref"] == proposal["generation_ref"]
        assert pool["consumer_effective"] is False
    finally:
        service.close()
        store.close()
        confirmation_store.close()

    reopened_store = PolicyCatalogStore(
        str(catalog_path), trusted_approver_principals=_APPROVERS
    )
    reopened_confirmations = ConfirmedPolicyStore(str(confirmation_path))
    reopened_service = PolicyCatalogService(
        reopened_store, confirmation_store=reopened_confirmations
    )
    try:
        persisted = _success(
            reopened_service,
            "policy.budget.read",
            principal_ref="maker",
            scope=group_scope,
            arguments={"generation_ref": proposal["generation_ref"]},
        )
        assert persisted["state"] == "authority_ready"
        assert persisted["total_amount"] == "60"
        assert persisted["unallocated_amount"] == "10"
        assert all(member["state"] == "confirmed" for member in persisted["members"])
    finally:
        reopened_service.close()
        reopened_store.close()
        reopened_confirmations.close()


def test_missing_confirmation_and_unknown_result_keep_whole_claim_held(
    tmp_path: Path,
) -> None:
    store = PolicyCatalogStore(
        str(tmp_path / "policy-catalog.sqlite3"),
        trusted_approver_principals=_APPROVERS,
    )
    confirmation_store = ConfirmedPolicyStore(str(tmp_path / "confirmed.sqlite3"))
    service = PolicyCatalogService(store, confirmation_store=confirmation_store)
    _configure_pool(store, ("acct-a", "acct-b", "acct-c"))
    proposal, group_scope, member_scopes = _prepare_and_propose(
        service,
        "generation-unknown-v1",
        (("acct-a", "25"), ("acct-b", "25")),
        total_amount="60",
        unallocated_amount="10",
    )
    _success(
        service,
        "policy.budget.approve",
        principal_ref="checker",
        scope=group_scope,
        arguments={"generation_ref": proposal["generation_ref"]},
    )
    publication = _success(
        service,
        "policy.budget.publish_member",
        principal_ref="checker",
        scope=group_scope,
        arguments={
            "generation_ref": proposal["generation_ref"],
            "account_ref": "acct-a",
        },
    )

    try:
        _failure(
            service,
            "policy.budget.confirm_member",
            "POLICY_NOT_CONFIRMED",
            principal_ref="maker",
            scope=member_scopes["acct-a"],
            arguments={
                "generation_ref": proposal["generation_ref"],
                "account_ref": "acct-a",
            },
        )
        held = _success(
            service,
            "policy.budget.read",
            principal_ref="maker",
            scope=group_scope,
            arguments={"generation_ref": proposal["generation_ref"]},
        )
        assert held["state"] == "unknown_hold"
        assert held["members"][0]["state"] == "unknown"
        pool = store.configure_budget_pool(
            "pool-a-v1",
            capacity_amount="100",
            currency=_CURRENCY,
            metric=_METRIC,
            scale=2,
            portfolio_ref=_PORTFOLIO,
            membership_version=_MEMBERSHIP_VERSION,
            membership_sha256=_MEMBERSHIP_DIGEST,
            account_refs=("acct-a", "acct-b", "acct-c"),
        )
        assert pool["used_amount"] == "60"
        assert pool["available_amount"] == "40"

        _failure(
            service,
            "policy.budget.publish_member",
            "BUDGET_GENERATION_HELD",
            principal_ref="checker",
            scope=group_scope,
            arguments={
                "generation_ref": proposal["generation_ref"],
                "account_ref": "acct-b",
            },
        )
        _failure(
            service,
            "policy.budget.retract",
            "BUDGET_RETRACTION_UNSAFE",
            principal_ref="maker",
            scope=group_scope,
            arguments={"generation_ref": proposal["generation_ref"]},
        )
        confirmation_store.confirm(publication["member"])
        still_held = _success(
            service,
            "policy.budget.confirm_member",
            principal_ref="maker",
            scope=member_scopes["acct-a"],
            arguments={
                "generation_ref": proposal["generation_ref"],
                "account_ref": "acct-a",
            },
        )
        assert still_held["state"] == "unknown_hold"
        assert still_held["consumer_effective"] is False
    finally:
        service.close()
        store.close()
        confirmation_store.close()


def test_partial_publish_rejection_retains_capacity_and_cannot_retract(
    tmp_path: Path,
) -> None:
    store = PolicyCatalogStore(
        str(tmp_path / "policy-catalog.sqlite3"),
        trusted_approver_principals=_APPROVERS,
    )
    confirmation_store = ConfirmedPolicyStore(str(tmp_path / "confirmed.sqlite3"))
    service = PolicyCatalogService(store, confirmation_store=confirmation_store)
    roster = ("acct-a", "acct-b", "acct-c")
    _configure_pool(store, roster)
    proposal, group_scope, member_scopes = _prepare_and_propose(
        service,
        "generation-partial-v1",
        (("acct-a", "25"), ("acct-b", "25")),
        total_amount="60",
        unallocated_amount="10",
    )
    _success(
        service,
        "policy.budget.approve",
        principal_ref="checker",
        scope=group_scope,
        arguments={"generation_ref": proposal["generation_ref"]},
    )
    _success(
        service,
        "policy.budget.publish_member",
        principal_ref="checker",
        scope=group_scope,
        arguments={
            "generation_ref": proposal["generation_ref"],
            "account_ref": "acct-a",
        },
    )

    try:
        rejected = _success(
            service,
            "policy.budget.reject_member",
            principal_ref="maker",
            scope=member_scopes["acct-b"],
            arguments={
                "generation_ref": proposal["generation_ref"],
                "account_ref": "acct-b",
            },
        )
        assert rejected["state"] == "partial_hold"
        _failure(
            service,
            "policy.budget.retract",
            "BUDGET_RETRACTION_UNSAFE",
            principal_ref="maker",
            scope=group_scope,
            arguments={"generation_ref": proposal["generation_ref"]},
        )
        _failure(
            service,
            "policy.budget.publish_member",
            "BUDGET_GENERATION_HELD",
            principal_ref="checker",
            scope=group_scope,
            arguments={
                "generation_ref": proposal["generation_ref"],
                "account_ref": "acct-b",
            },
        )
        _failure(
            service,
            "policy.budget.confirm_member",
            "BUDGET_MEMBER_REJECTED",
            principal_ref="maker",
            scope=member_scopes["acct-b"],
            arguments={
                "generation_ref": proposal["generation_ref"],
                "account_ref": "acct-b",
            },
        )
        pool = store.configure_budget_pool(
            "pool-a-v1",
            capacity_amount="100",
            currency=_CURRENCY,
            metric=_METRIC,
            scale=2,
            portfolio_ref=_PORTFOLIO,
            membership_version=_MEMBERSHIP_VERSION,
            membership_sha256=_MEMBERSHIP_DIGEST,
            account_refs=roster,
        )
        assert pool["used_amount"] == "60"
        assert pool["available_amount"] == "40"

        another, another_scope, _ = _prepare_generation(
            service,
            "generation-over-capacity-v1",
            (("acct-c", "35"),),
            total_amount="45",
            unallocated_amount="10",
        )
        _failure(
            service,
            "policy.budget.propose",
            "BUDGET_CAPACITY_EXCEEDED",
            principal_ref="maker",
            scope=another_scope,
            arguments=another,
        )
    finally:
        service.close()
        store.close()
        confirmation_store.close()


def test_budget_dimension_conservation_overlap_and_prepublication_release(
    tmp_path: Path,
) -> None:
    store = PolicyCatalogStore(
        str(tmp_path / "policy-catalog.sqlite3"),
        trusted_approver_principals=_APPROVERS,
    )
    service = PolicyCatalogService(store)
    _configure_pool(store, ("acct-a", "acct-b"))
    proposal, group_scope, member_scopes = _prepare_generation(
        service,
        "generation-dimension-v1",
        (("acct-a", "25"),),
        total_amount="30",
        unallocated_amount="5",
    )

    try:
        fx_proposal = {
            **proposal,
            "metric": "fx_rate",
            "allocations": [dict(proposal["allocations"][0])],
        }
        fx_proposal["allocations"][0]["metric"] = "fx_rate"
        _failure(
            service,
            "policy.budget.propose",
            "INVALID_BUDGET_PROPOSAL",
            principal_ref="maker",
            scope=group_scope,
            arguments=fx_proposal,
        )

        currency_proposal = {
            **proposal,
            "currency": "EUR",
            "allocations": [dict(proposal["allocations"][0])],
        }
        currency_proposal["allocations"][0]["currency"] = "EUR"
        _refresh_allocation_digest(currency_proposal)
        _failure(
            service,
            "policy.budget.propose",
            "STALE_OR_MIXED_BUDGET_SCOPE",
            principal_ref="maker",
            scope=group_scope,
            arguments=currency_proposal,
        )

        nonconserved = {
            **proposal,
            "unallocated_amount": "4",
            "allocations": [dict(proposal["allocations"][0])],
        }
        _refresh_allocation_digest(nonconserved)
        _failure(
            service,
            "policy.budget.propose",
            "BUDGET_NOT_CONSERVED",
            principal_ref="maker",
            scope=group_scope,
            arguments=nonconserved,
        )

        fractional = {
            **proposal,
            "allocations": [dict(proposal["allocations"][0])],
        }
        fractional["allocations"][0]["amount"] = "25.001"
        _failure(
            service,
            "policy.budget.propose",
            "INVALID_BUDGET_AMOUNT",
            principal_ref="maker",
            scope=group_scope,
            arguments=fractional,
        )

        _success(
            service,
            "policy.budget.propose",
            principal_ref="maker",
            scope=group_scope,
            arguments=proposal,
        )
        overlapping, overlapping_scope, _ = _prepare_generation(
            service,
            "generation-overlap-v1",
            (("acct-a", "10"),),
            total_amount="15",
            unallocated_amount="5",
        )
        _failure(
            service,
            "policy.budget.propose",
            "ACCOUNT_ALREADY_CLAIMED",
            principal_ref="maker",
            scope=overlapping_scope,
            arguments=overlapping,
        )

        rejected = _success(
            service,
            "policy.budget.reject_member",
            principal_ref="maker",
            scope=member_scopes["acct-a"],
            arguments={
                "generation_ref": proposal["generation_ref"],
                "account_ref": "acct-a",
            },
        )
        assert rejected["state"] == "rejected"
        pool = store.configure_budget_pool(
            "pool-a-v1",
            capacity_amount="100",
            currency=_CURRENCY,
            metric=_METRIC,
            scale=2,
            portfolio_ref=_PORTFOLIO,
            membership_version=_MEMBERSHIP_VERSION,
            membership_sha256=_MEMBERSHIP_DIGEST,
            account_refs=("acct-a", "acct-b"),
        )
        assert pool["used_amount"] == "0"
        assert pool["available_amount"] == "100"
        _success(
            service,
            "policy.budget.propose",
            principal_ref="maker",
            scope=overlapping_scope,
            arguments=overlapping,
        )
    finally:
        service.close()
        store.close()


def test_capacity_and_account_claims_serialize_across_sqlite_connections(
    tmp_path: Path,
) -> None:
    catalog_path = tmp_path / "shared-policy-catalog.sqlite3"
    first_store = PolicyCatalogStore(
        str(catalog_path), trusted_approver_principals=_APPROVERS
    )
    second_store = PolicyCatalogStore(
        str(catalog_path), trusted_approver_principals=_APPROVERS
    )
    first_service = PolicyCatalogService(first_store)
    second_service = PolicyCatalogService(second_store)
    roster = ("acct-a", "acct-b")
    _configure_pool(first_store, roster)
    first, first_scope, _ = _prepare_generation(
        first_service,
        "generation-race-a-v1",
        (("acct-a", "50"),),
        total_amount="60",
        unallocated_amount="10",
    )
    second, second_scope, _ = _prepare_generation(
        second_service,
        "generation-race-b-v1",
        (("acct-b", "50"),),
        total_amount="60",
        unallocated_amount="10",
    )
    barrier = Barrier(2)

    def submit(
        service: PolicyCatalogService,
        proposal: dict[str, object],
        scope: WireScope,
    ) -> str:
        barrier.wait(timeout=5)
        response = service.handle(
            "policy.budget.propose",
            principal_ref="maker",
            scope=scope,
            arguments=proposal,
        )
        return str(response["code"])

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = (
                executor.submit(submit, first_service, first, first_scope),
                executor.submit(submit, second_service, second, second_scope),
            )
            codes = sorted(future.result(timeout=15) for future in futures)
        assert codes == ["BUDGET_CAPACITY_EXCEEDED", "OK"]
        pool = first_store.configure_budget_pool(
            "pool-a-v1",
            capacity_amount="100",
            currency=_CURRENCY,
            metric=_METRIC,
            scale=2,
            portfolio_ref=_PORTFOLIO,
            membership_version=_MEMBERSHIP_VERSION,
            membership_sha256=_MEMBERSHIP_DIGEST,
            account_refs=roster,
        )
        assert pool["used_amount"] == "60"
        assert pool["available_amount"] == "40"
    finally:
        first_service.close()
        second_service.close()
        first_store.close()
        second_store.close()


def test_budget_authority_uses_registered_risk_policy_wire_path(tmp_path: Path) -> None:
    """Exercise proposal, maker/checker and exact member confirmation over SDK RPC."""

    endpoint_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        endpoint_probe.bind(("127.0.0.1", 0))
        endpoint = f"tcp://127.0.0.1:{endpoint_probe.getsockname()[1]}"
    finally:
        endpoint_probe.close()

    service_id = "afi-budget-owner"
    instance_id = "risk-policy-catalog"
    service_principal = "afi-budget-owner-principal"
    service_scope_ref = "afi-budget-owner-scope-v1"
    security_ref = "afi-budget-curve-v1"
    registration_ref = "afi-budget-registration-v1"
    requirements_ref = "afi-budget-requirements-v1"
    transport_ref = "afi-budget-listener"
    group_ref = "afi-budget-group-v1"
    member_refs = {account: f"afi-budget-{account}-v1" for account in ("acct-a", "acct-b")}
    group_scope = _group_scope(("acct-a", "acct-b"))
    member_scopes = {account: _member_scope(account) for account in member_refs}
    checker_group_ops = frozenset(
        {
            "policy.budget.approve",
            "policy.budget.publish_member",
            "policy.budget.read",
        }
    )
    maker_group_ops = frozenset(
        {
            "policy.budget.propose",
            "policy.budget.approve",
            "policy.budget.read",
        }
    )
    intruder_group_ops = frozenset({"policy.budget.approve"})

    server_public, server_secret = zmq.curve_keypair()
    client_keys = {
        principal: zmq.curve_keypair()
        for principal in ("maker", "checker", "intruder")
    }
    service_raw = {
        "service_config_schema_version": 1,
        "process_role": "service",
        "service_id": service_id,
        "scope_ref": service_scope_ref,
        "transport_ref": transport_ref,
        "registration_policy_ref": registration_ref,
        "service_requirements_ref": requirements_ref,
        "components": {
            "risk": {
                "config_schema_version": 2,
                "settings": {
                    "instance_id": instance_id,
                    "bind_ports": ["service.risk_policy"],
                    "options": {"role": "policy_catalog"},
                },
            }
        },
        "communication": {
            "config_schema_version": 1,
            "profiles": {
                transport_ref: {
                    "backend": "zmq",
                    "config_schema_version": 1,
                    "endpoints": {"rpc_bind": endpoint},
                    "security_profile_ref": security_ref,
                    "options": {"high_water_mark": 32, "max_message_bytes": 65_536},
                }
            },
        },
    }

    principals = {
        principal: f"afi-budget-{principal}-app" for principal in client_keys
    }
    identities = {
        principal: WireIdentity(WireRole.APPLICATION_CLIENT, principal, actor)
        for principal, actor in principals.items()
    }

    def grant(
        scope_ref: str, scope: WireScope, operations: frozenset[str]
    ) -> ResourceGrant:
        return ResourceGrant(
            instance_id,
            "service.risk_policy",
            scope_ref,
            scope,
            operations,
        )

    member_draft_confirm = frozenset(
        {"policy.draft", "policy.budget.confirm_member"}
    )
    grants = {
        "maker": (
            PrincipalGrant(
                identities["maker"],
                (
                    grant(group_ref, group_scope, frozenset({"policy.budget.propose", "policy.budget.approve", "policy.budget.read"})),
                    *(grant(member_refs[account], member_scopes[account], member_draft_confirm) for account in member_refs),
                ),
            ),
        ),
        "checker": (
            PrincipalGrant(
                identities["checker"],
                (grant(group_ref, group_scope, checker_group_ops),),
            ),
        ),
        "intruder": (
            PrincipalGrant(
                identities["intruder"],
                (
                    grant(
                        group_ref,
                        group_scope,
                        frozenset({"policy.budget.approve"}),
                    ),
                ),
            ),
        ),
    }
    authority = TrustedServiceAuthority(
        identity=WireIdentity(WireRole.SERVICE, service_principal, service_id),
        scope=WireScope(_DOMAIN),
        scope_ref=service_scope_ref,
        scope_version="afi-budget-scope-v1",
        security_ref=security_ref,
        security_version="afi-budget-curve-version-v1",
        registration_policy_ref=registration_ref,
        registration_policy_version="afi-budget-registration-version-v1",
        service_requirements_ref=requirements_ref,
        service_requirements_version="afi-budget-requirements-version-v1",
        curve_public_key=server_public,
        curve_secret_key=server_secret,
        principals={keypair[0]: principal for principal, keypair in client_keys.items()},
        grants=grants,
    )

    scopes = {
        group_ref: group_scope,
        **{member_refs[account]: scope for account, scope in member_scopes.items()},
    }

    def client_config(
        principal: str, *, scope_ref: str, account_ref: str | None
    ) -> dict[str, object]:
        binding: dict[str, object] = {
            "mount": "application.risk_policy",
            "service_id": service_id,
            "instance_id": instance_id,
            "scope_ref": scope_ref,
            "transport_ref": "afi-budget-connect",
        }
        if account_ref is None:
            binding["portfolio_ref"] = _PORTFOLIO
        else:
            binding["account_ref"] = account_ref
        return {
            "client_config_schema_version": 1,
            "process_role": "application_client",
            "registration": {"application_ref": principals[principal]},
            "clients": {
                "risk": {
                    "config_schema_version": 1,
                    "settings": {
                        "bindings": [binding],
                        "options": {"request_timeout_ms": 3_000},
                    },
                }
            },
            "communication": {
                "config_schema_version": 1,
                "profiles": {
                    "afi-budget-connect": {
                        "backend": "zmq",
                        "config_schema_version": 1,
                        "endpoints": {"rpc_connect": endpoint},
                        "security_profile_ref": security_ref,
                        "options": {"high_water_mark": 32, "max_message_bytes": 65_536},
                    }
                },
            },
        }

    client_context: dict[str, object] = {
        "phase": "not_started",
        "principal": None,
        "scope_ref": None,
        "operation": None,
    }
    runtime_principals: dict[int, str] = {}

    def set_client_context(
        phase: str,
        *,
        principal: str | None,
        scope_ref: str | None,
        operation: str | None = None,
    ) -> None:
        client_context.update(
            {
                "phase": phase,
                "principal": principal,
                "scope_ref": scope_ref,
                "operation": operation,
            }
        )

    def make_runtime(
        principal: str,
        *,
        scope_ref: str,
        account_ref: str | None,
        operations: frozenset[str],
    ) -> ServiceClientRuntime:
        set_client_context(
            "runtime.construct",
            principal=principal,
            scope_ref=scope_ref,
        )
        public_key, secret_key = client_keys[principal]
        runtime = ServiceClientRuntime(
            parse_client_config(
                client_config(
                    principal, scope_ref=scope_ref, account_ref=account_ref
                )
            ),
            identity=identities[principal],
            scope_resolver=lambda scope_ref: scopes[scope_ref],
            peer_resolver=lambda _service_id: WireIdentity(
                WireRole.SERVICE, service_principal, service_id
            ),
            transport_factory=ZmqTransportFactory(
                {security_ref: ClientCurveKeys(server_public, public_key, secret_key)}
            ),
            requested_operations={"application.risk_policy": operations},
        )
        runtime_principals[id(runtime)] = principal
        set_client_context(
            "runtime.start",
            principal=principal,
            scope_ref=scope_ref,
        )
        runtime.start()
        return runtime

    def call(
        runtime: ServiceClientRuntime,
        operation: str,
        arguments: dict[str, object],
        *,
        scope_ref: str = group_ref,
        account_ref: str | None = None,
    ) -> Mapping[str, object]:
        set_client_context(
            "rpc.call",
            principal=runtime_principals.get(id(runtime)),
            scope_ref=scope_ref,
            operation=operation,
        )
        body = runtime.call(
            "application.risk_policy",
            operation,
            arguments,
            account_ref=account_ref,
            portfolio_ref=None if account_ref is not None else _PORTFOLIO,
            scope_ref=scope_ref,
        )
        set_client_context(
            "rpc.reply",
            principal=runtime_principals.get(id(runtime)),
            scope_ref=scope_ref,
            operation=operation,
        )
        body = _mapping_with_fields(body, _SDK_REPLY_FIELDS, label="SDK policy reply")
        assert type(body["ok"]) is bool, body
        assert type(body["code"]) is str, body
        assert isinstance(body["result"], Mapping), body
        return body

    catalog = PolicyCatalogStore(
        str(tmp_path / "host-budget-catalog.sqlite3"),
        trusted_approver_principals=("maker", "checker"),
    )
    confirmation_store = ConfirmedPolicyStore(
        str(tmp_path / "host-budget-confirmed.sqlite3")
    )
    _configure_pool(catalog, ("acct-a", "acct-b"))

    def resources(component: str, _instance_id: str, options: dict[str, object], _scope: WireScope):
        if component != "risk" or options.get("role") != "policy_catalog":
            raise AssertionError("the host must select the fixed risk policy_catalog role")
        return ComponentResources.borrowed(
            {"catalog": catalog, "confirmed_policy_store": confirmation_store},
            ready=lambda: True,
        )

    host = ServiceHost(
        parse_service_config(service_raw),
        authority,
        str(tmp_path / "host-budget-registry.sqlite3"),
        resources,
    )
    receipts_to_pin: Queue[list[Mapping[str, object]]] = Queue()
    receipts_pinned = threading.Event()
    client_done = threading.Event()
    client_errors: list[dict[str, object]] = []
    observed: dict[str, object] = {}

    def client_flow() -> None:
        runtimes: list[ServiceClientRuntime] = []
        try:
            allocations = [
                {
                    "account_ref": account,
                    "policy_ref": f"afi-budget-{account}-v1",
                    "amount": "25",
                    "max_increase_count": 10 + index,
                    "metric": _METRIC,
                    "currency": _CURRENCY,
                }
                for index, account in enumerate(("acct-a", "acct-b"))
            ]
            proposal: dict[str, object] = {
                "pool_ref": "pool-a-v1",
                "generation_ref": "afi-budget-generation-v1",
                "portfolio_ref": _PORTFOLIO,
                "membership_version": _MEMBERSHIP_VERSION,
                "membership_sha256": _MEMBERSHIP_DIGEST,
                "allocation_set_sha256": "0" * 64,
                "currency": _CURRENCY,
                "metric": _METRIC,
                "total_amount": "60",
                "unallocated_amount": "10",
                "allocations": allocations,
            }
            _refresh_allocation_digest(proposal)
            draft_versions: dict[str, str] = {}
            for allocation in allocations:
                account = str(allocation["account_ref"])
                maker_member = make_runtime(
                    "maker",
                    scope_ref=member_refs[account],
                    account_ref=account,
                    operations=member_draft_confirm,
                )
                runtimes.append(maker_member)
                assert maker_member.state == "registered"
                assert len(maker_member.bindings) == 1
                assert maker_member.bindings[0].operations == member_draft_confirm
                policy_ref = str(allocation["policy_ref"])
                amount = str(allocation["amount"])
                content = {
                    "afi_budget": {
                        "kind": "afi.static_account_budget",
                        "schema_version": 1,
                        "portfolio_ref": _PORTFOLIO,
                        "membership_version": _MEMBERSHIP_VERSION,
                        "membership_sha256": _MEMBERSHIP_DIGEST,
                        "allocation_set_sha256": proposal["allocation_set_sha256"],
                        "metric": _METRIC,
                        "currency": _CURRENCY,
                        "total_amount": "60",
                        "unallocated_amount": "10",
                        "account_ref": account,
                        "allocated_amount": amount,
                    },
                    "risk_policy": {
                        "policy_id": policy_ref,
                        "max_increase_notional": amount,
                        "max_increase_count": allocation["max_increase_count"],
                        "notional_unit": _CURRENCY,
                    },
                }
                draft = call(
                    maker_member,
                    "policy.draft",
                    {"policy_ref": policy_ref, "content": content},
                    scope_ref=member_refs[account],
                    account_ref=account,
                )
                assert draft["ok"] is True and draft["code"] == "OK", draft
                draft_result = _mapping_with_fields(
                    draft["result"],
                    frozenset({"policy_ref", "policy_version", "state"}),
                    label="draft policy result",
                )
                assert draft_result["policy_ref"] == policy_ref, draft_result
                assert type(draft_result["policy_version"]) is str
                assert len(draft_result["policy_version"]) == 64
                assert all(
                    character in "0123456789abcdef"
                    for character in draft_result["policy_version"]
                )
                assert draft_result["state"] == "draft", draft_result
                draft_versions[account] = str(draft_result["policy_version"])
                maker_member.close()
                runtimes.remove(maker_member)

            maker = make_runtime(
                "maker",
                scope_ref=group_ref,
                account_ref=None,
                operations=maker_group_ops,
            )
            runtimes.append(maker)
            assert maker.state == "registered"
            assert len(maker.bindings) == 1
            assert maker.bindings[0].operations == maker_group_ops
            proposed = call(maker, "policy.budget.propose", proposal)
            assert proposed["ok"] is True and proposed["code"] == "OK", proposed
            proposal_summary = _budget_summary(
                proposed["result"],
                expected_state="proposed",
                expected_approved_by=None,
                expected_member_states=("pending", "pending"),
                expected_policy_versions=draft_versions,
            )
            assert proposal_summary["allocation_set_sha256"] == proposal["allocation_set_sha256"]
            self_approval = call(
                maker,
                "policy.budget.approve",
                {"generation_ref": proposal["generation_ref"]},
            )
            assert self_approval == {
                "ok": False,
                "code": "MAKER_CHECKER_REQUIRED",
                "result": {},
            }, self_approval
            observed["proposal"] = proposal_summary
            maker.close()
            runtimes.remove(maker)

            intruder = make_runtime(
                "intruder",
                scope_ref=group_ref,
                account_ref=None,
                operations=intruder_group_ops,
            )
            runtimes.append(intruder)
            assert intruder.bindings[0].operations == intruder_group_ops
            unauthorized = call(
                intruder,
                "policy.budget.approve",
                {"generation_ref": proposal["generation_ref"]},
            )
            assert unauthorized == {
                "ok": False,
                "code": "APPROVER_NOT_AUTHORIZED",
                "result": {},
            }, unauthorized
            intruder.close()
            runtimes.remove(intruder)

            checker = make_runtime(
                "checker",
                scope_ref=group_ref,
                account_ref=None,
                operations=checker_group_ops,
            )
            runtimes.append(checker)
            assert checker.bindings[0].operations == checker_group_ops
            approved = call(
                checker,
                "policy.budget.approve",
                {"generation_ref": proposal["generation_ref"]},
            )
            assert approved["ok"] is True and approved["code"] == "OK", approved
            approval_summary = _budget_summary(
                approved["result"],
                expected_state="approved",
                expected_approved_by="checker",
                expected_member_states=("pending", "pending"),
                expected_policy_versions=draft_versions,
            )
            assert approval_summary["allocation_set_sha256"] == proposal["allocation_set_sha256"]
            publications = []
            for allocation in allocations:
                account = str(allocation["account_ref"])
                published = call(
                    checker,
                    "policy.budget.publish_member",
                    {
                        "generation_ref": proposal["generation_ref"],
                        "account_ref": account,
                    },
                )
                assert published["ok"] is True and published["code"] == "OK", published
                publication = _mapping_with_fields(
                    published["result"],
                    _BUDGET_PUBLICATION_FIELDS,
                    label="budget member publication result",
                )
                assert publication["generation_ref"] == proposal["generation_ref"]
                assert publication["state"] == "publishing", publication
                assert publication["consumer_effective"] is False, publication
                receipt = _mapping_with_fields(
                    publication["member"],
                    _POLICY_RECEIPT_FIELDS,
                    label="published policy receipt",
                )
                owner_scope = _mapping_with_fields(
                    receipt["owner_scope"],
                    _POLICY_SCOPE_FIELDS,
                    label="published policy owner scope",
                )
                assert receipt["policy_ref"] == f"afi-budget-{account}-v1", receipt
                assert type(receipt["policy_version"]) is str
                assert len(receipt["policy_version"]) == 64
                assert receipt["policy_version"] == draft_versions[account], receipt
                assert all(
                    character in "0123456789abcdef" for character in receipt["policy_version"]
                )
                assert receipt["owner_principal"] == "maker", receipt
                assert type(receipt["published_utc"]) is str
                assert receipt["published_utc"].endswith("Z"), receipt
                assert owner_scope == {
                    "execution_domain_ref": _DOMAIN,
                    "account_ref": account,
                    "account_refs": (),
                    "strategy_ref": None,
                    "run_id": None,
                    "manual_book_ref": None,
                    "portfolio_ref": _PORTFOLIO,
                    "group_id": None,
                    "leg_id": None,
                }, owner_scope
                publications.append(receipt)
            observed["published_states"] = tuple(
                item["owner_scope"]["account_ref"] for item in publications
            )
            observed["draft_versions"] = dict(draft_versions)
            receipts_to_pin.put(publications)
            set_client_context(
                "checker.wait_for_owner_receipt_pin",
                principal="checker",
                scope_ref=group_ref,
            )
            if not receipts_pinned.wait(15):
                raise AssertionError("trusted owner did not pin member receipts")
            checker.close()
            runtimes.remove(checker)

            owner_member = make_runtime(
                "maker",
                scope_ref=member_refs["acct-a"],
                account_ref="acct-a",
                operations=member_draft_confirm,
            )
            runtimes.append(owner_member)
            assert owner_member.bindings[0].operations == member_draft_confirm
            forged_member_receipt = _thaw_rpc_value(publications[0])
            assert type(forged_member_receipt) is dict
            assert set(forged_member_receipt) == _POLICY_RECEIPT_FIELDS
            assert type(forged_member_receipt["owner_scope"]) is dict
            assert set(forged_member_receipt["owner_scope"]) == _POLICY_SCOPE_FIELDS
            assert type(forged_member_receipt["owner_scope"]["account_refs"]) is list
            forged_receipt = call(
                owner_member,
                "policy.budget.confirm_member",
                {
                    "generation_ref": proposal["generation_ref"],
                    "account_ref": "acct-a",
                    "member_receipt": forged_member_receipt,
                },
                scope_ref=member_refs["acct-a"],
                account_ref="acct-a",
            )
            assert forged_receipt == {
                "ok": False,
                "code": "INVALID_REQUEST",
                "result": {},
            }, forged_receipt
            confirmed = call(
                owner_member,
                "policy.budget.confirm_member",
                {
                    "generation_ref": proposal["generation_ref"],
                    "account_ref": "acct-a",
                },
                scope_ref=member_refs["acct-a"],
                account_ref="acct-a",
            )
            assert confirmed["ok"] is True and confirmed["code"] == "OK", confirmed
            _budget_summary(
                confirmed["result"],
                expected_state="publishing",
                expected_approved_by="checker",
                expected_member_states=("confirmed", "published"),
                expected_policy_versions=draft_versions,
            )
            owner_member.close()
            runtimes.remove(owner_member)

            owner_member_b = make_runtime(
                "maker",
                scope_ref=member_refs["acct-b"],
                account_ref="acct-b",
                operations=member_draft_confirm,
            )
            runtimes.append(owner_member_b)
            assert owner_member_b.bindings[0].operations == member_draft_confirm
            for account in ("acct-b",):
                confirmed = call(
                    owner_member_b,
                    "policy.budget.confirm_member",
                    {
                        "generation_ref": proposal["generation_ref"],
                        "account_ref": account,
                    },
                    scope_ref=member_refs[account],
                    account_ref=account,
                )
                assert confirmed["ok"] is True and confirmed["code"] == "OK", confirmed
                final_confirmation_summary = _budget_summary(
                    confirmed["result"],
                    expected_state="authority_ready",
                    expected_approved_by="checker",
                    expected_member_states=("confirmed", "confirmed"),
                    expected_policy_versions=draft_versions,
                )
                observed["final_generation"] = final_confirmation_summary
            owner_member_b.close()
            runtimes.remove(owner_member_b)

            owner = make_runtime(
                "maker",
                scope_ref=group_ref,
                account_ref=None,
                operations=frozenset({"policy.budget.read"}),
            )
            runtimes.append(owner)
            assert owner.bindings[0].operations == frozenset({"policy.budget.read"})
            summary = call(
                owner,
                "policy.budget.read",
                {"generation_ref": proposal["generation_ref"]},
            )
            assert summary["ok"] is True and summary["code"] == "OK", summary
            read_summary = _budget_summary(
                summary["result"],
                expected_state="authority_ready",
                expected_approved_by="checker",
                expected_member_states=("confirmed", "confirmed"),
                expected_policy_versions=draft_versions,
            )
            observed["final_generation"] = read_summary
            owner.close()
            runtimes.remove(owner)
        except BaseException as exc:  # pragma: no cover - surfaced to the test
            client_errors.append(
                {
                    "exception_type": type(exc).__name__,
                    "exception_text": str(exc),
                    "context": dict(client_context),
                    "traceback": traceback.format_exc(),
                }
            )
        finally:
            for runtime in reversed(runtimes):
                with suppress(BaseException):
                    runtime.close()
            client_done.set()

    try:
        host.start()
        host_summary = host.summary
        assert isinstance(host_summary, Mapping), type(host_summary).__name__
        components = host_summary["components"]
        assert type(components) is tuple, ("ServiceHost.summary components", components)
        assert len(components) == 1, components
        component_summary = _mapping_with_fields(
            components[0],
            frozenset(
                {"component", "instance_id", "declared_ports", "capabilities", "internal_ports"}
            ),
            label="ServiceHost component summary",
        )
        assert component_summary["component"] == "risk", component_summary
        assert component_summary["instance_id"] == instance_id, component_summary
        assert component_summary["declared_ports"] == ("service.risk_policy",), component_summary
        assert type(component_summary["internal_ports"]) is tuple, component_summary
        capability_rows = component_summary["capabilities"]
        assert type(capability_rows) is tuple, component_summary
        assert capability_rows, component_summary
        published_operations: set[str] = set()
        for capability in capability_rows:
            row = _mapping_with_fields(
                capability,
                frozenset({"port", "operations"}),
                label="ServiceHost capability summary",
            )
            assert row["port"] == "service.risk_policy", row
            operations = row["operations"]
            assert type(operations) is tuple, row
            assert all(type(operation) is str for operation in operations), row
            published_operations.update(operations)
        assert published_operations == PolicyCatalogService.SUPPORTED_OPERATIONS

        worker = threading.Thread(target=client_flow, name="afi-budget-sdk-client")
        worker.start()
        deadline = time.monotonic() + 30
        while not client_done.is_set():
            if time.monotonic() >= deadline:
                raise AssertionError("budget SDK client did not finish within the bound")
            host.serve_once(timeout_ms=25)
            try:
                receipts = receipts_to_pin.get_nowait()
            except Empty:
                continue
            for receipt in receipts:
                confirmation_store.confirm(receipt)
            receipts_pinned.set()
        worker.join(5)
        assert not worker.is_alive()
        if client_errors:
            diagnostic = tmp_path / "budget-client-errors.json"
            diagnostic.write_text(
                json.dumps(client_errors, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            raise AssertionError(f"budget SDK client failed; full traceback: {diagnostic}")
        assert observed["published_states"] == ("acct-a", "acct-b")
        final = _budget_summary(
            observed["final_generation"],
            expected_state="authority_ready",
            expected_approved_by="checker",
            expected_member_states=("confirmed", "confirmed"),
            expected_policy_versions=_mapping_with_fields(
                observed["draft_versions"],
                frozenset({"acct-a", "acct-b"}),
                label="observed draft versions",
            ),
        )
        proposal_summary = _mapping_with_fields(
            observed["proposal"],
            _BUDGET_SUMMARY_FIELDS,
            label="observed proposal summary",
        )
        assert final["allocation_set_sha256"] == proposal_summary["allocation_set_sha256"]
        assert tuple(member["state"] for member in final["members"]) == (
            "confirmed",
            "confirmed",
        )
    finally:
        with suppress(BaseException):
            host.close()
        confirmation_store.close()
        catalog.close()
