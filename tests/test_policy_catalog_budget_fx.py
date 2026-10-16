"""AFI FX budgets must cross the real Risk catalog and stay source-current."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import time
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

from bt_api_base.service_protocol import WireScope
from bt_api_risk.budget_admission import (
    BudgetAdmissionResolutionError,
    PolicyCatalogBudgetAdmissionResolver,
)
from bt_api_risk.portfolio_analytics import FxObservationV1
from bt_api_risk.service_component import (
    ConfirmedPolicyStore,
    PolicyCatalogService,
    PolicyCatalogStore,
)

_DOMAIN = "paper:budget"
_PORTFOLIO = "portfolio-fx"
_POOL = "pool-fx-v1"
_GENERATION = "generation-fx-v1"
_MEMBERSHIP_DIGEST = "1" * 64
_CURRENCY = "USD"
_METRIC = "max_increase_notional"


class _FxSource:
    """Service-side fixture independent of the budget RPC request."""

    def __init__(self, observation: FxObservationV1) -> None:
        self.observation = observation
        self.reads: list[str] = []

    def __call__(self, observation_ref: str) -> dict[str, object]:
        self.reads.append(observation_ref)
        if observation_ref != self.observation.observation_ref:
            raise KeyError(observation_ref)
        return _fx_observation(self.observation)


class _FxClock:
    def __init__(self, now_ns: int) -> None:
        self.now_ns = now_ns

    def __call__(self) -> int:
        return self.now_ns


def _fx_fact(
    rate: Decimal = Decimal("1.25"),
    *,
    now_ns: int | None = None,
) -> FxObservationV1:
    current_ns = time.time_ns() if now_ns is None else now_ns
    as_of_ns = current_ns - 1_000_000_000
    return FxObservationV1(
        observation_ref="fx-eur-usd-v1",
        base_currency="EUR",
        quote_currency="USD",
        direction="BASE_TO_QUOTE",
        rate_unit="QUOTE_PER_BASE",
        rate=rate,
        as_of_ns=as_of_ns,
        valid_until_ns=as_of_ns + 172_800_000_000_000,
        source_ref="market-fx-v1",
        source_version="rates-v1",
        source_generation="generation-4",
        source_cursor="cursor-101",
    )


def _fx_observation(fact: FxObservationV1 | None = None) -> dict[str, object]:
    """Project the accepted typed Risk fact to the R258 compiler wire schema."""

    item = _fx_fact() if fact is None else fact
    rate = format(item.rate, "f")
    if "." in rate:
        rate = rate.rstrip("0").rstrip(".")
    return {
        "observation_ref": item.observation_ref,
        "base_currency": item.base_currency,
        "quote_currency": item.quote_currency,
        "direction": item.direction,
        "rate_unit": item.rate_unit,
        "rate": rate,
        "as_of_ns": item.as_of_ns,
        "valid_until_ns": item.valid_until_ns,
        "source_ref": item.source_ref,
        "source_version": item.source_version,
        "source_generation": item.source_generation,
        "source_cursor": item.source_cursor,
    }


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _group_scope() -> WireScope:
    return WireScope(
        execution_domain_ref=_DOMAIN,
        account_refs=("acct-a", "acct-b"),
        portfolio_ref=_PORTFOLIO,
        group_id="budget-group",
    )


def _member_scope(account_ref: str) -> WireScope:
    return WireScope(
        execution_domain_ref=_DOMAIN,
        account_ref=account_ref,
        portfolio_ref=_PORTFOLIO,
    )


def _load_afi_budget_compiler() -> Any | None:
    source = os.environ.get("AFI_RISK_POLICY_BUDGET_SOURCE")
    if source is None:
        return None
    source_path = Path(source)
    assert source_path.is_file(), source_path
    module_name = "afi_risk_policy_budget_candidate"
    spec = importlib.util.spec_from_file_location(module_name, source_path)
    assert spec is not None and spec.loader is not None, source_path
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _plan(
    fact: FxObservationV1,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    compiler = _load_afi_budget_compiler()
    if compiler is not None:
        typed_plan = compiler.StaticPortfolioBudgetPlan(
            portfolio_ref=_PORTFOLIO,
            membership_version=1,
            membership_sha256=_MEMBERSHIP_DIGEST,
            currency=_CURRENCY,
            total_amount=Decimal("25"),
            unallocated_amount=Decimal("7.5"),
            allocations=(
                compiler.AccountBudgetAllocation(
                    account_ref="acct-a",
                    amount=Decimal("10"),
                    currency="EUR",
                    metric=_METRIC,
                    max_increase_count=3,
                ),
                compiler.AccountBudgetAllocation(
                    account_ref="acct-b",
                    amount=Decimal("5"),
                    currency=_CURRENCY,
                    metric=_METRIC,
                    max_increase_count=2,
                ),
            ),
            metric=_METRIC,
        )
        compiled = compiler.compile_static_portfolio_budget(
            typed_plan,
            policy_refs={
                "acct-a": "afi-budget-acct-a-v1",
                "acct-b": "afi-budget-acct-b-v1",
            },
            fx_observations={"EUR": fact},
        )
        contents: dict[str, dict[str, object]] = {}
        allocations: list[dict[str, object]] = []
        for request in compiled.catalog_requests():
            content = request["content"]
            budget = content["afi_budget"]
            policy = content["risk_policy"]
            account_ref = budget["account_ref"]
            contents[account_ref] = content
            allocations.append(
                {
                    "account_ref": account_ref,
                    "policy_ref": request["policy_ref"],
                    "amount": budget["allocated_amount"],
                    "source_amount": budget["source_amount"],
                    "source_currency": budget["source_currency"],
                    "fx_observation": budget["fx_observation"],
                    "max_increase_count": policy["max_increase_count"],
                    "metric": compiled.metric,
                    "currency": compiled.currency,
                }
            )
        proposal = {
            "pool_ref": _POOL,
            "generation_ref": _GENERATION,
            "portfolio_ref": compiled.portfolio_ref,
            "membership_version": compiled.membership_version,
            "membership_sha256": _MEMBERSHIP_DIGEST,
            "allocation_set_sha256": compiled.allocation_set_sha256,
            "currency": compiled.currency,
            "metric": compiled.metric,
            "total_amount": compiled.total_amount,
            "unallocated_amount": compiled.unallocated_amount,
            "allocations": allocations,
        }
        return proposal, contents

    observation = _fx_observation(fact)
    allocations = [
        {
            "account_ref": "acct-a",
            "policy_ref": "afi-budget-acct-a-v1",
            "amount": "12.5",
            "source_amount": "10",
            "source_currency": "EUR",
            "fx_observation": observation,
            "max_increase_count": 3,
            "metric": _METRIC,
            "currency": _CURRENCY,
        },
        {
            "account_ref": "acct-b",
            "policy_ref": "afi-budget-acct-b-v1",
            "amount": "5",
            "source_amount": "5",
            "source_currency": _CURRENCY,
            "fx_observation": None,
            "max_increase_count": 2,
            "metric": _METRIC,
            "currency": _CURRENCY,
        },
    ]
    manifest = {
        "kind": "afi.static_account_budget",
        "schema_version": 1,
        "portfolio_ref": _PORTFOLIO,
        "membership_version": 1,
        "membership_sha256": _MEMBERSHIP_DIGEST,
        "metric": _METRIC,
        "currency": _CURRENCY,
        "total_amount": "25",
        "unallocated_amount": "7.5",
        "allocations": allocations,
    }
    allocation_set_sha256 = _digest(manifest)
    proposal = {
        "pool_ref": _POOL,
        "generation_ref": _GENERATION,
        "portfolio_ref": _PORTFOLIO,
        "membership_version": 1,
        "membership_sha256": _MEMBERSHIP_DIGEST,
        "allocation_set_sha256": allocation_set_sha256,
        "currency": _CURRENCY,
        "metric": _METRIC,
        "total_amount": "25",
        "unallocated_amount": "7.5",
        "allocations": allocations,
    }
    contents: dict[str, dict[str, object]] = {}
    for allocation in allocations:
        account_ref = allocation["account_ref"]
        policy_ref = allocation["policy_ref"]
        contents[account_ref] = {
            "afi_budget": {
                "kind": "afi.static_account_budget",
                "schema_version": 1,
                "portfolio_ref": _PORTFOLIO,
                "membership_version": 1,
                "membership_sha256": _MEMBERSHIP_DIGEST,
                "allocation_set_sha256": allocation_set_sha256,
                "metric": _METRIC,
                "currency": _CURRENCY,
                "total_amount": "25",
                "unallocated_amount": "7.5",
                "account_ref": account_ref,
                "source_amount": allocation["source_amount"],
                "source_currency": allocation["source_currency"],
                "allocated_amount": allocation["amount"],
                "fx_observation": allocation["fx_observation"],
            },
            "risk_policy": {
                "policy_id": policy_ref,
                "max_increase_notional": allocation["amount"],
                "max_increase_count": allocation["max_increase_count"],
                "permit_ttl_seconds": 30.0,
                "require_strategy_allocation": False,
                "notional_unit": _CURRENCY,
            },
        }
    return proposal, contents


def _call(
    service: PolicyCatalogService,
    operation: str,
    *,
    principal: str,
    scope: WireScope,
    arguments: dict[str, object],
) -> dict[str, Any]:
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


def _error(
    service: PolicyCatalogService,
    operation: str,
    *,
    principal: str,
    scope: WireScope,
    arguments: dict[str, object],
    code: str,
) -> None:
    reply = service.handle(
        operation,
        principal_ref=principal,
        scope=scope,
        arguments=arguments,
    )
    assert reply["ok"] is False, reply
    assert reply["code"] == code, reply


def _stores(
    tmp_path: Path,
    *,
    source: _FxSource | None,
    clock: _FxClock,
) -> tuple[PolicyCatalogStore, ConfirmedPolicyStore, PolicyCatalogService]:
    store = PolicyCatalogStore(
        str(tmp_path / "catalog.sqlite3"),
        trusted_approver_principals=("checker",),
        trusted_fx_observation_reader=None if source is None else source,
        fx_clock_ns=clock,
    )
    confirmations = ConfirmedPolicyStore(str(tmp_path / "confirmed.sqlite3"))
    service = PolicyCatalogService(store, confirmation_store=confirmations)
    store.configure_budget_pool(
        _POOL,
        capacity_amount="30",
        currency=_CURRENCY,
        metric=_METRIC,
        scale=1,
        portfolio_ref=_PORTFOLIO,
        membership_version=1,
        membership_sha256=_MEMBERSHIP_DIGEST,
        account_refs=("acct-a", "acct-b"),
    )
    return store, confirmations, service


def _draft(
    service: PolicyCatalogService,
    fact: FxObservationV1,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    proposal, contents = _plan(fact)
    for account_ref, content in contents.items():
        _call(
            service,
            "policy.draft",
            principal="maker",
            scope=_member_scope(account_ref),
            arguments={
                "policy_ref": content["risk_policy"]["policy_id"],
                "content": content,
            },
        )
    return proposal, contents


def _propose(service: PolicyCatalogService, proposal: dict[str, object]) -> dict[str, Any]:
    return _call(
        service,
        "policy.budget.propose",
        principal="maker",
        scope=_group_scope(),
        arguments=proposal,
    )


def test_budget_fx_generation_uses_real_catalog_and_rechecks_source_at_resolution(
    tmp_path: Path,
) -> None:
    source_fact = _fx_fact()
    observation = _fx_observation(source_fact)
    source = _FxSource(source_fact)
    clock = _FxClock(source_fact.as_of_ns + 1)
    catalog_path = tmp_path / "catalog.sqlite3"
    confirmation_path = tmp_path / "confirmed.sqlite3"
    store, confirmations, service = _stores(tmp_path, source=source, clock=clock)
    try:
        proposal, _ = _draft(service, source_fact)
        proposed = _propose(service, proposal)
        assert proposed["state"] == "proposed", proposed
        assert proposed["consumer_effective"] is False, proposed
        assert proposed["fx_observations"] == (observation,), proposed
        assert source.reads == [observation["observation_ref"]]

        clock.now_ns = source_fact.as_of_ns + 86_400_000_000_001
        _error(
            service,
            "policy.budget.approve",
            principal="checker",
            scope=_group_scope(),
            arguments={"generation_ref": _GENERATION},
            code="BUDGET_FX_STALE",
        )
        assert source.reads == [observation["observation_ref"]] * 2
        held = store.read_budget_generation(_GENERATION, scope=_group_scope())
        assert held["state"] == "proposed", held
        assert held["total_amount"] == "25", held
        clock.now_ns = source_fact.as_of_ns + 1

        approved = _call(
            service,
            "policy.budget.approve",
            principal="checker",
            scope=_group_scope(),
            arguments={"generation_ref": _GENERATION},
        )
        assert approved["state"] == "approved", approved
        assert approved["fx_observations"] == (observation,), approved
        assert source.reads == [observation["observation_ref"]] * 3

        source.observation = replace(source.observation, rate=Decimal("1.3"))
        _error(
            service,
            "policy.budget.publish_member",
            principal="checker",
            scope=_group_scope(),
            arguments={"generation_ref": _GENERATION, "account_ref": "acct-a"},
            code="BUDGET_FX_SOURCE_MISMATCH",
        )
        assert source.reads == [observation["observation_ref"]] * 4
        held = store.read_budget_generation(_GENERATION, scope=_group_scope())
        assert held["state"] == "approved", held
        source.observation = source_fact

        clock.now_ns = observation["valid_until_ns"]
        _error(
            service,
            "policy.budget.publish_member",
            principal="checker",
            scope=_group_scope(),
            arguments={"generation_ref": _GENERATION, "account_ref": "acct-a"},
            code="BUDGET_FX_NOT_CURRENT",
        )
        assert source.reads == [observation["observation_ref"]] * 5
        held = store.read_budget_generation(_GENERATION, scope=_group_scope())
        assert held["state"] == "approved", held
        clock.now_ns = source_fact.as_of_ns + 1

        for account_ref in ("acct-a", "acct-b"):
            publication = _call(
                service,
                "policy.budget.publish_member",
                principal="checker",
                scope=_group_scope(),
                arguments={"generation_ref": _GENERATION, "account_ref": account_ref},
            )
            assert publication["state"] == "publishing", publication
            assert publication["consumer_effective"] is False, publication
            assert publication["fx_observations"] == (observation,), publication
            confirmations.confirm(publication["member"])
        assert source.reads == [observation["observation_ref"]] * 7

        for account_ref in ("acct-a", "acct-b"):
            confirmed = _call(
                service,
                "policy.budget.confirm_member",
                principal="maker",
                scope=_member_scope(account_ref),
                arguments={"generation_ref": _GENERATION, "account_ref": account_ref},
            )
        assert confirmed["state"] == "authority_ready", confirmed
        assert confirmed["consumer_effective"] is False, confirmed
        assert confirmed["fx_observations"] == (observation,), confirmed
        assert source.reads == [observation["observation_ref"]] * 9

        service.close()
        confirmations.close()
        store.close()
        store = PolicyCatalogStore(
            str(catalog_path),
            trusted_approver_principals=("checker",),
            trusted_fx_observation_reader=source,
            fx_clock_ns=clock,
        )
        confirmations = ConfirmedPolicyStore(str(confirmation_path))
        resolver = PolicyCatalogBudgetAdmissionResolver(store, confirmations)
        resolved = resolver.resolve(_POOL, "acct-a", scope=_member_scope("acct-a"))
        assert resolved.risk_policy.max_increase_notional == Decimal("12.5")
        assert resolved.risk_policy.notional_unit == _CURRENCY
        assert resolved.fx_observations == (observation,), resolved
        assert source.reads == [observation["observation_ref"]] * 10

        clock.now_ns = source_fact.as_of_ns + 86_400_000_000_001
        try:
            resolver.resolve(_POOL, "acct-a", scope=_member_scope("acct-a"))
        except BudgetAdmissionResolutionError as error:
            assert error.code == "BUDGET_FX_STALE"
        else:
            raise AssertionError("expired FX fact remained resolvable")
        assert source.reads == [observation["observation_ref"]] * 11
        still_reserved = store.read_budget_generation(_GENERATION, scope=_group_scope())
        assert still_reserved["state"] == "authority_ready", still_reserved
        assert still_reserved["total_amount"] == "25", still_reserved

        service = PolicyCatalogService(store, confirmation_store=confirmations)
        _error(
            service,
            "policy.budget.confirm_member",
            principal="maker",
            scope=_member_scope("acct-a"),
            arguments={"generation_ref": _GENERATION, "account_ref": "acct-a"},
            code="BUDGET_FX_STALE",
        )
        assert source.reads == [observation["observation_ref"]] * 12
        after_idempotent_confirm = store.read_budget_generation(
            _GENERATION, scope=_group_scope()
        )
        assert after_idempotent_confirm == still_reserved, after_idempotent_confirm
    finally:
        service.close()
        confirmations.close()
        store.close()


def test_budget_fx_proposal_fails_closed_without_service_side_source(tmp_path: Path) -> None:
    source_fact = _fx_fact()
    clock = _FxClock(source_fact.as_of_ns + 1)
    unavailable_root = tmp_path / "unavailable"
    unavailable_root.mkdir()
    store, confirmations, service = _stores(
        unavailable_root, source=None, clock=clock
    )
    try:
        proposal, _ = _draft(service, source_fact)
        _error(
            service,
            "policy.budget.propose",
            principal="maker",
            scope=_group_scope(),
            arguments=proposal,
            code="BUDGET_FX_AUTHORITY_UNAVAILABLE",
        )
        _error(
            service,
            "policy.budget.read",
            principal="maker",
            scope=_group_scope(),
            arguments={"generation_ref": _GENERATION},
            code="BUDGET_GENERATION_NOT_FOUND",
        )
    finally:
        service.close()
        confirmations.close()
        store.close()

    stale_root = tmp_path / "stale"
    stale_root.mkdir()
    stale_source_fact = _fx_fact()
    stale_source = _FxSource(stale_source_fact)
    stale_clock = _FxClock(
        stale_source_fact.as_of_ns + 86_400_000_000_001
    )
    store, confirmations, service = _stores(
        stale_root, source=stale_source, clock=stale_clock
    )
    try:
        proposal, _ = _draft(service, stale_source_fact)
        _error(
            service,
            "policy.budget.propose",
            principal="maker",
            scope=_group_scope(),
            arguments=proposal,
            code="BUDGET_FX_STALE",
        )
        _error(
            service,
            "policy.budget.read",
            principal="maker",
            scope=_group_scope(),
            arguments={"generation_ref": _GENERATION},
            code="BUDGET_GENERATION_NOT_FOUND",
        )
    finally:
        service.close()
        confirmations.close()
        store.close()
