"""Exact Risk catalog draft replay must preserve immutable state."""

from __future__ import annotations

from pathlib import Path

from bt_api_base.service_protocol import WireScope
from bt_api_risk.service_component import PolicyCatalogService, PolicyCatalogStore


def _call(
    service: PolicyCatalogService,
    operation: str,
    *,
    principal_ref: str,
    scope: WireScope,
    arguments: dict[str, object],
) -> dict[str, object]:
    reply = service.handle(
        operation,
        principal_ref=principal_ref,
        scope=scope,
        arguments=arguments,
    )
    assert type(reply) is dict, (operation, reply)
    return reply


def test_exact_draft_replay_after_restart_preserves_approval_and_publish_state(
    tmp_path: Path,
) -> None:
    catalog_path = tmp_path / "policy-catalog.sqlite3"
    scope = WireScope(
        execution_domain_ref="paper:budget",
        account_ref="acct-a",
        portfolio_ref="portfolio-a",
    )
    other_scope = WireScope(
        execution_domain_ref="paper:budget",
        account_ref="acct-b",
        portfolio_ref="portfolio-a",
    )
    arguments: dict[str, object] = {
        "policy_ref": "afi-budget-acct-a-v1",
        "content": {
            "risk_policy": {
                "policy_id": "afi-budget-acct-a-v1",
                "max_increase_notional": "25",
                "max_increase_count": 1,
                "notional_unit": "USD",
            }
        },
    }

    store = PolicyCatalogStore(str(catalog_path))
    service = PolicyCatalogService(store)
    first = _call(
        service,
        "policy.draft",
        principal_ref="maker-principal",
        scope=scope,
        arguments=arguments,
    )
    assert first["ok"] is True and first["code"] == "OK", first
    assert first["result"]["policy_ref"] == "afi-budget-acct-a-v1", first
    assert first["result"]["state"] == "draft", first
    assert type(first["result"]["policy_version"]) is str, first
    first_version = first["result"]["policy_version"]
    service.close()
    store.close()

    # A new catalog/service instance models the normal process restart path.
    store = PolicyCatalogStore(str(catalog_path))
    service = PolicyCatalogService(store)
    try:
        replay = _call(
            service,
            "policy.draft",
            principal_ref="maker-principal",
            scope=scope,
            arguments=arguments,
        )
        assert replay["ok"] is True and replay["code"] == "OK", replay
        assert replay["result"] == {
            "policy_ref": "afi-budget-acct-a-v1",
            "policy_version": first_version,
            "state": "draft",
        }, replay
        canonical_replay = _call(
            service,
            "policy.draft",
            principal_ref="maker-principal",
            scope=scope,
            arguments={
                "policy_ref": "afi-budget-acct-a-v1",
                "content": {
                    "risk_policy": {
                        "notional_unit": "USD",
                        "max_increase_count": 1,
                        "max_increase_notional": "25",
                        "policy_id": "afi-budget-acct-a-v1",
                    }
                },
            },
        )
        assert canonical_replay == replay, canonical_replay

        approved = _call(
            service,
            "policy.approve",
            principal_ref="checker-principal",
            scope=scope,
            arguments={"policy_ref": "afi-budget-acct-a-v1"},
        )
        assert approved["ok"] is True and approved["code"] == "OK", approved
        approved_replay = _call(
            service,
            "policy.draft",
            principal_ref="maker-principal",
            scope=scope,
            arguments=arguments,
        )
        assert approved_replay["ok"] is True, approved_replay
        assert approved_replay["result"] == {
            "policy_ref": "afi-budget-acct-a-v1",
            "policy_version": first_version,
            "state": "approved",
        }, approved_replay

        published = _call(
            service,
            "policy.publish",
            principal_ref="checker-principal",
            scope=scope,
            arguments={"policy_ref": "afi-budget-acct-a-v1"},
        )
        assert published["ok"] is True and published["code"] == "OK", published
        published_replay = _call(
            service,
            "policy.draft",
            principal_ref="maker-principal",
            scope=scope,
            arguments=arguments,
        )
        assert published_replay["ok"] is True, published_replay
        assert published_replay["result"] == {
            "policy_ref": "afi-budget-acct-a-v1",
            "policy_version": first_version,
            "state": "published",
        }, published_replay

        changed_content = {
            **arguments,
            "content": {
                "risk_policy": {
                    "policy_id": "afi-budget-acct-a-v1",
                    "max_increase_notional": "26",
                    "max_increase_count": 1,
                    "notional_unit": "USD",
                }
            },
        }
        content_conflict = _call(
            service,
            "policy.draft",
            principal_ref="maker-principal",
            scope=scope,
            arguments=changed_content,
        )
        assert content_conflict == {
            "ok": False,
            "code": "POLICY_DRAFT_CONFLICT",
            "result": {},
        }, content_conflict

        principal_conflict = _call(
            service,
            "policy.draft",
            principal_ref="other-principal",
            scope=scope,
            arguments=arguments,
        )
        assert principal_conflict == {
            "ok": False,
            "code": "POLICY_DRAFT_CONFLICT",
            "result": {},
        }, principal_conflict

        scope_conflict = _call(
            service,
            "policy.draft",
            principal_ref="maker-principal",
            scope=other_scope,
            arguments=arguments,
        )
        assert scope_conflict == {
            "ok": False,
            "code": "POLICY_DRAFT_CONFLICT",
            "result": {},
        }, scope_conflict
        unchanged = _call(
            service,
            "policy.draft",
            principal_ref="maker-principal",
            scope=scope,
            arguments=arguments,
        )
        assert unchanged["ok"] is True, unchanged
        assert unchanged["result"] == {
            "policy_ref": "afi-budget-acct-a-v1",
            "policy_version": first_version,
            "state": "published",
        }, unchanged
    finally:
        service.close()
        store.close()
