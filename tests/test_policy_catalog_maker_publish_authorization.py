from __future__ import annotations

from pathlib import Path

from bt_api_base.service_protocol import WireScope
from bt_api_risk.service_component import PolicyCatalogService, PolicyCatalogStore


def _document(policy_ref: str) -> dict[str, object]:
    return {
        "risk_policy": {
            "policy_id": policy_ref,
            "max_increase_notional": "25",
            "max_increase_count": 2,
            "permit_ttl_seconds": 30.0,
            "require_strategy_allocation": False,
            "notional_unit": "USD",
        }
    }


def _call(
    service: PolicyCatalogService,
    operation: str,
    *,
    principal_ref: str,
    scope: WireScope,
    arguments: dict[str, object],
) -> dict[str, object]:
    return dict(
        service.handle(
            operation,
            principal_ref=principal_ref,
            scope=scope,
            arguments=arguments,
        )
    )


def _draft(
    service: PolicyCatalogService,
    *,
    policy_ref: str,
    principal_ref: str,
    scope: WireScope,
) -> None:
    result = _call(
        service,
        "policy.draft",
        principal_ref=principal_ref,
        scope=scope,
        arguments={"policy_ref": policy_ref, "content": _document(policy_ref)},
    )
    assert result["ok"] is True, result


def test_trusted_distinct_checker_approval_allows_exact_owner_publish(
    tmp_path: Path,
) -> None:
    store = PolicyCatalogStore(
        str(tmp_path / "policy-catalog.sqlite3"),
        trusted_approver_principals=("checker", "maker"),
    )
    service = PolicyCatalogService(store)
    owner_scope = WireScope("portfolio:ordinary-policy", account_ref="acct-a")
    other_scope = WireScope("portfolio:ordinary-policy", account_ref="acct-b")
    policy_ref = "acct-a-risk-v1"
    arguments = {"policy_ref": policy_ref}
    try:
        _draft(
            service,
            policy_ref=policy_ref,
            principal_ref="maker",
            scope=owner_scope,
        )

        self_approval = _call(
            service,
            "policy.approve",
            principal_ref="maker",
            scope=owner_scope,
            arguments=arguments,
        )
        assert self_approval["code"] == "APPROVER_MUST_DIFFER_FROM_OWNER", self_approval

        untrusted_approval = _call(
            service,
            "policy.approve",
            principal_ref="intruder",
            scope=owner_scope,
            arguments=arguments,
        )
        assert untrusted_approval["code"] == "APPROVER_NOT_AUTHORIZED", untrusted_approval

        wrong_scope_approval = _call(
            service,
            "policy.approve",
            principal_ref="checker",
            scope=other_scope,
            arguments=arguments,
        )
        assert wrong_scope_approval["code"] == "SCOPE_NOT_OWNER", wrong_scope_approval

        draft_state = _call(
            service,
            "policy.inspect",
            principal_ref="maker",
            scope=owner_scope,
            arguments=arguments,
        )
        assert draft_state["ok"] is True, draft_state
        assert draft_state["result"]["state"] == "draft", draft_state

        approved = _call(
            service,
            "policy.approve",
            principal_ref="checker",
            scope=owner_scope,
            arguments=arguments,
        )
        assert approved["ok"] is True, approved
        assert approved["result"]["state"] == "approved", approved

        wrong_scope_publish = _call(
            service,
            "policy.publish",
            principal_ref="maker",
            scope=other_scope,
            arguments=arguments,
        )
        assert wrong_scope_publish["code"] == "SCOPE_NOT_OWNER", wrong_scope_publish

        unrelated_publish = _call(
            service,
            "policy.publish",
            principal_ref="intruder",
            scope=owner_scope,
            arguments=arguments,
        )
        assert unrelated_publish["code"] == "POLICY_PUBLISH_NOT_AUTHORIZED", unrelated_publish

        still_approved = _call(
            service,
            "policy.inspect",
            principal_ref="maker",
            scope=owner_scope,
            arguments=arguments,
        )
        assert still_approved["ok"] is True, still_approved
        assert still_approved["result"]["state"] == "approved", still_approved

        published = _call(
            service,
            "policy.publish",
            principal_ref="maker",
            scope=owner_scope,
            arguments=arguments,
        )
        assert published["ok"] is True, published
        assert published["result"]["policy_ref"] == policy_ref, published
        assert (
            published["result"]["policy_version"]
            == approved["result"]["policy_version"]
        ), published
        assert published["result"]["owner_principal"] == "maker", published
        published_state = _call(
            service,
            "policy.inspect",
            principal_ref="maker",
            scope=owner_scope,
            arguments=arguments,
        )
        assert published_state["ok"] is True, published_state
        assert published_state["result"]["state"] == "published", published_state

        # Preserve the existing trusted-checker publication compatibility.
        checker_policy = "acct-a-risk-v2"
        _draft(
            service,
            policy_ref=checker_policy,
            principal_ref="maker",
            scope=owner_scope,
        )
        checker_approval = _call(
            service,
            "policy.approve",
            principal_ref="checker",
            scope=owner_scope,
            arguments={"policy_ref": checker_policy},
        )
        assert checker_approval["ok"] is True, checker_approval
        checker_publish = _call(
            service,
            "policy.publish",
            principal_ref="checker",
            scope=owner_scope,
            arguments={"policy_ref": checker_policy},
        )
        assert checker_publish["ok"] is True, checker_publish
        assert checker_publish["result"]["policy_ref"] == checker_policy, checker_publish
        assert (
            checker_publish["result"]["policy_version"]
            == checker_approval["result"]["policy_version"]
        ), checker_publish
        assert checker_publish["result"]["owner_principal"] == "maker", checker_publish
        checker_published_state = _call(
            service,
            "policy.inspect",
            principal_ref="maker",
            scope=owner_scope,
            arguments={"policy_ref": checker_policy},
        )
        assert checker_published_state["ok"] is True, checker_published_state
        assert checker_published_state["result"]["state"] == "published", checker_published_state
    finally:
        service.close()
        store.close()
