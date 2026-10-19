from __future__ import annotations

from pathlib import Path

from bt_api_base.service_protocol import WireScope
from bt_api_risk.core.admission import AccountScope, DurableRiskGate
from bt_api_risk.policy_admission import PolicyCatalogAccountAdmissionResolver
from bt_api_risk.service_component import (
    ConfirmedPolicyStore,
    PolicyCatalogService,
    PolicyCatalogStore,
)


def _scope(account_ref: str = "acct-a") -> WireScope:
    return WireScope("portfolio:ordinary-risk-policy", account_ref=account_ref)


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


def test_policy_approval_requires_trusted_non_owner_and_owner_can_publish(
    tmp_path: Path,
) -> None:
    store = PolicyCatalogStore(
        str(tmp_path / "catalog.sqlite3"),
        trusted_approver_principals=("maker", "checker", "other"),
    )
    service = PolicyCatalogService(store)
    scope = _scope()
    policy_ref = "acct-a-risk-v1"
    arguments = {"policy_ref": policy_ref}
    try:
        draft = _call(
            service,
            "policy.draft",
            principal_ref="maker",
            scope=scope,
            arguments={"policy_ref": policy_ref, "content": _document(policy_ref)},
        )
        assert draft["ok"] is True, draft

        self_approval = _call(
            service,
            "policy.approve",
            principal_ref="maker",
            scope=scope,
            arguments=arguments,
        )
        assert self_approval == {
            "ok": False,
            "code": "APPROVER_MUST_DIFFER_FROM_OWNER",
            "result": {},
        }
        untrusted = _call(
            service,
            "policy.approve",
            principal_ref="untrusted",
            scope=scope,
            arguments=arguments,
        )
        assert untrusted["code"] == "APPROVER_NOT_AUTHORIZED"

        approved = _call(
            service,
            "policy.approve",
            principal_ref="checker",
            scope=scope,
            arguments=arguments,
        )
        assert approved["ok"] is True, approved
        wrong_publisher = _call(
            service,
            "policy.publish",
            principal_ref="other",
            scope=scope,
            arguments=arguments,
        )
        assert wrong_publisher["code"] == "POLICY_PUBLISH_NOT_AUTHORIZED"

        # AFI's maker may publish only after this trusted, distinct checker
        # approved the exact owner scope.
        published = _call(
            service,
            "policy.publish",
            principal_ref="maker",
            scope=scope,
            arguments=arguments,
        )
        assert published["ok"] is True, published

        # Preserve the existing trusted-checker publication compatibility.
        checker_policy = "acct-a-risk-v2"
        assert _call(
            service,
            "policy.draft",
            principal_ref="maker",
            scope=scope,
            arguments={
                "policy_ref": checker_policy,
                "content": _document(checker_policy),
            },
        )["ok"] is True
        assert _call(
            service,
            "policy.approve",
            principal_ref="checker",
            scope=scope,
            arguments={"policy_ref": checker_policy},
        )["ok"] is True
        checker_publish = _call(
            service,
            "policy.publish",
            principal_ref="checker",
            scope=scope,
            arguments={"policy_ref": checker_policy},
        )
        assert checker_publish["ok"] is True, checker_publish
    finally:
        service.close()
        store.close()


def test_confirmation_read_is_exact_scope_and_reports_persisted_gate_binding(
    tmp_path: Path,
) -> None:
    catalog = PolicyCatalogStore(
        str(tmp_path / "catalog.sqlite3"),
        trusted_approver_principals=("checker",),
    )
    confirmations = ConfirmedPolicyStore(str(tmp_path / "confirmed.sqlite3"))
    service = PolicyCatalogService(catalog, confirmation_store=confirmations)
    scope = _scope()
    policy_ref = "acct-a-risk-v3"
    arguments = {"policy_ref": policy_ref}
    content = _document(policy_ref)
    try:
        assert _call(
            service,
            "policy.draft",
            principal_ref="maker",
            scope=scope,
            arguments={"policy_ref": policy_ref, "content": content},
        )["ok"] is True
        assert _call(
            service,
            "policy.approve",
            principal_ref="checker",
            scope=scope,
            arguments=arguments,
        )["ok"] is True
        assert _call(
            service,
            "policy.publish",
            principal_ref="maker",
            scope=scope,
            arguments=arguments,
        )["ok"] is True

        before = _call(
            service,
            "policy.confirmation.read",
            principal_ref="maker",
            scope=scope,
            arguments=arguments,
        )
        assert before["ok"] is True, before
        assert before["result"] == {
            "policy_ref": policy_ref,
            "owner_confirmed": False,
            "policy_version": None,
            "confirmed_utc": None,
            "document_available": False,
        }

        resolver = PolicyCatalogAccountAdmissionResolver(catalog, confirmations)
        candidate = resolver.resolve_published(policy_ref, "acct-a", scope=scope)
        gate = DurableRiskGate(
            str(tmp_path / "account-risk.sqlite3"), candidate.risk_policy
        )
        bound = resolver.confirm_after_gate_binding(
            policy_ref,
            "acct-a",
            principal_ref="maker",
            scope=scope,
            account_scope=AccountScope("paper", "provider-acct-a", "demo"),
            gate=gate,
        )
        assert bound.binding.policy_fingerprint == candidate.risk_policy.fingerprint

        after = _call(
            service,
            "policy.confirmation.read",
            principal_ref="maker",
            scope=scope,
            arguments=arguments,
        )
        assert after["ok"] is True, after
        assert after["result"]["owner_confirmed"] is True
        assert after["result"]["policy_version"] == candidate.policy_version
        assert after["result"]["document_available"] is True
        assert "content" not in after["result"]
        assert "consumer_effective" not in after["result"]

        wrong_scope = _call(
            service,
            "policy.confirmation.read",
            principal_ref="maker",
            scope=_scope("acct-b"),
            arguments=arguments,
        )
        assert wrong_scope["code"] == "SCOPE_NOT_OWNER"
    finally:
        service.close()
        catalog.close()
        confirmations.close()
