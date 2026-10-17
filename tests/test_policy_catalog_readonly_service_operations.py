from __future__ import annotations

import inspect
import sqlite3
from contextlib import closing
from pathlib import Path

from bt_api_base.service_protocol import WireScope
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
    scope: WireScope,
    arguments: dict[str, object],
    principal_ref: str = "authenticated-owner",
) -> dict[str, object]:
    return dict(
        service.handle(
            operation,
            principal_ref=principal_ref,
            scope=scope,
            arguments=arguments,
        )
    )


def _assert_fixed_source_origins() -> None:
    root = Path(__file__).resolve().parents[1]
    assert Path(inspect.getsourcefile(PolicyCatalogService)).resolve() == (
        root / "risk" / "src" / "bt_api_risk" / "service_component.py"
    )
    assert Path(inspect.getsourcefile(WireScope)).resolve() == (
        root / "base" / "src" / "bt_api_base" / "service_protocol.py"
    )


def test_policy_inspect_and_confirmation_status_are_scoped_and_persisted(
    tmp_path: Path,
) -> None:
    _assert_fixed_source_origins()
    catalog_path = tmp_path / "catalog.sqlite3"
    confirmation_path = tmp_path / "confirmed.sqlite3"
    catalog = PolicyCatalogStore(
        str(catalog_path), trusted_approver_principals=("trusted-checker",)
    )
    confirmations = ConfirmedPolicyStore(str(confirmation_path))
    service = PolicyCatalogService(catalog, confirmation_store=confirmations)
    scope = _scope()
    policy_ref = "ordinary-account-policy-v1"
    document = _document(policy_ref)
    arguments = {"policy_ref": policy_ref}

    try:
        assert "policy.inspect" in service.supported_operations
        assert "policy.confirmation.read" in service.supported_operations

        draft = _call(
            service,
            "policy.draft",
            scope=scope,
            arguments={"policy_ref": policy_ref, "content": document},
        )
        assert draft["ok"] is True, draft

        inspected = _call(
            service, "policy.inspect", scope=scope, arguments=arguments
        )
        assert inspected["ok"] is True, inspected
        assert inspected["result"]["policy_ref"] == policy_ref
        assert inspected["result"]["state"] == "draft"
        assert inspected["result"]["content"] == document
        assert type(inspected["result"]["policy_version"]) is str

        assert _call(
            service,
            "policy.inspect",
            scope=scope,
            arguments={**arguments, "unexpected": True},
        )["code"] == "INVALID_REQUEST"
        assert _call(
            service,
            "policy.inspect",
            scope=scope,
            arguments={"policy_ref": "missing-policy-v1"},
        )["code"] == "POLICY_NOT_FOUND"
        assert _call(
            service,
            "policy.inspect",
            scope=_scope("acct-b"),
            arguments=arguments,
        )["code"] == "SCOPE_NOT_OWNER"

        missing_confirmation = _call(
            service,
            "policy.confirmation.read",
            scope=scope,
            arguments=arguments,
        )
        assert missing_confirmation["ok"] is True, missing_confirmation
        assert missing_confirmation["result"] == {
            "policy_ref": policy_ref,
            "owner_confirmed": False,
            "policy_version": None,
            "confirmed_utc": None,
            "document_available": False,
        }
        assert _call(
            service,
            "policy.confirmation.read",
            scope=scope,
            arguments={**arguments, "unexpected": True},
        )["code"] == "INVALID_REQUEST"

        approved = _call(
            service,
            "policy.approve",
            scope=scope,
            arguments=arguments,
            principal_ref="trusted-checker",
        )
        assert approved["ok"] is True, approved
        published = _call(
            service,
            "policy.publish",
            scope=scope,
            arguments=arguments,
            principal_ref="trusted-checker",
        )
        assert published["ok"] is True, published
        receipt = published["result"]
        confirmations.confirm_document(receipt, document)

        confirmed = _call(
            service,
            "policy.confirmation.read",
            scope=scope,
            arguments=arguments,
        )
        assert confirmed["ok"] is True, confirmed
        assert confirmed["result"]["owner_confirmed"] is True
        assert confirmed["result"]["policy_version"] == receipt["policy_version"]
        assert confirmed["result"]["document_available"] is True
        assert type(confirmed["result"]["confirmed_utc"]) is str
        assert "content" not in confirmed["result"]
        assert "consumer_effective" not in confirmed["result"]
        assert _call(
            service,
            "policy.confirmation.read",
            scope=_scope("acct-b"),
            arguments=arguments,
        )["code"] == "SCOPE_NOT_OWNER"
    finally:
        service.close()
        catalog.close()
        confirmations.close()

    # Re-open both stores to prove that reads report persisted state rather
    # than consulting a mutable latest pointer.
    reopened_catalog = PolicyCatalogStore(str(catalog_path))
    reopened_confirmations = ConfirmedPolicyStore(str(confirmation_path))
    reopened_service = PolicyCatalogService(
        reopened_catalog, confirmation_store=reopened_confirmations
    )
    try:
        replay = _call(
            reopened_service,
            "policy.inspect",
            scope=scope,
            arguments=arguments,
        )
        assert replay["ok"] is True, replay
        assert replay["result"]["state"] == "published"
        assert replay["result"]["policy_version"] == receipt["policy_version"]
        status = _call(
            reopened_service,
            "policy.confirmation.read",
            scope=scope,
            arguments=arguments,
        )
        assert status["ok"] is True, status
        assert status["result"]["owner_confirmed"] is True
        assert status["result"]["policy_version"] == receipt["policy_version"]
    finally:
        reopened_service.close()
        reopened_catalog.close()
        reopened_confirmations.close()


def test_confirmation_status_fails_closed_without_store_or_on_corrupt_document(
    tmp_path: Path,
) -> None:
    _assert_fixed_source_origins()
    catalog_path = tmp_path / "catalog.sqlite3"
    confirmation_path = tmp_path / "confirmed.sqlite3"
    catalog = PolicyCatalogStore(
        str(catalog_path), trusted_approver_principals=("trusted-checker",)
    )
    service_without_store = PolicyCatalogService(catalog)
    scope = _scope()
    policy_ref = "ordinary-account-policy-v2"
    arguments = {"policy_ref": policy_ref}
    document = _document(policy_ref)
    try:
        unavailable = _call(
            service_without_store,
            "policy.confirmation.read",
            scope=scope,
            arguments=arguments,
        )
        assert unavailable == {
            "ok": False,
            "code": "CONFIRMATION_STORE_UNAVAILABLE",
            "result": {},
        }
    finally:
        service_without_store.close()

    confirmations = ConfirmedPolicyStore(str(confirmation_path))
    service = PolicyCatalogService(catalog, confirmation_store=confirmations)
    try:
        assert _call(
            service,
            "policy.draft",
            scope=scope,
            arguments={"policy_ref": policy_ref, "content": document},
        )["ok"] is True
        assert _call(
            service,
            "policy.approve",
            scope=scope,
            arguments=arguments,
            principal_ref="trusted-checker",
        )["ok"] is True
        published = _call(
            service,
            "policy.publish",
            scope=scope,
            arguments=arguments,
            principal_ref="trusted-checker",
        )
        assert published["ok"] is True, published
        receipt = published["result"]
        confirmations.confirm_document(receipt, document)

        with closing(sqlite3.connect(confirmation_path)) as connection:
            connection.execute(
                "UPDATE confirmed_policies SET content_json=? WHERE reference=?",
                ('{"risk_policy":{}}', policy_ref),
            )
            connection.commit()

        service.close()
        confirmations.close()
        confirmations = ConfirmedPolicyStore(str(confirmation_path))
        service = PolicyCatalogService(catalog, confirmation_store=confirmations)
        corrupt = _call(
            service,
            "policy.confirmation.read",
            scope=scope,
            arguments=arguments,
        )
        assert corrupt == {
            "ok": False,
            "code": "POLICY_DOCUMENT_CORRUPT",
            "result": {},
        }
    finally:
        service.close()
        catalog.close()
        confirmations.close()
