from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from decimal import Decimal
from pathlib import Path

import pytest
from bt_api_base.service_protocol import WireScope

from bt_api_risk.core.admission import (
    AccountScope,
    DurableRiskGate,
    IntentAction,
    RiskIntent,
)
from bt_api_risk.policy_admission import (
    PolicyAdmissionResolutionError,
    PolicyCatalogAccountAdmissionResolver,
)
from bt_api_risk.service_component import (
    ConfirmedPolicyStore,
    PolicyCatalogError,
    PolicyCatalogService,
    PolicyCatalogStore,
)

_DOMAIN = "paper:account-policy"
_PORTFOLIO = "portfolio-a"
_ACCOUNT_REF = "acct-a"
_OWNER = "account-owner"
_CHECKER = "risk-checker"


def _wire_scope(account_ref: str = _ACCOUNT_REF) -> WireScope:
    return WireScope(
        execution_domain_ref=_DOMAIN,
        account_ref=account_ref,
        portfolio_ref=_PORTFOLIO,
    )


def _account_scope(account_id: str = "provider-account-a") -> AccountScope:
    # Provider account IDs are intentionally distinct from service account refs.
    return AccountScope(provider="paper", account_id=account_id, environment="paper")


def _policy_document(
    policy_ref: str, *, maximum: str = "25", count: int = 3
) -> dict[str, object]:
    return {
        "risk_policy": {
            "policy_id": policy_ref,
            "max_increase_notional": maximum,
            "max_increase_count": count,
            "permit_ttl_seconds": 30.0,
            "require_strategy_allocation": False,
            "notional_unit": "USD",
        }
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


def _catalog_service(tmp_path: Path):
    catalog_path = tmp_path / "policy-catalog.sqlite3"
    confirmed_path = tmp_path / "confirmed-policy.sqlite3"
    catalog = PolicyCatalogStore(
        str(catalog_path), trusted_approver_principals=(_CHECKER,)
    )
    confirmed = ConfirmedPolicyStore(str(confirmed_path))
    service = PolicyCatalogService(catalog, confirmation_store=confirmed)
    return catalog_path, confirmed_path, catalog, confirmed, service


def _publish(
    service: PolicyCatalogService,
    policy_ref: str,
    *,
    content: dict[str, object] | None = None,
) -> dict[str, object]:
    scope = _wire_scope()
    draft = service.handle(
        "policy.draft",
        principal_ref=_OWNER,
        scope=scope,
        arguments={
            "policy_ref": policy_ref,
            "content": _policy_document(policy_ref) if content is None else content,
        },
    )
    assert draft["ok"] is True, draft
    approved = service.handle(
        "policy.approve",
        principal_ref=_CHECKER,
        scope=scope,
        arguments={"policy_ref": policy_ref},
    )
    assert approved["ok"] is True, approved
    published = service.handle(
        "policy.publish",
        principal_ref=_CHECKER,
        scope=scope,
        arguments={"policy_ref": policy_ref},
    )
    assert published["ok"] is True, published
    return published["result"]


def test_owner_confirms_only_after_actual_gate_binding_and_offline_restart(
    tmp_path: Path,
) -> None:
    catalog_path, confirmation_path, catalog, confirmations, service = _catalog_service(
        tmp_path
    )
    risk_database = tmp_path / "account-risk.sqlite3"
    policy_ref = "account-risk-a-v1"
    published = _publish(service, policy_ref)
    resolver = PolicyCatalogAccountAdmissionResolver(catalog, confirmations)
    account_scope = _account_scope()
    candidate = resolver.resolve_published(policy_ref, _ACCOUNT_REF, scope=_wire_scope())
    gate = DurableRiskGate(risk_database, candidate.risk_policy)

    try:
        with pytest.raises(PolicyAdmissionResolutionError) as wrong_owner:
            resolver.confirm_after_gate_binding(
                policy_ref,
                _ACCOUNT_REF,
                principal_ref="different-owner",
                scope=_wire_scope(),
                account_scope=account_scope,
                gate=gate,
            )
        assert wrong_owner.value.code == "POLICY_OWNER_PRINCIPAL_MISMATCH"
        with pytest.raises(PolicyCatalogError) as not_confirmed:
            confirmations.resolve(policy_ref)
        assert not_confirmed.value.code == "POLICY_NOT_CONFIRMED"

        confirmed = resolver.confirm_after_gate_binding(
            policy_ref,
            _ACCOUNT_REF,
            principal_ref=_OWNER,
            scope=_wire_scope(),
            account_scope=account_scope,
            gate=gate,
        )
        assert confirmed.resolved.policy_version == published["policy_version"]
        assert confirmed.binding.scope == account_scope
        assert confirmed.binding.policy_id == policy_ref
        assert confirmed.binding.policy_fingerprint == candidate.risk_policy.fingerprint
        assert confirmed.binding.ledger_identity_ref == gate.ledger_identity_ref

        replayed = resolver.confirm_after_gate_binding(
            policy_ref,
            _ACCOUNT_REF,
            principal_ref=_OWNER,
            scope=_wire_scope(),
            account_scope=account_scope,
            gate=gate,
        )
        assert replayed.binding == confirmed.binding
        assert replayed.resolved.confirmed_utc == confirmed.resolved.confirmed_utc

        changed_content = _policy_document(policy_ref, maximum="30")
        with pytest.raises(PolicyCatalogError) as wrong_document:
            confirmations.confirm_document(published, changed_content)
        assert wrong_document.value.code == "POLICY_DOCUMENT_DIGEST_MISMATCH"
        changed_receipt = dict(published, policy_version=_digest(changed_content))
        with pytest.raises(PolicyCatalogError) as conflicting_version:
            confirmations.confirm_document(changed_receipt, changed_content)
        assert conflicting_version.value.code == "POLICY_VERSION_CONFLICT"

        persisted = confirmations.resolve_document(policy_ref)
        assert persisted["content"] == _policy_document(policy_ref)
        assert persisted["policy_version"] == published["policy_version"]
        assert persisted["owner_principal"] == _OWNER
        with pytest.raises(TypeError):
            persisted["content"]["risk_policy"]["max_increase_notional"] = "999"
    finally:
        service.close()
        catalog.close()
        confirmations.close()

    # Restart with only the owner-side durable confirmed store. The catalog is
    # intentionally absent, so this cannot fall through to a mutable latest.
    reopened_confirmations = ConfirmedPolicyStore(str(confirmation_path))
    try:
        offline = PolicyCatalogAccountAdmissionResolver(None, reopened_confirmations)
        reopened = offline.resolve_confirmed(
            policy_ref, _ACCOUNT_REF, scope=_wire_scope()
        )
        assert reopened.policy_version == published["policy_version"]
        assert reopened.owner_principal == _OWNER
        assert reopened.confirmed_utc is not None
        assert reopened.risk_policy == candidate.risk_policy

        restarted_gate = DurableRiskGate(risk_database, reopened.risk_policy)
        bound = offline.resolve_confirmed_and_bind(
            policy_ref,
            _ACCOUNT_REF,
            scope=_wire_scope(),
            account_scope=account_scope,
            gate=restarted_gate,
        )
        assert bound.binding == confirmed.binding
    finally:
        reopened_confirmations.close()


def test_new_policy_cannot_replace_old_policy_with_active_reservation(
    tmp_path: Path,
) -> None:
    _, _, catalog, confirmations, service = _catalog_service(tmp_path)
    risk_database = tmp_path / "account-risk.sqlite3"
    resolver = PolicyCatalogAccountAdmissionResolver(catalog, confirmations)
    old_ref = "account-risk-a-v1"
    new_ref = "account-risk-a-v2"
    try:
        _publish(service, old_ref)
        old_candidate = resolver.resolve_published(
            old_ref, _ACCOUNT_REF, scope=_wire_scope()
        )
        old_gate = DurableRiskGate(risk_database, old_candidate.risk_policy)
        owner_confirmation = resolver.confirm_after_gate_binding(
            old_ref,
            _ACCOUNT_REF,
            principal_ref=_OWNER,
            scope=_wire_scope(),
            account_scope=_account_scope(),
            gate=old_gate,
        )
        intent = RiskIntent(
            intent_id="old-policy-active-reservation",
            scope=_account_scope(),
            action=IntentAction.INCREASE,
            notional=Decimal("10"),
            payload_fingerprint="synthetic-local-risk-policy-test",
            notional_unit="USD",
        )
        permit = old_gate.reserve(intent)
        before = old_gate.snapshot(_account_scope())
        assert before["increase_notional"] == Decimal("10")

        _publish(service, new_ref, content=_policy_document(new_ref, maximum="40"))
        new_candidate = resolver.resolve_published(
            new_ref, _ACCOUNT_REF, scope=_wire_scope()
        )
        new_gate = DurableRiskGate(risk_database, new_candidate.risk_policy)
        with pytest.raises(PolicyAdmissionResolutionError) as mismatch:
            resolver.confirm_after_gate_binding(
                new_ref,
                _ACCOUNT_REF,
                principal_ref=_OWNER,
                scope=_wire_scope(),
                account_scope=_account_scope(),
                gate=new_gate,
            )
        assert mismatch.value.code == "RISK_POLICY_BINDING_MISMATCH"
        with pytest.raises(PolicyCatalogError) as no_new_confirmation:
            confirmations.resolve(new_ref)
        assert no_new_confirmation.value.code == "POLICY_NOT_CONFIRMED"

        after = old_gate.snapshot(_account_scope())
        assert after == before
        assert after["increase_notional"] == Decimal("10")
        with closing(sqlite3.connect(risk_database)) as connection:
            active = connection.execute(
                "SELECT permit_id, status, notional, policy_hash "
                "FROM risk_reservations WHERE permit_id=?",
                (permit.permit_id,),
            ).fetchone()
        assert active == (
            permit.permit_id,
            "active",
            "10",
            old_candidate.risk_policy.fingerprint,
        )
        still_confirmed = confirmations.resolve_document(old_ref)
        assert still_confirmed["policy_version"] == owner_confirmation.resolved.policy_version
    finally:
        service.close()
        catalog.close()
        confirmations.close()


def test_confirmed_document_store_migrates_receipt_only_rows_without_claiming_doc(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-confirmed.sqlite3"
    scope_payload = {
        "execution_domain_ref": _DOMAIN,
        "account_ref": _ACCOUNT_REF,
        "account_refs": [],
        "strategy_ref": None,
        "run_id": None,
        "manual_book_ref": None,
        "portfolio_ref": _PORTFOLIO,
        "group_id": None,
        "leg_id": None,
    }
    version = hashlib.sha256(b"not-a-persisted-document").hexdigest()
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE confirmed_policies ("
            "reference TEXT PRIMARY KEY, policy_version TEXT NOT NULL, "
            "owner_principal TEXT NOT NULL, owner_scope_json TEXT NOT NULL, "
            "published_utc TEXT NOT NULL, confirmed_utc TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO confirmed_policies VALUES (?,?,?,?,?,?)",
            (
                "account-risk-a-v1",
                version,
                _OWNER,
                json.dumps(scope_payload, sort_keys=True, separators=(",", ":")),
                "2026-10-17T00:00:00Z",
                "2026-10-17T00:00:01Z",
            ),
        )
        connection.commit()
    finally:
        connection.close()

    store = ConfirmedPolicyStore(str(path))
    try:
        receipt = store.resolve("account-risk-a-v1")
        assert receipt["policy_version"] == version
        with pytest.raises(PolicyCatalogError) as unavailable:
            store.resolve_document("account-risk-a-v1")
        assert unavailable.value.code == "POLICY_DOCUMENT_UNAVAILABLE"
    finally:
        store.close()
