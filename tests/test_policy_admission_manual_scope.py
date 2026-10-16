from __future__ import annotations

from pathlib import Path

import pytest
from bt_api_base.service_protocol import WireScope

from bt_api_risk.core.admission import AccountScope, DurableRiskGate
from bt_api_risk.policy_admission import (
    PolicyAdmissionResolutionError,
    PolicyCatalogAccountAdmissionResolver,
)
from bt_api_risk.service_component import (
    ConfirmedPolicyStore,
    PolicyCatalogService,
    PolicyCatalogStore,
)


_DOMAIN = "paper:ordinary-account-policy"
_ACCOUNT = "account-ref-a"
_BOOK = "manual-book-a"
_OWNER = "owner-principal-a"
_CHECKER = "checker-principal"
_POLICY_REF = "account-policy-manual-a-v1"


def _scope(
    *,
    account_ref: str = _ACCOUNT,
    manual_book_ref: str | None = _BOOK,
    portfolio_ref: str | None = None,
    strategy_ref: str | None = None,
    run_id: str | None = None,
) -> WireScope:
    return WireScope(
        execution_domain_ref=_DOMAIN,
        account_ref=account_ref,
        manual_book_ref=manual_book_ref,
        portfolio_ref=portfolio_ref,
        strategy_ref=strategy_ref,
        run_id=run_id,
    )


def _policy_document() -> dict[str, object]:
    return {
        "risk_policy": {
            "policy_id": _POLICY_REF,
            "max_increase_notional": "25",
            "max_increase_count": 3,
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
    reply = service.handle(
        operation,
        principal_ref=principal_ref,
        scope=scope,
        arguments=arguments,
    )
    assert reply["ok"] is True, reply
    result = reply["result"]
    assert type(result) is dict
    return result


def test_manual_account_scope_resolves_confirms_and_rejects_scope_expansion(
    tmp_path: Path,
) -> None:
    catalog = PolicyCatalogStore(
        str(tmp_path / "catalog.sqlite3"),
        trusted_approver_principals=(_CHECKER,),
    )
    confirmations = ConfirmedPolicyStore(str(tmp_path / "confirmed.sqlite3"))
    service = PolicyCatalogService(catalog, confirmation_store=confirmations)
    risk_database = tmp_path / "account-a-risk.sqlite3"
    account_scope = AccountScope(
        provider="paper", account_id="provider-account-a", environment="paper"
    )
    exact_scope = _scope()
    try:
        _call(
            service,
            "policy.draft",
            principal_ref=_OWNER,
            scope=exact_scope,
            arguments={"policy_ref": _POLICY_REF, "content": _policy_document()},
        )
        _call(
            service,
            "policy.approve",
            principal_ref=_CHECKER,
            scope=exact_scope,
            arguments={"policy_ref": _POLICY_REF},
        )
        published = _call(
            service,
            "policy.publish",
            principal_ref=_CHECKER,
            scope=exact_scope,
            arguments={"policy_ref": _POLICY_REF},
        )

        resolver = PolicyCatalogAccountAdmissionResolver(catalog, confirmations)
        candidate = resolver.resolve_published(
            _POLICY_REF, _ACCOUNT, scope=exact_scope
        )
        assert candidate.policy_version == published["policy_version"]
        gate = DurableRiskGate(risk_database, candidate.risk_policy)
        confirmed = resolver.confirm_after_gate_binding(
            _POLICY_REF,
            _ACCOUNT,
            principal_ref=_OWNER,
            scope=exact_scope,
            account_scope=account_scope,
            gate=gate,
        )
        assert confirmed.binding.scope == account_scope
        assert confirmed.binding.policy_id == _POLICY_REF
        assert confirmed.binding.policy_fingerprint == candidate.risk_policy.fingerprint
        assert confirmed.binding.ledger_identity_ref == gate.ledger_identity_ref

        reopened = PolicyCatalogAccountAdmissionResolver(None, confirmations)
        restored = reopened.resolve_confirmed_and_bind(
            _POLICY_REF,
            _ACCOUNT,
            scope=exact_scope,
            account_scope=account_scope,
            gate=DurableRiskGate(risk_database, candidate.risk_policy),
        )
        assert restored.binding == confirmed.binding
        assert restored.resolved.policy_version == candidate.policy_version

        with pytest.raises(PolicyAdmissionResolutionError) as wrong_book:
            resolver.resolve_published(
                _POLICY_REF,
                _ACCOUNT,
                scope=_scope(manual_book_ref="manual-book-b"),
            )
        assert wrong_book.value.code == "SCOPE_NOT_OWNER"

        for expanded_scope in (
            _scope(account_ref="account-ref-b"),
            _scope(portfolio_ref="portfolio-a"),
            _scope(manual_book_ref=None, strategy_ref="strategy-a"),
            _scope(manual_book_ref=None, strategy_ref="strategy-a", run_id="run-a"),
        ):
            with pytest.raises(PolicyAdmissionResolutionError) as rejected:
                resolver.resolve_published(
                    _POLICY_REF, _ACCOUNT, scope=expanded_scope
                )
            assert rejected.value.code == "ACCOUNT_POLICY_SCOPE_REQUIRED"
    finally:
        service.close()
        catalog.close()
        confirmations.close()
