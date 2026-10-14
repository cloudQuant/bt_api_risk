"""Focused tests for the pure risk service adapter and its local ledger reads."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
from bt_api_base.service_protocol import WireScope

from bt_api_risk import AccountScope, DurableRiskGate, IntentAction, RiskIntent, RiskPolicy
from bt_api_risk.service_component import (
    RiskReadService,
    RiskServiceError,
    validate_service_options,
)


class MutableClock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _policy(*, ttl: float = 30.0) -> RiskPolicy:
    return RiskPolicy(
        policy_id="service-policy",
        max_increase_notional=Decimal("250"),
        max_increase_count=4,
        permit_ttl_seconds=ttl,
    )


def _wire_scope(**changes: Any) -> WireScope:
    values: dict[str, Any] = {
        "execution_domain_ref": "paper:sim-a",
        "account_ref": "account-a",
    }
    values.update(changes)
    return WireScope(**values)


def _service(
    tmp_path: Path,
    *,
    scope: WireScope | None = None,
    clock: MutableClock | None = None,
    ttl: float = 30.0,
) -> tuple[RiskReadService, DurableRiskGate, AccountScope, WireScope]:
    wire_scope = scope or _wire_scope()
    account_scope = AccountScope("simnow", "acct-01", "paper")
    gate = DurableRiskGate(
        tmp_path / "risk-service.db",
        _policy(ttl=ttl),
        clock=clock,
    )
    return RiskReadService(gate, {wire_scope: account_scope}), gate, account_scope, wire_scope


def _reserve(gate: DurableRiskGate, scope: AccountScope, *, intent_id: str) -> None:
    gate.reserve(
        RiskIntent(
            intent_id=intent_id,
            scope=scope,
            action=IntentAction.INCREASE,
            notional=Decimal("12.50"),
            payload_fingerprint="service-test-payload",
        )
    )


@pytest.mark.parametrize(
    ("options", "ports", "expected"),
    [
        (
            {"role": "account_admission", "account_policy_ref": "account-policy-v2"},
            ("service.order_admission", "service.risk_query"),
            {"role": "account_admission", "account_policy_ref": "account-policy-v2"},
        ),
        (
            {"role": "group_policy", "group_policy_ref": "group-policy-v3"},
            ("service.group_admission",),
            {"role": "group_policy", "group_policy_ref": "group-policy-v3"},
        ),
        (
            {
                "role": "portfolio_analytics",
                "model_profile_ref": "model-profile-v1",
                "allowed_source_modes": ["research", "imported"],
                "max_concurrent_tasks": 4,
                "max_input_bytes": 1_048_576,
            },
            ("service.risk_analysis",),
            {
                "role": "portfolio_analytics",
                "model_profile_ref": "model-profile-v1",
                "allowed_source_modes": ("research", "imported"),
                "max_concurrent_tasks": 4,
                "max_input_bytes": 1_048_576,
            },
        ),
        (
            {
                "role": "portfolio_analytics",
                "model_profile_ref": "model-v1",
                "allowed_source_modes": ("paper",),
            },
            ("service.risk_analysis",),
            {
                "role": "portfolio_analytics",
                "model_profile_ref": "model-v1",
                "allowed_source_modes": ("paper",),
            },
        ),
        (
            {"role": "policy_catalog"},
            ("service.risk_policy",),
            {"role": "policy_catalog"},
        ),
    ],
)
def test_service_options_match_parent_contract_and_return_immutable_mapping(
    options: dict[str, object], ports: tuple[str, ...], expected: dict[str, object]
) -> None:
    original = dict(options)
    result = validate_service_options(options, ports)

    assert options == original
    assert dict(result) == expected
    assert isinstance(result, MappingProxyType)
    with pytest.raises(TypeError):
        result["extra"] = "value"  # type: ignore[index]
    if "allowed_source_modes" in result:
        assert type(result["allowed_source_modes"]) is tuple


@pytest.mark.parametrize(
    ("options", "ports", "code"),
    [
        (
            {"role": "account_admission", "account_policy_ref": "account-v1", "extra": True},
            ("service.order_admission",),
            "INVALID_OPTIONS",
        ),
        (
            {"role": "account_admission", "account_policy_ref": "latest"},
            ("service.order_admission",),
            "VERSIONED_REFERENCE_REQUIRED",
        ),
        (
            {"role": "group_policy", "group_policy_ref": "group-v1"},
            ("service.order_admission",),
            "PORT_ROLE_MISMATCH",
        ),
        (
            {
                "role": "portfolio_analytics",
                "model_profile_ref": "model-v1",
                "allowed_source_modes": ["paper", "paper"],
            },
            ("service.risk_analysis",),
            "DUPLICATE_SOURCE_MODE",
        ),
        (
            {
                "role": "portfolio_analytics",
                "model_profile_ref": "model-v1",
                "allowed_source_modes": ["production"],
            },
            ("service.risk_analysis",),
            "INVALID_SOURCE_MODES",
        ),
        (
            {
                "role": "portfolio_analytics",
                "model_profile_ref": "model-v1",
                "allowed_source_modes": ["research"],
                "max_concurrent_tasks": True,
            },
            ("service.risk_analysis",),
            "INVALID_OPTION_VALUE",
        ),
        (
            {"role": "policy_catalog", "policy_ref": "policy-v1"},
            ("service.risk_policy",),
            "INVALID_OPTIONS",
        ),
    ],
)
def test_service_options_reject_extra_fields_bad_refs_and_wrong_ports(
    options: dict[str, object], ports: tuple[str, ...], code: str
) -> None:
    with pytest.raises(RiskServiceError) as exc_info:
        validate_service_options(options, ports)
    assert exc_info.value.code == code
    assert str(exc_info.value) == code


def test_account_admission_ports_are_a_nonempty_subset_of_parent_role_ports() -> None:
    options = {"role": "account_admission", "account_policy_ref": "risk-policy-v4"}
    result = validate_service_options(options, ("service.group_reservations",))
    assert result["account_policy_ref"] == "risk-policy-v4"

    for ports in ((), ("service.risk_analysis",), ("service.risk_query", "service.risk_query")):
        with pytest.raises(RiskServiceError):
            validate_service_options(options, ports)


def test_snapshot_reads_real_gate_and_returns_json_safe_owner_ledger_projection(
    tmp_path: Path,
) -> None:
    service, gate, account_scope, wire_scope = _service(tmp_path)
    _reserve(gate, account_scope, intent_id="snapshot-active")

    result = service.handle(
        "risk.snapshot",
        principal_ref="authenticated-client",
        scope=wire_scope,
        arguments={},
    )

    assert result["source"] == "local_risk_reservation_ledger"
    assert result["increase_count"] == 1
    assert result["increase_notional"] == "12.5"
    assert result["active_freeze_reasons"] == ()
    assert type(result["policy_fingerprint"]) is str
    assert len(result["policy_fingerprint"]) == 64
    assert isinstance(result, MappingProxyType)
    assert service.order_admission is gate
    with pytest.raises(TypeError):
        result["increase_count"] = 99  # type: ignore[index]


def test_snapshot_preserves_gate_expiration_housekeeping_semantics(tmp_path: Path) -> None:
    clock = MutableClock()
    service, gate, account_scope, wire_scope = _service(tmp_path, clock=clock, ttl=5)
    _reserve(gate, account_scope, intent_id="snapshot-expiring")

    before = service.handle(
        "risk.snapshot",
        principal_ref="authenticated-client",
        scope=wire_scope,
        arguments={},
    )
    clock.value += 6
    after = service.handle(
        "risk.snapshot",
        principal_ref="authenticated-client",
        scope=wire_scope,
        arguments={},
    )

    assert before["increase_count"] == 1
    assert after["increase_count"] == 0
    assert after["increase_notional"] == "0"


def test_strategy_scope_template_allows_only_runtime_filled_run_id(tmp_path: Path) -> None:
    template = _wire_scope(strategy_ref="strategy-a")
    service, gate, account_scope, _ = _service(tmp_path, scope=template)
    _reserve(gate, account_scope, intent_id="strategy-snapshot")
    requested = _wire_scope(strategy_ref="strategy-a", run_id="run-17")

    result = service.handle(
        "risk.snapshot",
        principal_ref="authenticated-strategy",
        scope=requested,
        arguments={},
    )
    assert result["increase_count"] == 1

    for changed in (
        _wire_scope(strategy_ref="strategy-b", run_id="run-17"),
        _wire_scope(strategy_ref="strategy-a", run_id=None),
        _wire_scope(strategy_ref="strategy-a", run_id="run-17", account_ref="account-b"),
        _wire_scope(
            execution_domain_ref="live:sim-a",
            account_ref="account-a",
            strategy_ref="strategy-a",
            run_id="run-17",
        ),
    ):
        with pytest.raises(RiskServiceError) as exc_info:
            service.handle(
                "risk.snapshot",
                principal_ref="authenticated-strategy",
                scope=changed,
                arguments={},
            )
        assert exc_info.value.code == "SCOPE_DENIED"


def test_scope_and_arguments_cannot_select_or_widen_an_account(tmp_path: Path) -> None:
    service, _, _, trusted_scope = _service(tmp_path)
    with pytest.raises(RiskServiceError) as wrong_account:
        service.handle(
            "risk.snapshot",
            principal_ref="authenticated-client",
            scope=_wire_scope(account_ref="account-b"),
            arguments={},
        )
    assert wrong_account.value.code == "SCOPE_DENIED"

    with pytest.raises(RiskServiceError) as account_argument:
        service.handle(
            "risk.snapshot",
            principal_ref="authenticated-client",
            scope=trusted_scope,
            arguments={"account_id": "acct-other", "provider": "other"},
        )
    assert account_argument.value.code == "INVALID_ARGUMENTS"

    with pytest.raises(RiskServiceError) as mapping_scope:
        service.handle(
            "risk.snapshot",
            principal_ref="authenticated-client",
            scope={"execution_domain_ref": "paper:sim-a", "account_ref": "account-a"},  # type: ignore[arg-type]
            arguments={},
        )
    assert mapping_scope.value.code == "INVALID_SCOPE"


def test_group_parent_cannot_be_mapped_to_one_account_ledger(tmp_path: Path) -> None:
    group = _wire_scope(
        account_ref=None,
        account_refs=("account-a", "account-b"),
        portfolio_ref="portfolio-a",
        group_id="group-a",
    )
    gate = DurableRiskGate(tmp_path / "group.db", _policy())
    account_scope = AccountScope("simnow", "acct-01", "paper")

    with pytest.raises(RiskServiceError) as exc_info:
        RiskReadService(gate, {group: account_scope})
    assert exc_info.value.code == "SINGLE_ACCOUNT_SCOPE_REQUIRED"


def test_group_child_scope_is_bound_to_its_exact_single_account(tmp_path: Path) -> None:
    child = _wire_scope(
        portfolio_ref="portfolio-a",
        group_id="group-a",
        leg_id="leg-a",
    )
    service, gate, account_scope, _ = _service(tmp_path, scope=child)
    _reserve(gate, account_scope, intent_id="group-child-snapshot")

    result = service.handle(
        "risk.snapshot",
        principal_ref="authenticated-client",
        scope=child,
        arguments={},
    )
    assert result["increase_count"] == 1

    widened_group = _wire_scope(
        account_ref=None,
        account_refs=("account-a", "account-b"),
        portfolio_ref="portfolio-a",
        group_id="group-a",
    )
    with pytest.raises(RiskServiceError) as exc_info:
        service.handle(
            "risk.snapshot",
            principal_ref="authenticated-client",
            scope=widened_group,
            arguments={},
        )
    assert exc_info.value.code == "SCOPE_DENIED"


@pytest.mark.parametrize("operation", ["risk.head", "risk.read_after", "risk.ack", "risk.replay"])
def test_only_snapshot_is_implemented(operation: str, tmp_path: Path) -> None:
    service, _, _, wire_scope = _service(tmp_path)

    with pytest.raises(RiskServiceError) as exc_info:
        service.handle(
            operation,
            principal_ref="authenticated-client",
            scope=wire_scope,
            arguments={},
        )
    assert exc_info.value.code == "UNSUPPORTED_OPERATION"


def test_constructor_rejects_unbound_run_template_and_invalid_principal(tmp_path: Path) -> None:
    gate = DurableRiskGate(tmp_path / "bad-template.db", _policy())
    target = AccountScope("simnow", "acct-01", "paper")
    run_bound_template = _wire_scope(strategy_ref="strategy-a", run_id="run-1")

    with pytest.raises(RiskServiceError) as template_error:
        RiskReadService(gate, {run_bound_template: target})
    assert template_error.value.code == "RUN_BOUND_SCOPE_TEMPLATE"

    service, _, _, scope = _service(tmp_path / "other")
    with pytest.raises(RiskServiceError) as principal_error:
        service.handle("risk.snapshot", principal_ref="", scope=scope, arguments={})
    assert principal_error.value.code == "INVALID_PRINCIPAL"
