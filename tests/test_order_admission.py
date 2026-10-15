"""Risk-side adapter coverage against the public neutral order contract."""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import json
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from pathlib import Path

import pytest

from bt_api_risk import (
    INSTRUMENT_METADATA_DIGEST_TAG,
    AccountScope,
    DurableRiskAdmissionAdapter,
    DurableRiskGate,
    ExposureAccountingMode,
    InstrumentRiskAdmissionMapper,
    InstrumentRiskMetadata,
    InstrumentRiskRegistry,
    RiskAdmissionDeniedError,
    RiskAdmissionPolicyBinding,
    RiskPolicy,
)


def _execution_contracts():
    """Load the sibling public order contract when this monorepo is present."""

    try:
        return importlib.import_module("bt_api_execution")
    except ModuleNotFoundError as error:
        if error.name != "bt_api_execution":
            raise

    execution_source = Path(__file__).resolve().parents[1].parent / "bt_api_execution" / "src"
    if not execution_source.is_dir():
        pytest.skip("the optional sibling execution contract is not installed")
    sys.path.insert(0, str(execution_source))
    return importlib.import_module("bt_api_execution")


def _metadata() -> InstrumentRiskMetadata:
    return InstrumentRiskMetadata(
        instrument="fixture/contract",
        metadata_version="instrument-v1",
        as_of_ns=1_000,
        expires_at_ns=2_000,
        tick_size=Decimal("0.1"),
        quantity_step=Decimal("0.25"),
        contract_multiplier=Decimal("1"),
        max_gross_notional=Decimal("500"),
        taker_fee_bps=Decimal("0"),
        fixed_fee=Decimal("0"),
        max_slippage_bps=Decimal("0"),
        quantity_unit="contract",
        valuation_unit="USD",
    )


def _order(
    execution,
    metadata,
    *,
    account: str = "account-1",
    intent_id: str = "intent-1",
    quantity: str = "2",
    include_digest: bool = True,
):
    scope = execution.ExecutionScope(
        provider="fake",
        environment="sandbox",
        account_ref=account,
        strategy_id="strategy-1",
    )
    tags = {INSTRUMENT_METADATA_DIGEST_TAG: metadata.digest} if include_digest else {}
    return execution.OrderIntent.limit(
        intent_id=intent_id,
        scope=scope,
        signal_id="signal-1",
        instrument=metadata.instrument,
        side=execution.Side.BUY,
        quantity=Decimal(quantity),
        price=Decimal("10"),
        position_effect=execution.PositionEffect.OPEN,
        metadata_version=metadata.metadata_version,
        tags=tags,
    )


def _mapper(account_scope, metadata, gate=None, *, wire_account_ref=None):
    allocation_reader = None
    if gate is not None:
        allocation_reader = lambda order_scope: gate.get_strategy_allocation(  # noqa: E731
            account_scope, order_scope.strategy_id
        )
    return InstrumentRiskAdmissionMapper(
        account_scope,
        InstrumentRiskRegistry((metadata,)),
        clock_ns=lambda: 1_500,
        allocation_reader=allocation_reader,
        wire_account_ref=wire_account_ref,
    )


@pytest.mark.parametrize(
    "mode",
    [ExposureAccountingMode.RESERVATIONS_ONLY, ExposureAccountingMode.LIVE_GROSS],
)
def test_adapter_policy_binding_projects_actual_policy_immutably(tmp_path, mode):
    live_gross = mode is ExposureAccountingMode.LIVE_GROSS
    policy = RiskPolicy(
        "policy-binding-test",
        Decimal("100"),
        10,
        require_strategy_allocation=live_gross,
        notional_unit="USD" if live_gross else None,
        exposure_accounting_mode=mode,
        max_gross_occupancy_notional=Decimal("500") if live_gross else None,
        max_gross_occupancy_intent_count=10 if live_gross else None,
        max_exposure_facts_age_seconds=60.0 if live_gross else None,
    )
    gate = DurableRiskGate(
        tmp_path / f"{mode.value}.sqlite",
        policy,
        clock=lambda: 1_700_000_000.0,
    )
    adapter = DurableRiskAdmissionAdapter(gate, lambda _order: None)

    binding = adapter.policy_binding

    assert type(binding) is RiskAdmissionPolicyBinding
    assert binding.policy_id == policy.policy_id
    assert binding.policy_fingerprint == policy.fingerprint
    assert binding.exposure_accounting_mode is mode
    assert adapter.policy_binding == binding
    with pytest.raises(FrozenInstanceError):
        binding.exposure_accounting_mode = ExposureAccountingMode.RESERVATIONS_ONLY
    gate.close()


def test_policy_binding_rejects_untyped_mode_and_invalid_fingerprint():
    with pytest.raises(ValueError, match="ExposureAccountingMode"):
        RiskAdmissionPolicyBinding("policy", "a" * 64, "LIVE_GROSS")
    with pytest.raises(ValueError, match="SHA-256"):
        RiskAdmissionPolicyBinding(
            "policy", "A" * 64, ExposureAccountingMode.RESERVATIONS_ONLY
        )


def test_adapter_policy_binding_preserves_policy_ids_accepted_by_gate(tmp_path):
    policy = RiskPolicy(" policy-binding-test ", Decimal("100"), 10)
    gate = DurableRiskGate(
        tmp_path / "whitespace-policy.sqlite",
        policy,
        clock=lambda: 1_700_000_000.0,
    )
    adapter = DurableRiskAdmissionAdapter(gate, lambda _order: None)

    binding = adapter.policy_binding

    assert binding.policy_id == " policy-binding-test "
    assert binding.policy_fingerprint == policy.fingerprint
    assert binding.exposure_accounting_mode is ExposureAccountingMode.RESERVATIONS_ONLY
    gate.close()


def test_actual_order_contract_maps_to_durable_permit_and_recovers_settlement(tmp_path):
    execution = _execution_contracts()
    metadata = _metadata()
    account_scope = AccountScope("fake", "account-1", "sandbox")
    policy = RiskPolicy(
        "adapter-policy",
        Decimal("100"),
        3,
        permit_ttl_seconds=30.0,
        require_strategy_allocation=True,
        notional_unit="USD",
    )
    database = tmp_path / "risk.sqlite3"
    gate = DurableRiskGate(database, policy, clock=lambda: 1_700_000_000.0)
    gate.set_strategy_allocation(
        account_scope,
        "strategy-1",
        "allocation-v1",
        max_notional=Decimal("25"),
        max_position=Decimal("3"),
        position_instrument=metadata.instrument,
        position_unit=metadata.quantity_unit,
        notional_unit=metadata.valuation_unit,
    )
    adapter = DurableRiskAdmissionAdapter(gate, _mapper(account_scope, metadata, gate))
    order = _order(execution, metadata)

    permit = adapter.reserve(order)
    duplicate = adapter.reserve(order)
    assert duplicate.permit_id == permit.permit_id
    assert permit.scope == account_scope
    assert permit.strategy_id == "strategy-1"
    assert permit.allocation_version == "allocation-v1"
    assert permit.notional == Decimal("20")
    assert adapter.validate(permit.permit_id, order) == permit
    assert adapter.claim_for_dispatch(permit.permit_id, order) == permit

    with pytest.raises(RiskAdmissionDeniedError) as duplicate_claim:
        adapter.claim_for_dispatch(permit.permit_id, order)
    assert duplicate_claim.value.code == "DISPATCH_CLAIM_ALREADY_ISSUED"

    settled = adapter.settle(permit.permit_id)
    gate.close()

    recovered_gate = DurableRiskGate(database, policy, clock=lambda: 1_700_000_000.0)
    recovered_adapter = DurableRiskAdmissionAdapter(
        recovered_gate,
        _mapper(account_scope, metadata, recovered_gate),
    )
    assert recovered_adapter.ensure_settled(permit.permit_id) == settled

    snapshot = recovered_gate.snapshot(account_scope)
    assert snapshot["increase_count"] == 1
    assert snapshot["increase_notional"] == Decimal("20")
    assert snapshot["active_freeze_reasons"] == ["dispatch-inflight:intent-1"]

    blocked_order = _order(execution, metadata, intent_id="intent-blocked", quantity="0.25")
    with pytest.raises(RiskAdmissionDeniedError) as frozen:
        recovered_adapter.reserve(blocked_order)
    assert isinstance(frozen.value, PermissionError)
    assert frozen.value.code == "FROZEN"

    release_scope = AccountScope("fake", "account-2", "sandbox")
    release_policy = RiskPolicy(
        "release-policy", Decimal("100"), 3, notional_unit=metadata.valuation_unit
    )
    release_gate = DurableRiskGate(tmp_path / "release.sqlite3", release_policy)
    release_adapter = DurableRiskAdmissionAdapter(
        release_gate,
        _mapper(release_scope, metadata),
    )
    unreached = _order(
        execution,
        metadata,
        account="account-2",
        intent_id="intent-released",
        quantity="0.25",
    )
    released = release_adapter.reserve(unreached)
    release_adapter.release(released.permit_id, "owner_rejected_before_dispatch")
    with pytest.raises(RiskAdmissionDeniedError) as inactive:
        release_adapter.validate(released.permit_id, unreached)
    assert inactive.value.code == "PERMIT_NOT_ACTIVE"

    # A separate pre-dispatch release cannot clear the claimed order's latch.
    assert recovered_gate.snapshot(account_scope)["active_freeze_reasons"] == [
        "dispatch-inflight:intent-1"
    ]
    release_gate.close()
    recovered_gate.close()


def test_scope_and_required_instrument_facts_fail_before_reservation(tmp_path):
    execution = _execution_contracts()
    metadata = _metadata()
    account_scope = AccountScope("fake", "account-1", "sandbox")
    policy = RiskPolicy("adapter-policy", Decimal("100"), 3)
    gate = DurableRiskGate(tmp_path / "risk.sqlite3", policy)
    adapter = DurableRiskAdmissionAdapter(gate, _mapper(account_scope, metadata))

    wrong_account = _order(execution, metadata, account="account-2")
    with pytest.raises(RiskAdmissionDeniedError) as scope_error:
        adapter.reserve(wrong_account)
    assert scope_error.value.code == "ACCOUNT_SCOPE_MISMATCH"

    missing_digest = _order(execution, metadata, include_digest=False)
    with pytest.raises(RiskAdmissionDeniedError) as metadata_error:
        adapter.reserve(missing_digest)
    assert metadata_error.value.code == "INSTRUMENT_METADATA_DIGEST_REQUIRED"

    snapshot = gate.snapshot(account_scope)
    assert snapshot["increase_count"] == 0
    assert snapshot["increase_notional"] == Decimal("0")
    gate.close()


def test_ordinary_order_adapter_accepts_only_the_mapper_configured_wire_alias(tmp_path):
    execution = _execution_contracts()
    metadata = _metadata()
    risk_scope = AccountScope("fake", "risk-account-1", "sandbox")
    gate = DurableRiskGate(
        tmp_path / "ordinary-wire-alias.sqlite3",
        RiskPolicy("ordinary-wire-alias", Decimal("100"), 3, notional_unit="USD"),
        clock=lambda: 1_700_000_000.0,
    )
    mapper = _mapper(
        risk_scope,
        metadata,
        wire_account_ref="venue-account-ref",
    )
    adapter = DurableRiskAdmissionAdapter(gate, mapper)
    order = _order(execution, metadata, account="venue-account-ref")
    original_scope = order.scope
    original_fingerprint = order.fingerprint

    permit = adapter.reserve(order)

    assert permit.scope == risk_scope
    assert order.scope is original_scope
    assert order.scope.account_ref == "venue-account-ref"
    assert order.fingerprint == original_fingerprint
    with pytest.raises(RiskAdmissionDeniedError) as wrong_alias:
        adapter.reserve(_order(execution, metadata, account="another-account-ref"))
    assert wrong_alias.value.code == "ACCOUNT_SCOPE_MISMATCH"
    assert gate.snapshot(risk_scope)["increase_count"] == 1
    gate.close()


def test_open_mapper_binds_trusted_unit_without_strategy_allocation_reader(tmp_path):
    execution = _execution_contracts()
    metadata = _metadata()
    account_scope = AccountScope("fake", "account-1", "sandbox")
    gate = DurableRiskGate(
        tmp_path / "risk.sqlite3",
        RiskPolicy("account-unit-policy", Decimal("100"), 3, notional_unit="USD"),
        clock=lambda: 1_700_000_000.0,
    )
    mapper = _mapper(account_scope, metadata)
    order = _order(execution, metadata)
    mapped = mapper(order)

    assert mapped.notional_unit == "USD"
    assert mapped.strategy_id is None
    permit = DurableRiskAdmissionAdapter(gate, mapper).reserve(order)
    assert permit.notional_unit == "USD"
    assert gate.snapshot(account_scope)["increase_notional"] == Decimal("20")
    gate.close()


def test_missing_valuation_unit_remains_denied_by_a_fixed_unit_policy(tmp_path):
    execution = _execution_contracts()
    metadata = replace(_metadata(), valuation_unit=None)
    account_scope = AccountScope("fake", "account-1", "sandbox")
    gate = DurableRiskGate(
        tmp_path / "risk.sqlite3",
        RiskPolicy("account-unit-policy", Decimal("100"), 3, notional_unit="USD"),
        clock=lambda: 1_700_000_000.0,
    )
    mapper = _mapper(account_scope, metadata)
    order = _order(execution, metadata)
    mapped = mapper(order)
    adapter = DurableRiskAdmissionAdapter(gate, mapper)

    assert mapped.notional_unit is None
    with pytest.raises(RiskAdmissionDeniedError) as denial:
        adapter.reserve(order)
    assert denial.value.code == "NOTIONAL_UNIT_MISMATCH"
    assert gate.snapshot(account_scope)["increase_count"] == 0
    gate.close()


def test_managed_facade_rejects_known_risk_denial_but_blocks_unexpected_error(
    tmp_path, monkeypatch
):
    execution = _execution_contracts()
    metadata = _metadata()
    account_scope = AccountScope("fake", "account-1", "sandbox")
    execution_scope = execution.ExecutionScope("fake", "sandbox", "account-1", "strategy-1")
    gate = DurableRiskGate(
        tmp_path / "risk.sqlite3",
        RiskPolicy("facade-admission-policy", Decimal("10"), 3, notional_unit="USD"),
        clock=lambda: 1_700_000_000.0,
    )
    adapter = DurableRiskAdmissionAdapter(gate, _mapper(account_scope, metadata))
    store = execution.SqliteExecutionStore(tmp_path / "execution.sqlite3")
    facade = execution.ManagedExecutionFacade(
        store,
        execution_scope,
        writer_id="risk-admission-test",
        admission_gate=adapter,
    )
    dispatched: list[str] = []

    def dispatch(order):
        dispatched.append(order.intent_id)
        return execution.ProviderObservation.accepted(order.intent_id, "provider-order-1")

    denied_order = _order(execution, metadata, quantity="2")
    try:
        with pytest.raises(RiskAdmissionDeniedError) as denial:
            adapter.reserve(denied_order)
        assert denial.value.code == "ACCOUNT_LIMIT_EXHAUSTED"

        rejected = facade.submit(denied_order, dispatch)
        assert rejected.state is execution.ExecutionState.REJECTED
        assert rejected.unknown_reason == "admission_denied"
        assert rejected.dispatch_attempts == 0
        assert dispatched == []

        failure = RuntimeError("synthetic risk storage failure")

        def unexpected_reserve(_gate, _intent):
            raise failure

        monkeypatch.setattr(DurableRiskGate, "reserve", unexpected_reserve)
        unexpected_order = _order(execution, metadata, intent_id="intent-storage-error")
        with pytest.raises(RuntimeError) as propagated:
            adapter.reserve(unexpected_order)
        assert propagated.value is failure

        blocked = facade.submit(unexpected_order, dispatch)
        assert blocked.state is execution.ExecutionState.BLOCKED
        assert blocked.unknown_reason == "admission_gate_error"
        assert blocked.dispatch_attempts == 0
        assert dispatched == []
    finally:
        facade.close()
        store.close()
        gate.close()


def test_root_export_is_lazy_and_adapter_imports_no_execution_or_gateway(tmp_path):
    risk_spec = importlib.util.find_spec("bt_api_risk")
    assert risk_spec is not None and risk_spec.origin is not None
    base_spec = importlib.util.find_spec("bt_api_base")
    assert base_spec is not None and base_spec.origin is not None
    paths = [
        str(Path(risk_spec.origin).resolve().parent.parent),
        str(Path(base_spec.origin).resolve().parent.parent),
    ]
    script = r"""
import importlib
import importlib.abc
import sys

sys.path[:0] = __import__('json').loads(sys.argv[1])
blocked = {'bt_api_execution', 'bt_api_gateway', 'bt_api_py', 'numpy', 'scipy', 'sklearn', 'pandas'}

class NoOptionalDomainImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in blocked:
            raise AssertionError('unexpected adapter import: ' + fullname)

sys.meta_path.insert(0, NoOptionalDomainImports())
import bt_api_risk
assert 'DurableRiskAdmissionAdapter' not in vars(bt_api_risk)
assert 'RiskAdmissionPolicyBinding' not in vars(bt_api_risk)
adapter = bt_api_risk.DurableRiskAdmissionAdapter
assert adapter.__module__ == 'bt_api_risk.order_admission'
binding = bt_api_risk.RiskAdmissionPolicyBinding
assert binding.__module__ == 'bt_api_risk.order_admission'
assert 'bt_api_execution' not in sys.modules
assert 'bt_api_gateway' not in sys.modules
assert not (blocked & {name.split('.')[0] for name in sys.modules})
"""
    result = subprocess.run(  # noqa: S603 -- fixed interpreter and synthetic import arguments.
        [sys.executable, "-I", "-c", script, json.dumps(paths)],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
