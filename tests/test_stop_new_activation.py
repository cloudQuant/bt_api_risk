from __future__ import annotations

import multiprocessing
from decimal import Decimal
from pathlib import Path

import pytest

from bt_api_risk import (
    AccountScope,
    DurableRiskGate,
    RiskPolicy,
    StopNewActivationResult,
    StopNewActivationStatus,
    StopNewResolutionStatus,
)


def _policy() -> RiskPolicy:
    return RiskPolicy("freeze-activation-test", Decimal("1000"), 10)


def _delayed_duplicate_activation(database: str, output) -> None:
    gate = DurableRiskGate(database, _policy())
    scope = AccountScope("synthetic", "freeze-once", "test")
    result = gate.activate_stop_new_once(scope, "monitor-test-cause", "late duplicate")
    output.put((result.status.value, result.has_other_active_freezes))


def test_activate_stop_new_once_keeps_first_reason_and_never_reactivates_resolved_cause(
    tmp_path: Path,
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.sqlite", _policy())
    scope = AccountScope("synthetic", "freeze-once", "test")

    created = gate.activate_stop_new_once(scope, "cause-a", "first reason")
    duplicate = gate.activate_stop_new_once(scope, "cause-a", "stale replacement reason")
    assert created == StopNewActivationResult(StopNewActivationStatus.CREATED, False)
    assert duplicate == StopNewActivationResult(StopNewActivationStatus.ALREADY_ACTIVE, False)
    assert gate.active_entry_block_reasons(scope) == ["first reason"]

    gate.stop_new(scope, "cause-b", "independent cause")
    resolved = gate.resolve_stop_new_exact(scope, "cause-a")
    assert resolved.status is StopNewResolutionStatus.CLEARED
    assert resolved.has_other_active_freezes is True

    delayed = gate.activate_stop_new_once(scope, "cause-a", "late duplicate")
    assert delayed == StopNewActivationResult(StopNewActivationStatus.ALREADY_RESOLVED, True)
    assert gate.active_entry_block_reasons(scope) == ["independent cause"]


def test_activation_status_is_account_scoped_and_absent_resolution_is_distinct(
    tmp_path: Path,
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.sqlite", _policy())
    first = AccountScope("synthetic", "account-a", "test")
    second = AccountScope("synthetic", "account-b", "test")

    result = gate.activate_stop_new_once(first, "same-cause", "first account")
    assert result.status is StopNewActivationStatus.CREATED
    absent = gate.resolve_stop_new_exact(second, "same-cause")
    assert absent.status is StopNewResolutionStatus.NOT_FOUND
    assert absent.has_other_active_freezes is False
    assert gate.active_entry_block_reasons(first) == ["first account"]
    assert gate.active_entry_block_reasons(second) == []


def test_activation_reports_other_active_causes_without_counting_target(
    tmp_path: Path,
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.sqlite", _policy())
    scope = AccountScope("synthetic", "other-causes", "test")
    gate.stop_new(scope, "cause-existing", "existing")

    created = gate.activate_stop_new_once(scope, "cause-new", "new")
    duplicate = gate.activate_stop_new_once(scope, "cause-new", "changed")
    assert created == StopNewActivationResult(StopNewActivationStatus.CREATED, True)
    assert duplicate == StopNewActivationResult(StopNewActivationStatus.ALREADY_ACTIVE, True)
    assert gate.active_entry_block_reasons(scope) == ["existing", "new"]


def test_reserved_dispatch_cause_cannot_use_apply_once_api(tmp_path: Path) -> None:
    gate = DurableRiskGate(tmp_path / "risk.sqlite", _policy())
    scope = AccountScope("synthetic", "dispatch-cause", "test")

    with pytest.raises(ValueError, match="dispatch-inflight"):
        gate.activate_stop_new_once(scope, "dispatch-inflight:intent-1", "reserved")


def test_stop_new_retains_explicit_upsert_behavior(tmp_path: Path) -> None:
    gate = DurableRiskGate(tmp_path / "risk.sqlite", _policy())
    scope = AccountScope("synthetic", "legacy-upsert", "test")
    gate.stop_new(scope, "legacy-cause", "first")
    gate.resolve_stop_new_exact(scope, "legacy-cause")

    gate.stop_new(scope, "legacy-cause", "explicit replacement")
    assert gate.active_entry_block_reasons(scope) == ["explicit replacement"]


def test_cross_process_delayed_activation_after_resume_stays_resolved(tmp_path: Path) -> None:
    database = tmp_path / "risk.sqlite"
    scope = AccountScope("synthetic", "freeze-once", "test")
    gate = DurableRiskGate(database, _policy())
    created = gate.activate_stop_new_once(scope, "monitor-test-cause", "original")
    assert created.status is StopNewActivationStatus.CREATED
    assert gate.resolve_stop_new_exact(scope, "monitor-test-cause").status is (
        StopNewResolutionStatus.CLEARED
    )

    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    process = context.Process(
        target=_delayed_duplicate_activation,
        args=(str(database), output),
    )
    process.start()
    result = output.get(timeout=20)
    process.join(timeout=20)

    assert process.exitcode == 0
    assert result == (StopNewActivationStatus.ALREADY_RESOLVED.value, False)
    assert gate.active_entry_block_reasons(scope) == []
