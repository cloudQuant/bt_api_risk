from __future__ import annotations

import multiprocessing
from decimal import Decimal
from pathlib import Path

import pytest

from bt_api_risk import (
    AccountScope,
    DurableRiskGate,
    FreezeActivationResult,
    FreezeActivationStatus,
    FreezeResolutionStatus,
    RiskPolicy,
)


def _policy() -> RiskPolicy:
    return RiskPolicy("freeze-activation-test", Decimal("1000"), 10)


def _delayed_duplicate_activation(database: str, output) -> None:
    gate = DurableRiskGate(database, _policy())
    scope = AccountScope("synthetic", "freeze-once", "test")
    result = gate.activate_freeze_once(scope, "monitor-test-cause", "late duplicate")
    output.put((result.status.value, result.has_other_active_freezes))


def test_activate_freeze_once_keeps_first_reason_and_never_reactivates_resolved_cause(
    tmp_path: Path,
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.sqlite", _policy())
    scope = AccountScope("synthetic", "freeze-once", "test")

    created = gate.activate_freeze_once(scope, "cause-a", "first reason")
    duplicate = gate.activate_freeze_once(scope, "cause-a", "stale replacement reason")
    assert created == FreezeActivationResult(FreezeActivationStatus.CREATED, False)
    assert duplicate == FreezeActivationResult(FreezeActivationStatus.ALREADY_ACTIVE, False)
    assert gate.active_freeze_reasons(scope) == ["first reason"]

    gate.freeze(scope, "cause-b", "independent cause")
    resolved = gate.resolve_freeze_exact(scope, "cause-a")
    assert resolved.status is FreezeResolutionStatus.CLEARED
    assert resolved.has_other_active_freezes is True

    delayed = gate.activate_freeze_once(scope, "cause-a", "late duplicate")
    assert delayed == FreezeActivationResult(FreezeActivationStatus.ALREADY_RESOLVED, True)
    assert gate.active_freeze_reasons(scope) == ["independent cause"]


def test_activation_status_is_account_scoped_and_absent_resolution_is_distinct(
    tmp_path: Path,
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.sqlite", _policy())
    first = AccountScope("synthetic", "account-a", "test")
    second = AccountScope("synthetic", "account-b", "test")

    result = gate.activate_freeze_once(first, "same-cause", "first account")
    assert result.status is FreezeActivationStatus.CREATED
    absent = gate.resolve_freeze_exact(second, "same-cause")
    assert absent.status is FreezeResolutionStatus.NOT_FOUND
    assert absent.has_other_active_freezes is False
    assert gate.active_freeze_reasons(first) == ["first account"]
    assert gate.active_freeze_reasons(second) == []


def test_activation_reports_other_active_causes_without_counting_target(
    tmp_path: Path,
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.sqlite", _policy())
    scope = AccountScope("synthetic", "other-causes", "test")
    gate.freeze(scope, "cause-existing", "existing")

    created = gate.activate_freeze_once(scope, "cause-new", "new")
    duplicate = gate.activate_freeze_once(scope, "cause-new", "changed")
    assert created == FreezeActivationResult(FreezeActivationStatus.CREATED, True)
    assert duplicate == FreezeActivationResult(FreezeActivationStatus.ALREADY_ACTIVE, True)
    assert gate.active_freeze_reasons(scope) == ["existing", "new"]


def test_reserved_dispatch_cause_cannot_use_apply_once_api(tmp_path: Path) -> None:
    gate = DurableRiskGate(tmp_path / "risk.sqlite", _policy())
    scope = AccountScope("synthetic", "dispatch-cause", "test")

    with pytest.raises(ValueError, match="dispatch-inflight"):
        gate.activate_freeze_once(scope, "dispatch-inflight:intent-1", "reserved")


def test_legacy_freeze_retains_explicit_upsert_behavior(tmp_path: Path) -> None:
    gate = DurableRiskGate(tmp_path / "risk.sqlite", _policy())
    scope = AccountScope("synthetic", "legacy-upsert", "test")
    gate.freeze(scope, "legacy-cause", "first")
    gate.resolve_freeze_exact(scope, "legacy-cause")

    gate.freeze(scope, "legacy-cause", "explicit replacement")
    assert gate.active_freeze_reasons(scope) == ["explicit replacement"]


def test_cross_process_delayed_activation_after_resume_stays_resolved(tmp_path: Path) -> None:
    database = tmp_path / "risk.sqlite"
    scope = AccountScope("synthetic", "freeze-once", "test")
    gate = DurableRiskGate(database, _policy())
    created = gate.activate_freeze_once(scope, "monitor-test-cause", "original")
    assert created.status is FreezeActivationStatus.CREATED
    assert gate.resolve_freeze_exact(scope, "monitor-test-cause").status is (
        FreezeResolutionStatus.CLEARED
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
    assert result == (FreezeActivationStatus.ALREADY_RESOLVED.value, False)
    assert gate.active_freeze_reasons(scope) == []
