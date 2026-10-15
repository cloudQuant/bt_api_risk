"""RISK01 account and strategy budget contention across real processes.

The test intentionally uses a bounded set of submitter processes instead of
one process per strategy.  Twenty independent processes represent two
contenders for each of ten strategies in every one of ten account scopes.
The same twenty workers synchronize before each account's calls so SQLite
transactions contend across process boundaries.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

import bt_api_base

import bt_api_risk
from bt_api_risk.core import admission as admission_module
from bt_api_risk.core.admission import (
    AccountScope,
    DurableRiskGate,
    IntentAction,
    RiskIntent,
    RiskPolicy,
)

_ACCOUNT_COUNT = 10
_STRATEGY_COUNT = 10
_CONTENDERS_PER_STRATEGY = 2
_WORKER_COUNT = _STRATEGY_COUNT * _CONTENDERS_PER_STRATEGY
_ORDER_NOTIONAL = Decimal("20")
_FIXED_CLOCK = 1_700_000_000.0

_WORKER_SCRIPT = r"""
import hashlib
import json
import sys
import time
from decimal import Decimal
from pathlib import Path

config = json.loads(sys.argv[1])
sys.path[:0] = [config["risk_source"], config["base_source"]]

import bt_api_base
import bt_api_risk
from bt_api_risk.core import admission as admission_module
from bt_api_risk.core.admission import (
    AccountScope,
    DurableRiskGate,
    IntentAction,
    RiskDeniedError,
    RiskIntent,
    RiskPolicy,
)

expected_origins = {
    "risk_package": str(Path(config["risk_package_origin"]).resolve()),
    "risk_admission": str(Path(config["risk_admission_origin"]).resolve()),
    "base_package": str(Path(config["base_package_origin"]).resolve()),
}
actual_origins = {
    "risk_package": str(Path(bt_api_risk.__file__).resolve()),
    "risk_admission": str(Path(admission_module.__file__).resolve()),
    "base_package": str(Path(bt_api_base.__file__).resolve()),
}
if actual_origins != expected_origins:
    raise RuntimeError("source_origin_mismatch")

phase = config["phase"]
worker_id = config["worker_id"]
strategy_index = worker_id // 2
contender_index = worker_id % 2
database_path = Path(config["database_path"])
barrier_root = Path(config["barrier_root"])
policy = RiskPolicy(
    policy_id="risk01-" + phase,
    max_increase_notional=Decimal(config["account_limit"]),
    max_increase_count=100,
    permit_ttl_seconds=300.0,
    require_strategy_allocation=True,
    notional_unit="USD",
)
gate = DurableRiskGate(database_path, policy, clock=lambda: 1700000000.0)

def wait_for(path, timeout=45.0):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("barrier_timeout")
        time.sleep(0.01)

Path(config["init_ready_path"]).write_text("ready", encoding="ascii")
wait_for(Path(config["start_path"]))
outcomes = []
try:
    for account_index in range(10):
        ready = barrier_root / (
            phase + "-account-" + str(account_index) + "-worker-" + str(worker_id) + ".ready"
        )
        ready.write_text("ready", encoding="ascii")
        for contender in range(20):
            wait_for(
                barrier_root
                / (
                    phase
                    + "-account-"
                    + str(account_index)
                    + "-worker-"
                    + str(contender)
                    + ".ready"
                )
            )

        account_id = "account-" + str(account_index)
        strategy_id = "strategy-" + str(strategy_index)
        intent_id = (
            phase
            + ":"
            + account_id
            + ":"
            + strategy_id
            + ":contender-"
            + str(contender_index)
        )
        instrument = "fixture/contract-" + str((strategy_index + contender_index) % 5)
        intent = RiskIntent(
            intent_id=intent_id,
            scope=AccountScope("fixture", account_id, "sandbox"),
            action=IntentAction.INCREASE,
            notional=Decimal("20"),
            payload_fingerprint=hashlib.sha256(intent_id.encode("utf-8")).hexdigest(),
            strategy_id=strategy_id,
            allocation_version="allocation-v1",
            instrument=instrument,
            quantity=Decimal("1"),
            quantity_unit="contract",
            notional_unit="USD",
        )
        try:
            permit = gate.reserve(intent)
        except RiskDeniedError as error:
            outcome = {
                "status": "denied",
                "code": error.code,
            }
        else:
            outcome = {
                "status": "reserved",
                "permit_id": permit.permit_id,
                "permit_scope": permit.scope.account_id,
                "permit_strategy": permit.strategy_id,
            }
        outcomes.append(
            {
                "account_id": account_id,
                "strategy_id": strategy_id,
                "instrument": instrument,
                "intent_id": intent_id,
                **outcome,
            }
        )
finally:
    gate.close()

print(
    json.dumps(
        {
            "phase": phase,
            "worker_id": worker_id,
            "origins": actual_origins,
            "outcomes": outcomes,
        },
        sort_keys=True,
    )
)
"""


def _policy(phase: str, account_limit: str) -> RiskPolicy:
    return RiskPolicy(
        policy_id="risk01-" + phase,
        max_increase_notional=Decimal(account_limit),
        max_increase_count=100,
        permit_ttl_seconds=300.0,
        require_strategy_allocation=True,
        notional_unit="USD",
    )


def _scope(account_index: int) -> AccountScope:
    return AccountScope("fixture", "account-" + str(account_index), "sandbox")


def _intent(
    phase: str,
    account_index: int,
    strategy_index: int,
    contender_index: int,
) -> RiskIntent:
    account_id = "account-" + str(account_index)
    strategy_id = "strategy-" + str(strategy_index)
    intent_id = phase + ":" + account_id + ":" + strategy_id + ":contender-" + str(contender_index)
    return RiskIntent(
        intent_id=intent_id,
        scope=_scope(account_index),
        action=IntentAction.INCREASE,
        notional=_ORDER_NOTIONAL,
        payload_fingerprint=hashlib.sha256(intent_id.encode("utf-8")).hexdigest(),
        strategy_id=strategy_id,
        allocation_version="allocation-v1",
        instrument="fixture/contract-" + str((strategy_index + contender_index) % 5),
        quantity=Decimal("1"),
        quantity_unit="contract",
        notional_unit="USD",
    )


def _wait_for_file(path: Path, process: subprocess.Popen[str], timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError("risk worker exited before ready: " + stdout + "\n" + stderr)
        if time.monotonic() >= deadline:
            raise TimeoutError("risk worker readiness timed out")
        time.sleep(0.01)


def _prepare_database(
    database_path: Path,
    *,
    phase: str,
    account_limit: str,
    strategy_limit: str,
) -> RiskPolicy:
    policy = _policy(phase, account_limit)
    gate = DurableRiskGate(database_path, policy, clock=lambda: _FIXED_CLOCK)
    for account_index in range(_ACCOUNT_COUNT):
        scope = _scope(account_index)
        for strategy_index in range(_STRATEGY_COUNT):
            gate.set_strategy_allocation(
                scope,
                "strategy-" + str(strategy_index),
                "allocation-v1",
                max_notional=Decimal(strategy_limit),
                notional_unit="USD",
            )
    gate.close()
    return policy


def _run_contenders(
    tmp_path: Path,
    *,
    phase: str,
    database_path: Path,
    account_limit: str,
) -> list[dict[str, Any]]:
    barrier_root = tmp_path / (phase + "-barrier")
    barrier_root.mkdir()
    risk_source = Path(__file__).resolve().parents[1] / "src"
    base_source = Path(__file__).resolve().parents[2] / "bt_api_base" / "src"
    risk_package_origin = risk_source / "bt_api_risk" / "__init__.py"
    risk_admission_origin = risk_source / "bt_api_risk" / "core" / "admission.py"
    base_package_origin = base_source / "bt_api_base" / "__init__.py"
    start_path = barrier_root / "start"
    processes: list[subprocess.Popen[str]] = []
    outcomes: list[dict[str, Any]] = []

    try:
        for worker_id in range(_WORKER_COUNT):
            ready_path = barrier_root / ("init-" + str(worker_id) + ".ready")
            config = {
                "phase": phase,
                "worker_id": worker_id,
                "database_path": str(database_path),
                "account_limit": account_limit,
                "barrier_root": str(barrier_root),
                "init_ready_path": str(ready_path),
                "start_path": str(start_path),
                "risk_source": str(risk_source),
                "base_source": str(base_source),
                "risk_package_origin": str(risk_package_origin),
                "risk_admission_origin": str(risk_admission_origin),
                "base_package_origin": str(base_package_origin),
            }
            process = subprocess.Popen(  # noqa: S603 -- launches this test's fixed worker script.
                [
                    sys.executable,
                    "-I",
                    "-c",
                    _WORKER_SCRIPT,
                    json.dumps(config, separators=(",", ":")),
                ],
                cwd=tmp_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            processes.append(process)
            _wait_for_file(ready_path, process)

        start_path.write_text("start", encoding="ascii")
        for process in processes:
            stdout, stderr = process.communicate(timeout=90.0)
            assert process.returncode == 0, stdout + "\n" + stderr
            assert stderr == ""
            worker_result = json.loads(stdout)
            assert worker_result["phase"] == phase
            assert worker_result["origins"] == {
                "risk_package": str(risk_package_origin.resolve()),
                "risk_admission": str(risk_admission_origin.resolve()),
                "base_package": str(base_package_origin.resolve()),
            }
            outcomes.extend(worker_result["outcomes"])
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            if process.poll() is None:
                try:
                    process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5.0)

    return outcomes


def _assert_runtime_origins() -> None:
    risk_source = Path(__file__).resolve().parents[1] / "src"
    base_source = Path(__file__).resolve().parents[2] / "bt_api_base" / "src"
    assert Path(bt_api_risk.__file__).resolve() == risk_source / "bt_api_risk" / "__init__.py"
    assert (
        Path(admission_module.__file__).resolve()
        == risk_source / "bt_api_risk" / "core" / "admission.py"
    )
    assert Path(bt_api_base.__file__).resolve() == base_source / "bt_api_base" / "__init__.py"


def _assert_persisted_scope(
    database_path: Path,
    policy: RiskPolicy,
    phase: str,
    expected_count: int,
    expected_notional: Decimal,
    expected_strategy_reservation: Decimal,
) -> None:
    reopened = DurableRiskGate(database_path, policy, clock=lambda: _FIXED_CLOCK)
    try:
        for account_index in range(_ACCOUNT_COUNT):
            scope = _scope(account_index)
            account_snapshot = reopened.snapshot(scope)
            assert account_snapshot["increase_count"] == expected_count
            assert account_snapshot["increase_notional"] == expected_notional
            assert account_snapshot["active_freeze_reasons"] == []

            strategy_reserved = Decimal("0")
            for strategy_index in range(_STRATEGY_COUNT):
                strategy_id = "strategy-" + str(strategy_index)
                allocation = reopened.get_strategy_allocation(scope, strategy_id)
                assert allocation.scope == scope
                assert allocation.strategy_id == strategy_id
                assert allocation.source == "local_risk_reservation_ledger"
                assert allocation.completeness == "LOCAL_LEDGER_COMPLETE"
                assert allocation.reason is None
                assert allocation.reserved_notional is not None
                assert allocation.reserved_notional <= expected_strategy_reservation
                strategy_reserved += allocation.reserved_notional

            assert strategy_reserved == expected_notional

        if phase == "strategy-limit":
            for account_index in range(_ACCOUNT_COUNT):
                scope = _scope(account_index)
                for strategy_index in range(_STRATEGY_COUNT):
                    allocation = reopened.get_strategy_allocation(
                        scope, "strategy-" + str(strategy_index)
                    )
                    assert allocation.reserved_notional == Decimal("20")
                    assert allocation.allocated_notional == Decimal("25")
                    assert allocation.available_notional == Decimal("5")
    finally:
        reopened.close()


def _assert_restart_idempotency(
    database_path: Path,
    policy: RiskPolicy,
    phase: str,
    outcomes: list[dict[str, Any]],
) -> None:
    reopened = DurableRiskGate(database_path, policy, clock=lambda: _FIXED_CLOCK)
    try:
        for outcome in outcomes:
            if outcome["status"] != "reserved":
                continue
            account_index = int(outcome["account_id"].removeprefix("account-"))
            strategy_index = int(outcome["strategy_id"].removeprefix("strategy-"))
            contender_index = int(outcome["intent_id"].rsplit("contender-", 1)[1])
            existing = reopened.reserve(
                _intent(phase, account_index, strategy_index, contender_index)
            )
            assert existing.permit_id == outcome["permit_id"]
            assert existing.scope.account_id == outcome["account_id"]
            assert existing.strategy_id == outcome["strategy_id"]
    finally:
        reopened.close()


def _assert_phase_results(
    phase: str,
    outcomes: list[dict[str, Any]],
    *,
    accepted_per_account: int,
    denial_code: str,
) -> None:
    assert len(outcomes) == _ACCOUNT_COUNT * _WORKER_COUNT
    logical_strategies = {(outcome["account_id"], outcome["strategy_id"]) for outcome in outcomes}
    assert len(logical_strategies) == _ACCOUNT_COUNT * _STRATEGY_COUNT

    for account_index in range(_ACCOUNT_COUNT):
        account_id = "account-" + str(account_index)
        account_rows = [row for row in outcomes if row["account_id"] == account_id]
        accepted = [row for row in account_rows if row["status"] == "reserved"]
        denied = [row for row in account_rows if row["status"] == "denied"]
        assert len(accepted) == accepted_per_account
        assert len(denied) == _WORKER_COUNT - accepted_per_account
        assert {row["code"] for row in denied} == {denial_code}
        assert all(row["permit_scope"] == account_id for row in accepted)
        assert all(row["permit_strategy"] == row["strategy_id"] for row in accepted)

        if phase == "account-limit":
            # There are four contenders per instrument; five admitted orders
            # therefore prove the account budget aggregates across instruments.
            assert len({row["instrument"] for row in accepted}) >= 2
        else:
            assert {row["strategy_id"] for row in accepted} == {
                "strategy-" + str(index) for index in range(_STRATEGY_COUNT)
            }
            for strategy_index in range(_STRATEGY_COUNT):
                strategy_id = "strategy-" + str(strategy_index)
                strategy_rows = [row for row in account_rows if row["strategy_id"] == strategy_id]
                assert len({row["instrument"] for row in strategy_rows}) == 2
                strategy_accepted = [row for row in strategy_rows if row["status"] == "reserved"]
                assert len(strategy_accepted) == 1


def test_risk01_ten_accounts_one_hundred_strategies_contend_across_processes(
    tmp_path,
) -> None:
    _assert_runtime_origins()

    account_database = tmp_path / "account-limits.sqlite3"
    account_policy = _prepare_database(
        account_database,
        phase="account-limit",
        account_limit="100",
        strategy_limit="1000",
    )
    account_results = _run_contenders(
        tmp_path,
        phase="account-limit",
        database_path=account_database,
        account_limit="100",
    )
    _assert_phase_results(
        "account-limit",
        account_results,
        accepted_per_account=5,
        denial_code="ACCOUNT_LIMIT_EXHAUSTED",
    )
    _assert_persisted_scope(
        account_database,
        account_policy,
        "account-limit",
        expected_count=5,
        expected_notional=Decimal("100"),
        expected_strategy_reservation=Decimal("1000"),
    )
    _assert_restart_idempotency(
        account_database,
        account_policy,
        "account-limit",
        account_results,
    )
    _assert_persisted_scope(
        account_database,
        account_policy,
        "account-limit",
        expected_count=5,
        expected_notional=Decimal("100"),
        expected_strategy_reservation=Decimal("1000"),
    )

    strategy_database = tmp_path / "strategy-limits.sqlite3"
    strategy_policy = _prepare_database(
        strategy_database,
        phase="strategy-limit",
        account_limit="500",
        strategy_limit="25",
    )
    strategy_results = _run_contenders(
        tmp_path,
        phase="strategy-limit",
        database_path=strategy_database,
        account_limit="500",
    )
    _assert_phase_results(
        "strategy-limit",
        strategy_results,
        accepted_per_account=10,
        denial_code="STRATEGY_ALLOCATION_EXHAUSTED",
    )
    _assert_persisted_scope(
        strategy_database,
        strategy_policy,
        "strategy-limit",
        expected_count=10,
        expected_notional=Decimal("200"),
        expected_strategy_reservation=Decimal("25"),
    )
    _assert_restart_idempotency(
        strategy_database,
        strategy_policy,
        "strategy-limit",
        strategy_results,
    )
    _assert_persisted_scope(
        strategy_database,
        strategy_policy,
        "strategy-limit",
        expected_count=10,
        expected_notional=Decimal("200"),
        expected_strategy_reservation=Decimal("25"),
    )
