"""RISK01 account and strategy limits under one hundred process contenders."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
import time
import uuid
from collections import Counter
from contextlib import suppress
from decimal import Decimal
from pathlib import Path
from typing import Any

import bt_api_base
import pytest

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

_ACCOUNT_COUNT = 10
_STRATEGIES_PER_ACCOUNT = 10
_STRATEGY_PROCESS_COUNT = _ACCOUNT_COUNT * _STRATEGIES_PER_ACCOUNT
_NOTIONAL = Decimal("20")
_FIXED_CLOCK = 1_700_000_000.0
_PROCESS_TIMEOUT_SECONDS = 180.0
_CLEANUP_GRACE_SECONDS = 5.0
_CLEANUP_KILL_WAIT_SECONDS = 3.0

_WORKER_SCRIPT = r"""
import hashlib
import json
import os
import sys
import time
from decimal import Decimal
from pathlib import Path

config = json.loads(sys.argv[1])
sys.dont_write_bytecode = True
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

worker_id = config["worker_id"]
account_index = worker_id // 10
strategy_index = worker_id % 10
phase = config["phase"]
barrier_timeout = config["barrier_timeout"]

def wait_for(path, timeout):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("worker_barrier_timeout")
        time.sleep(0.02)

def mark(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp-" + str(os.getpid()))
    temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    temporary.replace(path)

account_id = "account-" + str(account_index)
strategy_id = "strategy-" + str(strategy_index)
scope = AccountScope("fixture", account_id, "sandbox")
policy = RiskPolicy(
    policy_id="risk01-" + phase,
    max_increase_notional=Decimal(config["account_limit"]),
    max_increase_count=100,
    permit_ttl_seconds=300.0,
    require_strategy_allocation=True,
    notional_unit="USD",
)

mark(Path(config["loaded_path"]), {"worker_id": worker_id, "pid": os.getpid()})
wait_for(Path(config["initialize_path"]), barrier_timeout)
gate = DurableRiskGate(config["database_path"], policy, clock=lambda: 1700000000.0)
mark(Path(config["ready_path"]), {"worker_id": worker_id, "pid": os.getpid()})
wait_for(Path(config["start_path"]), barrier_timeout)
release_token = Path(config["start_path"]).read_text(encoding="ascii")
mark(
    Path(config["started_path"]),
    {
        "worker_id": worker_id,
        "pid": os.getpid(),
        "release_token": release_token,
        "observed_ns": time.monotonic_ns(),
    },
)

outcomes = []
try:
    intent_count = config["intent_count"]
    for intent_index in range(intent_count):
        if phase == "account-limit":
            instrument_index = strategy_index // 2
        else:
            instrument_index = intent_index
        instrument = "fixture/contract-" + str(instrument_index)
        intent_id = (
            phase
            + ":"
            + account_id
            + ":"
            + strategy_id
            + ":intent-"
            + str(intent_index)
        )
        intent = RiskIntent(
            intent_id=intent_id,
            scope=scope,
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
            outcome = {"status": "denied", "code": error.code}
        else:
            outcome = {
                "status": "reserved",
                "permit_id": permit.permit_id,
                "permit_scope": permit.scope.account_id,
                "permit_strategy": permit.strategy_id,
            }
        outcomes.append(
            {
                "phase": phase,
                "worker_id": worker_id,
                "pid": os.getpid(),
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
            "pid": os.getpid(),
            "release_token": release_token,
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
    intent_index: int,
) -> RiskIntent:
    account_id = "account-" + str(account_index)
    strategy_id = "strategy-" + str(strategy_index)
    instrument_index = strategy_index // 2 if phase == "account-limit" else intent_index
    intent_id = (
        phase
        + ":"
        + account_id
        + ":"
        + strategy_id
        + ":intent-"
        + str(intent_index)
    )
    return RiskIntent(
        intent_id=intent_id,
        scope=_scope(account_index),
        action=IntentAction.INCREASE,
        notional=_NOTIONAL,
        payload_fingerprint=hashlib.sha256(intent_id.encode("utf-8")).hexdigest(),
        strategy_id=strategy_id,
        allocation_version="allocation-v1",
        instrument="fixture/contract-" + str(instrument_index),
        quantity=Decimal("1"),
        quantity_unit="contract",
        notional_unit="USD",
    )


def _prepare_database(
    database_path: Path,
    *,
    phase: str,
    account_limit: str,
    strategy_limit: str,
) -> RiskPolicy:
    policy = _policy(phase, account_limit)
    gate = DurableRiskGate(database_path, policy, clock=lambda: _FIXED_CLOCK)
    try:
        for account_index in range(_ACCOUNT_COUNT):
            scope = _scope(account_index)
            for strategy_index in range(_STRATEGIES_PER_ACCOUNT):
                gate.set_strategy_allocation(
                    scope,
                    "strategy-" + str(strategy_index),
                    "allocation-v1",
                    max_notional=Decimal(strategy_limit),
                    notional_unit="USD",
                )
    finally:
        gate.close()
    return policy


def _worker_failure(process: subprocess.Popen[str], label: str) -> AssertionError:
    stdout, stderr = process.communicate(timeout=5.0)
    return AssertionError(
        label
        + " exited before its expected barrier (exit="
        + str(process.returncode)
        + ")\nstdout:\n"
        + stdout[-4000:]
        + "\nstderr:\n"
        + stderr[-4000:]
    )


def _wait_for_path(
    path: Path,
    process: subprocess.Popen[str],
    *,
    deadline: float,
    label: str,
) -> None:
    while not path.exists():
        if process.poll() is not None:
            raise _worker_failure(process, label)
        if time.monotonic() >= deadline:
            raise TimeoutError(label + " timed out waiting for " + str(path.name))
        time.sleep(0.01)


def _cleanup_workers(processes: list[subprocess.Popen[str]]) -> dict[str, Any]:
    requested = 0
    for process in processes:
        if process.poll() is None:
            process.terminate()
            requested += 1

    deadline = time.monotonic() + _CLEANUP_GRACE_SECONDS
    for process in processes:
        if process.poll() is not None:
            continue
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=max(0.01, deadline - time.monotonic()))

    forced = [process for process in processes if process.poll() is None]
    for process in forced:
        process.kill()
    for process in forced:
        process.wait(timeout=_CLEANUP_KILL_WAIT_SECONDS)

    return {
        "termination_requests": requested,
        "forced_kill_count": len(forced),
        "all_reaped": all(process.poll() is not None for process in processes),
        "grace_seconds": _CLEANUP_GRACE_SECONDS,
        "kill_wait_seconds": _CLEANUP_KILL_WAIT_SECONDS,
    }


def _run_phase(
    tmp_path: Path,
    *,
    phase: str,
    database_path: Path,
    account_limit: str,
    intent_count: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    phase_root = tmp_path / (phase + "-100-process-run")
    phase_root.mkdir()
    barrier_root = phase_root / "barrier"
    barrier_root.mkdir()
    risk_source = Path(__file__).resolve().parents[1] / "src"
    base_source = Path(__file__).resolve().parents[2] / "bt_api_base" / "src"
    expected_origins = {
        "risk_package": str((risk_source / "bt_api_risk" / "__init__.py").resolve()),
        "risk_admission": str(
            (risk_source / "bt_api_risk" / "core" / "admission.py").resolve()
        ),
        "base_package": str((base_source / "bt_api_base" / "__init__.py").resolve()),
    }
    start_path = barrier_root / "shared-start"
    processes: list[subprocess.Popen[str]] = []
    process_by_id: dict[int, subprocess.Popen[str]] = {}
    loaded_paths: dict[int, Path] = {}
    ready_paths: dict[int, Path] = {}
    started_paths: dict[int, Path] = {}
    result_rows: list[dict[str, Any]] = []
    deadline = time.monotonic() + _PROCESS_TIMEOUT_SECONDS

    try:
        for worker_id in range(_STRATEGY_PROCESS_COUNT):
            loaded_path = barrier_root / ("loaded-" + str(worker_id) + ".json")
            initialize_path = barrier_root / ("initialize-" + str(worker_id))
            ready_path = barrier_root / ("ready-" + str(worker_id) + ".json")
            started_path = barrier_root / ("started-" + str(worker_id) + ".json")
            config = {
                "phase": phase,
                "worker_id": worker_id,
                "database_path": str(database_path),
                "account_limit": account_limit,
                "intent_count": intent_count,
                "barrier_timeout": _PROCESS_TIMEOUT_SECONDS,
                "risk_source": str(risk_source),
                "base_source": str(base_source),
                "risk_package_origin": expected_origins["risk_package"],
                "risk_admission_origin": expected_origins["risk_admission"],
                "base_package_origin": expected_origins["base_package"],
                "loaded_path": str(loaded_path),
                "initialize_path": str(initialize_path),
                "ready_path": str(ready_path),
                "start_path": str(start_path),
                "started_path": str(started_path),
            }
            process = subprocess.Popen(  # noqa: S603 -- fixed inline worker, no provider inputs.
                [
                    sys.executable,
                    "-I",
                    "-c",
                    _WORKER_SCRIPT,
                    json.dumps(config, separators=(",", ":")),
                ],
                cwd=phase_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            processes.append(process)
            process_by_id[worker_id] = process
            loaded_paths[worker_id] = loaded_path
            ready_paths[worker_id] = ready_path
            started_paths[worker_id] = started_path

        for worker_id, loaded_path in loaded_paths.items():
            _wait_for_path(
                loaded_path,
                process_by_id[worker_id],
                deadline=deadline,
                label="worker " + str(worker_id) + " import",
            )
        loaded_records = {
            worker_id: json.loads(path.read_text(encoding="utf-8"))
            for worker_id, path in loaded_paths.items()
        }
        assert len(loaded_records) == _STRATEGY_PROCESS_COUNT
        assert len({record["pid"] for record in loaded_records.values()}) == _STRATEGY_PROCESS_COUNT
        assert all(process.poll() is None for process in processes)

        # Serialize schema-opening only. Every strategy process is already
        # loaded and remains alive; all reservations use the shared start file.
        for worker_id, initialize_path in (
            (worker_id, barrier_root / ("initialize-" + str(worker_id)))
            for worker_id in range(_STRATEGY_PROCESS_COUNT)
        ):
            initialize_path.write_text("initialize", encoding="ascii")
            _wait_for_path(
                ready_paths[worker_id],
                process_by_id[worker_id],
                deadline=deadline,
                label="worker " + str(worker_id) + " gate initialization",
            )

        ready_records = {
            worker_id: json.loads(path.read_text(encoding="utf-8"))
            for worker_id, path in ready_paths.items()
        }
        assert len(ready_records) == _STRATEGY_PROCESS_COUNT
        assert len({record["pid"] for record in ready_records.values()}) == _STRATEGY_PROCESS_COUNT
        assert all(process.poll() is None for process in processes)

        release_token = phase + ":" + uuid.uuid4().hex
        # One atomic file publication releases all 100 live strategy processes.
        temporary_start_path = start_path.with_suffix(".tmp")
        temporary_start_path.write_text(release_token, encoding="ascii")
        temporary_start_path.replace(start_path)

        for worker_id, started_path in started_paths.items():
            _wait_for_path(
                started_path,
                process_by_id[worker_id],
                deadline=deadline,
                label="worker " + str(worker_id) + " shared-barrier release",
            )
        started_records = {
            worker_id: json.loads(path.read_text(encoding="utf-8"))
            for worker_id, path in started_paths.items()
        }
        assert len(started_records) == _STRATEGY_PROCESS_COUNT
        assert {record["release_token"] for record in started_records.values()} == {
            release_token
        }
        observed_ns = [record["observed_ns"] for record in started_records.values()]
        release_spread_seconds = (max(observed_ns) - min(observed_ns)) / 1_000_000_000
        assert release_spread_seconds <= 5.0

        process_exit_codes: dict[str, int] = {}
        worker_results: list[dict[str, Any]] = []
        for worker_id, process in process_by_id.items():
            remaining = max(0.1, deadline - time.monotonic())
            stdout, stderr = process.communicate(timeout=remaining)
            assert process.returncode == 0, stdout + "\n" + stderr
            assert stderr == ""
            result = json.loads(stdout)
            assert result["phase"] == phase
            assert result["worker_id"] == worker_id
            assert result["pid"] == ready_records[worker_id]["pid"]
            assert result["release_token"] == release_token
            assert result["origins"] == expected_origins
            assert len(result["outcomes"]) == intent_count
            worker_results.append(result)
            process_exit_codes[str(worker_id)] = process.returncode
            result_rows.extend(result["outcomes"])

        cleanup = _cleanup_workers(processes)
        assert cleanup["all_reaped"] is True
        assert cleanup["termination_requests"] == 0
        assert cleanup["forced_kill_count"] == 0
        assert len(result_rows) == _STRATEGY_PROCESS_COUNT * intent_count
        assert {row["pid"] for row in result_rows} == {
            record["pid"] for record in ready_records.values()
        }

        run_record = {
            "phase": phase,
            "worker_process_count": _STRATEGY_PROCESS_COUNT,
            "loaded_count_before_initialization": len(loaded_records),
            "ready_count_at_shared_release": len(ready_records),
            "ready_pids": sorted(record["pid"] for record in ready_records.values()),
            "shared_release_token": release_token,
            "release_observed_count": len(started_records),
            "release_spread_seconds": release_spread_seconds,
            "process_exit_codes": process_exit_codes,
            "normal_exit_count": sum(code == 0 for code in process_exit_codes.values()),
            "reservation_attempt_count": len(result_rows),
            "bounded_cleanup": cleanup,
        }
        record_path = phase_root / (phase + "-process-observation.json")
        record_path.write_text(json.dumps(run_record, indent=2, sort_keys=True), encoding="utf-8")
        return result_rows, run_record
    finally:
        _cleanup_workers(processes)


def _assert_result_counts(
    phase: str,
    rows: list[dict[str, Any]],
    *,
    accepted_per_account: int,
    expected_attempts_per_strategy: int,
    denial_code: str,
) -> None:
    expected_rows = _STRATEGY_PROCESS_COUNT * expected_attempts_per_strategy
    assert len(rows) == expected_rows
    assert len({row["intent_id"] for row in rows}) == expected_rows
    assert len({row["pid"] for row in rows}) == _STRATEGY_PROCESS_COUNT

    for account_index in range(_ACCOUNT_COUNT):
        account_id = "account-" + str(account_index)
        account_rows = [row for row in rows if row["account_id"] == account_id]
        accepted = [row for row in account_rows if row["status"] == "reserved"]
        denied = [row for row in account_rows if row["status"] == "denied"]
        assert len(accepted) == accepted_per_account
        assert len(denied) == len(account_rows) - accepted_per_account
        assert {row["code"] for row in denied} == {denial_code}
        assert all(row["permit_scope"] == account_id for row in accepted)
        assert all(row["permit_strategy"] == row["strategy_id"] for row in accepted)

        if phase == "account-limit":
            # Two strategies share each contract, so any five reservations
            # necessarily consume the account budget across at least three.
            assert len({row["instrument"] for row in accepted}) >= 3
        else:
            assert len({row["strategy_id"] for row in accepted}) == _STRATEGIES_PER_ACCOUNT
            for strategy_index in range(_STRATEGIES_PER_ACCOUNT):
                strategy_id = "strategy-" + str(strategy_index)
                strategy_rows = [row for row in account_rows if row["strategy_id"] == strategy_id]
                assert len(strategy_rows) == 2
                assert len({row["instrument"] for row in strategy_rows}) == 2
                assert sum(row["status"] == "reserved" for row in strategy_rows) == 1
                assert sum(row["status"] == "denied" for row in strategy_rows) == 1
                assert {row["code"] for row in strategy_rows if row["status"] == "denied"} == {
                    denial_code
                }


def _assert_persisted_state(
    database_path: Path,
    policy: RiskPolicy,
    phase: str,
    rows: list[dict[str, Any]],
    *,
    expected_count_per_account: int,
    expected_notional_per_account: Decimal,
    expected_strategy_limit: Decimal,
) -> None:
    reopened = DurableRiskGate(database_path, policy, clock=lambda: _FIXED_CLOCK)
    try:
        expected_by_strategy = Counter(
            (row["account_id"], row["strategy_id"])
            for row in rows
            if row["status"] == "reserved"
        )
        for account_index in range(_ACCOUNT_COUNT):
            scope = _scope(account_index)
            snapshot = reopened.snapshot(scope)
            assert snapshot["increase_count"] == expected_count_per_account
            assert snapshot["increase_notional"] == expected_notional_per_account
            assert snapshot["active_freeze_reasons"] == []

            strategy_total = Decimal("0")
            for strategy_index in range(_STRATEGIES_PER_ACCOUNT):
                strategy_id = "strategy-" + str(strategy_index)
                allocation = reopened.get_strategy_allocation(scope, strategy_id)
                assert allocation.scope == scope
                assert allocation.strategy_id == strategy_id
                assert allocation.source == "local_risk_reservation_ledger"
                assert allocation.completeness == "LOCAL_LEDGER_COMPLETE"
                assert allocation.reason is None
                assert allocation.allocated_notional == expected_strategy_limit
                assert allocation.reserved_notional is not None
                assert allocation.reserved_notional <= expected_strategy_limit
                if phase == "strategy-limit":
                    assert allocation.reserved_notional == Decimal("20")
                    assert allocation.available_notional == Decimal("5")
                else:
                    expected_reserved = (
                        Decimal("20")
                        if expected_by_strategy[(scope.account_id, strategy_id)]
                        else Decimal("0")
                    )
                    assert allocation.reserved_notional == expected_reserved
                strategy_total += allocation.reserved_notional
            assert strategy_total == expected_notional_per_account

        expected_db_rows = {
            (
                row["account_id"],
                row["strategy_id"],
                row["instrument"],
                row["intent_id"],
                "20",
            )
            for row in rows
            if row["status"] == "reserved"
        }
        with sqlite3.connect(database_path) as connection:
            persisted_rows = connection.execute(
                """SELECT account_id, strategy_id, instrument, intent_id, notional,
                          provider, environment, scope_key, status
                   FROM risk_reservations
                   WHERE action = ?""",
                (IntentAction.INCREASE.value,),
            ).fetchall()
        actual_db_rows = {
            (account_id, strategy_id, instrument, intent_id, notional)
            for (
                account_id,
                strategy_id,
                instrument,
                intent_id,
                notional,
                _provider,
                _environment,
                _scope_key,
                _status,
            ) in persisted_rows
        }
        assert actual_db_rows == expected_db_rows
        assert len(persisted_rows) == len(expected_db_rows)
        assert all(provider == "fixture" for _, _, _, _, _, provider, *_ in persisted_rows)
        assert all(environment == "sandbox" for *_, environment, _, _ in persisted_rows)
        assert all(status == "active" for *_, status in persisted_rows)
        for row in persisted_rows:
            account_id = row[0]
            account_index = int(account_id.removeprefix("account-"))
            assert row[7] == _scope(account_index).key
    finally:
        reopened.close()


def _assert_restart_idempotency(
    database_path: Path,
    policy: RiskPolicy,
    rows: list[dict[str, Any]],
) -> None:
    reopened = DurableRiskGate(database_path, policy, clock=lambda: _FIXED_CLOCK)
    try:
        for row in rows:
            worker_id = row["worker_id"]
            account_index = worker_id // _STRATEGIES_PER_ACCOUNT
            strategy_index = worker_id % _STRATEGIES_PER_ACCOUNT
            intent_index = int(row["intent_id"].rsplit("intent-", 1)[1])
            intent = _intent(row["phase"], account_index, strategy_index, intent_index)
            if row["status"] == "reserved":
                permit = reopened.reserve(intent)
                assert permit.permit_id == row["permit_id"]
                assert permit.scope.account_id == row["account_id"]
                assert permit.strategy_id == row["strategy_id"]
            else:
                with pytest.raises(RiskDeniedError) as denied:
                    reopened.reserve(intent)
                assert denied.value.code == row["code"]
    finally:
        reopened.close()


def _assert_runtime_origins() -> None:
    risk_source = Path(__file__).resolve().parents[1] / "src"
    base_source = Path(__file__).resolve().parents[2] / "bt_api_base" / "src"
    assert Path(bt_api_risk.__file__).resolve() == risk_source / "bt_api_risk" / "__init__.py"
    assert (
        Path(admission_module.__file__).resolve()
        == risk_source / "bt_api_risk" / "core" / "admission.py"
    )
    assert Path(bt_api_base.__file__).resolve() == base_source / "bt_api_base" / "__init__.py"


def test_risk01_hundred_strategy_processes_compete_and_reopen_sqlite(tmp_path: Path) -> None:
    _assert_runtime_origins()
    assert _STRATEGY_PROCESS_COUNT == 100

    account_database = tmp_path / "account-limit.sqlite3"
    account_policy = _prepare_database(
        account_database,
        phase="account-limit",
        account_limit="100",
        strategy_limit="1000",
    )
    account_rows, account_run = _run_phase(
        tmp_path,
        phase="account-limit",
        database_path=account_database,
        account_limit="100",
        intent_count=1,
    )
    assert account_run["loaded_count_before_initialization"] == 100
    assert account_run["ready_count_at_shared_release"] == 100
    assert account_run["release_observed_count"] == 100
    assert account_run["normal_exit_count"] == 100
    assert account_run["reservation_attempt_count"] == 100
    assert account_run["bounded_cleanup"]["all_reaped"] is True
    assert account_run["bounded_cleanup"]["forced_kill_count"] == 0
    _assert_result_counts(
        "account-limit",
        account_rows,
        accepted_per_account=5,
        expected_attempts_per_strategy=1,
        denial_code="ACCOUNT_LIMIT_EXHAUSTED",
    )
    _assert_persisted_state(
        account_database,
        account_policy,
        "account-limit",
        account_rows,
        expected_count_per_account=5,
        expected_notional_per_account=Decimal("100"),
        expected_strategy_limit=Decimal("1000"),
    )
    _assert_restart_idempotency(account_database, account_policy, account_rows)
    _assert_persisted_state(
        account_database,
        account_policy,
        "account-limit",
        account_rows,
        expected_count_per_account=5,
        expected_notional_per_account=Decimal("100"),
        expected_strategy_limit=Decimal("1000"),
    )

    strategy_database = tmp_path / "strategy-limit.sqlite3"
    strategy_policy = _prepare_database(
        strategy_database,
        phase="strategy-limit",
        account_limit="500",
        strategy_limit="25",
    )
    strategy_rows, strategy_run = _run_phase(
        tmp_path,
        phase="strategy-limit",
        database_path=strategy_database,
        account_limit="500",
        intent_count=2,
    )
    assert strategy_run["loaded_count_before_initialization"] == 100
    assert strategy_run["ready_count_at_shared_release"] == 100
    assert strategy_run["release_observed_count"] == 100
    assert strategy_run["normal_exit_count"] == 100
    assert strategy_run["reservation_attempt_count"] == 200
    assert strategy_run["bounded_cleanup"]["all_reaped"] is True
    assert strategy_run["bounded_cleanup"]["forced_kill_count"] == 0
    _assert_result_counts(
        "strategy-limit",
        strategy_rows,
        accepted_per_account=10,
        expected_attempts_per_strategy=2,
        denial_code="STRATEGY_ALLOCATION_EXHAUSTED",
    )
    _assert_persisted_state(
        strategy_database,
        strategy_policy,
        "strategy-limit",
        strategy_rows,
        expected_count_per_account=10,
        expected_notional_per_account=Decimal("200"),
        expected_strategy_limit=Decimal("25"),
    )
    _assert_restart_idempotency(strategy_database, strategy_policy, strategy_rows)
    _assert_persisted_state(
        strategy_database,
        strategy_policy,
        "strategy-limit",
        strategy_rows,
        expected_count_per_account=10,
        expected_notional_per_account=Decimal("200"),
        expected_strategy_limit=Decimal("25"),
    )
