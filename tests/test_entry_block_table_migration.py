"""Iteration 64: the legacy ``risk_freezes`` table migrates to ``risk_entry_blocks``.

The table holds STOP_NEW causes and dispatch in-flight latches. Opening a gate
renames the legacy table inside one write transaction; a conflicting or
unexpected legacy schema refuses to open and leaves the file unchanged.
Evidence level: UNIT (local SQLite files only).
"""

from __future__ import annotations

import sqlite3
from decimal import Decimal
from pathlib import Path

import pytest

from bt_api_risk import (
    AccountScope,
    DurableRiskGate,
    IntentAction,
    RiskDeniedError,
    RiskIntent,
    RiskLedgerSchemaError,
    RiskPolicy,
)

# DDL exactly as written by the pre-iteration-64 gate (``blocking`` was added by
# a later ALTER, so the oldest ledgers lack it).
_LEGACY_DDL_WITH_BLOCKING = """
CREATE TABLE risk_freezes (
    scope_key TEXT NOT NULL,
    cause_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    active INTEGER NOT NULL,
    blocking INTEGER NOT NULL DEFAULT 1,
    updated_at REAL NOT NULL,
    PRIMARY KEY(scope_key, cause_id)
)
"""
_LEGACY_DDL_WITHOUT_BLOCKING = """
CREATE TABLE risk_freezes (
    scope_key TEXT NOT NULL,
    cause_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    active INTEGER NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY(scope_key, cause_id)
)
"""
_CURRENT_DDL = _LEGACY_DDL_WITH_BLOCKING.replace("risk_freezes", "risk_entry_blocks")


def _policy() -> RiskPolicy:
    return RiskPolicy(
        policy_id="entry-block-migration",
        max_increase_notional=Decimal("100"),
        max_increase_count=3,
        permit_ttl_seconds=10.0,
    )


def _scope() -> AccountScope:
    return AccountScope(provider="fake", account_id="account-1", environment="sandbox")


def _intent(intent_id: str) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=_scope(),
        action=IntentAction.INCREASE,
        notional=Decimal("10"),
        payload_fingerprint="deterministic-test-payload",
    )


def _schema(path: Path) -> list[tuple[str, str, str, str]]:
    with sqlite3.connect(path) as connection:
        return sorted(
            tuple(str(value) for value in row)
            for row in connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_master")
        )


def _rows(path: Path, table: str) -> list[tuple[object, ...]]:
    with sqlite3.connect(path) as connection:
        return sorted(connection.execute(f"SELECT * FROM {table}").fetchall())  # noqa: S608


def _legacy_ledger(path: Path, ddl: str) -> None:
    scope_key = _scope().key
    with sqlite3.connect(path) as connection:
        connection.execute(ddl)
        connection.execute("CREATE INDEX legacy_reason_idx ON risk_freezes(reason)")
        connection.execute(
            """CREATE TRIGGER legacy_reason_guard BEFORE UPDATE OF reason ON risk_freezes
               BEGIN SELECT RAISE(ABORT, 'reason is immutable'); END"""
        )
        columns = "scope_key, cause_id, reason, active, updated_at"
        connection.executemany(
            f"INSERT INTO risk_freezes ({columns}) VALUES (?, ?, ?, ?, ?)",  # noqa: S608
            [
                (scope_key, "operator-hold", "operator hold", 1, 1.0),
                (scope_key, "resolved-hold", "resolved hold", 0, 2.0),
                (scope_key, "dispatch-inflight:intent-a", "dispatch-inflight:intent-a", 1, 3.0),
            ],
        )


@pytest.mark.parametrize(
    "ddl", [_LEGACY_DDL_WITH_BLOCKING, _LEGACY_DDL_WITHOUT_BLOCKING], ids=["blocking", "oldest"]
)
def test_legacy_table_is_renamed_with_rows_index_and_trigger(tmp_path: Path, ddl: str) -> None:
    path = tmp_path / "risk.db"
    _legacy_ledger(path, ddl)
    legacy_rows = _rows(path, "risk_freezes")

    gate = DurableRiskGate(path, _policy())

    names = {row[1]: row for row in _schema(path)}
    assert "risk_freezes" not in names
    assert names["risk_entry_blocks"][0] == "table"
    assert names["legacy_reason_idx"][2] == "risk_entry_blocks"
    assert names["legacy_reason_guard"][2] == "risk_entry_blocks"
    assert "risk_freezes" not in names["legacy_reason_guard"][3]
    migrated = _rows(path, "risk_entry_blocks")
    # Same rows; the oldest ledger gains the ``blocking`` column with default 1.
    assert [row[:4] for row in migrated] == [row[:4] for row in legacy_rows]
    assert sorted(gate.active_entry_block_reasons(_scope())) == [
        "dispatch-inflight:intent-a",
        "operator hold",
    ]
    with pytest.raises(RiskDeniedError) as denied:
        gate.reserve(_intent("blocked-open"))
    assert denied.value.code == "STOP_NEW_ACTIVE"
    with sqlite3.connect(path) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute("UPDATE risk_entry_blocks SET reason = 'changed'")

    # Reopening an already migrated ledger is a no-op.
    DurableRiskGate(path, _policy())
    assert _rows(path, "risk_entry_blocks") == migrated


def test_fresh_ledger_creates_only_the_current_table(tmp_path: Path) -> None:
    path = tmp_path / "risk.db"
    gate = DurableRiskGate(path, _policy())
    gate.stop_new(_scope(), "operator-hold", "operator hold")

    names = {row[1] for row in _schema(path)}
    assert "risk_entry_blocks" in names
    assert "risk_freezes" not in names


def test_both_tables_present_refuses_to_open_and_changes_nothing(tmp_path: Path) -> None:
    path = tmp_path / "risk.db"
    _legacy_ledger(path, _LEGACY_DDL_WITH_BLOCKING)
    with sqlite3.connect(path) as connection:
        connection.execute(_CURRENT_DDL)
    before = _schema(path)
    legacy_rows = _rows(path, "risk_freezes")

    with pytest.raises(RiskLedgerSchemaError) as refused:
        DurableRiskGate(path, _policy())

    assert refused.value.code == "RISK_ENTRY_BLOCK_TABLE_CONFLICT"
    assert _schema(path) == before
    assert _rows(path, "risk_freezes") == legacy_rows
    assert _rows(path, "risk_entry_blocks") == []


def test_failed_migration_rolls_back_and_refuses_to_open(tmp_path: Path) -> None:
    path = tmp_path / "risk.db"
    # A legacy table with a column no released gate ever wrote: the rename
    # itself succeeds, the post-rename shape check fails, and the whole step
    # must roll back so the file is exactly as before.
    _legacy_ledger(
        path,
        _LEGACY_DDL_WITH_BLOCKING.replace(
            "updated_at REAL NOT NULL,", "updated_at REAL NOT NULL,\n    unexpected TEXT,"
        ),
    )
    before = _schema(path)
    legacy_rows = _rows(path, "risk_freezes")

    with pytest.raises(RiskLedgerSchemaError) as refused:
        DurableRiskGate(path, _policy())

    assert refused.value.code == "RISK_ENTRY_BLOCK_MIGRATION_FAILED"
    assert _schema(path) == before
    assert _rows(path, "risk_freezes") == legacy_rows
