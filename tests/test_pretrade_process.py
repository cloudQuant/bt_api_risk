"""Writer fence across processes, sequential engines, schema guards, import boundary.

UNIT evidence on one host (local SQLite file and OS lock); not a cross-host fence (INV64-13).
"""

from __future__ import annotations

import queue
import sqlite3
import subprocess
import sys
import threading

import pytest
from test_pretrade_support import (
    DAY,
    SCOPE,
    Harness,
    base_policy,
    make_view,
)

from bt_api_risk.pretrade import PretradeLedger
from bt_api_risk.risk_order_journal import RiskOrderJournal
from bt_api_risk.risk_order_journal_contracts import RiskOrderJournalError

HOLDER = r"""
import sys
from bt_api_risk.core.admission import AccountScope
from bt_api_risk.pretrade import PretradeLedger
from bt_api_risk.risk_order_journal import RiskOrderJournal

journal = RiskOrderJournal(sys.argv[1], writer_id=sys.argv[2])
scope = AccountScope(provider="ctp", account_id="acct-hash", environment="simnow")
with journal.writer_fence(scope) as fence:
    PretradeLedger(journal, fence)
    print("ACQUIRED", fence.fencing_token, flush=True)
    sys.stdin.readline()
print("RELEASED", flush=True)
"""


def _spawn(path, writer):
    process = subprocess.Popen(  # noqa: S603 -- fixed interpreter and script, local temp path.
        [sys.executable, "-c", HOLDER, str(path), writer],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lines: queue.Queue[str] = queue.Queue()

    def pump():
        for line in process.stdout:
            lines.put(line.strip())

    threading.Thread(target=pump, daemon=True).start()
    return process, lines


def test_two_processes_cannot_hold_the_account_writer_fence_at_once(tmp_path):
    path = tmp_path / "risk.db"
    first, first_lines = _spawn(path, "proc-a")
    second = None
    try:
        acquired = first_lines.get(timeout=60)
        assert acquired.startswith("ACQUIRED")
        first_token = int(acquired.split()[1])
        second, second_lines = _spawn(path, "proc-b")
        with pytest.raises(queue.Empty):
            second_lines.get(timeout=2.0)  # blocked while the first process holds the fence
        first.stdin.write("\n")
        first.stdin.flush()
        assert first_lines.get(timeout=60) == "RELEASED"
        acquired = second_lines.get(timeout=60)
        assert acquired.startswith("ACQUIRED")
        assert int(acquired.split()[1]) == first_token + 1  # a new owner gets a new generation
        second.stdin.write("\n")
        second.stdin.flush()
        assert second_lines.get(timeout=60) == "RELEASED"
    finally:
        for process in (first, second):
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=30)
                process.stdin.close()
                process.stdout.close()
                process.stderr.close()


def test_a_ledger_whose_fence_was_replaced_cannot_write(tmp_path):
    harness = Harness(tmp_path / "risk.db")
    try:
        stale = harness.ledger
        harness.restart()
        with pytest.raises(RiskOrderJournalError) as error, stale.transaction():
            pass
        assert error.value.code in ("WRITER_FENCE_NOT_HELD", "WRITER_FENCE_STALE")
    finally:
        harness.close()


def test_sequential_engines_on_the_same_database_keep_exact_counters(tmp_path):
    harness = Harness(tmp_path / "risk.db")
    try:
        harness.publish(
            base_policy(
                counters={"orders": {"warn": 2, "block": 3}}, closable_check={"enabled": False}
            )
        )
        harness.verify_stream()
        for key, price in (("a1", "99"), ("a2", "98")):
            assert harness.place(make_view(key=key, price=price)).outcome == "DISPATCHED"
        first_token = harness.fence.fencing_token
        harness.restart()
        assert harness.fence.fencing_token == first_token + 1
        assert harness.place(make_view(key="a3", price="97")).outcome == "DISPATCHED"
        assert harness.place(make_view(key="a4", price="96")).code == "risk_order_count_limit"
        harness.restart()
        counts = harness.engine.export_counts(DAY, "csv").splitlines()
        assert counts[1:] == [DAY + ",rb2701,order,3"]
        assert len(harness.engine.list_latches(active_only=True)) == 1
    finally:
        harness.close()


def test_append_only_tables_refuse_update_and_delete(tmp_path):
    harness = Harness(tmp_path / "risk.db")
    try:
        harness.publish(base_policy())
    finally:
        harness.close()
    connection = sqlite3.connect(tmp_path / "risk.db")
    try:
        for statement in (
            "UPDATE risk_pretrade_audit SET kind='x'",
            "DELETE FROM risk_pretrade_audit",
            "UPDATE risk_pretrade_policy_versions SET reason='x'",
            "DELETE FROM risk_pretrade_policy_versions",
        ):
            with pytest.raises(sqlite3.DatabaseError):
                connection.execute(statement)
    finally:
        connection.close()


def test_schema_version_mismatch_refuses_to_open(tmp_path):
    Harness(tmp_path / "risk.db").close()
    connection = sqlite3.connect(tmp_path / "risk.db")
    connection.execute("UPDATE risk_pretrade_meta SET schema_version=2")
    connection.commit()
    connection.close()
    journal = RiskOrderJournal(tmp_path / "risk.db", writer_id="risk-test")
    with journal.writer_fence(SCOPE) as fence, pytest.raises(RiskOrderJournalError) as error:
        PretradeLedger(journal, fence)
    assert error.value.code == "PRETRADE_SCHEMA_MISMATCH"


def test_pretrade_does_not_import_sdk_gateway_or_execution(tmp_path):
    script = r"""
import importlib.abc, sys
blocked = {"bt_api_py", "bt_api_gateway", "bt_api_execution"}
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in blocked:
            raise AssertionError("forbidden import: " + fullname)
sys.meta_path.insert(0, Block())
import bt_api_risk.pretrade as pretrade
assert pretrade.PretradeEngine
assert not (blocked & {name.split(".")[0] for name in sys.modules})
print("OK")
"""
    result = subprocess.run(  # noqa: S603 -- fixed interpreter and script.
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode == 0 and result.stdout.strip() == "OK", result.stderr
