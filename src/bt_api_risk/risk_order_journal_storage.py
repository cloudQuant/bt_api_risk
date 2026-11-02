"""SQLite and OS lock mechanics for the risk-only direct-order journal.

The SDK composition retains the account fence, domain events and authority.
This storage implementation does not require the optional Execution package.
"""
from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path


_SCHEMA_VERSION = 1


class RiskOrderJournalStorage:
    """SQLite and file-lock implementation inherited by the journal owner."""

    _storage_error_type: type[Exception]
    _path: Path

    def _initialize(self) -> None:
        with closing(self._connection()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS risk_order_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS risk_order_fences (
                    scope_key TEXT PRIMARY KEY,
                    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0)
                );
                CREATE TABLE IF NOT EXISTS risk_order_commands (
                    scope_key TEXT NOT NULL,
                    principal_ref TEXT NOT NULL,
                    intent_id TEXT NOT NULL,
                    risk_intent_id TEXT NOT NULL UNIQUE,
                    payload_sha256 TEXT NOT NULL,
                    canonical_payload_json TEXT NOT NULL,
                    wire_scope_json TEXT NOT NULL,
                    exchange_name TEXT NOT NULL,
                    provider_account_id TEXT NOT NULL,
                    client_order_id TEXT NOT NULL,
                    order_request_json TEXT NOT NULL,
                    order_request_sha256 TEXT NOT NULL,
                    created_revision INTEGER NOT NULL,
                    created_record_sha256 TEXT NOT NULL,
                    PRIMARY KEY(scope_key, principal_ref, intent_id),
                    UNIQUE(scope_key, client_order_id)
                );
                CREATE TABLE IF NOT EXISTS risk_order_events (
                    scope_key TEXT NOT NULL,
                    principal_ref TEXT NOT NULL,
                    intent_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK(revision > 0),
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_account_sha256 TEXT NOT NULL,
                    previous_command_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    writer_owner_id TEXT NOT NULL,
                    writer_fencing_token INTEGER NOT NULL,
                    writer_fence_sha256 TEXT NOT NULL,
                    PRIMARY KEY(scope_key, revision),
                    UNIQUE(scope_key, principal_ref, intent_id, revision),
                    FOREIGN KEY(scope_key, principal_ref, intent_id)
                      REFERENCES risk_order_commands(scope_key, principal_ref, intent_id)
                );
                CREATE TABLE IF NOT EXISTS risk_order_exposure_references (
                    scope_key TEXT NOT NULL,
                    principal_ref TEXT NOT NULL,
                    intent_id TEXT NOT NULL,
                    reservation_id TEXT NOT NULL,
                    reference_sha256 TEXT NOT NULL,
                    reference_json TEXT NOT NULL,
                    created_revision INTEGER NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    PRIMARY KEY(scope_key, principal_ref, intent_id),
                    UNIQUE(scope_key, reservation_id),
                    FOREIGN KEY(scope_key, principal_ref, intent_id)
                      REFERENCES risk_order_commands(scope_key, principal_ref, intent_id)
                );
                CREATE TABLE IF NOT EXISTS risk_order_terminal_close_proofs (
                    scope_key TEXT NOT NULL,
                    principal_ref TEXT NOT NULL,
                    intent_id TEXT NOT NULL,
                    proof_sha256 TEXT NOT NULL,
                    proof_json TEXT NOT NULL,
                    source_order_revision INTEGER NOT NULL CHECK(source_order_revision > 0),
                    source_order_record_sha256 TEXT NOT NULL,
                    source_fill_revision INTEGER NOT NULL CHECK(source_fill_revision > 0),
                    source_fill_record_sha256 TEXT NOT NULL,
                    writer_owner_id TEXT NOT NULL,
                    writer_fencing_token INTEGER NOT NULL CHECK(writer_fencing_token > 0),
                    writer_fence_sha256 TEXT NOT NULL,
                    created_at_ns INTEGER NOT NULL CHECK(created_at_ns > 0),
                    PRIMARY KEY(scope_key, principal_ref, intent_id),
                    FOREIGN KEY(scope_key, principal_ref, intent_id)
                      REFERENCES risk_order_commands(scope_key, principal_ref, intent_id)
                );
                CREATE TABLE IF NOT EXISTS risk_order_gross_baselines (
                    scope_key TEXT NOT NULL,
                    account_revision INTEGER NOT NULL CHECK(account_revision > 0),
                    proof_sha256 TEXT NOT NULL,
                    source_snapshot_json TEXT NOT NULL,
                    source_snapshot_sha256 TEXT NOT NULL,
                    writer_owner_id TEXT NOT NULL,
                    writer_fencing_token INTEGER NOT NULL CHECK(writer_fencing_token > 0),
                    writer_fence_sha256 TEXT NOT NULL,
                    created_at_ns INTEGER NOT NULL CHECK(created_at_ns > 0),
                    PRIMARY KEY(scope_key, account_revision)
                );
                CREATE TRIGGER IF NOT EXISTS risk_order_commands_no_update
                BEFORE UPDATE ON risk_order_commands BEGIN
                    SELECT RAISE(ABORT, 'risk_order_commands are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS risk_order_commands_no_delete
                BEFORE DELETE ON risk_order_commands BEGIN
                    SELECT RAISE(ABORT, 'risk_order_commands are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS risk_order_events_no_update
                BEFORE UPDATE ON risk_order_events BEGIN
                    SELECT RAISE(ABORT, 'risk_order_events are append only');
                END;
                CREATE TRIGGER IF NOT EXISTS risk_order_events_no_delete
                BEFORE DELETE ON risk_order_events BEGIN
                    SELECT RAISE(ABORT, 'risk_order_events are append only');
                END;
                CREATE TRIGGER IF NOT EXISTS risk_order_exposure_refs_no_update
                BEFORE UPDATE ON risk_order_exposure_references BEGIN
                    SELECT RAISE(ABORT, 'risk-order exposure references are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS risk_order_exposure_refs_no_delete
                BEFORE DELETE ON risk_order_exposure_references BEGIN
                    SELECT RAISE(ABORT, 'risk-order exposure references are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS risk_order_terminal_close_proofs_no_update
                BEFORE UPDATE ON risk_order_terminal_close_proofs BEGIN
                    SELECT RAISE(ABORT, 'risk-order terminal close proofs are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS risk_order_terminal_close_proofs_no_delete
                BEFORE DELETE ON risk_order_terminal_close_proofs BEGIN
                    SELECT RAISE(ABORT, 'risk-order terminal close proofs are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS risk_order_gross_baselines_no_update
                BEFORE UPDATE ON risk_order_gross_baselines BEGIN
                    SELECT RAISE(ABORT, 'risk-order gross baselines are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS risk_order_gross_baselines_no_delete
                BEFORE DELETE ON risk_order_gross_baselines BEGIN
                    SELECT RAISE(ABORT, 'risk-order gross baselines are immutable');
                END;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO risk_order_meta(key, value) VALUES('schema_version', ?)",
                (str(_SCHEMA_VERSION),),
            )
            version = connection.execute(
                "SELECT value FROM risk_order_meta WHERE key='schema_version'"
            ).fetchone()
            if version is None or version[0] != str(_SCHEMA_VERSION):
                raise self._storage_error_type("JOURNAL_SCHEMA_MISMATCH")

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=30.0, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
        except BaseException:
            connection.close()
            raise
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _open_and_lock(path: Path):
        owner_file = open(path, "a+b")  # noqa: SIM115 -- held for the full writer-fence lifetime.
        owner_file.seek(0, os.SEEK_END)
        if owner_file.tell() == 0:
            owner_file.write(b"\0")
            owner_file.flush()
        owner_file.seek(0)
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    msvcrt.locking(owner_file.fileno(), msvcrt.LK_NBLCK, 1)
                    return owner_file
                except OSError:
                    time.sleep(0.01)
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(owner_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return owner_file
                except BlockingIOError:
                    time.sleep(0.01)

    @staticmethod
    def _unlock_and_close(owner_file) -> None:
        try:
            if os.name == "nt":
                import msvcrt

                owner_file.seek(0)
                msvcrt.locking(owner_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(owner_file.fileno(), fcntl.LOCK_UN)
        finally:
            owner_file.close()

