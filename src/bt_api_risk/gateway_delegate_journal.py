"""Account-fenced durable storage for explicitly selected Gateway delegation.

This journal stores opaque canonical JSON only. It is not an admission or
provider authority; the SDK's typed adapter validates all command bindings.
The optional, independently versioned schema shares the Risk order journal's
SQLite database and its account-wide writer fence.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading

from .core.admission import AccountScope
from .risk_order_journal import RiskOrderJournal
from .risk_order_journal_contracts import RiskOrderJournalError, RiskOrderWriterFence

_SCHEMA_VERSION = 1
_KINDS = frozenset(("intent", "observation", "dispatch_marker", "cancel_intent",
                    "cancel_observation", "cancel_dispatch_marker", "release_intent",
                    "release_marker", "release_observation"))
_PREDECESSORS = {"observation": "intent", "dispatch_marker": "observation",
                 "cancel_observation": "cancel_intent", "cancel_dispatch_marker": "cancel_intent",
                 "release_observation": "release_intent", "release_marker": "release_intent"}
_OBSERVATIONS = frozenset(("observation", "cancel_observation", "release_observation"))


def _canonical(value: str) -> str:
    if type(value) is not str or not value or len(value) > 1048576:
        raise RiskOrderJournalError("DELEGATE_INVALID_PAYLOAD")
    try:
        decoded = json.loads(value)
        encoded = json.dumps(decoded, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise RiskOrderJournalError("DELEGATE_INVALID_PAYLOAD") from None
    if encoded != value or type(decoded) not in (dict, list):
        raise RiskOrderJournalError("DELEGATE_INVALID_PAYLOAD")
    return value


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class RiskGatewayDelegateJournal:
    """Store immutable records and monotonic observations under a held fence.

    Creation is an explicit opt-in, transactional, additive v1 feature migration.
    The object is bound to the creating thread, process, journal and current
    non-expiring writer-fence lifetime. It cannot itself authorize a request.
    """

    def __init__(self, journal: RiskOrderJournal, fence: RiskOrderWriterFence) -> None:
        if not isinstance(journal, RiskOrderJournal) or type(fence) is not RiskOrderWriterFence:
            raise RiskOrderJournalError("DELEGATE_WRITER_REQUIRED")
        self._journal, self._fence = journal, fence
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._check()
        with journal._transaction() as connection:
            journal._assert_current_in(connection, fence)
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='risk_gateway_delegate_meta'"
            ).fetchone()
            if exists is None:
                connection.execute("CREATE TABLE risk_gateway_delegate_meta (schema_version INTEGER NOT NULL)")
                connection.execute("INSERT INTO risk_gateway_delegate_meta VALUES (?)", (_SCHEMA_VERSION,))
                connection.execute("""CREATE TABLE risk_gateway_delegate_records (
                    scope_key TEXT NOT NULL, kind TEXT NOT NULL, request_key TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK(version >= 0), payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL, writer_owner_id TEXT NOT NULL,
                    writer_fencing_token INTEGER NOT NULL CHECK(writer_fencing_token > 0),
                    writer_fence_sha256 TEXT NOT NULL,
                    PRIMARY KEY(scope_key, kind, request_key, version))""")
                connection.execute("""CREATE TRIGGER risk_gateway_delegate_records_no_update
                    BEFORE UPDATE ON risk_gateway_delegate_records BEGIN
                    SELECT RAISE(ABORT, 'risk_gateway_delegate_records are immutable'); END""")
                connection.execute("""CREATE TRIGGER risk_gateway_delegate_records_no_delete
                    BEFORE DELETE ON risk_gateway_delegate_records BEGIN
                    SELECT RAISE(ABORT, 'risk_gateway_delegate_records are immutable'); END""")
            self._check_schema(connection)
            journal._assert_current_in(connection, fence)

    @staticmethod
    def _check_schema(connection) -> None:
        versions = connection.execute("SELECT schema_version FROM risk_gateway_delegate_meta").fetchall()
        objects = connection.execute("""SELECT name FROM sqlite_master WHERE
            (type='table' AND name='risk_gateway_delegate_records') OR
            (type='trigger' AND name IN ('risk_gateway_delegate_records_no_update',
                                          'risk_gateway_delegate_records_no_delete'))""").fetchall()
        if len(versions) != 1 or versions[0][0] != _SCHEMA_VERSION or len(objects) != 3:
            raise RiskOrderJournalError("DELEGATE_SCHEMA_MISMATCH")

    def _check(self) -> None:
        if (os.getpid() != self._pid or threading.current_thread() is not self._thread
                or self._fence.owner_id != self._journal._owner_id):
            raise RiskOrderJournalError("DELEGATE_WRITER_NOT_OWNED")
        self._journal._assert_current(self._fence)

    @property
    def account_scope(self) -> AccountScope:
        """Return the account scope only while this writer fence is held."""
        self._check()
        return self._fence.scope

    @staticmethod
    def _key(kind: str, request_key: str) -> None:
        if (kind not in _KINDS or type(request_key) is not str or not request_key
                or request_key != request_key.strip() or len(request_key) > 256):
            raise RiskOrderJournalError("DELEGATE_INVALID_KEY")

    def save(self, kind: str, request_key: str, canonical_json: str, *, version: int = 0) -> str:
        self._check()
        self._key(kind, request_key)
        _canonical(canonical_json)
        if (type(version) is not int or version < 0 or version > 9223372036854775807
                or ((kind in _OBSERVATIONS) != (version > 0))):
            raise RiskOrderJournalError("DELEGATE_INVALID_VERSION")
        journal, fence = self._journal, self._fence
        with journal._transaction() as connection:
            journal._assert_current_in(connection, fence)
            self._check_schema(connection)
            required = _PREDECESSORS.get(kind)
            if required is not None:
                previous = connection.execute(
                    "SELECT 1 FROM risk_gateway_delegate_records "
                    "WHERE scope_key=? AND kind=? AND request_key=? LIMIT 1",
                    (fence.scope.key, required, request_key),
                ).fetchone()
                if previous is None:
                    raise RiskOrderJournalError("DELEGATE_PREDECESSOR_REQUIRED")
            row = connection.execute(
                "SELECT version, payload_json, payload_sha256 FROM risk_gateway_delegate_records "
                "WHERE scope_key=? AND kind=? AND request_key=? ORDER BY version DESC LIMIT 1",
                (fence.scope.key, kind, request_key),
            ).fetchone()
            if row is not None:
                self._validate_row(row)
                if row["version"] > version or (row["version"] == version and row["payload_json"] != canonical_json):
                    raise RiskOrderJournalError("DELEGATE_RECORD_CONFLICT")
                if row["version"] == version:
                    journal._assert_current_in(connection, fence)
                    return canonical_json
            connection.execute(
                "INSERT INTO risk_gateway_delegate_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (fence.scope.key, kind, request_key, version, canonical_json, _digest(canonical_json),
                 fence.owner_id, fence.fencing_token, fence.fence_sha256),
            )
            journal._assert_current_in(connection, fence)
        return canonical_json

    @staticmethod
    def _validate_row(row) -> None:
        payload = _canonical(row["payload_json"])
        if row["payload_sha256"] != _digest(payload):
            raise RiskOrderJournalError("DELEGATE_RECORD_CORRUPT")

    def load(self, kind: str, request_key: str) -> str | None:
        self._check()
        self._key(kind, request_key)
        journal, fence = self._journal, self._fence
        with journal._transaction() as connection:
            journal._assert_current_in(connection, fence)
            self._check_schema(connection)
            row = connection.execute(
                "SELECT version, payload_json, payload_sha256 FROM risk_gateway_delegate_records "
                "WHERE scope_key=? AND kind=? AND request_key=? ORDER BY version DESC LIMIT 1",
                (fence.scope.key, kind, request_key),
            ).fetchone()
            if row is not None:
                self._validate_row(row)
            journal._assert_current_in(connection, fence)
        return None if row is None else row["payload_json"]
