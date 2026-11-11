"""Durable pre-trade ledger in the Risk order journal's SQLite file (freeze 64.01 section 2).

The ledger is an optional, independently versioned schema (``risk_pretrade_*``,
schema version 1) that shares the :class:`RiskOrderJournal` database and its
account writer fence. Every transaction is ``BEGIN IMMEDIATE`` and asserts the
fence on entry and before commit. The object is bound to the creating thread,
process, journal and fence lifetime. It stores decisions; it does not decide.
No port is ever called while a ledger transaction is open (the engine's duty).
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from ..risk_order_journal import RiskOrderJournal
from ..risk_order_journal_contracts import RiskOrderJournalError, RiskOrderWriterFence

SCHEMA_VERSION = 1

# Permit states (bt_api_base.risk_service_protocol.RISK_PERMIT_STATES).
OCCUPYING_STATES = ("RESERVING", "RESERVED", "CLAIMED", "DISPATCHED", "UNKNOWN", "RELEASING")
WORKING_STATES = ("CLAIMED", "DISPATCHED", "UNKNOWN")
FINAL_STATES = ("RELEASED", "DENIED", "TERMINAL")

_TABLES = (
    "risk_pretrade_meta",
    "risk_pretrade_policy_versions",
    "risk_pretrade_permits",
    "risk_pretrade_parents",
    "risk_pretrade_counters",
    "risk_pretrade_latches",
    "risk_pretrade_cursor",
    "risk_pretrade_orders",
    "risk_pretrade_trades",
    "risk_pretrade_positions",
    "risk_pretrade_day_values",
    "risk_pretrade_control_intents",
    "risk_pretrade_cancel_intents",
    "risk_pretrade_seen_events",
    "risk_pretrade_audit",
)
_TRIGGERS = (
    "risk_pretrade_audit_no_update",
    "risk_pretrade_audit_no_delete",
    "risk_pretrade_policy_versions_no_update",
    "risk_pretrade_policy_versions_no_delete",
    "risk_pretrade_trades_no_update",
    "risk_pretrade_trades_no_delete",
)

_SCHEMA = """
CREATE TABLE risk_pretrade_meta (schema_version INTEGER NOT NULL);
CREATE TABLE risk_pretrade_policy_versions (
    scope_key TEXT NOT NULL, version INTEGER NOT NULL CHECK(version > 0),
    policy_id TEXT NOT NULL, digest TEXT NOT NULL, document_json TEXT NOT NULL,
    exchange_rules_text TEXT, published_ns INTEGER NOT NULL, operator_ref TEXT NOT NULL,
    reason TEXT, classification_json TEXT NOT NULL,
    writer_owner_id TEXT NOT NULL, writer_fencing_token INTEGER NOT NULL,
    PRIMARY KEY(scope_key, version));
CREATE TABLE risk_pretrade_permits (
    scope_key TEXT NOT NULL, permit_id TEXT NOT NULL, strategy_ref TEXT NOT NULL,
    request_key TEXT NOT NULL, run_id TEXT, principal_ref TEXT NOT NULL, origin TEXT NOT NULL,
    view_json TEXT NOT NULL, view_digest TEXT NOT NULL, payload_json TEXT NOT NULL,
    payload_digest TEXT NOT NULL, instrument_id TEXT NOT NULL, instrument_json TEXT NOT NULL,
    side TEXT NOT NULL, order_offset TEXT NOT NULL, effect TEXT NOT NULL,
    position_side TEXT NOT NULL, bucket TEXT NOT NULL, quantity TEXT NOT NULL,
    limit_price TEXT, parent_ref TEXT, child_id TEXT, trading_day TEXT NOT NULL,
    policy_version INTEGER NOT NULL, state TEXT NOT NULL, row_version INTEGER NOT NULL,
    code TEXT, gateway_code TEXT, gateway_state TEXT, reservation_id TEXT,
    gw_version INTEGER, gw_digest TEXT, owner_generation TEXT, reservation_generation TEXT,
    margin_per_unit TEXT, trades_quantity TEXT NOT NULL, order_filled TEXT NOT NULL,
    created_ns INTEGER NOT NULL, expires_ns INTEGER, claimed_ns INTEGER,
    updated_ns INTEGER NOT NULL,
    PRIMARY KEY(scope_key, permit_id), UNIQUE(scope_key, strategy_ref, request_key));
CREATE INDEX risk_pretrade_permits_state ON risk_pretrade_permits(scope_key, state);
CREATE INDEX risk_pretrade_permits_instrument
    ON risk_pretrade_permits(scope_key, instrument_id, state);
CREATE TABLE risk_pretrade_parents (
    scope_key TEXT NOT NULL, strategy_ref TEXT NOT NULL, parent_ref TEXT NOT NULL,
    run_id TEXT, principal_ref TEXT NOT NULL, view_json TEXT NOT NULL,
    view_digest TEXT NOT NULL, instrument_id TEXT NOT NULL, instrument_json TEXT NOT NULL,
    side TEXT NOT NULL, order_offset TEXT NOT NULL, effect TEXT NOT NULL,
    position_side TEXT NOT NULL, bucket TEXT NOT NULL, total_quantity TEXT NOT NULL,
    limit_price TEXT, created_trading_day TEXT NOT NULL,
    valid_until_trading_day TEXT NOT NULL, policy_version INTEGER NOT NULL,
    state TEXT NOT NULL, code TEXT, row_version INTEGER NOT NULL, margin_per_unit TEXT,
    created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL,
    PRIMARY KEY(scope_key, strategy_ref, parent_ref));
CREATE TABLE risk_pretrade_counters (
    scope_key TEXT NOT NULL, instrument_id TEXT NOT NULL, trading_day TEXT NOT NULL,
    kind TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY(scope_key, instrument_id, trading_day, kind));
CREATE TABLE risk_pretrade_latches (
    scope_key TEXT NOT NULL, latch_id TEXT NOT NULL, scope_kind TEXT NOT NULL,
    scope_value TEXT NOT NULL, control TEXT NOT NULL, code TEXT NOT NULL,
    reason TEXT NOT NULL, trading_day TEXT NOT NULL, row_version INTEGER NOT NULL,
    active INTEGER NOT NULL, created_ns INTEGER NOT NULL, released_by TEXT,
    released_ns INTEGER, release_reason TEXT,
    PRIMARY KEY(scope_key, latch_id));
CREATE UNIQUE INDEX risk_pretrade_latches_active
    ON risk_pretrade_latches(scope_key, control, scope_kind, scope_value) WHERE active = 1;
CREATE TABLE risk_pretrade_cursor (
    scope_key TEXT PRIMARY KEY, epoch TEXT, last_sequence INTEGER NOT NULL,
    head_sequence INTEGER, continuity TEXT NOT NULL, verified_from_zero INTEGER NOT NULL,
    gap_reason TEXT, updated_ns INTEGER NOT NULL);
CREATE TABLE risk_pretrade_orders (
    scope_key TEXT NOT NULL, identity TEXT NOT NULL, origin TEXT NOT NULL,
    strategy_ref TEXT, request_key TEXT, reservation_id TEXT, order_ref TEXT, permit_id TEXT,
    instrument_id TEXT NOT NULL, instrument_json TEXT NOT NULL, side TEXT NOT NULL,
    order_offset TEXT, limit_price TEXT, quantity TEXT NOT NULL,
    filled_quantity TEXT NOT NULL, status TEXT NOT NULL, terminal INTEGER NOT NULL,
    counted_order INTEGER NOT NULL, counted_cancel INTEGER NOT NULL,
    counted_reject INTEGER NOT NULL, bypass INTEGER NOT NULL, trading_day TEXT,
    last_epoch TEXT NOT NULL, last_sequence INTEGER NOT NULL, updated_ns INTEGER NOT NULL,
    PRIMARY KEY(scope_key, identity));
CREATE INDEX risk_pretrade_orders_working
    ON risk_pretrade_orders(scope_key, instrument_id, terminal);
CREATE TABLE risk_pretrade_trades (
    scope_key TEXT NOT NULL, trade_id TEXT NOT NULL, identity TEXT NOT NULL,
    permit_id TEXT, strategy_ref TEXT, origin TEXT NOT NULL, instrument_id TEXT NOT NULL,
    side TEXT NOT NULL, order_offset TEXT, position_side TEXT, effect TEXT NOT NULL,
    bucket TEXT NOT NULL, price TEXT NOT NULL, quantity TEXT NOT NULL, trading_day TEXT,
    applied_ns INTEGER NOT NULL, epoch TEXT NOT NULL, sequence INTEGER NOT NULL,
    PRIMARY KEY(scope_key, trade_id));
CREATE TABLE risk_pretrade_positions (
    scope_key TEXT NOT NULL, strategy_ref TEXT NOT NULL, instrument_id TEXT NOT NULL,
    position_side TEXT NOT NULL, quantity TEXT NOT NULL,
    PRIMARY KEY(scope_key, strategy_ref, instrument_id, position_side));
CREATE TABLE risk_pretrade_day_values (
    scope_key TEXT NOT NULL, subject TEXT NOT NULL, trading_day TEXT NOT NULL,
    day_start TEXT, high_water TEXT, updated_ns INTEGER NOT NULL,
    PRIMARY KEY(scope_key, subject, trading_day));
CREATE TABLE risk_pretrade_control_intents (
    scope_key TEXT NOT NULL, cause_id TEXT NOT NULL, mode TEXT NOT NULL,
    scope_kind TEXT NOT NULL, scope_value TEXT NOT NULL, latch_id TEXT, rule TEXT NOT NULL,
    state TEXT NOT NULL, attempts INTEGER NOT NULL, last_outcome TEXT, last_code TEXT,
    gw_version INTEGER, created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL,
    row_version INTEGER NOT NULL, PRIMARY KEY(scope_key, cause_id));
CREATE TABLE risk_pretrade_cancel_intents (
    scope_key TEXT NOT NULL, operation_id TEXT NOT NULL, source TEXT NOT NULL,
    scope_kind TEXT NOT NULL, scope_value TEXT NOT NULL, latch_id TEXT, wait_cause_id TEXT,
    state TEXT NOT NULL, attempts INTEGER NOT NULL, last_outcome TEXT, last_code TEXT,
    created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL, row_version INTEGER NOT NULL,
    PRIMARY KEY(scope_key, operation_id));
CREATE TABLE risk_pretrade_seen_events (
    scope_key TEXT NOT NULL, epoch TEXT NOT NULL, sequence INTEGER NOT NULL,
    PRIMARY KEY(scope_key, epoch, sequence));
CREATE TABLE risk_pretrade_audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, scope_key TEXT NOT NULL, at_ns INTEGER NOT NULL,
    kind TEXT NOT NULL, strategy_ref TEXT, request_key TEXT, permit_id TEXT,
    instrument_id TEXT, effect TEXT, policy_version INTEGER, code TEXT,
    detail_json TEXT NOT NULL, writer_owner_id TEXT NOT NULL,
    writer_fencing_token INTEGER NOT NULL);
CREATE TRIGGER risk_pretrade_audit_no_update BEFORE UPDATE ON risk_pretrade_audit BEGIN
    SELECT RAISE(ABORT, 'risk_pretrade_audit is append only'); END;
CREATE TRIGGER risk_pretrade_audit_no_delete BEFORE DELETE ON risk_pretrade_audit BEGIN
    SELECT RAISE(ABORT, 'risk_pretrade_audit is append only'); END;
CREATE TRIGGER risk_pretrade_policy_versions_no_update
    BEFORE UPDATE ON risk_pretrade_policy_versions BEGIN
    SELECT RAISE(ABORT, 'risk_pretrade_policy_versions are immutable'); END;
CREATE TRIGGER risk_pretrade_policy_versions_no_delete
    BEFORE DELETE ON risk_pretrade_policy_versions BEGIN
    SELECT RAISE(ABORT, 'risk_pretrade_policy_versions are immutable'); END;
CREATE TRIGGER risk_pretrade_trades_no_update BEFORE UPDATE ON risk_pretrade_trades BEGIN
    SELECT RAISE(ABORT, 'risk_pretrade_trades are immutable'); END;
CREATE TRIGGER risk_pretrade_trades_no_delete BEFORE DELETE ON risk_pretrade_trades BEGIN
    SELECT RAISE(ABORT, 'risk_pretrade_trades are immutable'); END;
"""

# Columns that a conditional update may set (fixed allowlists, never caller input).
_PERMIT_UPDATABLE = frozenset(
    {
        "state",
        "code",
        "gateway_code",
        "gateway_state",
        "reservation_id",
        "gw_version",
        "gw_digest",
        "owner_generation",
        "reservation_generation",
        "trades_quantity",
        "order_filled",
        "claimed_ns",
        "expires_ns",
        "updated_ns",
    }
)
_PARENT_UPDATABLE = frozenset({"state", "code", "updated_ns"})
_INTENT_UPDATABLE = frozenset(
    {"state", "attempts", "last_outcome", "last_code", "gw_version", "updated_ns"}
)


def D(value: str | None) -> Decimal | None:
    return None if value is None else Decimal(value)


def T(value: Decimal | None) -> str | None:
    if value is None:
        return None
    text = format(value.normalize(), "f")
    return "0" if text in ("-0", "") else text


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class Permit:
    """One permit row (exact decimals)."""

    permit_id: str
    strategy_ref: str
    request_key: str
    run_id: str | None
    principal_ref: str
    origin: str
    view_json: str
    view_digest: str
    payload_json: str
    payload_digest: str
    instrument_id: str
    instrument_json: str
    side: str
    offset: str
    effect: str
    position_side: str
    bucket: str
    quantity: Decimal
    limit_price: Decimal | None
    parent_ref: str | None
    child_id: str | None
    trading_day: str
    policy_version: int
    state: str
    row_version: int
    code: str | None
    gateway_code: str | None
    gateway_state: str | None
    reservation_id: str | None
    gw_version: int | None
    gw_digest: str | None
    owner_generation: str | None
    reservation_generation: str | None
    margin_per_unit: Decimal | None
    trades_quantity: Decimal
    order_filled: Decimal
    created_ns: int
    expires_ns: int | None
    claimed_ns: int | None
    updated_ns: int

    @property
    def occupancy(self) -> Decimal:
        """Worst-case in-flight quantity still occupied by this permit."""
        if self.state in OCCUPYING_STATES:
            return max(Decimal(0), self.quantity - self.trades_quantity)
        if self.state == "TERMINAL":
            # Fills reported on the order but not yet seen as trades stay occupied.
            return max(Decimal(0), self.order_filled - self.trades_quantity)
        return Decimal(0)

    @property
    def allocation(self) -> Decimal:
        """Quantity drawn from a parent envelope by this child."""
        if self.state in ("DENIED", "RELEASED"):
            return Decimal(0)
        if self.state == "TERMINAL":
            return max(self.order_filled, self.trades_quantity)
        return self.quantity


@dataclass(frozen=True)
class Parent:
    strategy_ref: str
    parent_ref: str
    run_id: str | None
    principal_ref: str
    view_json: str
    view_digest: str
    instrument_id: str
    instrument_json: str
    side: str
    offset: str
    effect: str
    position_side: str
    bucket: str
    total_quantity: Decimal
    limit_price: Decimal | None
    created_trading_day: str
    valid_until_trading_day: str
    policy_version: int
    state: str
    code: str | None
    row_version: int
    margin_per_unit: Decimal | None
    created_ns: int
    updated_ns: int


def _permit(row: sqlite3.Row) -> Permit:
    return Permit(
        permit_id=row["permit_id"],
        strategy_ref=row["strategy_ref"],
        request_key=row["request_key"],
        run_id=row["run_id"],
        principal_ref=row["principal_ref"],
        origin=row["origin"],
        view_json=row["view_json"],
        view_digest=row["view_digest"],
        payload_json=row["payload_json"],
        payload_digest=row["payload_digest"],
        instrument_id=row["instrument_id"],
        instrument_json=row["instrument_json"],
        side=row["side"],
        offset=row["order_offset"],
        effect=row["effect"],
        position_side=row["position_side"],
        bucket=row["bucket"],
        quantity=Decimal(row["quantity"]),
        limit_price=D(row["limit_price"]),
        parent_ref=row["parent_ref"],
        child_id=row["child_id"],
        trading_day=row["trading_day"],
        policy_version=row["policy_version"],
        state=row["state"],
        row_version=row["row_version"],
        code=row["code"],
        gateway_code=row["gateway_code"],
        gateway_state=row["gateway_state"],
        reservation_id=row["reservation_id"],
        gw_version=row["gw_version"],
        gw_digest=row["gw_digest"],
        owner_generation=row["owner_generation"],
        reservation_generation=row["reservation_generation"],
        margin_per_unit=D(row["margin_per_unit"]),
        trades_quantity=Decimal(row["trades_quantity"]),
        order_filled=Decimal(row["order_filled"]),
        created_ns=row["created_ns"],
        expires_ns=row["expires_ns"],
        claimed_ns=row["claimed_ns"],
        updated_ns=row["updated_ns"],
    )


def _parent(row: sqlite3.Row) -> Parent:
    return Parent(
        strategy_ref=row["strategy_ref"],
        parent_ref=row["parent_ref"],
        run_id=row["run_id"],
        principal_ref=row["principal_ref"],
        view_json=row["view_json"],
        view_digest=row["view_digest"],
        instrument_id=row["instrument_id"],
        instrument_json=row["instrument_json"],
        side=row["side"],
        offset=row["order_offset"],
        effect=row["effect"],
        position_side=row["position_side"],
        bucket=row["bucket"],
        total_quantity=Decimal(row["total_quantity"]),
        limit_price=D(row["limit_price"]),
        created_trading_day=row["created_trading_day"],
        valid_until_trading_day=row["valid_until_trading_day"],
        policy_version=row["policy_version"],
        state=row["state"],
        code=row["code"],
        row_version=row["row_version"],
        margin_per_unit=D(row["margin_per_unit"]),
        created_ns=row["created_ns"],
        updated_ns=row["updated_ns"],
    )


class LedgerTxn:
    """Operations inside one ``BEGIN IMMEDIATE`` transaction under the writer fence."""

    def __init__(self, connection: sqlite3.Connection, scope_key: str, fence) -> None:
        self._c = connection
        self._scope = scope_key
        self._fence = fence

    # ------------------------------------------------------------ generic helpers

    def _one(self, sql: str, args: tuple) -> sqlite3.Row | None:
        return self._c.execute(sql, args).fetchone()

    def _all(self, sql: str, args: tuple) -> list[sqlite3.Row]:
        return self._c.execute(sql, args).fetchall()

    def _cas(
        self,
        table: str,
        keys: Mapping[str, Any],
        expected: int,
        fields: Mapping[str, Any],
        allowed: frozenset[str],
    ) -> bool:
        if not fields or not set(fields) <= allowed:
            raise RiskOrderJournalError("PRETRADE_UPDATE_INVALID")
        assignments = ", ".join(name + "=?" for name in sorted(fields))
        where = " AND ".join(name + "=?" for name in sorted(keys))
        sql = (
            "UPDATE " + table + " SET " + assignments + ", row_version=row_version+1 "  # noqa: S608
            "WHERE scope_key=? AND " + where + " AND row_version=?"
        )
        args = tuple(fields[name] for name in sorted(fields))
        args += (self._scope,) + tuple(keys[name] for name in sorted(keys)) + (expected,)
        return self._c.execute(sql, args).rowcount == 1

    # ------------------------------------------------------------ policy versions

    def latest_policy(self) -> sqlite3.Row | None:
        return self._one(
            "SELECT * FROM risk_pretrade_policy_versions WHERE scope_key=? "
            "ORDER BY version DESC LIMIT 1",
            (self._scope,),
        )

    def insert_policy(
        self,
        *,
        version: int,
        policy_id: str,
        digest: str,
        document_json: str,
        exchange_rules_text: str | None,
        published_ns: int,
        operator_ref: str,
        reason: str | None,
        classification_json: str,
    ) -> None:
        self._c.execute(
            "INSERT INTO risk_pretrade_policy_versions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                self._scope,
                version,
                policy_id,
                digest,
                document_json,
                exchange_rules_text,
                published_ns,
                operator_ref,
                reason,
                classification_json,
                self._fence.owner_id,
                self._fence.fencing_token,
            ),
        )

    # ------------------------------------------------------------ permits

    def insert_permit(self, values: Mapping[str, Any]) -> None:
        columns = (
            "permit_id",
            "strategy_ref",
            "request_key",
            "run_id",
            "principal_ref",
            "origin",
            "view_json",
            "view_digest",
            "payload_json",
            "payload_digest",
            "instrument_id",
            "instrument_json",
            "side",
            "order_offset",
            "effect",
            "position_side",
            "bucket",
            "quantity",
            "limit_price",
            "parent_ref",
            "child_id",
            "trading_day",
            "policy_version",
            "state",
            "row_version",
            "code",
            "gateway_code",
            "gateway_state",
            "reservation_id",
            "gw_version",
            "gw_digest",
            "owner_generation",
            "reservation_generation",
            "margin_per_unit",
            "trades_quantity",
            "order_filled",
            "created_ns",
            "expires_ns",
            "claimed_ns",
            "updated_ns",
        )
        row = {name: values.get(name) for name in columns}
        row["row_version"] = 1
        row["trades_quantity"] = row["trades_quantity"] or "0"
        row["order_filled"] = row["order_filled"] or "0"
        self._c.execute(
            "INSERT INTO risk_pretrade_permits (scope_key, " + ", ".join(columns) + ") "
            "VALUES (?" + ",?" * len(columns) + ")",
            (self._scope,) + tuple(row[name] for name in columns),
        )

    def permit(self, permit_id: str) -> Permit | None:
        row = self._one(
            "SELECT * FROM risk_pretrade_permits WHERE scope_key=? AND permit_id=?",
            (self._scope, permit_id),
        )
        return None if row is None else _permit(row)

    def permit_by_key(self, strategy_ref: str, request_key: str) -> Permit | None:
        row = self._one(
            "SELECT * FROM risk_pretrade_permits WHERE scope_key=? AND strategy_ref=? "
            "AND request_key=?",
            (self._scope, strategy_ref, request_key),
        )
        return None if row is None else _permit(row)

    def permits_in(self, states: tuple[str, ...], instrument_id: str | None = None) -> list[Permit]:
        marks = ",".join("?" * len(states))
        if instrument_id is None:
            rows = self._all(
                "SELECT * FROM risk_pretrade_permits WHERE scope_key=? "  # noqa: S608
                "AND state IN (" + marks + ") ORDER BY created_ns, permit_id",
                (self._scope, *states),
            )
        else:
            rows = self._all(
                "SELECT * FROM risk_pretrade_permits WHERE scope_key=? AND instrument_id=? "  # noqa: S608
                "AND state IN (" + marks + ") ORDER BY created_ns, permit_id",
                (self._scope, instrument_id, *states),
            )
        return [_permit(row) for row in rows]

    def terminal_with_pending_fills(self, instrument_id: str) -> list[Permit]:
        rows = self._all(
            "SELECT * FROM risk_pretrade_permits WHERE scope_key=? AND instrument_id=? "
            "AND state='TERMINAL'",
            (self._scope, instrument_id),
        )
        permits = [_permit(row) for row in rows]
        return [permit for permit in permits if permit.occupancy > 0]

    def permits_since(self, strategy_ref: str, instrument_id: str, since_ns: int) -> list[Permit]:
        rows = self._all(
            "SELECT * FROM risk_pretrade_permits WHERE scope_key=? AND strategy_ref=? "
            "AND instrument_id=? AND created_ns>=? AND state<>'DENIED'",
            (self._scope, strategy_ref, instrument_id, since_ns),
        )
        return [_permit(row) for row in rows]

    def claims_since(self, strategy_ref: str, since_ns: int) -> int:
        row = self._one(
            "SELECT COUNT(*) FROM risk_pretrade_permits WHERE scope_key=? AND strategy_ref=? "
            "AND claimed_ns IS NOT NULL AND claimed_ns>=?",
            (self._scope, strategy_ref, since_ns),
        )
        return int(row[0])

    def children(self, strategy_ref: str, parent_ref: str) -> list[Permit]:
        rows = self._all(
            "SELECT * FROM risk_pretrade_permits WHERE scope_key=? AND strategy_ref=? "
            "AND parent_ref=?",
            (self._scope, strategy_ref, parent_ref),
        )
        return [_permit(row) for row in rows]

    def update_permit(self, permit_id: str, expected_row_version: int, **fields: Any) -> bool:
        """Conditional update: succeeds only if the row version is unchanged."""
        return self._cas(
            "risk_pretrade_permits",
            {"permit_id": permit_id},
            expected_row_version,
            fields,
            _PERMIT_UPDATABLE,
        )

    def transition(self, permit: Permit, from_states: tuple[str, ...], **fields: Any) -> bool:
        """Conditional state change; the permit must still be in one of ``from_states``."""
        if permit.state not in from_states:
            return False
        return self.update_permit(permit.permit_id, permit.row_version, **fields)

    # ------------------------------------------------------------ parents

    def insert_parent(self, values: Mapping[str, Any]) -> None:
        columns = (
            "strategy_ref",
            "parent_ref",
            "run_id",
            "principal_ref",
            "view_json",
            "view_digest",
            "instrument_id",
            "instrument_json",
            "side",
            "order_offset",
            "effect",
            "position_side",
            "bucket",
            "total_quantity",
            "limit_price",
            "created_trading_day",
            "valid_until_trading_day",
            "policy_version",
            "state",
            "code",
            "row_version",
            "margin_per_unit",
            "created_ns",
            "updated_ns",
        )
        row = {name: values.get(name) for name in columns}
        row["row_version"] = 1
        self._c.execute(
            "INSERT INTO risk_pretrade_parents (scope_key, " + ", ".join(columns) + ") "
            "VALUES (?" + ",?" * len(columns) + ")",
            (self._scope,) + tuple(row[name] for name in columns),
        )

    def parent(self, strategy_ref: str, parent_ref: str) -> Parent | None:
        row = self._one(
            "SELECT * FROM risk_pretrade_parents WHERE scope_key=? AND strategy_ref=? "
            "AND parent_ref=?",
            (self._scope, strategy_ref, parent_ref),
        )
        return None if row is None else _parent(row)

    def holding_parents(self, instrument_id: str | None = None) -> list[Parent]:
        if instrument_id is None:
            rows = self._all(
                "SELECT * FROM risk_pretrade_parents WHERE scope_key=? "
                "AND state IN ('ACTIVE','FROZEN')",
                (self._scope,),
            )
        else:
            rows = self._all(
                "SELECT * FROM risk_pretrade_parents WHERE scope_key=? AND instrument_id=? "
                "AND state IN ('ACTIVE','FROZEN')",
                (self._scope, instrument_id),
            )
        return [_parent(row) for row in rows]

    def update_parent(self, parent: Parent, **fields: Any) -> bool:
        return self._cas(
            "risk_pretrade_parents",
            {"strategy_ref": parent.strategy_ref, "parent_ref": parent.parent_ref},
            parent.row_version,
            fields,
            _PARENT_UPDATABLE,
        )

    # ------------------------------------------------------------ counters

    def counter(self, instrument_id: str, trading_day: str, kind: str) -> Decimal:
        row = self._one(
            "SELECT value FROM risk_pretrade_counters WHERE scope_key=? AND instrument_id=? "
            "AND trading_day=? AND kind=?",
            (self._scope, instrument_id, trading_day, kind),
        )
        return Decimal(0) if row is None else Decimal(row[0])

    def add_counter(
        self, instrument_id: str, trading_day: str, kind: str, delta: Decimal
    ) -> Decimal:
        value = self.counter(instrument_id, trading_day, kind) + delta
        self._c.execute(
            "INSERT INTO risk_pretrade_counters VALUES (?,?,?,?,?) ON CONFLICT"
            "(scope_key, instrument_id, trading_day, kind) DO UPDATE SET value=excluded.value",
            (self._scope, instrument_id, trading_day, kind, T(value)),
        )
        return value

    def counters_for_day(self, trading_day: str) -> list[sqlite3.Row]:
        return self._all(
            "SELECT instrument_id, kind, value FROM risk_pretrade_counters WHERE scope_key=? "
            "AND trading_day=? ORDER BY instrument_id, kind",
            (self._scope, trading_day),
        )

    # ------------------------------------------------------------ latches

    def active_latches(self) -> list[sqlite3.Row]:
        return self._all(
            "SELECT * FROM risk_pretrade_latches WHERE scope_key=? AND active=1 "
            "ORDER BY created_ns, latch_id",
            (self._scope,),
        )

    def all_latches(self) -> list[sqlite3.Row]:
        return self._all(
            "SELECT * FROM risk_pretrade_latches WHERE scope_key=? ORDER BY created_ns, latch_id",
            (self._scope,),
        )

    def latch(self, latch_id: str) -> sqlite3.Row | None:
        return self._one(
            "SELECT * FROM risk_pretrade_latches WHERE scope_key=? AND latch_id=?",
            (self._scope, latch_id),
        )

    def ensure_latch(
        self,
        *,
        scope_kind: str,
        scope_value: str,
        control: str,
        code: str,
        reason: str,
        trading_day: str,
        now_ns: int,
    ) -> tuple[sqlite3.Row, bool]:
        row = self._one(
            "SELECT * FROM risk_pretrade_latches WHERE scope_key=? AND control=? "
            "AND scope_kind=? AND scope_value=? AND active=1",
            (self._scope, control, scope_kind, scope_value),
        )
        if row is not None:
            return row, False
        latch_id = uuid.uuid4().hex
        self._c.execute(
            "INSERT INTO risk_pretrade_latches VALUES (?,?,?,?,?,?,?,?,1,1,?,NULL,NULL,NULL)",
            (
                self._scope,
                latch_id,
                scope_kind,
                scope_value,
                control,
                code,
                reason,
                trading_day,
                now_ns,
            ),
        )
        return self.latch(latch_id), True  # type: ignore[return-value]

    def release_latch(
        self,
        latch_id: str,
        expected_row_version: int,
        *,
        released_by: str,
        released_ns: int,
        release_reason: str,
    ) -> bool:
        cursor = self._c.execute(
            "UPDATE risk_pretrade_latches SET active=0, released_by=?, released_ns=?, "
            "release_reason=?, row_version=row_version+1 WHERE scope_key=? AND latch_id=? "
            "AND active=1 AND row_version=?",
            (released_by, released_ns, release_reason, self._scope, latch_id, expected_row_version),
        )
        return cursor.rowcount == 1

    # ------------------------------------------------------------ observation cursor

    def cursor(self) -> dict[str, Any]:
        row = self._one("SELECT * FROM risk_pretrade_cursor WHERE scope_key=?", (self._scope,))
        if row is None:
            return {
                "epoch": None,
                "last_sequence": -1,
                "head_sequence": None,
                "continuity": "UNVERIFIED",
                "verified_from_zero": 0,
                "gap_reason": "never_started",
            }
        return dict(row)

    def save_cursor(self, cursor: Mapping[str, Any], now_ns: int) -> None:
        self._c.execute(
            "INSERT INTO risk_pretrade_cursor VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(scope_key) "
            "DO UPDATE SET epoch=excluded.epoch, last_sequence=excluded.last_sequence, "
            "head_sequence=excluded.head_sequence, continuity=excluded.continuity, "
            "verified_from_zero=excluded.verified_from_zero, gap_reason=excluded.gap_reason, "
            "updated_ns=excluded.updated_ns",
            (
                self._scope,
                cursor["epoch"],
                cursor["last_sequence"],
                cursor["head_sequence"],
                cursor["continuity"],
                cursor["verified_from_zero"],
                cursor["gap_reason"],
                now_ns,
            ),
        )

    def mark_seen(self, epoch: str, sequence: int) -> bool:
        cursor = self._c.execute(
            "INSERT OR IGNORE INTO risk_pretrade_seen_events VALUES (?,?,?)",
            (self._scope, epoch, sequence),
        )
        return cursor.rowcount == 1

    # ------------------------------------------------------------ observed orders and trades

    def order(self, identity: str) -> sqlite3.Row | None:
        return self._one(
            "SELECT * FROM risk_pretrade_orders WHERE scope_key=? AND identity=?",
            (self._scope, identity),
        )

    def insert_order(self, values: Mapping[str, Any]) -> None:
        columns = (
            "identity",
            "origin",
            "strategy_ref",
            "request_key",
            "reservation_id",
            "order_ref",
            "permit_id",
            "instrument_id",
            "instrument_json",
            "side",
            "order_offset",
            "limit_price",
            "quantity",
            "filled_quantity",
            "status",
            "terminal",
            "counted_order",
            "counted_cancel",
            "counted_reject",
            "bypass",
            "trading_day",
            "last_epoch",
            "last_sequence",
            "updated_ns",
        )
        self._c.execute(
            "INSERT INTO risk_pretrade_orders (scope_key, " + ", ".join(columns) + ") "
            "VALUES (?" + ",?" * len(columns) + ")",
            (self._scope,) + tuple(values.get(name) for name in columns),
        )

    def update_order(self, identity: str, values: Mapping[str, Any]) -> None:
        allowed = {
            "status",
            "terminal",
            "filled_quantity",
            "limit_price",
            "counted_order",
            "counted_cancel",
            "counted_reject",
            "last_epoch",
            "last_sequence",
            "updated_ns",
            "permit_id",
            "reservation_id",
            "order_ref",
        }
        if not values or not set(values) <= allowed:
            raise RiskOrderJournalError("PRETRADE_UPDATE_INVALID")
        names = sorted(values)
        assignments = ", ".join(n + "=?" for n in names)  # names from the fixed allowlist
        self._c.execute(
            "UPDATE risk_pretrade_orders SET " + assignments + " WHERE scope_key=? AND identity=?",  # noqa: S608
            tuple(values[n] for n in names) + (self._scope, identity),
        )

    def working_orders(self, instrument_id: str) -> list[sqlite3.Row]:
        return self._all(
            "SELECT * FROM risk_pretrade_orders WHERE scope_key=? AND instrument_id=? "
            "AND terminal=0 AND permit_id IS NULL",
            (self._scope, instrument_id),
        )

    def bypass_count(self) -> int:
        row = self._one(
            "SELECT COUNT(*) FROM risk_pretrade_orders WHERE scope_key=? AND bypass=1",
            (self._scope,),
        )
        return int(row[0])

    def has_trade(self, trade_id: str) -> bool:
        return (
            self._one(
                "SELECT 1 FROM risk_pretrade_trades WHERE scope_key=? AND trade_id=?",
                (self._scope, trade_id),
            )
            is not None
        )

    def insert_trade(self, values: Mapping[str, Any]) -> None:
        columns = (
            "trade_id",
            "identity",
            "permit_id",
            "strategy_ref",
            "origin",
            "instrument_id",
            "side",
            "order_offset",
            "position_side",
            "effect",
            "bucket",
            "price",
            "quantity",
            "trading_day",
            "applied_ns",
            "epoch",
            "sequence",
        )
        self._c.execute(
            "INSERT INTO risk_pretrade_trades (scope_key, " + ", ".join(columns) + ") "
            "VALUES (?" + ",?" * len(columns) + ")",
            (self._scope,) + tuple(values.get(name) for name in columns),
        )

    def trades_after(self, instrument_id: str, after_ns: int) -> list[sqlite3.Row]:
        return self._all(
            "SELECT * FROM risk_pretrade_trades WHERE scope_key=? AND instrument_id=? "
            "AND applied_ns>?",
            (self._scope, instrument_id, after_ns),
        )

    # ------------------------------------------------------------ positions

    def position(self, strategy_ref: str, instrument_id: str, position_side: str) -> Decimal:
        row = self._one(
            "SELECT quantity FROM risk_pretrade_positions WHERE scope_key=? AND strategy_ref=? "
            "AND instrument_id=? AND position_side=?",
            (self._scope, strategy_ref, instrument_id, position_side),
        )
        return Decimal(0) if row is None else Decimal(row[0])

    def add_position(
        self, strategy_ref: str, instrument_id: str, position_side: str, delta: Decimal
    ) -> None:
        value = self.position(strategy_ref, instrument_id, position_side) + delta
        self._c.execute(
            "INSERT INTO risk_pretrade_positions VALUES (?,?,?,?,?) ON CONFLICT"
            "(scope_key, strategy_ref, instrument_id, position_side) "
            "DO UPDATE SET quantity=excluded.quantity",
            (self._scope, strategy_ref, instrument_id, position_side, T(value)),
        )

    # ------------------------------------------------------------ day values (R-07)

    def day_value(self, subject: str, trading_day: str) -> sqlite3.Row | None:
        return self._one(
            "SELECT * FROM risk_pretrade_day_values WHERE scope_key=? AND subject=? "
            "AND trading_day=?",
            (self._scope, subject, trading_day),
        )

    def set_day_value(
        self,
        subject: str,
        trading_day: str,
        *,
        day_start: Decimal | None,
        high_water: Decimal | None,
        now_ns: int,
    ) -> None:
        self._c.execute(
            "INSERT INTO risk_pretrade_day_values VALUES (?,?,?,?,?,?) ON CONFLICT"
            "(scope_key, subject, trading_day) DO UPDATE SET day_start=excluded.day_start, "
            "high_water=excluded.high_water, updated_ns=excluded.updated_ns",
            (self._scope, subject, trading_day, T(day_start), T(high_water), now_ns),
        )

    # ------------------------------------------------------------ control and cancel intents

    def control_intent(self, cause_id: str) -> sqlite3.Row | None:
        return self._one(
            "SELECT * FROM risk_pretrade_control_intents WHERE scope_key=? AND cause_id=?",
            (self._scope, cause_id),
        )

    def ensure_control_intent(
        self,
        *,
        cause_id: str,
        mode: str,
        scope_kind: str,
        scope_value: str,
        latch_id: str | None,
        rule: str,
        now_ns: int,
    ) -> bool:
        cursor = self._c.execute(
            "INSERT OR IGNORE INTO risk_pretrade_control_intents VALUES "
            "(?,?,?,?,?,?,?,'PENDING',0,NULL,NULL,NULL,?,?,1)",
            (self._scope, cause_id, mode, scope_kind, scope_value, latch_id, rule, now_ns, now_ns),
        )
        return cursor.rowcount == 1

    def control_intents(self, states: tuple[str, ...] | None = None) -> list[sqlite3.Row]:
        if states is None:
            return self._all(
                "SELECT * FROM risk_pretrade_control_intents WHERE scope_key=? "
                "ORDER BY created_ns, cause_id",
                (self._scope,),
            )
        marks = ",".join("?" * len(states))
        return self._all(
            "SELECT * FROM risk_pretrade_control_intents WHERE scope_key=? "  # noqa: S608
            "AND state IN (" + marks + ") ORDER BY created_ns, cause_id",
            (self._scope, *states),
        )

    def update_control_intent(
        self, cause_id: str, expected_row_version: int, **fields: Any
    ) -> bool:
        return self._cas(
            "risk_pretrade_control_intents",
            {"cause_id": cause_id},
            expected_row_version,
            fields,
            _INTENT_UPDATABLE,
        )

    def cancel_intent(self, operation_id: str) -> sqlite3.Row | None:
        return self._one(
            "SELECT * FROM risk_pretrade_cancel_intents WHERE scope_key=? AND operation_id=?",
            (self._scope, operation_id),
        )

    def ensure_cancel_intent(
        self,
        *,
        operation_id: str,
        source: str,
        scope_kind: str,
        scope_value: str,
        latch_id: str | None,
        wait_cause_id: str | None,
        now_ns: int,
    ) -> bool:
        state = "PENDING" if wait_cause_id is None else "WAITING_CONTROL"
        cursor = self._c.execute(
            "INSERT OR IGNORE INTO risk_pretrade_cancel_intents VALUES "
            "(?,?,?,?,?,?,?,?,0,NULL,NULL,?,?,1)",
            (
                self._scope,
                operation_id,
                source,
                scope_kind,
                scope_value,
                latch_id,
                wait_cause_id,
                state,
                now_ns,
                now_ns,
            ),
        )
        return cursor.rowcount == 1

    def cancel_intents(self, states: tuple[str, ...] | None = None) -> list[sqlite3.Row]:
        if states is None:
            return self._all(
                "SELECT * FROM risk_pretrade_cancel_intents WHERE scope_key=? "
                "ORDER BY created_ns, operation_id",
                (self._scope,),
            )
        marks = ",".join("?" * len(states))
        return self._all(
            "SELECT * FROM risk_pretrade_cancel_intents WHERE scope_key=? "  # noqa: S608
            "AND state IN (" + marks + ") ORDER BY created_ns, operation_id",
            (self._scope, *states),
        )

    def update_cancel_intent(
        self, operation_id: str, expected_row_version: int, **fields: Any
    ) -> bool:
        return self._cas(
            "risk_pretrade_cancel_intents",
            {"operation_id": operation_id},
            expected_row_version,
            fields,
            _INTENT_UPDATABLE,
        )

    # ------------------------------------------------------------ audit

    def audit(
        self,
        kind: str,
        *,
        at_ns: int,
        strategy_ref: str | None = None,
        request_key: str | None = None,
        permit_id: str | None = None,
        instrument_id: str | None = None,
        effect: str | None = None,
        policy_version: int | None = None,
        code: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        self._c.execute(
            "INSERT INTO risk_pretrade_audit (scope_key, at_ns, kind, strategy_ref, request_key, "
            "permit_id, instrument_id, effect, policy_version, code, detail_json, "
            "writer_owner_id, writer_fencing_token) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                self._scope,
                at_ns,
                kind,
                strategy_ref,
                request_key,
                permit_id,
                instrument_id,
                effect,
                policy_version,
                code,
                canonical(dict(detail or {})),
                self._fence.owner_id,
                self._fence.fencing_token,
            ),
        )

    def read_audit(self, after: int, limit: int) -> list[sqlite3.Row]:
        return self._all(
            "SELECT seq, at_ns, kind, strategy_ref, request_key, permit_id, instrument_id, "
            "effect, policy_version, code, detail_json FROM risk_pretrade_audit "
            "WHERE scope_key=? AND seq>? ORDER BY seq LIMIT ?",
            (self._scope, after, limit),
        )


class PretradeLedger:
    """Fence-bound access to the ``risk_pretrade_*`` schema.

    Creation is an explicit, transactional, additive schema installation. The
    object is bound to the creating thread, process, journal and the current
    writer fence; another process cannot hold the same account fence at once.
    """

    def __init__(self, journal: RiskOrderJournal, fence: RiskOrderWriterFence) -> None:
        if not isinstance(journal, RiskOrderJournal) or type(fence) is not RiskOrderWriterFence:
            raise RiskOrderJournalError("PRETRADE_WRITER_REQUIRED")
        self._journal, self._fence = journal, fence
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._check()
        with journal._transaction() as connection:
            journal._assert_current_in(connection, fence)
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='risk_pretrade_meta'"
            ).fetchone()
            if exists is None:
                for statement in _split_statements(_SCHEMA):
                    connection.execute(statement)
                connection.execute("INSERT INTO risk_pretrade_meta VALUES (?)", (SCHEMA_VERSION,))
            self._check_schema(connection)
            journal._assert_current_in(connection, fence)

    @staticmethod
    def _check_schema(connection: sqlite3.Connection) -> None:
        versions = connection.execute("SELECT schema_version FROM risk_pretrade_meta").fetchall()
        tables = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'risk_pretrade_%'"
        ).fetchone()[0]
        triggers = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
            "AND name LIKE 'risk_pretrade_%'"
        ).fetchone()[0]
        if (
            len(versions) != 1
            or versions[0][0] != SCHEMA_VERSION
            or tables != len(_TABLES)
            or triggers != len(_TRIGGERS)
        ):
            raise RiskOrderJournalError("PRETRADE_SCHEMA_MISMATCH")

    def _check(self) -> None:
        if (
            os.getpid() != self._pid
            or threading.current_thread() is not self._thread
            or self._fence.owner_id != self._journal._owner_id
        ):
            raise RiskOrderJournalError("PRETRADE_WRITER_NOT_OWNED")
        self._journal._assert_current(self._fence)

    @property
    def fence(self) -> RiskOrderWriterFence:
        self._check()
        return self._fence

    @contextmanager
    def transaction(self) -> Iterator[LedgerTxn]:
        """One ``BEGIN IMMEDIATE`` transaction asserting the fence on entry and before commit."""
        self._check()
        journal, fence = self._journal, self._fence
        with journal._transaction() as connection:
            journal._assert_current_in(connection, fence)
            yield LedgerTxn(connection, fence.scope.key, fence)
            journal._assert_current_in(connection, fence)


def _split_statements(script: str) -> list[str]:
    """Split the fixed schema script; triggers contain inner semicolons ending with END;."""
    statements: list[str] = []
    buffer: list[str] = []
    in_trigger = False
    for line in script.strip().splitlines():
        buffer.append(line)
        stripped = line.strip()
        if stripped.startswith("CREATE TRIGGER"):
            in_trigger = True
        if (in_trigger and stripped.endswith("END;")) or (
            not in_trigger and stripped.endswith(";")
        ):
            statements.append("\n".join(buffer).strip())
            buffer = []
            in_trigger = False
    if buffer:
        raise RiskOrderJournalError("PRETRADE_SCHEMA_SCRIPT_INVALID")
    return statements


__all__ = [
    "FINAL_STATES",
    "LedgerTxn",
    "OCCUPYING_STATES",
    "Parent",
    "Permit",
    "PretradeLedger",
    "SCHEMA_VERSION",
    "WORKING_STATES",
    "canonical",
]
