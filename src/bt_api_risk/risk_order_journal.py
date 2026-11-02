"""Durable, provider-observation journal for the risk-only order owner.

This is a small dispatch/idempotency journal, not an order-management system.
Provider APIs remain the authority for order and fill facts.  The journal keeps
the one allowed dispatch attempt, the normalized observations and a durable
reference to the Risk reservation used to resolve that attempt.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import replace
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from functools import partial
from pathlib import Path
from types import MappingProxyType
from typing import Any

from bt_api_risk.risk_order_journal_storage import RiskOrderJournalStorage
from bt_api_risk.risk_order_journal_contracts import (
    CancelResolutionTargetBindingV1,
    DispatchProofRecoverySource,
    RiskOrderCommand,
    RiskOrderJournalError,
    RiskOrderJournalEvent,
    RiskOrderWriterFence,
    _require_sha256,
)
from bt_api_risk.position_baseline import (
    PositionBaselineError,
    require_matching_revaluation,
    revalue_position_facts,
    strategy_baseline_totals,
    summarize_position_rows,
)

from bt_api_risk import (
    AccountPositionRiskFact,
    AccountScope,
    CancelDispatchResolutionProof,
    DispatchClaimBinding,
    DispatchEvidenceClass,
    DispatchExposureResolutionProof,
    DispatchExposureResolutionReceipt,
    DispatchExposureResolutionReceiptStatus,
    DispatchRecoveryAttestation,
    DispatchResolutionReceipt,
    DispatchResolutionReceiptStatus,
    DispatchTerminalProof,
    DispatchTerminalResolutionReceipt,
    DispatchTerminalResolutionReceiptStatus,
    DispatchTerminalState,
    DispatchTrackedOrderProof,
    GrossExposureBaselineProof,
    InstrumentRiskFxRate,
    OrderExposureObservationProof,
    OrderExposureState,
    OrderFillFact,
    PositionSnapshotCoverage,
    VerifiedDispatchExposureResolution,
    VerifiedDispatchRecoveryResolution,
    VerifiedDispatchResolution,
    VerifiedCancelDispatchResolution,
    VerifiedGrossExposureBaseline,
    VerifiedOrderExposureObservation,
)

_SHA256_LENGTH = 64
_WIRE_SCOPE_KEYS = frozenset(
    {
        "account_ref",
        "account_refs",
        "execution_domain_ref",
        "group_id",
        "leg_id",
        "manual_book_ref",
        "portfolio_ref",
        "run_id",
        "strategy_ref",
    }
)
_PROCESS_LOCK_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_THREAD_FENCES = threading.local()


def canonical_json(value: Any) -> str:
    """Encode the deliberately scalar journal DTOs without lossy defaults."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        raise RiskOrderJournalError("JOURNAL_PAYLOAD_INVALID") from None


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


def _position_dimensions_from_payload(payload: object) -> tuple[str, str]:
    from bt_api_risk.position_payload import RiskPositionPayloadError, position_dimensions_from_payload

    try:
        return position_dimensions_from_payload(payload)
    except RiskPositionPayloadError as exc:
        raise RiskOrderJournalError(exc.code) from None


def _position_dimensions_match(payload: object, expected: tuple[str, str]) -> bool:
    from bt_api_risk.position_payload import position_dimensions_match

    return position_dimensions_match(payload, expected)


def _terminal_close_proof_payload(proof: DispatchExposureResolutionProof) -> dict[str, Any]:
    from bt_api_risk.order_proof_payload import RiskOrderProofPayloadError, terminal_close_proof_payload

    try:
        return terminal_close_proof_payload(proof, decimal_text=_decimal_text)
    except RiskOrderProofPayloadError as exc:
        raise RiskOrderJournalError(exc.code) from None


def _terminal_close_proof_from_payload(
    payload: object, *, scope: AccountScope,
) -> DispatchExposureResolutionProof:
    from bt_api_risk.order_proof_payload import RiskOrderProofPayloadError, terminal_close_proof_from_payload

    try:
        return terminal_close_proof_from_payload(payload, scope=scope)
    except RiskOrderProofPayloadError as exc:
        raise RiskOrderJournalError(exc.code) from None


def _position_risk_fact_from_payload(value: object) -> AccountPositionRiskFact:
    from bt_api_risk.position_payload import RiskPositionPayloadError, position_risk_fact_from_payload

    try:
        return position_risk_fact_from_payload(value)
    except RiskPositionPayloadError as exc:
        raise RiskOrderJournalError(exc.code) from None


def _position_coverage_from_payload(
    value: object, *, scope: AccountScope
) -> PositionSnapshotCoverage:
    from bt_api_risk.position_payload import RiskPositionPayloadError, position_coverage_from_payload

    try:
        return position_coverage_from_payload(value, scope=scope)
    except RiskPositionPayloadError as exc:
        raise RiskOrderJournalError(exc.code) from None




def _same_wire_scope_for_idempotency(
    persisted: Mapping[str, Any], requested: Mapping[str, Any]
) -> bool:
    """Permit a new trusted strategy run without changing business identity."""

    if set(persisted) != _WIRE_SCOPE_KEYS or set(requested) != _WIRE_SCOPE_KEYS:
        return False
    if any(persisted.get(key) != requested.get(key) for key in _WIRE_SCOPE_KEYS if key != "run_id"):
        return False
    persisted_run = persisted.get("run_id")
    requested_run = requested.get("run_id")
    if persisted_run == requested_run:
        return True
    return (
        type(persisted_run) is str
        and bool(persisted_run)
        and type(requested_run) is str
        and bool(requested_run)
        and type(persisted.get("strategy_ref")) is str
        and bool(persisted.get("strategy_ref"))
    )


def _scope_key(scope: AccountScope) -> str:
    if type(scope) is not AccountScope:
        raise RiskOrderJournalError("INVALID_ACCOUNT_SCOPE")
    return scope.key


def _thread_fences() -> dict[str, RiskOrderWriterFence]:
    value = getattr(_THREAD_FENCES, "by_scope", None)
    if value is None:
        value = {}
        _THREAD_FENCES.by_scope = value
    return value


class RiskOrderJournal(RiskOrderJournalStorage):
    """Append-only scoped intent/evidence journal with a durable writer fence.

    The advisory lock does not expire while a provider call is in flight.  A
    monotonically increasing SQLite fencing token changes on every new owner.
    Every append rechecks that token; dispatch evidence is accepted by the Risk
    resolver only while the same account lock remains held.
    """

    _storage_error_type = RiskOrderJournalError

    def _init_cancel_resolution_sources(self):
        """An SDK composition may install an optional Execution source bridge."""

    def bind_cancel_resolution_source(self, *args, **kwargs):
        raise RiskOrderJournalError("CANCEL_EXECUTION_SOURCE_UNAVAILABLE")

    def _read_cancel_resolution_source(self, *args, **kwargs):
        raise RiskOrderJournalError("CANCEL_EXECUTION_SOURCE_UNAVAILABLE")

    def _read_cancel_target_risk_source(self, *args, **kwargs):
        raise RiskOrderJournalError("CANCEL_EXECUTION_SOURCE_UNAVAILABLE")

    def _build_cancel_dispatch_resolution_proof(self, *args, **kwargs):
        raise RiskOrderJournalError("CANCEL_EXECUTION_SOURCE_UNAVAILABLE")

    @staticmethod
    def _risk_dispatch_profile(provider: str):
        raise RiskOrderJournalError("RISK_DISPATCH_EVIDENCE_PROVIDER_UNAVAILABLE")

    @staticmethod
    def _verify_gateway_position_source_receipt(receipt, **kwargs):
        raise RiskOrderJournalError("GROSS_BASELINE_POSITION_SOURCE_UNAVAILABLE")

    def __init__(self, path: str | os.PathLike[str], *, writer_id: str) -> None:
        if type(writer_id) is not str or not writer_id or writer_id != writer_id.strip():
            raise RiskOrderJournalError("INVALID_WRITER_ID")
        if len(writer_id) > 96:
            raise RiskOrderJournalError("INVALID_WRITER_ID")
        self._path = Path(path).expanduser().resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._writer_id = writer_id
        self._instance_id = uuid.uuid4().hex
        self._owner_id = f"{writer_id}:{os.getpid()}:{self._instance_id}"
        self._init_cancel_resolution_sources()
        self._initialize()

    @property
    def path(self) -> Path:
        """Return the resolved journal path for trusted service assembly."""

        return self._path

    @contextmanager
    def writer_fence(self, scope: AccountScope) -> Iterator[RiskOrderWriterFence]:
        """Hold one account-wide, non-expiring OS lock and issue its generation."""

        key = _scope_key(scope)
        active = _thread_fences().get(key)
        if active is not None:
            self._assert_current(active)
            yield active
            return

        lock_path = self._lock_path(scope)
        lock_key = str(lock_path).casefold()
        with _PROCESS_LOCK_GUARD:
            process_lock = _PROCESS_LOCKS.setdefault(lock_key, threading.RLock())
        process_lock.acquire()
        owner_file = None
        try:
            owner_file = self._open_and_lock(lock_path)
            token = self._next_fencing_token(scope)
            material = canonical_json(
                {
                    "account_scope_key": scope.key,
                    "fencing_token": token,
                    "owner_id": self._owner_id,
                    "schema": "bt-api-risk-order-writer-fence-v1",
                }
            )
            fence = RiskOrderWriterFence(
                scope=scope,
                owner_id=self._owner_id,
                fencing_token=token,
                fence_sha256=sha256_text(material),
            )
            _thread_fences()[key] = fence
            self._assert_current(fence)
            yield fence
        finally:
            _thread_fences().pop(key, None)
            if owner_file is not None:
                try:
                    self._unlock_and_close(owner_file)
                finally:
                    process_lock.release()
            else:
                process_lock.release()

    def ingest_gross_exposure_baseline(
        self,
        fence: RiskOrderWriterFence,
        *,
        source_snapshot: Mapping[str, Any],
        position_source_receipt: object | None = None,
    ) -> GrossExposureBaselineProof:
        """Persist a complete, source-shaped account baseline under the account fence.

        The server-side producer supplies its normalized account snapshot.
        Dimension-enabled baselines also require the canonical full-query
        coverage receipt and every position's typed mark, metadata, FX, and
        optional Greek facts. Their strategy gross values are revalued here and
        must exactly match the producer's attributed summary. A legacy
        completeness boolean remains readable for policies without dimension
        caps; Risk refuses it when those caps are configured.
        """

        self._assert_current(fence)
        if not isinstance(source_snapshot, Mapping):
            raise RiskOrderJournalError("GROSS_BASELINE_SOURCE_INVALID")
        snapshot = dict(source_snapshot)
        required = {
            "account_revision",
            "account_scope",
            "complete_open_orders",
            "complete_positions",
            "notional_unit",
            "observed_at_ns",
            "open_orders",
            "positions",
            "source_schema_version",
            "valid_until_ns",
            "valuation_facts",
        }
        position_detail_keys = {"position_coverage", "position_risk_facts"}
        position_source_keys = {
            "position_account_key_id",
            "position_source_receipt_sha256",
            "provider_positions",
        }
        if set(snapshot) not in (
            required,
            required | position_detail_keys,
            required | position_detail_keys | position_source_keys,
        ):
            raise RiskOrderJournalError("GROSS_BASELINE_SOURCE_INVALID")
        has_position_details = position_detail_keys <= set(snapshot)
        account_scope = snapshot.get("account_scope")
        if (
            not isinstance(account_scope, Mapping)
            or dict(account_scope)
            != {
                "account_id": fence.scope.account_id,
                "environment": fence.scope.environment,
                "provider": fence.scope.provider,
            }
            or type(snapshot.get("account_revision")) is not int
            or snapshot["account_revision"] <= 0
            or type(snapshot.get("source_schema_version")) is not str
            or not snapshot["source_schema_version"]
            or type(snapshot.get("notional_unit")) is not str
            or type(snapshot.get("complete_positions")) is not bool
            or snapshot["complete_positions"] is not True
            or type(snapshot.get("complete_open_orders")) is not bool
            or snapshot["complete_open_orders"] is not True
            or type(snapshot.get("positions")) is not list
            or type(snapshot.get("open_orders")) is not list
            or type(snapshot.get("valuation_facts")) is not list
            or snapshot["open_orders"]
        ):
            raise RiskOrderJournalError("GROSS_BASELINE_SOURCE_INCOMPLETE")

        position_coverage = None
        position_facts: tuple[AccountPositionRiskFact, ...] = ()
        source_gross_by_strategy: dict[str, Fraction] = {}
        if has_position_details:
            raw_facts = snapshot.get("position_risk_facts")
            if type(raw_facts) is not list:
                raise RiskOrderJournalError("GROSS_BASELINE_POSITION_FACTS_INCOMPLETE")
            position_coverage = _position_coverage_from_payload(
                snapshot.get("position_coverage"), scope=fence.scope
            )
            if (
                position_coverage.account_revision != snapshot["account_revision"]
                or position_coverage.source_schema_version != snapshot["source_schema_version"]
                or position_coverage.observed_at_ns != snapshot["observed_at_ns"]
                or position_coverage.valid_until_ns > snapshot["valid_until_ns"]
            ):
                raise RiskOrderJournalError("GROSS_BASELINE_POSITION_COVERAGE_MISMATCH")
            parsed_facts = tuple(_position_risk_fact_from_payload(item) for item in raw_facts)
            if len({item.position_id for item in parsed_facts}) != len(parsed_facts):
                raise RiskOrderJournalError("GROSS_BASELINE_POSITION_FACT_DUPLICATE")
            if snapshot["valuation_facts"] != [item.to_payload() for item in parsed_facts]:
                raise RiskOrderJournalError("GROSS_BASELINE_POSITION_VALUATION_MISMATCH")
            try:
                source_gross_by_strategy = revalue_position_facts(
                    parsed_facts,
                    notional_unit=snapshot["notional_unit"],
                    observed_at_ns=position_coverage.observed_at_ns,
                )
            except PositionBaselineError as exc:
                raise RiskOrderJournalError(exc.code) from None
            position_facts = parsed_facts

        try:
            by_strategy = summarize_position_rows(
                snapshot["positions"],
                notional_unit=snapshot["notional_unit"],
                require_sha256=_require_sha256,
            )
            if has_position_details:
                require_matching_revaluation(by_strategy, source_gross_by_strategy)
        except PositionBaselineError as exc:
            raise RiskOrderJournalError(exc.code) from None

        has_position_source = position_source_receipt is not None
        if has_position_source:
            if not has_position_details or not position_source_keys <= set(snapshot):
                raise RiskOrderJournalError("GROSS_BASELINE_POSITION_SOURCE_MISMATCH")
            self._verify_gateway_position_source_receipt(
                position_source_receipt,
                scope=fence.scope,
                snapshot=snapshot,
                coverage=position_coverage,
                facts=position_facts,
                summary_counts={
                    strategy_id: count
                    for strategy_id, (_, count) in by_strategy.items()
                },
            )
        elif position_source_keys & set(snapshot):
            raise RiskOrderJournalError("GROSS_BASELINE_POSITION_SOURCE_REQUIRED")

        try:
            strategies, account_gross, account_count = strategy_baseline_totals(by_strategy)
        except PositionBaselineError as exc:
            raise RiskOrderJournalError(exc.code) from None
        positions_sha = sha256_text(canonical_json(snapshot["positions"]))
        orders_sha = sha256_text(canonical_json(snapshot["open_orders"]))
        valuation_sha = sha256_text(canonical_json(snapshot["valuation_facts"]))
        snapshot_sha = sha256_text(canonical_json(snapshot))
        proof = GrossExposureBaselineProof(
            scope=fence.scope,
            account_revision=snapshot["account_revision"],
            notional_unit=snapshot["notional_unit"],
            account_gross_notional=account_gross,
            account_active_increase_intent_count=account_count,
            strategy_baselines=strategies,
            unmanaged_open_order_count=len(snapshot["open_orders"]),
            complete_positions=True,
            complete_open_orders=True,
            source_snapshot_sha256=snapshot_sha,
            positions_sha256=positions_sha,
            open_orders_sha256=orders_sha,
            valuation_facts_sha256=valuation_sha,
            source_schema_version=snapshot["source_schema_version"],
            observed_at_ns=snapshot["observed_at_ns"],
            valid_until_ns=snapshot["valid_until_ns"],
            writer_owner_id=fence.owner_id,
            writer_fencing_token=fence.fencing_token,
            writer_fence_sha256=fence.fence_sha256,
            # Shape-only legacy mappings remain readable for policies without
            # dimensions, but their coverage/facts never become admission
            # evidence. Only a current Gateway owner receipt gets projected
            # into the typed Risk proof.
            position_coverage=position_coverage if has_position_source else None,
            position_risk_facts=position_facts if has_position_source else (),
        )
        snapshot_json = canonical_json(snapshot)
        with self._transaction() as connection:
            self._assert_current_in(connection, fence)
            prior_scope_rows = connection.execute(
                """SELECT source_snapshot_json FROM risk_order_gross_baselines
                   WHERE scope_key=? ORDER BY account_revision""",
                (fence.scope.key,),
            ).fetchall()
            if has_position_source:
                account_key_id = position_source_receipt.account_key.account_key_id
                for prior_scope_row in prior_scope_rows:
                    try:
                        prior_snapshot = json.loads(prior_scope_row["source_snapshot_json"])
                    except (TypeError, ValueError, json.JSONDecodeError):
                        raise RiskOrderJournalError(
                            "GROSS_BASELINE_POSITION_ACCOUNT_IDENTITY_UNKNOWN"
                        ) from None
                    prior_account_key_id = (
                        prior_snapshot.get("position_account_key_id")
                        if isinstance(prior_snapshot, Mapping)
                        else None
                    )
                    if type(prior_account_key_id) is not str:
                        raise RiskOrderJournalError(
                            "GROSS_BASELINE_POSITION_ACCOUNT_IDENTITY_UNKNOWN"
                        )
                    if prior_account_key_id != account_key_id:
                        raise RiskOrderJournalError(
                            "GROSS_BASELINE_POSITION_ACCOUNT_IDENTITY_MISMATCH"
                        )
            else:
                for prior_scope_row in prior_scope_rows:
                    try:
                        prior_snapshot = json.loads(prior_scope_row["source_snapshot_json"])
                    except (TypeError, ValueError, json.JSONDecodeError):
                        raise RiskOrderJournalError(
                            "GROSS_BASELINE_POSITION_ACCOUNT_IDENTITY_UNKNOWN"
                        ) from None
                    if (
                        isinstance(prior_snapshot, Mapping)
                        and "position_account_key_id" in prior_snapshot
                    ):
                        raise RiskOrderJournalError(
                            "GROSS_BASELINE_POSITION_SOURCE_REQUIRED"
                        )
            prior = connection.execute(
                "SELECT * FROM risk_order_gross_baselines WHERE scope_key=? AND account_revision=?",
                (fence.scope.key, proof.account_revision),
            ).fetchone()
            if prior is not None:
                if (
                    prior["proof_sha256"] != proof.fingerprint
                    or prior["source_snapshot_json"] != snapshot_json
                    or prior["writer_fence_sha256"] != fence.fence_sha256
                ):
                    raise RiskOrderJournalError("GROSS_BASELINE_REVISION_CONFLICT")
                return proof
            connection.execute(
                """INSERT INTO risk_order_gross_baselines (
                    scope_key, account_revision, proof_sha256, source_snapshot_json,
                    source_snapshot_sha256, writer_owner_id, writer_fencing_token,
                    writer_fence_sha256, created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    fence.scope.key,
                    proof.account_revision,
                    proof.fingerprint,
                    snapshot_json,
                    proof.source_snapshot_sha256,
                    fence.owner_id,
                    fence.fencing_token,
                    fence.fence_sha256,
                    time.time_ns(),
                ),
            )
        return proof

    def has_matching_gateway_position_baseline(
        self,
        fence: RiskOrderWriterFence,
        *,
        source_snapshot: Mapping[str, Any],
    ) -> bool:
        """Check an immutable prior full-source row for exact baseline replay.

        The receipt digest itself is generation/cursor bound and naturally
        changes after a Gateway worker restart.  This read-only check accepts
        a same-revision replay only when the persisted row was originally
        inserted through the typed Gateway receipt path and every stable
        source, coverage, valuation and summary field is identical.
        """

        self._assert_current(fence)
        if not isinstance(source_snapshot, Mapping):
            raise RiskOrderJournalError("GROSS_BASELINE_SOURCE_INVALID")
        expected = dict(source_snapshot)
        revision = expected.get("account_revision")
        if (
            type(revision) is not int
            or revision <= 0
            or not {
                "position_account_key_id",
                "position_coverage",
                "position_risk_facts",
                "position_source_receipt_sha256",
                "provider_positions",
            }.issubset(expected)
        ):
            raise RiskOrderJournalError("GROSS_BASELINE_POSITION_SOURCE_REQUIRED")
        try:
            _require_sha256(
                expected.get("position_source_receipt_sha256"),
                "baseline position source receipt",
            )
            with closing(self._connection()) as connection:
                self._assert_current_in(connection, fence)
                row = connection.execute(
                    "SELECT * FROM risk_order_gross_baselines "
                    "WHERE scope_key=? AND account_revision=?",
                    (fence.scope.key, revision),
                ).fetchone()
            if row is None:
                return False
            stored_text = row["source_snapshot_json"]
            stored = json.loads(stored_text)
            if (
                type(stored) is not dict
                or canonical_json(stored) != stored_text
                or row["source_snapshot_sha256"]
                != sha256_text(stored_text)
                or type(row["proof_sha256"]) is not str
                or len(row["proof_sha256"]) != 64
            ):
                raise RiskOrderJournalError("GROSS_BASELINE_PRIOR_SOURCE_INVALID")
            stored_receipt_sha = stored.get("position_source_receipt_sha256")
            _require_sha256(stored_receipt_sha, "persisted position source receipt")
            stored_coverage = _position_coverage_from_payload(
                stored.get("position_coverage"), scope=fence.scope
            )
            stored_facts_raw = stored.get("position_risk_facts")
            stored_provider_positions = stored.get("provider_positions")
            if (
                type(stored_facts_raw) is not list
                or type(stored_provider_positions) is not list
                or stored_coverage.account_revision != revision
                or stored.get("complete_positions") is not True
                or stored.get("complete_open_orders") is not True
                or stored.get("open_orders") != []
            ):
                raise RiskOrderJournalError("GROSS_BASELINE_PRIOR_SOURCE_INVALID")
            stored_facts = tuple(
                _position_risk_fact_from_payload(item) for item in stored_facts_raw
            )
            if (
                stored.get("valuation_facts") != [fact.to_payload() for fact in stored_facts]
                or len({fact.position_id for fact in stored_facts}) != len(stored_facts)
            ):
                raise RiskOrderJournalError("GROSS_BASELINE_PRIOR_SOURCE_INVALID")
            for name in (
                "account_scope",
                "complete_open_orders",
                "complete_positions",
                "notional_unit",
                "observed_at_ns",
                "open_orders",
                "position_account_key_id",
                "position_coverage",
                "position_risk_facts",
                "positions",
                "provider_positions",
                "source_schema_version",
                "valid_until_ns",
                "valuation_facts",
            ):
                if name not in stored or name not in expected:
                    raise RiskOrderJournalError("GROSS_BASELINE_PRIOR_SOURCE_INVALID")
            # A new Gateway generation changes only the receipt fingerprint.
            # All provider rows and trusted valuation bindings remain exact.
            stored.pop("position_source_receipt_sha256", None)
            expected.pop("position_source_receipt_sha256", None)
            if canonical_json(stored) != canonical_json(expected):
                raise RiskOrderJournalError("GROSS_BASELINE_REVISION_CONFLICT")
        except RiskOrderJournalError:
            raise
        except Exception:
            raise RiskOrderJournalError("GROSS_BASELINE_PRIOR_SOURCE_INVALID") from None
        self._assert_current(fence)
        return True

    @contextmanager
    def baseline_guard(self, proof: GrossExposureBaselineProof) -> Iterator[VerifiedGrossExposureBaseline | None]:
        """Bind Risk's baseline commit to the exact ingested source snapshot."""

        if type(proof) is not GrossExposureBaselineProof:
            yield None
            return
        fence = _thread_fences().get(proof.scope.key)
        if fence is None or fence.scope != proof.scope:
            yield None
            return
        verified = None
        try:
            with closing(self._connection()) as connection:
                self._assert_current_in(connection, fence)
                row = connection.execute(
                    "SELECT * FROM risk_order_gross_baselines WHERE scope_key=? AND account_revision=?",
                    (proof.scope.key, proof.account_revision),
                ).fetchone()
            if row is not None and (
                row["proof_sha256"] == proof.fingerprint
                and row["source_snapshot_sha256"] == proof.source_snapshot_sha256
                and row["writer_owner_id"] == fence.owner_id
                and row["writer_fencing_token"] == fence.fencing_token
                and row["writer_fence_sha256"] == fence.fence_sha256
            ):
                verified = VerifiedGrossExposureBaseline(
                    scope=proof.scope,
                    proof_sha256=proof.fingerprint,
                    account_revision=proof.account_revision,
                    writer_owner_id=fence.owner_id,
                    writer_fencing_token=fence.fencing_token,
                    writer_fence_sha256=fence.fence_sha256,
                )
            self._assert_current(fence)
            yield verified
        finally:
            self._assert_current(fence)

    def store_terminal_exposure_reference(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        claim: DispatchClaimBinding,
        provider_order_id: str,
        accepted_request_sha256: str,
        order_event: RiskOrderJournalEvent,
        fill_event: RiskOrderJournalEvent,
        reconciliation_evidence_sha256: str,
    ) -> tuple[str, str]:
        """Persist the exact positive-fill terminal reservation reference."""

        reservation_id, reference_sha, _proof = self._store_terminal_exposure_reference(
            fence,
            principal_ref=principal_ref,
            intent_id=intent_id,
            claim=claim,
            provider_order_id=provider_order_id,
            accepted_request_sha256=accepted_request_sha256,
            order_event=order_event,
            fill_event=fill_event,
            reconciliation_evidence_sha256=reconciliation_evidence_sha256,
            proof_factory=None,
        )
        return reservation_id, reference_sha

    def store_terminal_close_resolution_source(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        claim: DispatchClaimBinding,
        provider_order_id: str,
        accepted_request_sha256: str,
        order_event: RiskOrderJournalEvent,
        fill_event: RiskOrderJournalEvent,
        reconciliation_evidence_sha256: str,
        proof_factory: Callable[[str, str], DispatchExposureResolutionProof],
    ) -> tuple[str, str, DispatchExposureResolutionProof]:
        """Atomically persist a CLOSE reference and its exact Risk proof."""

        if not callable(proof_factory):
            raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_REQUIRED")
        reservation_id, reference_sha, proof = self._store_terminal_exposure_reference(
            fence,
            principal_ref=principal_ref,
            intent_id=intent_id,
            claim=claim,
            provider_order_id=provider_order_id,
            accepted_request_sha256=accepted_request_sha256,
            order_event=order_event,
            fill_event=fill_event,
            reconciliation_evidence_sha256=reconciliation_evidence_sha256,
            proof_factory=proof_factory,
        )
        if proof is None:
            raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_MISSING")
        return reservation_id, reference_sha, proof

    def _store_terminal_exposure_reference(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        claim: DispatchClaimBinding,
        provider_order_id: str,
        accepted_request_sha256: str,
        order_event: RiskOrderJournalEvent,
        fill_event: RiskOrderJournalEvent,
        reconciliation_evidence_sha256: str,
        proof_factory: Callable[[str, str], DispatchExposureResolutionProof] | None,
    ) -> tuple[str, str, DispatchExposureResolutionProof | None]:
        """Build and atomically persist immutable terminal source material."""

        self._assert_current(fence)
        if (
            type(claim) is not DispatchClaimBinding
            or claim.scope != fence.scope
            or type(order_event) is not RiskOrderJournalEvent
            or type(fill_event) is not RiskOrderJournalEvent
            or order_event.event_type != "ORDER_OBSERVATION"
            or fill_event.event_type != "FILL_OBSERVATION"
            or order_event.scope != fence.scope
            or fill_event.scope != fence.scope
            or order_event.principal_ref != principal_ref
            or fill_event.principal_ref != principal_ref
            or order_event.intent_id != intent_id
            or fill_event.intent_id != intent_id
            or order_event.revision >= fill_event.revision
            or order_event.writer_fence_sha256 != fence.fence_sha256
            or fill_event.writer_fence_sha256 != fence.fence_sha256
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID")
        _require_sha256(accepted_request_sha256, "accepted request digest")
        _require_sha256(reconciliation_evidence_sha256, "reconciliation evidence digest")
        command = self.get_command(fence.scope, principal_ref, intent_id)
        if (
            command is None
            or command.state != "FILL_OBSERVATION"
            or command.risk_intent_id != claim.intent_id
            or command.permit_id != claim.permit_id
            or command.order_request_sha256 != accepted_request_sha256
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID")
        position_effect = str(command.canonical_payload.get("position_effect", "OPEN"))
        if position_effect not in {"OPEN", "CLOSE"}:
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID")
        try:
            position_dimensions = _position_dimensions_from_payload(command.canonical_payload)
        except RiskOrderJournalError:
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID") from None
        stored_order_event = self.get_event(
            fence.scope, principal_ref, intent_id, order_event.revision
        )
        stored_fill_event = self.get_event(
            fence.scope, principal_ref, intent_id, fill_event.revision
        )
        if (
            stored_order_event != order_event
            or stored_fill_event != fill_event
            or not _is_v2_order_event(order_event.payload)
            or not _is_v2_fill_event(fill_event.payload)
            or order_event.payload.get("exposure_state")
            not in {OrderExposureState.FILLED.value, OrderExposureState.CANCELLED.value}
            or Decimal(str(fill_event.payload.get("filled_quantity", "0"))) <= 0
            or order_event.payload.get("position_effect", "OPEN") != position_effect
            or fill_event.payload.get("position_effect", "OPEN") != position_effect
            or not _position_dimensions_match(order_event.payload, position_dimensions)
            or not _position_dimensions_match(fill_event.payload, position_dimensions)
            or command.canonical_payload.get("reduce_only", position_effect == "CLOSE")
            is not (position_effect == "CLOSE")
            or command.order_request.get("reduce_only") is not (position_effect == "CLOSE")
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID")
        is_close = position_effect == "CLOSE"
        if is_close and proof_factory is None:
            raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_REQUIRED")
        if is_close:
            try:
                requested = Decimal(str(order_event.payload["quantity"]))
                filled = Decimal(str(fill_event.payload["filled_quantity"]))
            except (KeyError, TypeError, ValueError, InvalidOperation):
                raise RiskOrderJournalError("TERMINAL_CLOSE_FULL_FILL_REQUIRED") from None
            if (
                order_event.payload.get("exposure_state") != OrderExposureState.FILLED.value
                or not requested.is_finite()
                or not filled.is_finite()
                or requested <= 0
                or filled != requested
            ):
                raise RiskOrderJournalError("TERMINAL_CLOSE_FULL_FILL_REQUIRED")
        reservation_id = (
            ("risk-order-close:" if is_close else "risk-order-exposure:")
            + sha256_text(
                canonical_json(
                    {
                        "intent_id": claim.intent_id,
                        "permit_id": claim.permit_id,
                        "provider_order_id": provider_order_id,
                        "scope_key": fence.scope.key,
                    }
                )
            )[:32]
        )
        reference = {
            "accepted_request_sha256": accepted_request_sha256,
            # Provider-executed weighted average price over the immutable fill
            # facts. Derived here so the durable terminal ACK can project the
            # executed price without re-reading the provider.
            "average_price": _weighted_average_price(fill_event.payload),
            "claim": _claim_payload(claim),
            "claim_digest": claim.claim_digest,
            "dispatch_attempt_count": 1,
            **(
                {"position_effect": "CLOSE", "close_proof_kind": "TERMINAL_CLOSE"}
                if is_close
                else {"exposure_proof_kind": "TERMINAL_EXPOSURE"}
            ),
            "fill_observation_record_sha256": fill_event.record_sha256,
            "fill_observation_revision": fill_event.revision,
            "filled_quantity": fill_event.payload.get("filled_quantity"),
            "intent_hash": claim.intent_hash,
            "intent_id": claim.intent_id,
            "order_observation_record_sha256": order_event.record_sha256,
            "order_observation_revision": order_event.revision,
            "permit_id": claim.permit_id,
            "provider_order_id": provider_order_id,
            "reservation_id": reservation_id,
            "reconciliation_evidence_sha256": reconciliation_evidence_sha256,
            "schema": (
                "bt-api-risk-order-terminal-close-reference-v1"
                if is_close
                else "bt-api-risk-order-terminal-exposure-reference-v1"
            ),
            "scope_key": fence.scope.key,
            "trade_count": fill_event.payload.get("trade_count"),
            "writer_fence_sha256": fence.fence_sha256,
        }
        reference_json = canonical_json(reference)
        reference_sha = sha256_text(reference_json)
        proof = None if proof_factory is None else proof_factory(reservation_id, reference_sha)
        proof_json = None if proof is None else canonical_json(_terminal_close_proof_payload(proof))
        proof_sha = None if proof is None else proof.fingerprint
        if proof is not None:
            observation = proof.observation
            if (
                position_effect != "CLOSE"
                or proof.claim != claim
                or proof.reconciliation_evidence_sha256 != reconciliation_evidence_sha256
                or observation.position_effect != "CLOSE"
                or (observation.position_side, observation.position_bucket)
                != position_dimensions
                or observation.writer_owner_id != fence.owner_id
                or observation.writer_fencing_token != fence.fencing_token
                or observation.writer_fence_sha256 != fence.fence_sha256
                or observation.order_revision != order_event.payload.get("order_revision")
                or observation.journal_revision != fill_event.revision
                or observation.journal_record_sha256 != fill_event.record_sha256
                or observation.provider_order_id != provider_order_id
                or observation.accepted_request_sha256 != accepted_request_sha256
                or observation.exposure_reservation_id != reservation_id
                or observation.exposure_reservation_sha256 != reference_sha
                or observation.state.value != order_event.payload.get("exposure_state")
                or observation.fill_trade_count != fill_event.payload.get("trade_count")
            ):
                raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_SOURCE_MISMATCH")
        with self._transaction() as connection:
            self._assert_current_in(connection, fence)
            prior = connection.execute(
                "SELECT * FROM risk_order_exposure_references WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            if prior is not None:
                if (
                    prior["reservation_id"] != reservation_id
                    or prior["reference_sha256"] != reference_sha
                    or prior["reference_json"] != reference_json
                ):
                    raise RiskOrderJournalError("EXPOSURE_REFERENCE_CONFLICT")
            else:
                connection.execute(
                    """INSERT INTO risk_order_exposure_references (
                        scope_key, principal_ref, intent_id, reservation_id,
                        reference_sha256, reference_json, created_revision, record_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        fence.scope.key,
                        principal_ref,
                        intent_id,
                        reservation_id,
                        reference_sha,
                        reference_json,
                        fill_event.revision,
                        fill_event.record_sha256,
                    ),
                )
            if proof is not None and proof_json is not None and proof_sha is not None:
                prior_proof = connection.execute(
                    "SELECT * FROM risk_order_terminal_close_proofs "
                    "WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                    (fence.scope.key, principal_ref, intent_id),
                ).fetchone()
                if prior_proof is not None:
                    if (
                        prior_proof["proof_sha256"] != proof_sha
                        or prior_proof["proof_json"] != proof_json
                        or prior_proof["source_order_revision"] != order_event.revision
                        or prior_proof["source_order_record_sha256"] != order_event.record_sha256
                        or prior_proof["source_fill_revision"] != fill_event.revision
                        or prior_proof["source_fill_record_sha256"] != fill_event.record_sha256
                        or prior_proof["writer_owner_id"] != fence.owner_id
                        or prior_proof["writer_fencing_token"] != fence.fencing_token
                        or prior_proof["writer_fence_sha256"] != fence.fence_sha256
                    ):
                        raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_CONFLICT")
                else:
                    connection.execute(
                        """INSERT INTO risk_order_terminal_close_proofs (
                            scope_key, principal_ref, intent_id, proof_sha256, proof_json,
                            source_order_revision, source_order_record_sha256,
                            source_fill_revision, source_fill_record_sha256,
                            writer_owner_id, writer_fencing_token, writer_fence_sha256,
                            created_at_ns
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            fence.scope.key,
                            principal_ref,
                            intent_id,
                            proof_sha,
                            proof_json,
                            order_event.revision,
                            order_event.record_sha256,
                            fill_event.revision,
                            fill_event.record_sha256,
                            fence.owner_id,
                            fence.fencing_token,
                            fence.fence_sha256,
                            time.time_ns(),
                        ),
                    )
        return reservation_id, reference_sha, proof

    def load_terminal_exposure_source(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
    ) -> tuple[RiskOrderJournalEvent, RiskOrderJournalEvent, Mapping[str, Any]]:
        """Load the one immutable, source-complete first terminal observation."""

        self._assert_current(fence)
        with closing(self._connection()) as connection:
            self._assert_current_in(connection, fence)
            command = connection.execute(
                "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            if command is None:
                raise RiskOrderJournalError("TERMINAL_EXPOSURE_COMMAND_MISSING")
            head = connection.execute(
                "SELECT revision FROM risk_order_events WHERE scope_key=? ORDER BY revision DESC LIMIT 1",
                (fence.scope.key,),
            ).fetchone()
            parsed_command = self._command_from_row(connection, command, fence.scope)
            if head is None or not self._verify_event_chains(
                connection,
                command,
                fence.scope,
                int(head["revision"]),
                target_revision=parsed_command.latest_revision,
            ):
                raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_CHAIN_INVALID")
            rows = connection.execute(
                "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? ORDER BY revision",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchall()
            events = tuple(self._event_from_row(row, fence.scope) for row in rows)
            source_command, source_events, source_fence, _ack_event = (
                _terminal_exposure_source_projection(
                    parsed_command,
                    command,
                    events,
                    fence,
                )
            )
            permit_id, order_event, fill_event, _unknown_event = (
                _terminal_exposure_lifecycle(
                    source_command,
                    command,
                    source_events,
                    source_fence,
                )
            )
            if (
                order_event.payload.get("exposure_state")
                not in {OrderExposureState.FILLED.value, OrderExposureState.CANCELLED.value}
                or Decimal(str(fill_event.payload.get("filled_quantity", "0"))) <= 0
            ):
                raise RiskOrderJournalError("TERMINAL_EXPOSURE_NOT_TERMINAL")
            ref_row = connection.execute(
                "SELECT * FROM risk_order_exposure_references WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            if ref_row is None or sha256_text(str(ref_row["reference_json"])) != str(
                ref_row["reference_sha256"]
            ):
                raise RiskOrderJournalError("TERMINAL_EXPOSURE_REFERENCE_MISSING")
            reference = json.loads(ref_row["reference_json"])
            position_effect = str(parsed_command.canonical_payload.get("position_effect", "OPEN"))
            if position_effect == "CLOSE":
                try:
                    requested = Decimal(str(order_event.payload["quantity"]))
                    filled = Decimal(str(fill_event.payload["filled_quantity"]))
                except (KeyError, TypeError, ValueError, InvalidOperation):
                    raise RiskOrderJournalError("TERMINAL_CLOSE_FULL_FILL_REQUIRED") from None
                if (
                    order_event.payload.get("exposure_state") != OrderExposureState.FILLED.value
                    or not requested.is_finite()
                    or not filled.is_finite()
                    or requested <= 0
                    or filled != requested
                ):
                    raise RiskOrderJournalError("TERMINAL_CLOSE_FULL_FILL_REQUIRED")
            reference_prefix = "risk-order-close:" if position_effect == "CLOSE" else "risk-order-exposure:"
            reference_schema = (
                "bt-api-risk-order-terminal-close-reference-v1"
                if position_effect == "CLOSE"
                else "bt-api-risk-order-terminal-exposure-reference-v1"
            )
            if (
                position_effect not in {"OPEN", "CLOSE"}
                or reference.get("schema") != reference_schema
                or reference.get("position_effect", position_effect) != position_effect
                or (
                    reference.get("close_proof_kind") != "TERMINAL_CLOSE"
                    if position_effect == "CLOSE"
                    else reference.get("exposure_proof_kind") != "TERMINAL_EXPOSURE"
                )
                or reference.get("scope_key") != fence.scope.key
                or reference.get("intent_id") != command["risk_intent_id"]
                or reference.get("permit_id") != permit_id
                or reference.get("accepted_request_sha256") != command["order_request_sha256"]
                or reference.get("average_price") != _weighted_average_price(fill_event.payload)
                or reference.get("order_observation_revision") != order_event.revision
                or reference.get("order_observation_record_sha256") != order_event.record_sha256
                or reference.get("fill_observation_revision") != fill_event.revision
                or reference.get("fill_observation_record_sha256") != fill_event.record_sha256
                or reference.get("writer_fence_sha256") != fill_event.writer_fence_sha256
                or ref_row["reservation_id"] != reference_prefix + sha256_text(
                    canonical_json(
                        {
                            "intent_id": command["risk_intent_id"],
                            "permit_id": permit_id,
                            "provider_order_id": reference.get("provider_order_id"),
                            "scope_key": fence.scope.key,
                        }
                    )
                )[:32]
            ):
                raise RiskOrderJournalError("TERMINAL_EXPOSURE_REFERENCE_INVALID")
            # The digest is stored beside the immutable JSON body to avoid a
            # self-referential hash. Expose that verified column in the read
            # projection so callers can bind receipts to the exact row without
            # pretending the digest was part of the persisted JSON payload.
            verified_reference = dict(reference)
            verified_reference["reference_sha256"] = str(ref_row["reference_sha256"])
            return order_event, fill_event, MappingProxyType(verified_reference)

    def load_terminal_close_resolution_proof(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
    ) -> DispatchExposureResolutionProof | None:
        """Load and re-attest the exact durable CLOSE proof before recovery."""

        self._assert_current(fence)
        with closing(self._connection()) as connection:
            self._assert_current_in(connection, fence)
            command_row = connection.execute(
                "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            if command_row is None:
                return None
            command = self._command_from_row(connection, command_row, fence.scope)
            if command.canonical_payload.get("position_effect", "OPEN") != "CLOSE":
                return None
            try:
                position_dimensions = _position_dimensions_from_payload(
                    command.canonical_payload
                )
            except RiskOrderJournalError:
                raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_SOURCE_MISMATCH") from None
            proof_row = connection.execute(
                "SELECT * FROM risk_order_terminal_close_proofs "
                "WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            if proof_row is None:
                return None
            try:
                raw_payload = str(proof_row["proof_json"])
                payload = json.loads(raw_payload)
                proof = _terminal_close_proof_from_payload(payload, scope=fence.scope)
            except (TypeError, ValueError, RiskOrderJournalError):
                raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_PAYLOAD_INVALID") from None
            observation = proof.observation
            if (
                canonical_json(payload) != raw_payload
                or proof.claim.intent_id != command.risk_intent_id
                or proof.claim.permit_id != command.permit_id
                or proof_row["proof_sha256"] != proof.fingerprint
                or int(proof_row["source_fill_revision"]) != observation.journal_revision
                or proof_row["source_fill_record_sha256"]
                != observation.journal_record_sha256
                or proof_row["writer_owner_id"] != observation.writer_owner_id
                or int(proof_row["writer_fencing_token"]) != observation.writer_fencing_token
                or proof_row["writer_fence_sha256"] != observation.writer_fence_sha256
                or (observation.position_side, observation.position_bucket)
                != position_dimensions
            ):
                raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_SOURCE_MISMATCH")
        verified = self._attest_dispatch_exposure_resolution(
            proof,
            proof.claim,
            fence,
        )
        if verified is None:
            raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_SOURCE_MISMATCH")
        return proof

    def append_terminal_exposure_ack(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        receipt: DispatchExposureResolutionReceipt,
        proof: DispatchExposureResolutionProof,
    ) -> RiskOrderCommand:
        """Append ACK only from the exact durable terminal Risk receipt."""

        if (
            type(receipt) is not DispatchExposureResolutionReceipt
            or type(proof) is not DispatchExposureResolutionProof
            or receipt.status
            not in {
                DispatchExposureResolutionReceiptStatus.TERMINAL_EXPOSURE_RESOLVED,
                DispatchExposureResolutionReceiptStatus.TERMINAL_CLOSE_RESOLVED,
            }
            or receipt.dispatch_latch_active is not False
            or receipt.proof_sha256 != proof.fingerprint
            or receipt.exposure_proof_sha256 != proof.observation.fingerprint
            or receipt.position_effect != proof.observation.position_effect
            or proof.claim != receipt.claim
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_RECEIPT_INVALID")
        command = self.get_command(fence.scope, principal_ref, intent_id)
        claim = receipt.claim
        if command is None:
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_COMMAND_MISSING")
        if command.state == "ACKED_TRACKED":
            # Idempotent replay is permitted only after the immutable fill
            # source and exact Risk-backed ACK have both been revalidated.
            with self._transaction() as connection:
                self._assert_current_in(connection, fence)
                row = self._require_command(
                    connection, fence.scope.key, principal_ref, intent_id
                )
                current = self._command_from_row(connection, row, fence.scope)
                self._validate_terminal_resolution_source_in(
                    connection,
                    fence,
                    principal_ref=principal_ref,
                    intent_id=intent_id,
                    receipt=receipt,
                    proof=proof,
                )
                if not self._has_terminal_ack_event_in(
                    connection, fence, current, receipt
                ):
                    raise RiskOrderJournalError("TERMINAL_EXPOSURE_ACK_CONFLICT")
                return current
        order_event, fill_event, reference = self.load_terminal_exposure_source(
            fence, principal_ref=principal_ref, intent_id=intent_id
        )
        if (
            claim.scope != fence.scope
            or claim.intent_id != command.risk_intent_id
            or claim.permit_id != command.permit_id
            or receipt.exposure_reservation_id != reference.get("reservation_id")
            or receipt.exposure_reservation_sha256 != reference.get("reference_sha256")
            or receipt.order_revision != order_event.payload.get("order_revision")
            or receipt.journal_revision != fill_event.revision
            or receipt.final_state.value != order_event.payload.get("exposure_state")
            or receipt.requested_quantity != Decimal(str(order_event.payload.get("quantity")))
            or receipt.filled_quantity != Decimal(str(fill_event.payload.get("filled_quantity")))
            or receipt.trade_count != fill_event.payload.get("trade_count")
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_RECEIPT_MISMATCH")
        with self._transaction() as connection:
            self._assert_current_in(connection, fence)
            row = self._require_command(connection, fence.scope.key, principal_ref, intent_id)
            current = self._command_from_row(connection, row, fence.scope)
            self._validate_terminal_resolution_source_in(
                connection,
                fence,
                principal_ref=principal_ref,
                intent_id=intent_id,
                receipt=receipt,
                proof=proof,
            )
            if current.state == "ACKED_TRACKED":
                if self._has_terminal_ack_event_in(
                    connection, fence, current, receipt
                ):
                    return current
                raise RiskOrderJournalError("TERMINAL_EXPOSURE_ACK_CONFLICT")
            if current.state not in {"FILL_OBSERVATION", "UNKNOWN"}:
                raise RiskOrderJournalError("TERMINAL_EXPOSURE_STATE_INVALID")
            revision, previous_account, previous_command = self._next_event_identity(
                connection, fence.scope.key, principal_ref, intent_id
            )
            event = self._event_from_body(
                fence,
                principal_ref,
                intent_id,
                revision,
                "ACKED_TRACKED",
                {
                    **_terminal_ack_payload(receipt, reference),
                    "updated_at_ns": time.time_ns(),
                },
                previous_account,
                previous_command,
            )
            self._insert_event(connection, fence, event)
            updated = self._require_command(connection, fence.scope.key, principal_ref, intent_id)
            return self._command_from_row(connection, updated, fence.scope)

    def has_resolved_terminal_exposure_history(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        receipt: DispatchExposureResolutionReceipt,
        proof: DispatchExposureResolutionProof | None = None,
    ) -> bool:
        """Validate ACKED_TRACKED against Risk's durable positive-fill receipt.

        The proof object exists only during initial resolution. Risk persists its
        proof fingerprints and returns a typed receipt on later reads, so replay
        validation binds that receipt to the immutable ACK, source events and
        reservation reference instead of expecting a non-persisted proof DTO.
        """

        self._assert_current(fence)
        try:
            with closing(self._connection()) as connection:
                self._assert_current_in(connection, fence)
                row = connection.execute(
                    "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                    (fence.scope.key, principal_ref, intent_id),
                ).fetchone()
                if row is None:
                    return False
                command = self._command_from_row(connection, row, fence.scope)
                self._validate_terminal_resolution_source_in(
                    connection,
                    fence,
                    principal_ref=principal_ref,
                    intent_id=intent_id,
                    receipt=receipt,
                    proof=proof,
                )
                return self._has_terminal_ack_event_in(connection, fence, command, receipt)
        except (RiskOrderJournalError, sqlite3.Error, KeyError, TypeError, ValueError, AttributeError):
            return False

    def append_terminal_dispatch_ack(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        receipt: DispatchTerminalResolutionReceipt,
        proof: DispatchTerminalProof,
    ) -> RiskOrderCommand:
        """Persist the exact Risk no-fill receipt after its proof chain is reread.

        The caller must first obtain this receipt from the durable Risk gate.
        This journal method validates its exact typed claim/proof against the
        current immutable event chain; it does not read or mutate Risk state.
        """

        _require_terminal_dispatch_receipt(receipt, proof)
        self._assert_current(fence)
        with self._transaction() as connection:
            self._assert_current_in(connection, fence)
            row = connection.execute(
                "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            if row is None:
                raise RiskOrderJournalError("TERMINAL_DISPATCH_COMMAND_MISSING")
            current = self._command_from_row(connection, row, fence.scope)
            command, by_type = self._validate_terminal_dispatch_source_in(
                connection,
                fence,
                principal_ref=principal_ref,
                intent_id=intent_id,
                claim=receipt.claim,
                proof=proof,
                allow_ack=True,
            )
            if command != current:
                raise RiskOrderJournalError("TERMINAL_DISPATCH_COMMAND_CHANGED")
            ack_events = by_type.get("ACKED_TERMINAL", [])
            if current.state == "ACKED_TERMINAL":
                if len(ack_events) != 1 and self._has_terminal_dispatch_ack_event_in(
                    connection, fence, current, receipt, proof, by_type
                ):
                    return current
                if not self._has_terminal_dispatch_ack_event_in(
                    connection, fence, current, receipt, proof, by_type
                ):
                    raise RiskOrderJournalError("TERMINAL_DISPATCH_ACK_CONFLICT")
                return current
            if current.state != "PROOF_READY" or ack_events:
                raise RiskOrderJournalError("TERMINAL_DISPATCH_STATE_INVALID")
            self._validate_transition(current.state, "ACKED_TERMINAL")
            revision, previous_account, previous_command = self._next_event_identity(
                connection, fence.scope.key, principal_ref, intent_id
            )
            payload = {
                **_terminal_dispatch_ack_payload(receipt, proof, by_type, profile_for=self._risk_dispatch_profile),
                "updated_at_ns": time.time_ns(),
            }
            event = self._event_from_body(
                fence,
                principal_ref,
                intent_id,
                revision,
                "ACKED_TERMINAL",
                payload,
                previous_account,
                previous_command,
            )
            self._insert_event(connection, fence, event)
            updated_row = self._require_command(
                connection, fence.scope.key, principal_ref, intent_id
            )
            updated = self._command_from_row(connection, updated_row, fence.scope)
            if updated.state != "ACKED_TERMINAL":
                raise RiskOrderJournalError("TERMINAL_DISPATCH_ACK_READBACK_FAILED")
            return updated

    def has_resolved_terminal_dispatch_history(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        receipt: DispatchTerminalResolutionReceipt,
    ) -> bool:
        """Read back ACKED_TERMINAL against the current exact Risk receipt."""

        self._assert_current(fence)
        if (
            type(receipt) is not DispatchTerminalResolutionReceipt
            or receipt.status
            is not DispatchTerminalResolutionReceiptStatus.NO_FILL_TERMINAL_RESOLVED
            or type(receipt.proof) is not DispatchTerminalProof
        ):
            return False
        try:
            with closing(self._connection()) as connection:
                self._assert_current_in(connection, fence)
                row = connection.execute(
                    "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                    (fence.scope.key, principal_ref, intent_id),
                ).fetchone()
                if row is None:
                    return False
                command, by_type = self._validate_terminal_dispatch_source_in(
                    connection,
                    fence,
                    principal_ref=principal_ref,
                    intent_id=intent_id,
                    claim=receipt.claim,
                    proof=receipt.proof,
                    allow_ack=True,
                )
                return command.state == "ACKED_TERMINAL" and self._has_terminal_dispatch_ack_event_in(
                    connection, fence, command, receipt, receipt.proof, by_type
                )
        except (
            RiskOrderJournalError,
            sqlite3.Error,
            KeyError,
            TypeError,
            ValueError,
            InvalidOperation,
            AttributeError,
        ):
            return False

    def _has_terminal_dispatch_ack_event_in(
        self,
        connection: sqlite3.Connection,
        fence: RiskOrderWriterFence,
        command: RiskOrderCommand,
        receipt: DispatchTerminalResolutionReceipt,
        proof: DispatchTerminalProof,
        events_by_type: Mapping[str, list[RiskOrderJournalEvent]],
    ) -> bool:
        acknowledgements = events_by_type.get("ACKED_TERMINAL", [])
        proof_events = events_by_type.get("PROOF_READY", [])
        if len(acknowledgements) != 1 or len(proof_events) != 1:
            return False
        event = acknowledgements[0]
        proof_event = proof_events[0]
        expected = _terminal_dispatch_ack_payload(receipt, proof, events_by_type, profile_for=self._risk_dispatch_profile)
        payload = dict(event.payload)
        timestamp = payload.pop("updated_at_ns", None)
        return (
            event.revision > proof_event.revision
            and event.writer_owner_id == fence.owner_id
            and event.writer_fencing_token == fence.fencing_token
            and event.writer_fence_sha256 == fence.fence_sha256
            and payload == expected
            and type(timestamp) is int
            and timestamp > 0
            and command.state == "ACKED_TERMINAL"
            and command.latest_revision == event.revision
            and command.latest_record_sha256 == event.record_sha256
        )

    def _validate_terminal_resolution_source_in(
        self,
        connection: sqlite3.Connection,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        receipt: DispatchExposureResolutionReceipt,
        proof: DispatchExposureResolutionProof | None,
    ) -> None:
        if (
            type(receipt) is not DispatchExposureResolutionReceipt
            or receipt.status not in {
                DispatchExposureResolutionReceiptStatus.TERMINAL_EXPOSURE_RESOLVED,
                DispatchExposureResolutionReceiptStatus.TERMINAL_CLOSE_RESOLVED,
            }
            or receipt.dispatch_latch_active is not False
            or type(receipt.claim) is not DispatchClaimBinding
            or (
                proof is not None
                and (
                    type(proof) is not DispatchExposureResolutionProof
                    or receipt.proof_sha256 != proof.fingerprint
                    or receipt.exposure_proof_sha256 != proof.observation.fingerprint
                    or proof.claim != receipt.claim
                )
            )
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_RECEIPT_INVALID")
        command = connection.execute(
            "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
            (fence.scope.key, principal_ref, intent_id),
        ).fetchone()
        if command is None:
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_COMMAND_MISSING")
        head = connection.execute(
            "SELECT revision FROM risk_order_events WHERE scope_key=? ORDER BY revision DESC LIMIT 1",
            (fence.scope.key,),
        ).fetchone()
        parsed_command = self._command_from_row(connection, command, fence.scope)
        position_effect = str(parsed_command.canonical_payload.get("position_effect", "OPEN"))
        is_close = position_effect == "CLOSE"
        try:
            position_dimensions = _position_dimensions_from_payload(
                parsed_command.canonical_payload
            )
        except RiskOrderJournalError:
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID") from None
        if (
            position_effect not in {"OPEN", "CLOSE"}
            or receipt.position_effect != position_effect
            or receipt.status
            is not (
                DispatchExposureResolutionReceiptStatus.TERMINAL_CLOSE_RESOLVED
                if is_close
                else DispatchExposureResolutionReceiptStatus.TERMINAL_EXPOSURE_RESOLVED
            )
            or (
                is_close
                and (
                    receipt.final_state is not OrderExposureState.FILLED
                    or receipt.filled_quantity != receipt.requested_quantity
                )
            )
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_RECEIPT_MISMATCH")
        if head is None or not self._verify_event_chains(
            connection,
            command,
            fence.scope,
            int(head["revision"]),
            target_revision=parsed_command.latest_revision,
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_CHAIN_INVALID")
        events_rows = connection.execute(
            "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? ORDER BY revision",
            (fence.scope.key, principal_ref, intent_id),
        ).fetchall()
        events = tuple(self._event_from_row(row, fence.scope) for row in events_rows)
        claim = receipt.claim
        ack_events = tuple(event for event in events if event.event_type == "ACKED_TRACKED")
        if proof is None and len(ack_events) != 1:
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_ACK_MISSING")
        source_command, source_events, source_fence, projected_ack = (
            _terminal_exposure_source_projection(
                parsed_command,
                command,
                events,
                fence,
            )
        )
        if len(ack_events) != (1 if projected_ack is not None else 0):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_SEQUENCE_INVALID")
        persisted_proof: DispatchExposureResolutionProof | None = proof
        proof_row = None
        if is_close:
            proof_row = connection.execute(
                "SELECT * FROM risk_order_terminal_close_proofs "
                "WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            if proof_row is None:
                raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_MISSING")
            try:
                proof_json = str(proof_row["proof_json"])
                stored_proof_payload = json.loads(proof_json)
                stored_proof = _terminal_close_proof_from_payload(
                    stored_proof_payload,
                    scope=fence.scope,
                )
            except (TypeError, ValueError, RiskOrderJournalError):
                raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_PAYLOAD_INVALID") from None
            if (
                canonical_json(stored_proof_payload) != proof_json
                or proof_row["proof_sha256"] != stored_proof.fingerprint
                or stored_proof.claim != claim
                or stored_proof.fingerprint != receipt.proof_sha256
                or stored_proof.observation.fingerprint != receipt.exposure_proof_sha256
                or (
                    stored_proof.observation.position_side,
                    stored_proof.observation.position_bucket,
                )
                != position_dimensions
                or (proof is not None and proof != stored_proof)
            ):
                raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_CONFLICT")
            persisted_proof = stored_proof
        permit_id, order_event, fill_event, _unknown_event = (
            _terminal_exposure_lifecycle(
                source_command,
                command,
                source_events,
                source_fence,
                expected_claim=claim,
            )
        )
        if (
            command["risk_intent_id"] != claim.intent_id
            or permit_id != claim.permit_id
            or claim.scope != fence.scope
            or order_event.payload.get("claim_digest") not in (None, claim.claim_digest)
            or not _is_v2_order_event(order_event.payload)
            or not _is_v2_fill_event(fill_event.payload)
            or not _position_dimensions_match(order_event.payload, position_dimensions)
            or not _position_dimensions_match(fill_event.payload, position_dimensions)
            or order_event.payload.get("provider_order_id") is None
            or order_event.payload.get("order_revision") != receipt.order_revision
            or fill_event.revision != receipt.journal_revision
            # Final order state is authoritative in ORDER_OBSERVATION; the
            # separate FILL_OBSERVATION carries only fill-history facts.
            or order_event.payload.get("exposure_state") != receipt.final_state.value
            or order_event.payload.get("exposure_state")
            not in {OrderExposureState.FILLED.value, OrderExposureState.CANCELLED.value}
            or fill_event.payload.get("trade_count") != receipt.trade_count
            or not _decimal_text_matches(
                order_event.payload.get("quantity"), receipt.requested_quantity
            )
            or not _decimal_text_matches(
                fill_event.payload.get("filled_quantity"), receipt.filled_quantity
            )
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_RECEIPT_MISMATCH")
        reservation = connection.execute(
            "SELECT * FROM risk_order_exposure_references WHERE scope_key=? AND principal_ref=? AND intent_id=?",
            (fence.scope.key, principal_ref, intent_id),
        ).fetchone()
        if reservation is None or sha256_text(str(reservation["reference_json"])) != str(
            reservation["reference_sha256"]
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_REFERENCE_MISSING")
        reference = json.loads(reservation["reference_json"])
        reference_schema = (
            "bt-api-risk-order-terminal-close-reference-v1"
            if is_close
            else "bt-api-risk-order-terminal-exposure-reference-v1"
        )
        reference_kind = (
            reference.get("close_proof_kind") if is_close else reference.get("exposure_proof_kind")
        )
        expected_reference_kind = "TERMINAL_CLOSE" if is_close else "TERMINAL_EXPOSURE"
        if (
            reference.get("schema") != reference_schema
            or reference_kind != expected_reference_kind
            or reference.get("position_effect", position_effect) != position_effect
            or reference.get("reservation_id") != receipt.exposure_reservation_id
            or reservation["reservation_id"] != receipt.exposure_reservation_id
            or reservation["reference_sha256"] != receipt.exposure_reservation_sha256
            or reference.get("scope_key") != fence.scope.key
            or reference.get("intent_id") != claim.intent_id
            or reference.get("intent_hash") != claim.intent_hash
            or reference.get("permit_id") != claim.permit_id
            or reference.get("claim_digest") != claim.claim_digest
            or reference.get("claim") != _claim_payload(claim)
            or reference.get("accepted_request_sha256") != command["order_request_sha256"]
            or reference.get("average_price") != _weighted_average_price(fill_event.payload)
            or reference.get("provider_order_id") != order_event.payload.get("provider_order_id")
            or reference.get("order_observation_revision") != order_event.revision
            or reference.get("order_observation_record_sha256") != order_event.record_sha256
            or reference.get("fill_observation_revision") != fill_event.revision
            or reference.get("fill_observation_record_sha256") != fill_event.record_sha256
            or reference.get("writer_fence_sha256") != fill_event.writer_fence_sha256
            or reference.get("reconciliation_evidence_sha256")
            is None
            or reference.get("filled_quantity") != fill_event.payload.get("filled_quantity")
            or reference.get("trade_count") != fill_event.payload.get("trade_count")
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_REFERENCE_MISMATCH")
        if reference.get("reconciliation_evidence_sha256") != (
            _reconciliation_evidence_sha256(parsed_command, order_event, fill_event)
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_RECONCILIATION_MISMATCH")
        if is_close and proof_row is not None and persisted_proof is not None:
            observation = persisted_proof.observation
            if (
                int(proof_row["source_order_revision"]) != order_event.revision
                or proof_row["source_order_record_sha256"] != order_event.record_sha256
                or int(proof_row["source_fill_revision"]) != fill_event.revision
                or proof_row["source_fill_record_sha256"] != fill_event.record_sha256
                or proof_row["writer_owner_id"] != observation.writer_owner_id
                or int(proof_row["writer_fencing_token"]) != observation.writer_fencing_token
                or proof_row["writer_fence_sha256"] != observation.writer_fence_sha256
            ):
                raise RiskOrderJournalError("TERMINAL_CLOSE_PROOF_SOURCE_MISMATCH")
        if persisted_proof is not None:
            proof = persisted_proof
            observation = proof.observation
            stored_contract = (fill_event.payload.get("metadata_facts") or {}).get(
                "provider_contract"
            )
            if (
                proof.reconciliation_evidence_sha256
                != reference.get("reconciliation_evidence_sha256")
                or observation.journal_revision != fill_event.revision
                or observation.journal_record_sha256 != fill_event.record_sha256
                or observation.order_revision != order_event.payload.get("order_revision")
                or observation.provider_order_id != reference.get("provider_order_id")
                or observation.accepted_request_sha256 != command["order_request_sha256"]
                or observation.exposure_reservation_id != receipt.exposure_reservation_id
                or observation.exposure_reservation_sha256 != receipt.exposure_reservation_sha256
                or observation.state.value != order_event.payload.get("exposure_state")
                or not _decimal_text_matches(
                    fill_event.payload.get("filled_quantity"),
                    observation.cumulative_filled_quantity,
                )
                or observation.fill_trade_count != fill_event.payload.get("trade_count")
                or observation.fills != tuple(_fill_facts_from_event(fill_event.payload))
                or (observation.position_side, observation.position_bucket)
                != position_dimensions
                or observation.writer_fence_sha256 != fill_event.writer_fence_sha256
                or observation.writer_owner_id != fill_event.writer_owner_id
                or observation.writer_fencing_token != fill_event.writer_fencing_token
                or not _trade_identity_declaration_matches(observation, stored_contract)
            ):
                raise RiskOrderJournalError("TERMINAL_EXPOSURE_PROOF_SOURCE_MISMATCH")
        if ack_events and not self._has_terminal_ack_event_in(
            connection, fence, parsed_command, receipt
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_ACK_INVALID")

    def _has_terminal_ack_event_in(
        self,
        connection: sqlite3.Connection,
        fence: RiskOrderWriterFence,
        command: RiskOrderCommand,
        receipt: DispatchExposureResolutionReceipt,
    ) -> bool:
        row = connection.execute(
            "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? AND event_type='ACKED_TRACKED' ORDER BY revision",
            (fence.scope.key, command.principal_ref, command.intent_id),
        ).fetchall()
        if len(row) != 1:
            return False
        event = self._event_from_row(row[0], fence.scope)
        reference_row = connection.execute(
            "SELECT reference_json, reference_sha256 FROM risk_order_exposure_references "
            "WHERE scope_key=? AND principal_ref=? AND intent_id=?",
            (fence.scope.key, command.principal_ref, command.intent_id),
        ).fetchone()
        if reference_row is None:
            return False
        try:
            reference_json = str(reference_row["reference_json"])
            reference = json.loads(reference_json)
        except (TypeError, ValueError):
            return False
        if (
            canonical_json(reference) != reference_json
            or sha256_text(reference_json) != str(reference_row["reference_sha256"])
        ):
            return False
        source_rows = connection.execute(
            "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? "
            "AND intent_id=? AND event_type='FILL_OBSERVATION' ORDER BY revision",
            (fence.scope.key, command.principal_ref, command.intent_id),
        ).fetchall()
        is_close = command.canonical_payload.get("position_effect", "OPEN") == "CLOSE"
        if not source_rows or (not is_close and len(source_rows) != 1):
            return False
        # A CLOSE may accumulate several query observations before terminal
        # resolution.  Its immutable exposure reference selects the exact
        # final fill row; do not reject the valid source history merely because
        # it contains an earlier partial-fill observation.
        source_row = source_rows[-1] if is_close else source_rows[0]
        if is_close and (
            type(reference.get("fill_observation_revision")) is not int
            or int(source_row["revision"]) != reference.get("fill_observation_revision")
            or str(source_row["record_sha256"])
            != reference.get("fill_observation_record_sha256")
        ):
            return False
        source_event = self._event_from_row(source_row, fence.scope)
        source_token = source_event.writer_fencing_token
        ack_token = event.writer_fencing_token
        if (
            source_event.writer_fence_sha256
            != _fence_digest(
                fence.scope, source_event.writer_owner_id, source_event.writer_fencing_token
            )
            or source_token > fence.fencing_token
            or (
                source_token == fence.fencing_token
                and (
                    source_event.writer_owner_id != fence.owner_id
                    or source_event.writer_fence_sha256 != fence.fence_sha256
                )
            )
            or event.writer_fence_sha256
            != _fence_digest(fence.scope, event.writer_owner_id, ack_token)
            or ack_token < source_token
            or ack_token > fence.fencing_token
            or (
                ack_token == source_token
                and (
                    event.writer_owner_id != source_event.writer_owner_id
                    or event.writer_fence_sha256 != source_event.writer_fence_sha256
                )
            )
            or (
                ack_token == fence.fencing_token
                and (
                    event.writer_owner_id != fence.owner_id
                    or event.writer_fence_sha256 != fence.fence_sha256
                )
            )
        ):
            # Source rows keep their original fence. A later owner may append
            # the ACK only while holding the current fence.
            return False
        expected = _terminal_ack_payload(receipt, reference)
        payload = dict(event.payload)
        timestamp = payload.pop("updated_at_ns", None)
        return (
            payload == expected
            and type(timestamp) is int
            and timestamp > 0
            and command.state == "ACKED_TRACKED"
            and command.latest_revision == event.revision
        )

    @contextmanager
    def dispatch_exposure_resolution_guard(
        self,
        proof: DispatchExposureResolutionProof,
        *,
        claim: DispatchClaimBinding,
    ) -> Iterator[VerifiedDispatchExposureResolution | None]:
        """Hold the account fence while Risk resolves a complete terminal fill proof."""

        if type(proof) is not DispatchExposureResolutionProof or type(claim) is not DispatchClaimBinding:
            yield None
            return
        fence = _thread_fences().get(proof.scope.key)
        if fence is None or fence.scope != proof.scope:
            yield None
            return
        verified = self._attest_dispatch_exposure_resolution(proof, claim, fence)
        self._assert_current(fence)
        try:
            yield verified
        finally:
            self._assert_current(fence)

    @contextmanager
    def order_observation_guard(
        self,
        proof: OrderExposureObservationProof,
        *,
        claim: DispatchClaimBinding,
        tracked_order: DispatchTrackedOrderProof,
    ) -> Iterator[VerifiedOrderExposureObservation | None]:
        """Hold the account fence through Risk's exact post-ACK observation commit."""

        if (
            type(proof) is not OrderExposureObservationProof
            or type(claim) is not DispatchClaimBinding
            or type(tracked_order) is not DispatchTrackedOrderProof
        ):
            yield None
            return
        fence = _thread_fences().get(proof.scope.key)
        if fence is None or fence.scope != proof.scope:
            yield None
            return
        verified = self._attest_order_observation(proof, claim, tracked_order, fence)
        self._assert_current(fence)
        try:
            yield verified
        finally:
            self._assert_current(fence)

    def _attest_dispatch_exposure_resolution(
        self,
        proof: DispatchExposureResolutionProof,
        claim: DispatchClaimBinding,
        fence: RiskOrderWriterFence,
    ) -> VerifiedDispatchExposureResolution | None:
        """Bind an initial positive-fill terminal proof to its immutable source rows."""

        try:
            if proof.claim != claim or proof.scope != fence.scope:
                return None
            with closing(self._connection()) as connection:
                self._assert_current_in(connection, fence)
                command_row = connection.execute(
                    "SELECT * FROM risk_order_commands WHERE scope_key=? AND risk_intent_id=?",
                    (fence.scope.key, claim.intent_id),
                ).fetchone()
                if command_row is None:
                    return None
                command = self._command_from_row(connection, command_row, fence.scope)
                position_dimensions = _position_dimensions_from_payload(
                    command.canonical_payload
                )
                is_close = command.canonical_payload.get("position_effect", "OPEN") == "CLOSE"
                if (
                    command.state
                    not in (
                        {"FILL_OBSERVATION", "UNKNOWN", "ACKED_TRACKED"}
                        if is_close
                        else {"FILL_OBSERVATION", "UNKNOWN"}
                    )
                    or command.permit_id != claim.permit_id
                    or command.risk_intent_id != claim.intent_id
                    or command.order_request_sha256 != proof.observation.accepted_request_sha256
                ):
                    return None
                head = connection.execute(
                    "SELECT revision FROM risk_order_events WHERE scope_key=? "
                    "ORDER BY revision DESC LIMIT 1",
                    (fence.scope.key,),
                ).fetchone()
                if head is None or not self._verify_event_chains(
                    connection,
                    command_row,
                    fence.scope,
                    int(head["revision"]),
                    target_revision=command.latest_revision,
                ):
                    return None
                rows = connection.execute(
                    "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? "
                    "AND intent_id=? ORDER BY revision",
                    (fence.scope.key, command.principal_ref, command.intent_id),
                ).fetchall()
                events = tuple(self._event_from_row(row, fence.scope) for row in rows)
                try:
                    source_command, source_events, source_fence, _ack_event = (
                        _terminal_exposure_source_projection(
                            command,
                            command_row,
                            events,
                            fence,
                        )
                    )
                    _permit_id, order_event, fill_event, _unknown_event = (
                        _terminal_exposure_lifecycle(
                            source_command,
                            command_row,
                            source_events,
                            source_fence,
                            expected_claim=claim,
                        )
                    )
                except RiskOrderJournalError:
                    return None
                order = order_event.payload
                fills = fill_event.payload
                order_revision = order.get("order_revision")
                if (
                    order.get("exposure_state") != proof.observation.state.value
                    or not _position_dimensions_match(order, position_dimensions)
                    or not _position_dimensions_match(fills, position_dimensions)
                    or (
                        proof.observation.position_side,
                        proof.observation.position_bucket,
                    )
                    != position_dimensions
                    or order_revision != proof.observation.order_revision
                    or order.get("provider_order_id") != proof.observation.provider_order_id
                    or not _decimal_text_matches(
                        order.get("quantity"), proof.observation.requested_quantity
                    )
                    or not _decimal_text_matches(
                        fills.get("filled_quantity"),
                        proof.observation.cumulative_filled_quantity,
                    )
                    or fills.get("trade_count") != proof.observation.fill_trade_count
                    or fills.get("fill_watermark_revision")
                    != proof.observation.fill_watermark_revision
                ):
                    return None
                reconciliation = _reconciliation_evidence_sha256(
                    command,
                    order_event,
                    fill_event,
                )
                if proof.reconciliation_evidence_sha256 != reconciliation:
                    return None
                reference_row = connection.execute(
                    "SELECT * FROM risk_order_exposure_references WHERE scope_key=? "
                    "AND principal_ref=? AND intent_id=?",
                    (fence.scope.key, command.principal_ref, command.intent_id),
                ).fetchone()
                if reference_row is None or sha256_text(str(reference_row["reference_json"])) != str(
                    reference_row["reference_sha256"]
                ):
                    return None
                reference = json.loads(reference_row["reference_json"])
                observation = proof.observation
                if is_close:
                    proof_row = connection.execute(
                        "SELECT * FROM risk_order_terminal_close_proofs "
                        "WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                        (fence.scope.key, command.principal_ref, command.intent_id),
                    ).fetchone()
                    if proof_row is None:
                        return None
                    try:
                        raw_proof_json = str(proof_row["proof_json"])
                        stored_proof_payload = json.loads(raw_proof_json)
                        stored_proof = _terminal_close_proof_from_payload(
                            stored_proof_payload,
                            scope=fence.scope,
                        )
                    except (TypeError, ValueError, RiskOrderJournalError):
                        return None
                    if (
                        canonical_json(stored_proof_payload) != raw_proof_json
                        or stored_proof != proof
                        or proof_row["proof_sha256"] != proof.fingerprint
                        or int(proof_row["source_order_revision"]) != order_event.revision
                        or proof_row["source_order_record_sha256"] != order_event.record_sha256
                        or int(proof_row["source_fill_revision"]) != fill_event.revision
                        or proof_row["source_fill_record_sha256"] != fill_event.record_sha256
                        or proof_row["writer_owner_id"] != observation.writer_owner_id
                        or int(proof_row["writer_fencing_token"])
                        != observation.writer_fencing_token
                        or proof_row["writer_fence_sha256"] != observation.writer_fence_sha256
                    ):
                        return None
                observation_fence = source_fence
                if is_close:
                    observation_fence = RiskOrderWriterFence(
                        fence.scope,
                        fill_event.writer_owner_id,
                        fill_event.writer_fencing_token,
                        fill_event.writer_fence_sha256,
                    )
                if not _terminal_exposure_source_matches(
                    observation=observation,
                    claim=claim,
                    command=source_command,
                    order_event=order_event,
                    fill_event=fill_event,
                    reference=reference,
                    reference_id=str(reference_row["reservation_id"]),
                    reference_sha256=str(reference_row["reference_sha256"]),
                    fence=observation_fence,
                    reconciliation_evidence_sha256=reconciliation,
                ):
                    return None
                return VerifiedDispatchExposureResolution(
                    scope=claim.scope,
                    permit_id=claim.permit_id,
                    intent_id=claim.intent_id,
                    intent_hash=claim.intent_hash,
                    cause_id=claim.cause_id,
                    claim_digest=claim.claim_digest,
                    proof_sha256=proof.fingerprint,
                    exposure_proof_sha256=observation.fingerprint,
                    provider_order_id=observation.provider_order_id,
                    accepted_request_sha256=observation.accepted_request_sha256,
                    exposure_reservation_id=observation.exposure_reservation_id,
                    exposure_reservation_sha256=observation.exposure_reservation_sha256,
                    final_state=observation.state,
                    requested_quantity=observation.requested_quantity,
                    filled_quantity=observation.cumulative_filled_quantity,
                    trade_count=observation.fill_trade_count,
                    order_revision=observation.order_revision,
                    journal_revision=observation.journal_revision,
                    journal_record_sha256=observation.journal_record_sha256,
                    writer_owner_id=observation.writer_owner_id,
                    writer_fencing_token=observation.writer_fencing_token,
                    writer_fence_sha256=observation.writer_fence_sha256,
                )
        except (RiskOrderJournalError, sqlite3.Error, KeyError, TypeError, ValueError, InvalidOperation):
            return None

    def _attest_order_observation(
        self,
        proof: OrderExposureObservationProof,
        claim: DispatchClaimBinding,
        tracked_order: DispatchTrackedOrderProof,
        fence: RiskOrderWriterFence,
    ) -> VerifiedOrderExposureObservation | None:
        """Verify a post-ACK normalized order/fill snapshot under the live fence."""

        try:
            if proof.scope != fence.scope or proof.scope != claim.scope:
                return None
            with closing(self._connection()) as connection:
                self._assert_current_in(connection, fence)
                command_row = connection.execute(
                    "SELECT * FROM risk_order_commands WHERE scope_key=? AND risk_intent_id=?",
                    (fence.scope.key, claim.intent_id),
                ).fetchone()
                if command_row is None:
                    return None
                command = self._command_from_row(connection, command_row, fence.scope)
                if command.permit_id != claim.permit_id or command.order_request_sha256 != proof.accepted_request_sha256:
                    return None
                position_dimensions = _position_dimensions_from_payload(
                    command.canonical_payload
                )
                if (
                    (proof.position_side, proof.position_bucket) != position_dimensions
                ):
                    return None
                head = connection.execute(
                    "SELECT revision FROM risk_order_events WHERE scope_key=? "
                    "ORDER BY revision DESC LIMIT 1",
                    (fence.scope.key,),
                ).fetchone()
                if head is None or int(head["revision"]) != proof.journal_revision:
                    return None
                if not self._verify_event_chains(
                    connection, command_row, fence.scope, int(head["revision"])
                ):
                    return None
                rows = connection.execute(
                    "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? "
                    "AND intent_id=? ORDER BY revision",
                    (fence.scope.key, command.principal_ref, command.intent_id),
                ).fetchall()
                events = tuple(self._event_from_row(row, fence.scope) for row in rows)
                by_type: dict[str, list[RiskOrderJournalEvent]] = {}
                for event in events:
                    by_type.setdefault(event.event_type, []).append(event)
                if any(
                    len(by_type.get(name, ())) != 1
                    for name in (
                        "RESERVED",
                        "CLAIMED",
                        "DISPATCHING",
                        "ORDER_OBSERVATION",
                        "FILL_OBSERVATION",
                        "PROOF_READY",
                        "ACKED_TRACKED",
                    )
                ):
                    return None
                order_event = by_type["ORDER_OBSERVATION"][0]
                fill_event = by_type["FILL_OBSERVATION"][0]
                if not _position_dimensions_match(
                    order_event.payload, position_dimensions
                ) or not _position_dimensions_match(fill_event.payload, position_dimensions):
                    return None
                ack = by_type["ACKED_TRACKED"][0]
                if any(
                    event.event_type not in {
                        "PREPARED",
                        "RESERVED",
                        "CLAIMED",
                        "DISPATCHING",
                        "ORDER_OBSERVATION",
                        "FILL_OBSERVATION",
                        "PROOF_READY",
                        "ACKED_TRACKED",
                        "PROVIDER_QUERY",
                        "EXPOSURE_APPLIED",
                        "UNKNOWN",
                    }
                    or (
                        event.event_type == "UNKNOWN"
                        and not _post_ack_unknown_payload_valid(
                            event.payload,
                            revision=event.revision,
                            ack_revision=ack.revision,
                            permit_id=command.permit_id,
                        )
                    )
                    for event in events
                ):
                    return None
                query_events = by_type.get("PROVIDER_QUERY", ())
                latest = events[-1]
                if not _acknowledged_query_history_valid(
                    events,
                    ack_index=events.index(ack),
                    command=command,
                    allow_pending_latest_query=True,
                ):
                    return None
                if (
                    not query_events
                    or latest != query_events[-1]
                    or latest.revision != proof.journal_revision
                    or latest.record_sha256 != proof.journal_record_sha256
                    or latest.writer_owner_id != fence.owner_id
                    or latest.writer_fencing_token != fence.fencing_token
                    or latest.writer_fence_sha256 != fence.fence_sha256
                    or latest.payload.get("public_state") != "UNKNOWN"
                    or latest.payload.get("dispatch_attempt_count") != 1
                    or latest.payload.get("risk_intent_id") != claim.intent_id
                    or latest.payload.get("dispatch_claim_digest") != claim.claim_digest
                    or by_type["CLAIMED"][0].payload.get("claim") != _claim_payload(claim)
                    or not _is_v2_order_event(latest.payload, combined_query=True)
                    or not _is_v2_fill_event(latest.payload, combined_query=True)
                ):
                    return None
                proof_event = by_type["PROOF_READY"][0]
                order_event = by_type["ORDER_OBSERVATION"][0]
                fill_event = by_type["FILL_OBSERVATION"][0]
                if not (
                    order_event.revision < fill_event.revision < proof_event.revision < ack.revision < latest.revision
                    and ack.writer_owner_id == proof_event.writer_owner_id
                    and ack.writer_fencing_token == proof_event.writer_fencing_token
                    and ack.writer_fence_sha256 == proof_event.writer_fence_sha256
                    and proof_event.payload.get("claim") == _claim_payload(claim)
                    and ack.payload.get("public_state") == "ACKED_TRACKED"
                    and tracked_order == _tracked_proof_from_events(
                        command,
                        claim,
                        proof_event,
                    )
                    and latest.payload.get("provider_order_id") == tracked_order.provider_order_id
                    and latest.payload.get("client_order_id") == command.client_order_id
                    and latest.payload.get("account_id") == command.provider_account_id
                    and latest.payload.get("quantity") == command.order_request.get("quantity")
                    and latest.payload.get("exposure_state") == proof.state.value
                    and latest.payload.get("order_revision") == proof.order_revision
                    and latest.payload.get("fill_watermark_revision") == proof.fill_watermark_revision
                    and proof.writer_owner_id == fence.owner_id
                    and proof.writer_fencing_token == fence.fencing_token
                    and proof.writer_fence_sha256 == fence.fence_sha256
                    and _order_observation_source_matches(
                        proof=proof,
                        command=command,
                        claim=claim,
                        tracked_order=tracked_order,
                        query_event=latest,
                        order_event=order_event,
                        fill_event=fill_event,
                        fence=fence,
                    )
                ):
                    return None
                return VerifiedOrderExposureObservation(
                    scope=proof.scope,
                    permit_id=proof.permit_id,
                    intent_id=proof.intent_id,
                    proof_sha256=proof.fingerprint,
                    dispatch_claim_digest=claim.claim_digest,
                    dispatch_proof_sha256=tracked_order.fingerprint,
                    order_revision=proof.order_revision,
                    journal_revision=proof.journal_revision,
                    writer_owner_id=fence.owner_id,
                    writer_fencing_token=fence.fencing_token,
                    writer_fence_sha256=fence.fence_sha256,
                )
        except (RiskOrderJournalError, sqlite3.Error, KeyError, TypeError, ValueError, InvalidOperation):
            return None

    def prepare_or_get(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        risk_intent_id: str,
        payload_sha256: str,
        canonical_payload: Mapping[str, Any],
        wire_scope: Mapping[str, Any],
        exchange_name: str,
        provider_account_id: str,
        client_order_id: str,
        order_request: Mapping[str, Any],
        order_request_sha256: str,
    ) -> tuple[RiskOrderCommand, bool]:
        """Persist an idempotency key before Risk or provider side effects."""

        self._assert_current(fence)
        _require_sha256(payload_sha256, "payload digest")
        _require_sha256(order_request_sha256, "provider request digest")
        values = (
            principal_ref,
            intent_id,
            risk_intent_id,
            exchange_name,
            provider_account_id,
            client_order_id,
        )
        if any(type(value) is not str or not value or value != value.strip() for value in values):
            raise RiskOrderJournalError("INVALID_COMMAND_IDENTITY")
        canonical_payload_json = canonical_json(dict(canonical_payload))
        wire_scope_json = canonical_json(dict(wire_scope))
        order_request_json = canonical_json(dict(order_request))
        scope_key = fence.scope.key
        with self._transaction() as connection:
            self._assert_current_in(connection, fence)
            row = connection.execute(
                "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (scope_key, principal_ref, intent_id),
            ).fetchone()
            if row is not None:
                command = self._command_from_row(connection, row, fence.scope)
                if (
                    command.payload_sha256 != payload_sha256
                    or command.risk_intent_id != risk_intent_id
                    or command.client_order_id != client_order_id
                    or command.order_request_sha256 != order_request_sha256
                    or not _same_wire_scope_for_idempotency(command.wire_scope, wire_scope)
                ):
                    raise RiskOrderJournalError("INTENT_CONFLICT")
                return command, False

            revision, previous_account, previous_command = self._next_event_identity(
                connection, scope_key, principal_ref, intent_id
            )
            created_at_ns = time.time_ns()
            body = {
                "canonical_payload": json.loads(canonical_payload_json),
                "client_order_id": client_order_id,
                "created_at_ns": created_at_ns,
                "exchange_name": exchange_name,
                "order_request": json.loads(order_request_json),
                "order_request_sha256": order_request_sha256,
                "provider_account_id": provider_account_id,
                "risk_intent_id": risk_intent_id,
                "wire_scope": json.loads(wire_scope_json),
            }
            event = self._event_from_body(
                fence,
                principal_ref,
                intent_id,
                revision,
                "PREPARED",
                {**body, "updated_at_ns": created_at_ns},
                previous_account,
                previous_command,
            )
            connection.execute(
                """INSERT INTO risk_order_commands (
                    scope_key, principal_ref, intent_id, risk_intent_id,
                    payload_sha256, canonical_payload_json, wire_scope_json,
                    exchange_name, provider_account_id, client_order_id,
                    order_request_json, order_request_sha256,
                    created_revision, created_record_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scope_key,
                    principal_ref,
                    intent_id,
                    risk_intent_id,
                    payload_sha256,
                    canonical_payload_json,
                    wire_scope_json,
                    exchange_name,
                    provider_account_id,
                    client_order_id,
                    order_request_json,
                    order_request_sha256,
                    revision,
                    event.record_sha256,
                ),
            )
            self._insert_event(connection, fence, event)
            row = connection.execute(
                "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (scope_key, principal_ref, intent_id),
            ).fetchone()
            assert row is not None
            return self._command_from_row(connection, row, fence.scope), True

    def append_event(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> RiskOrderJournalEvent:
        """Append one immutable event after validating the current owner token."""

        self._assert_current(fence)
        if type(event_type) is not str or event_type not in {
            "RESERVED",
            "CLAIMED",
            "DISPATCHING",
            "ORDER_OBSERVATION",
            "FILL_OBSERVATION",
            "PROOF_READY",
            "ACKED_TRACKED",
            "UNKNOWN",
            "ADMISSION_DENIED",
            "NO_DISPATCH",
            "PROVIDER_QUERY",
            "EXPOSURE_APPLIED",
        }:
            raise RiskOrderJournalError("INVALID_EVENT_TYPE")
        if not isinstance(payload, Mapping):
            raise RiskOrderJournalError("INVALID_EVENT_PAYLOAD")
        if event_type == "EXPOSURE_APPLIED" and not _valid_exposure_applied_payload(payload):
            raise RiskOrderJournalError("INVALID_EXPOSURE_APPLICATION")
        payload_json = canonical_json({**dict(payload), "updated_at_ns": time.time_ns()})
        with self._transaction() as connection:
            self._assert_current_in(connection, fence)
            self._require_command(connection, fence.scope.key, principal_ref, intent_id)
            current = connection.execute(
                "SELECT event_type FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? ORDER BY revision DESC LIMIT 1",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            if current is None:
                raise RiskOrderJournalError("COMMAND_EVENT_MISSING")
            self._validate_transition(str(current["event_type"]), event_type)
            revision, previous_account, previous_command = self._next_event_identity(
                connection, fence.scope.key, principal_ref, intent_id
            )
            event = self._event_from_body(
                fence,
                principal_ref,
                intent_id,
                revision,
                event_type,
                json.loads(payload_json),
                previous_account,
                previous_command,
            )
            self._insert_event(connection, fence, event)
            return event

    def store_exposure_reference(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        claim: DispatchClaimBinding,
        evidence_class: DispatchEvidenceClass,
        permit_id: str,
        provider_order_id: str,
        accepted_request_sha256: str,
        reconciliation_evidence_sha256: str,
        observation_revision: int,
        observation_record_sha256: str,
    ) -> tuple[str, str, Mapping[str, Any]]:
        """Store a durable per-order Risk exposure reference, not an exposure ledger."""

        self._assert_current(fence)
        if type(claim) is not DispatchClaimBinding:
            raise RiskOrderJournalError("DISPATCH_CLAIM_REQUIRED")
        if type(evidence_class) is not DispatchEvidenceClass:
            raise RiskOrderJournalError("DISPATCH_EVIDENCE_CLASS_REQUIRED")
        for value, name in (
            (permit_id, "permit id"),
            (provider_order_id, "provider order id"),
        ):
            if type(value) is not str or not value or value != value.strip():
                raise RiskOrderJournalError("INVALID_" + name.upper().replace(" ", "_"))
        _require_sha256(accepted_request_sha256, "accepted request digest")
        _require_sha256(reconciliation_evidence_sha256, "reconciliation digest")
        _require_sha256(observation_record_sha256, "observation record digest")
        if type(observation_revision) is not int or observation_revision <= 0:
            raise RiskOrderJournalError("INVALID_OBSERVATION_REVISION")
        command = self.get_command(fence.scope, principal_ref, intent_id)
        if (
            command is None
            or command.state != "FILL_OBSERVATION"
            or command.risk_intent_id != claim.intent_id
            or claim.scope != fence.scope
            or claim.permit_id != permit_id
        ):
            raise RiskOrderJournalError("COMPLETE_OBSERVATION_REQUIRED")
        reservation_id = (
            "risk-order-exposure:"
            + sha256_text(
                canonical_json(
                    {
                        "intent_id": command.risk_intent_id,
                        "permit_id": permit_id,
                        "provider_order_id": provider_order_id,
                        "scope_key": fence.scope.key,
                    }
                )
            )[:32]
        )
        with closing(self._connection()) as connection:
            order_row = connection.execute(
                "SELECT revision, record_sha256 FROM risk_order_events "
                "WHERE scope_key=? AND principal_ref=? AND intent_id=? "
                "AND event_type='ORDER_OBSERVATION' AND revision<? ORDER BY revision DESC LIMIT 1",
                (fence.scope.key, principal_ref, intent_id, command.latest_revision),
            ).fetchone()
            fill_row = connection.execute(
                "SELECT revision, record_sha256 FROM risk_order_events "
                "WHERE scope_key=? AND principal_ref=? AND intent_id=? AND revision=? "
                "AND event_type='FILL_OBSERVATION'",
                (fence.scope.key, principal_ref, intent_id, command.latest_revision),
            ).fetchone()
        if order_row is None or fill_row is None:
            raise RiskOrderJournalError("COMPLETE_OBSERVATION_REQUIRED")
        reference = {
            "accepted_request_sha256": accepted_request_sha256,
            "claim": _claim_payload(claim),
            "claim_digest": claim.claim_digest,
            "dispatch_attempt_count": 1,
            "evidence_class": evidence_class.value,
            "filled_quantity": 0,
            "intent_id": command.risk_intent_id,
            "intent_hash": claim.intent_hash,
            "order_observation_record_sha256": str(order_row["record_sha256"]),
            "order_observation_revision": int(order_row["revision"]),
            "observation_record_sha256": observation_record_sha256,
            "observation_revision": observation_revision,
            "permit_id": permit_id,
            "provider_order_id": provider_order_id,
            "reconciliation_evidence_sha256": reconciliation_evidence_sha256,
            "schema": "bt-api-risk-order-exposure-reference-v1",
            "scope_key": fence.scope.key,
            "trade_count": 0,
            "fill_observation_record_sha256": str(fill_row["record_sha256"]),
            "fill_observation_revision": int(fill_row["revision"]),
            "writer_fence_sha256": fence.fence_sha256,
        }
        reference_json = canonical_json(reference)
        reference_sha256 = sha256_text(reference_json)
        with self._transaction() as connection:
            self._assert_current_in(connection, fence)
            self._require_command(connection, fence.scope.key, principal_ref, intent_id)
            prior = connection.execute(
                "SELECT * FROM risk_order_exposure_references WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            if prior is not None:
                if prior["reference_sha256"] != reference_sha256:
                    raise RiskOrderJournalError("EXPOSURE_REFERENCE_CONFLICT")
                return reservation_id, reference_sha256, reference
            revision, previous_account, previous_command = self._next_event_identity(
                connection, fence.scope.key, principal_ref, intent_id
            )
            event = self._event_from_body(
                fence,
                principal_ref,
                intent_id,
                revision,
                "PROOF_READY",
                {
                    "accepted_request_sha256": accepted_request_sha256,
                    "cause_id": claim.cause_id,
                    "claim": _claim_payload(claim),
                    "claim_digest": claim.claim_digest,
                    "dispatch_attempt_count": 1,
                    "evidence_class": evidence_class.value,
                    "exposure_reference": reference,
                    "exposure_reference_id": reservation_id,
                    "exposure_reference_sha256": reference_sha256,
                    "filled_quantity": 0,
                    "intent_hash": claim.intent_hash,
                    "intent_id": claim.intent_id,
                    "permit_id": permit_id,
                    "provider_order_id": provider_order_id,
                    "reconciliation_evidence_sha256": reconciliation_evidence_sha256,
                    "observation_record_sha256": observation_record_sha256,
                    "observation_revision": observation_revision,
                    "risk_intent_id": command.risk_intent_id,
                    "trade_count": 0,
                    "writer_fence_sha256": fence.fence_sha256,
                    "updated_at_ns": time.time_ns(),
                },
                previous_account,
                previous_command,
            )
            connection.execute(
                """INSERT INTO risk_order_exposure_references (
                    scope_key, principal_ref, intent_id, reservation_id,
                    reference_sha256, reference_json, created_revision, record_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    fence.scope.key,
                    principal_ref,
                    intent_id,
                    reservation_id,
                    reference_sha256,
                    reference_json,
                    revision,
                    event.record_sha256,
                ),
            )
            self._insert_event(connection, fence, event)
        return reservation_id, reference_sha256, reference

    def get_command(
        self, scope: AccountScope, principal_ref: str, intent_id: str
    ) -> RiskOrderCommand | None:
        """Read one exact principal/account command; never accepts provider IDs."""

        with closing(self._connection()) as connection:
            row = connection.execute(
                "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (scope.key, principal_ref, intent_id),
            ).fetchone()
            return None if row is None else self._command_from_row(connection, row, scope)

    def get_event(
        self,
        scope: AccountScope,
        principal_ref: str,
        intent_id: str,
        revision: int,
    ) -> RiskOrderJournalEvent | None:
        """Read one event only after validating its account and command chains."""

        if type(revision) is not int or revision <= 0:
            raise RiskOrderJournalError("INVALID_EVENT_REVISION")
        with closing(self._connection()) as connection:
            command = connection.execute(
                "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (scope.key, principal_ref, intent_id),
            ).fetchone()
            if command is None:
                return None
            row = connection.execute(
                "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? AND revision=?",
                (scope.key, principal_ref, intent_id, revision),
            ).fetchone()
            if row is None:
                return None
            head = connection.execute(
                "SELECT revision FROM risk_order_events WHERE scope_key=? ORDER BY revision DESC LIMIT 1",
                (scope.key,),
            ).fetchone()
            if head is None or not self._verify_event_chains(
                connection,
                command,
                scope,
                int(head["revision"]),
                target_revision=revision,
            ):
                raise RiskOrderJournalError("EVENT_CHAIN_INVALID")
            return self._event_from_row(row, scope)

    def has_proof_ready_history(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
    ) -> bool:
        """Fail closed from provider reads when an immutable proof may exist."""

        self._assert_current(fence)
        with closing(self._connection()) as connection:
            self._assert_current_in(connection, fence)
            row = connection.execute(
                "SELECT 1 FROM risk_order_events WHERE scope_key=? AND principal_ref=? "
                "AND intent_id=? AND event_type='PROOF_READY' LIMIT 1",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            return row is not None

    def has_resolved_ack_history(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        receipt: DispatchResolutionReceipt,
    ) -> bool:
        """Verify an ACK event against Risk's exact resolved proof receipt.

        This check is separate from proof recovery: provider-query events after
        ACK are valid read history, but they must never be admitted into the
        immutable proof-recovery loader.
        """

        self._assert_current(fence)
        if (
            type(receipt) is not DispatchResolutionReceipt
            or receipt.status is not DispatchResolutionReceiptStatus.ACKED_TRACKED_RESOLVED
            or receipt.dispatch_latch_active is not False
            or type(receipt.claim) is not DispatchClaimBinding
            or type(receipt.proof) is not DispatchTrackedOrderProof
            or receipt.proof_sha256 != receipt.proof.fingerprint
        ):
            return False
        claim = receipt.claim
        proof = receipt.proof
        if (
            type(principal_ref) is not str
            or not principal_ref
            or type(intent_id) is not str
            or not intent_id
            or claim.scope != fence.scope
            or proof.scope != fence.scope
            or proof.permit_id != claim.permit_id
            or proof.intent_id != claim.intent_id
            or proof.intent_hash != claim.intent_hash
            or proof.cause_id != claim.cause_id
            or proof.claim_digest != claim.claim_digest
            or proof.dispatch_attempt_count != 1
            or proof.filled_quantity != 0
            or proof.trade_count != 0
        ):
            return False

        with closing(self._connection()) as connection:
            self._assert_current_in(connection, fence)
            command_row = connection.execute(
                "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            if command_row is None:
                return False
            command_events_rows = connection.execute(
                "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? ORDER BY revision",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchall()
            if not command_events_rows:
                return False
            head = connection.execute(
                "SELECT revision FROM risk_order_events WHERE scope_key=? ORDER BY revision DESC LIMIT 1",
                (fence.scope.key,),
            ).fetchone()
            if head is None or not self._verify_event_chains(
                connection,
                command_row,
                fence.scope,
                int(head["revision"]),
                target_revision=proof.journal_revision,
            ):
                return False

            command = self._command_from_row(connection, command_row, fence.scope)
            if (
                command.state
                not in {"ACKED_TRACKED", "PROVIDER_QUERY", "EXPOSURE_APPLIED", "UNKNOWN"}
                or command.risk_intent_id != claim.intent_id
                or command.permit_id != claim.permit_id
                or command.order_request_sha256 != proof.accepted_request_sha256
            ):
                return False
            events = tuple(self._event_from_row(row, fence.scope) for row in command_events_rows)
            by_type: dict[str, list[RiskOrderJournalEvent]] = {}
            for event in events:
                by_type.setdefault(event.event_type, []).append(event)
            reserved = by_type.get("RESERVED", [])
            claimed = by_type.get("CLAIMED", [])
            dispatching = by_type.get("DISPATCHING", [])
            proof_ready = by_type.get("PROOF_READY", [])
            acknowledgements = by_type.get("ACKED_TRACKED", [])
            if (
                len(reserved) != 1
                or len(claimed) != 1
                or len(dispatching) != 1
                or len(proof_ready) != 1
                or len(acknowledgements) != 1
            ):
                return False

            reserve_payload = dict(reserved[0].payload)
            claim_payload = dict(claimed[0].payload)
            dispatch_payload = dict(dispatching[0].payload)
            proof_event = proof_ready[0]
            proof_payload = dict(proof_event.payload)
            ack_event = acknowledgements[0]
            ack_payload = dict(ack_event.payload)
            if (
                reserved[0].revision >= claimed[0].revision
                or claimed[0].revision >= dispatching[0].revision
                or dispatching[0].revision >= proof_event.revision
                or proof_event.revision >= ack_event.revision
                or proof_event.revision != proof.journal_revision
                or proof_event.record_sha256 != proof.journal_record_sha256
                or proof_event.writer_fence_sha256 != proof.writer_fence_sha256
                or _fence_digest(
                    fence.scope,
                    proof_event.writer_owner_id,
                    proof_event.writer_fencing_token,
                )
                != proof_event.writer_fence_sha256
                or ack_event.writer_fencing_token < proof_event.writer_fencing_token
                or _fence_digest(
                    fence.scope, ack_event.writer_owner_id, ack_event.writer_fencing_token
                )
                != ack_event.writer_fence_sha256
                or set(reserve_payload) != {"permit_id", "risk_intent_id", "updated_at_ns"}
                or reserve_payload.get("permit_id") != claim.permit_id
                or reserve_payload.get("risk_intent_id") != claim.intent_id
                or type(reserve_payload.get("updated_at_ns")) is not int
                or reserve_payload.get("updated_at_ns") <= 0
                or set(claim_payload) != {"claim", "permit_id", "risk_intent_id", "updated_at_ns"}
                or claim_payload.get("claim") != _claim_payload(claim)
                or claim_payload.get("permit_id") != claim.permit_id
                or claim_payload.get("risk_intent_id") != claim.intent_id
                or type(claim_payload.get("updated_at_ns")) is not int
                or claim_payload.get("updated_at_ns") <= 0
                or not _provider_dispatch_payload_valid(
                    dispatch_payload, claim=claim, risk_scope_key=fence.scope.key,
                    profile_for=self._risk_dispatch_profile,
                )
                or dispatch_payload.get("dispatch_attempt_count") != 1
                or dispatch_payload.get("permit_id") != claim.permit_id
                or dispatch_payload.get("risk_intent_id") != claim.intent_id
                or type(dispatch_payload.get("updated_at_ns")) is not int
                or dispatch_payload.get("updated_at_ns") <= 0
            ):
                return False

            expected_proof_fields = {
                "accepted_request_sha256",
                "cause_id",
                "claim",
                "claim_digest",
                "dispatch_attempt_count",
                "evidence_class",
                "exposure_reference",
                "exposure_reference_id",
                "exposure_reference_sha256",
                "filled_quantity",
                "intent_hash",
                "intent_id",
                "observation_record_sha256",
                "observation_revision",
                "permit_id",
                "provider_order_id",
                "reconciliation_evidence_sha256",
                "risk_intent_id",
                "trade_count",
                "updated_at_ns",
                "writer_fence_sha256",
            }
            if (
                set(proof_payload) != expected_proof_fields
                or proof_payload.get("claim") != _claim_payload(claim)
                or proof_payload.get("claim_digest") != claim.claim_digest
                or proof_payload.get("cause_id") != proof.cause_id
                or proof_payload.get("intent_hash") != proof.intent_hash
                or proof_payload.get("intent_id") != proof.intent_id
                or proof_payload.get("risk_intent_id") != command.risk_intent_id
                or proof_payload.get("permit_id") != proof.permit_id
                or proof_payload.get("dispatch_attempt_count") != 1
                or proof_payload.get("evidence_class") != proof.evidence_class.value
                or proof_payload.get("accepted_request_sha256") != proof.accepted_request_sha256
                or proof_payload.get("provider_order_id") != proof.provider_order_id
                or proof_payload.get("exposure_reference_id") != proof.exposure_reservation_id
                or proof_payload.get("exposure_reference_sha256")
                != proof.exposure_reservation_sha256
                or proof_payload.get("reconciliation_evidence_sha256")
                != proof.reconciliation_evidence_sha256
                or proof_payload.get("filled_quantity") != 0
                or proof_payload.get("trade_count") != 0
                or proof_payload.get("writer_fence_sha256") != proof.writer_fence_sha256
                or type(proof_payload.get("updated_at_ns")) is not int
                or proof_payload.get("updated_at_ns") <= 0
            ):
                return False

            exposure = connection.execute(
                "SELECT * FROM risk_order_exposure_references WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
            if exposure is None:
                return False
            reference_json = str(exposure["reference_json"])
            if sha256_text(reference_json) != proof.exposure_reservation_sha256:
                return False
            try:
                reference = json.loads(reference_json)
            except (TypeError, ValueError):
                return False
            expected_reference_fields = {
                "accepted_request_sha256",
                "claim",
                "claim_digest",
                "dispatch_attempt_count",
                "evidence_class",
                "fill_observation_record_sha256",
                "fill_observation_revision",
                "filled_quantity",
                "intent_hash",
                "intent_id",
                "observation_record_sha256",
                "observation_revision",
                "order_observation_record_sha256",
                "order_observation_revision",
                "permit_id",
                "provider_order_id",
                "reconciliation_evidence_sha256",
                "schema",
                "scope_key",
                "trade_count",
                "writer_fence_sha256",
            }
            if (
                type(reference) is not dict
                or set(reference) != expected_reference_fields
                or str(exposure["reservation_id"]) != proof.exposure_reservation_id
                or str(exposure["reference_sha256"]) != proof.exposure_reservation_sha256
                or int(exposure["created_revision"]) != proof.journal_revision
                or str(exposure["record_sha256"]) != proof.journal_record_sha256
                or proof_payload.get("exposure_reference") != reference
                or reference.get("schema") != "bt-api-risk-order-exposure-reference-v1"
                or reference.get("scope_key") != fence.scope.key
                or reference.get("intent_id") != proof.intent_id
                or reference.get("intent_hash") != proof.intent_hash
                or reference.get("permit_id") != proof.permit_id
                or reference.get("claim_digest") != proof.claim_digest
                or reference.get("claim") != _claim_payload(claim)
                or reference.get("accepted_request_sha256") != proof.accepted_request_sha256
                or reference.get("provider_order_id") != proof.provider_order_id
                or reference.get("reconciliation_evidence_sha256")
                != proof.reconciliation_evidence_sha256
                or reference.get("writer_fence_sha256") != proof.writer_fence_sha256
                or reference.get("dispatch_attempt_count") != 1
                or reference.get("filled_quantity") != 0
                or reference.get("trade_count") != 0
            ):
                return False
            if reference.get("observation_revision") != proof_payload.get(
                "observation_revision"
            ) or reference.get("observation_record_sha256") != proof_payload.get(
                "observation_record_sha256"
            ):
                return False

            order_revision = reference.get("order_observation_revision")
            fill_revision = reference.get("fill_observation_revision")
            if (
                type(order_revision) is not int
                or order_revision <= 0
                or type(fill_revision) is not int
                or fill_revision <= order_revision
                or fill_revision >= proof_event.revision
            ):
                return False
            order_row = connection.execute(
                "SELECT event_type, record_sha256 FROM risk_order_events "
                "WHERE scope_key=? AND principal_ref=? AND intent_id=? AND revision=?",
                (fence.scope.key, principal_ref, intent_id, order_revision),
            ).fetchone()
            fill_row = connection.execute(
                "SELECT event_type, record_sha256 FROM risk_order_events "
                "WHERE scope_key=? AND principal_ref=? AND intent_id=? AND revision=?",
                (fence.scope.key, principal_ref, intent_id, fill_revision),
            ).fetchone()
            if (
                order_row is None
                or fill_row is None
                or order_row["event_type"] != "ORDER_OBSERVATION"
                or fill_row["event_type"] != "FILL_OBSERVATION"
                or order_row["record_sha256"] != reference.get("order_observation_record_sha256")
                or fill_row["record_sha256"] != reference.get("fill_observation_record_sha256")
                or fill_revision != proof_payload.get("observation_revision")
                or fill_row["record_sha256"] != proof_payload.get("observation_record_sha256")
            ):
                return False
            if set(dispatch_payload) != _DISPATCH_BASE_FIELDS:
                profile = self._risk_dispatch_profile(claim.scope.provider)
                order_event = next(
                    (event for event in events if event.revision == order_revision), None
                )
                fill_event = next(
                    (event for event in events if event.revision == fill_revision), None
                )
                if not _provider_zero_fill_dispatch_history_valid(
                    dispatch_payload.get(profile.binding_field),
                    claim=claim,
                    risk_scope_key=fence.scope.key,
                    command=command,
                    proof=proof,
                    reference=reference,
                    order_event=order_event,
                    fill_event=fill_event,
                    profile_for=self._risk_dispatch_profile,
                ):
                    return False

            common_ack_fields = {
                "dispatch_attempt_count",
                "exposure_reference_id",
                "exposure_reference_sha256",
                "filled_quantity",
                "permit_id",
                "provider_order_id",
                "public_state",
                "reconciliation_evidence_sha256",
                "risk_intent_id",
                "trade_count",
                "updated_at_ns",
            }
            recovered_ack_fields = common_ack_fields | {
                "claim_digest",
                "proof_ready_record_sha256",
                "proof_ready_revision",
                "proof_sha256",
                "recovery_attestation_sha256",
            }
            if set(ack_payload) not in (common_ack_fields, recovered_ack_fields):
                return False
            if (
                ack_payload.get("dispatch_attempt_count") != 1
                or ack_payload.get("exposure_reference_id") != proof.exposure_reservation_id
                or ack_payload.get("exposure_reference_sha256") != proof.exposure_reservation_sha256
                or ack_payload.get("filled_quantity") != 0
                or ack_payload.get("permit_id") != proof.permit_id
                or ack_payload.get("provider_order_id") != proof.provider_order_id
                or ack_payload.get("public_state") != "ACKED_TRACKED"
                or ack_payload.get("reconciliation_evidence_sha256")
                != proof.reconciliation_evidence_sha256
                or ack_payload.get("risk_intent_id") != proof.intent_id
                or ack_payload.get("trade_count") != 0
            ):
                return False
            if set(ack_payload) == recovered_ack_fields and (
                ack_payload.get("claim_digest") != claim.claim_digest
                or ack_payload.get("proof_ready_record_sha256") != proof.journal_record_sha256
                or ack_payload.get("proof_ready_revision") != proof.journal_revision
                or ack_payload.get("proof_sha256") != proof.fingerprint
                or ack_payload.get("recovery_attestation_sha256")
                != (
                    None
                    if receipt.recovery_attestation is None
                    else receipt.recovery_attestation.fingerprint
                )
            ):
                return False
            if (
                type(ack_payload.get("updated_at_ns")) is not int
                or ack_payload["updated_at_ns"] <= 0
            ):
                return False

            proof_index = events.index(proof_event)
            ack_index = events.index(ack_event)
            if ack_index <= proof_index:
                return False
            pending_query: RiskOrderJournalEvent | None = None
            for event in events[ack_index + 1 :]:
                payload = dict(event.payload)
                if event.event_type == "UNKNOWN":
                    if not _post_ack_unknown_payload_valid(
                        payload,
                        revision=event.revision,
                        ack_revision=ack_event.revision,
                        permit_id=proof.permit_id,
                    ):
                        return False
                    pending_query = None
                elif event.event_type == "PROVIDER_QUERY":
                    if (
                        payload.get("permit_id") is not None
                        or payload.get("dispatch_attempt_count") != 1
                        or payload.get("public_state") not in {"ACKED_TRACKED", "UNKNOWN"}
                        or payload.get("provider_order_id") != proof.provider_order_id
                        or payload.get("client_order_id") != command.client_order_id
                        or payload.get("account_id") != command.provider_account_id
                        or payload.get("complete") is not True
                        or payload.get("source_alignment_valid") is not True
                        or payload.get("fill_source_alignment_valid") is not True
                        or type(payload.get("updated_at_ns")) is not int
                        or payload.get("updated_at_ns") <= 0
                    ):
                        return False
                    query_digest = payload.get("provider_observation_sha256")
                    digest_payload = dict(payload)
                    digest_payload.pop("provider_observation_sha256", None)
                    digest_payload.pop("dispatch_attempt_count", None)
                    digest_payload.pop("updated_at_ns", None)
                    if query_digest != sha256_text(canonical_json(digest_payload)):
                        return False
                    if payload.get("public_state") == "ACKED_TRACKED":
                        record = payload.get("record")
                        try:
                            fill_is_zero = Decimal(str(payload.get("filled_quantity"))) == 0
                            record_fill_is_zero = (
                                type(record) is dict and Decimal(str(record.get("filled"))) == 0
                            )
                        except (InvalidOperation, ValueError):
                            return False
                        if (
                            payload.get("record_count") != 0
                            or payload.get("trade_count") != 0
                            or payload.get("records") != []
                            or not fill_is_zero
                            or type(record) is not dict
                            or record.get("order_id") != proof.provider_order_id
                            or record.get("client_order_id") != command.client_order_id
                            or record.get("account_id") != command.provider_account_id
                            or record.get("status") != "accepted"
                            or not record_fill_is_zero
                        ):
                            return False
                    elif payload.get("public_state") == "UNKNOWN":
                        # A complete v2 provider observation is represented as
                        # UNKNOWN until Risk commits the exact exposure proof.
                        # Its following EXPOSURE_APPLIED event must bind this
                        # query's immutable journal identity.
                        if not (
                            _is_v2_order_event(payload, combined_query=True)
                            and _is_v2_fill_event(payload, combined_query=True)
                        ):
                            return False
                        pending_query = event
                else:
                    if event.event_type == "EXPOSURE_APPLIED":
                        if (
                            pending_query is None
                            or event.revision != pending_query.revision + 1
                            or not _exposure_application_matches_query(
                                event, pending_query, command
                            )
                        ):
                            return False
                        pending_query = None
                    else:
                        return False
            latest = events[-1]
            if command.state == "PROVIDER_QUERY":
                return (
                    latest.event_type == "PROVIDER_QUERY"
                    and latest.payload.get("public_state") in {"ACKED_TRACKED", "UNKNOWN"}
                )
            if command.state == "UNKNOWN":
                return latest.event_type == "UNKNOWN"
            if command.state == "EXPOSURE_APPLIED":
                return latest.event_type == "EXPOSURE_APPLIED" and pending_query is None
            return command.state == "ACKED_TRACKED" and latest.event_type == "ACKED_TRACKED"

    def load_dispatch_proof_for_recovery(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        claim: DispatchClaimBinding,
    ) -> DispatchProofRecoverySource | None:
        """Verify immutable proof, observations, and exposure source rows.

        The read is scoped by the authenticated principal and logical intent.
        It never accepts a provider/client order ID as lookup authority.
        """

        self._assert_current(fence)
        if type(claim) is not DispatchClaimBinding or claim.scope != fence.scope:
            raise RiskOrderJournalError("RECOVERY_CLAIM_SCOPE_INVALID")
        with closing(self._connection()) as connection:
            self._assert_current_in(connection, fence)
            return self._load_dispatch_proof_for_recovery_in(
                connection,
                fence,
                principal_ref=principal_ref,
                intent_id=intent_id,
                claim=claim,
            )

    def append_proof_recovery_attestation(
        self,
        fence: RiskOrderWriterFence,
        source: DispatchProofRecoverySource,
    ) -> DispatchRecoveryAttestation:
        """Append a current-fence attestation without rebinding original rows."""

        self._assert_current(fence)
        if type(source) is not DispatchProofRecoverySource:
            raise RiskOrderJournalError("RECOVERY_SOURCE_REQUIRED")
        if source.proof.writer_fence_sha256 == fence.fence_sha256:
            raise RiskOrderJournalError("RECOVERY_NEW_FENCE_REQUIRED")
        with self._transaction() as connection:
            self._assert_current_in(connection, fence)
            current = self._load_dispatch_proof_for_recovery_in(
                connection,
                fence,
                principal_ref=source.command.principal_ref,
                intent_id=source.command.intent_id,
                claim=source.claim,
            )
            if current is None or not _same_recovery_source_snapshot(source, current):
                raise RiskOrderJournalError("RECOVERY_SOURCE_CHANGED")
            revision, previous_account, previous_command = self._next_event_identity(
                connection,
                fence.scope.key,
                source.command.principal_ref,
                source.command.intent_id,
            )
            recovery_event_id = sha256_text(
                canonical_json(
                    [
                        fence.scope.key,
                        source.command.principal_ref,
                        source.command.intent_id,
                        revision,
                    ]
                )
            )
            payload = _recovery_event_payload(
                source,
                fence,
                recovery_event_id=recovery_event_id,
                recovery_event_revision=revision,
            )
            payload["updated_at_ns"] = time.time_ns()
            self._validate_transition(source.command.state, "PROOF_RECOVERY_ATTESTED")
            event = self._event_from_body(
                fence,
                source.command.principal_ref,
                source.command.intent_id,
                revision,
                "PROOF_RECOVERY_ATTESTED",
                payload,
                previous_account,
                previous_command,
            )
            self._insert_event(connection, fence, event)
            return _recovery_attestation_from_event(source, event)

    @contextmanager
    def recovered_dispatch_resolution_guard(
        self,
        proof: DispatchTrackedOrderProof,
        attestation: DispatchRecoveryAttestation,
        *,
        claim: DispatchClaimBinding,
    ) -> Iterator[VerifiedDispatchRecoveryResolution | None]:
        """Hold the live account fence while Risk consumes recovered proof."""

        if (
            type(proof) is not DispatchTrackedOrderProof
            or type(attestation) is not DispatchRecoveryAttestation
            or type(claim) is not DispatchClaimBinding
        ):
            yield None
            return
        fence = _thread_fences().get(proof.scope.key)
        if fence is None or fence.scope != proof.scope or claim.scope != proof.scope:
            yield None
            return
        verified = self._attest_recovered_dispatch_resolution(proof, attestation, claim, fence)
        self._assert_current(fence)
        try:
            yield verified
        finally:
            self._assert_current(fence)

    def append_recovered_ack(
        self,
        fence: RiskOrderWriterFence,
        *,
        source: DispatchProofRecoverySource,
        receipt: DispatchResolutionReceipt,
    ) -> RiskOrderCommand:
        """Record ACKED_TRACKED only from the exact durable Risk receipt."""

        self._assert_current(fence)
        if (
            type(source) is not DispatchProofRecoverySource
            or type(receipt) is not DispatchResolutionReceipt
            or receipt.status is not DispatchResolutionReceiptStatus.ACKED_TRACKED_RESOLVED
            or receipt.proof is None
            or receipt.proof_sha256 != source.proof.fingerprint
            or receipt.proof != source.proof
            or receipt.claim != source.claim
            or receipt.dispatch_latch_active is not False
        ):
            raise RiskOrderJournalError("RECOVERY_RECEIPT_MISMATCH")
        if receipt.recovery_attestation is not None and receipt.recovery_attestation not in (
            source.recovery_attestations
        ):
            raise RiskOrderJournalError("RECOVERY_RECEIPT_ATTESTATION_MISMATCH")
        with self._transaction() as connection:
            self._assert_current_in(connection, fence)
            current = self._load_dispatch_proof_for_recovery_in(
                connection,
                fence,
                principal_ref=source.command.principal_ref,
                intent_id=source.command.intent_id,
                claim=source.claim,
            )
            if current is None or not _same_recovery_source_snapshot(source, current):
                raise RiskOrderJournalError("RECOVERY_SOURCE_CHANGED")
            if current.command.state == "UNKNOWN":
                # Only this proof-specific method may finish UNKNOWN. The
                # loader above has verified the unique immutable PROOF_READY
                # chain and the exact settled exposure reference, and the
                # receipt above proves Risk already resolved that same proof.
                # Keep the generic transition map closed so an UNKNOWN event
                # alone can never authorize ACKED_TRACKED.
                latest = current.command.latest_event
                if (
                    latest.get("permit_id") != current.proof.permit_id
                    or latest.get("dispatch_attempt_count") != 1
                    or latest.get("public_state") != "UNKNOWN"
                ):
                    raise RiskOrderJournalError("RECOVERY_UNKNOWN_EVENT_INVALID")
            else:
                self._validate_transition(current.command.state, "ACKED_TRACKED")
            proof = current.proof
            revision, previous_account, previous_command = self._next_event_identity(
                connection,
                fence.scope.key,
                current.command.principal_ref,
                current.command.intent_id,
            )
            event = self._event_from_body(
                fence,
                current.command.principal_ref,
                current.command.intent_id,
                revision,
                "ACKED_TRACKED",
                {
                    "claim_digest": current.claim.claim_digest,
                    "dispatch_attempt_count": 1,
                    "exposure_reference_id": proof.exposure_reservation_id,
                    "exposure_reference_sha256": proof.exposure_reservation_sha256,
                    "filled_quantity": 0,
                    "permit_id": proof.permit_id,
                    "proof_ready_record_sha256": proof.journal_record_sha256,
                    "proof_ready_revision": proof.journal_revision,
                    "proof_sha256": proof.fingerprint,
                    "provider_order_id": proof.provider_order_id,
                    "public_state": "ACKED_TRACKED",
                    "recovery_attestation_sha256": (
                        None
                        if receipt.recovery_attestation is None
                        else receipt.recovery_attestation.fingerprint
                    ),
                    "reconciliation_evidence_sha256": proof.reconciliation_evidence_sha256,
                    "risk_intent_id": proof.intent_id,
                    "trade_count": 0,
                    "updated_at_ns": time.time_ns(),
                },
                previous_account,
                previous_command,
            )
            self._insert_event(connection, fence, event)
            row = self._require_command(
                connection,
                fence.scope.key,
                current.command.principal_ref,
                current.command.intent_id,
            )
            return self._command_from_row(connection, row, fence.scope)

    def _load_dispatch_proof_for_recovery_in(
        self,
        connection: sqlite3.Connection,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        claim: DispatchClaimBinding,
    ) -> DispatchProofRecoverySource | None:
        return _load_dispatch_proof_for_recovery_in(
            self,
            connection,
            fence,
            principal_ref=principal_ref,
            intent_id=intent_id,
            claim=claim,
        )

    def _attest_recovered_dispatch_resolution(
        self,
        proof: DispatchTrackedOrderProof,
        attestation: DispatchRecoveryAttestation,
        claim: DispatchClaimBinding,
        fence: RiskOrderWriterFence,
    ) -> VerifiedDispatchRecoveryResolution | None:
        try:
            with closing(self._connection()) as connection:
                self._assert_current_in(connection, fence)
                command_row = connection.execute(
                    "SELECT * FROM risk_order_commands WHERE scope_key=? AND risk_intent_id=?",
                    (proof.scope.key, proof.intent_id),
                ).fetchone()
                if command_row is None:
                    return None
                source = self._load_dispatch_proof_for_recovery_in(
                    connection,
                    fence,
                    principal_ref=str(command_row["principal_ref"]),
                    intent_id=str(command_row["intent_id"]),
                    claim=claim,
                )
            if source is None or source.proof != proof or source.claim != claim:
                return None
            if not source.recovery_attestations or source.recovery_attestations[-1] != attestation:
                return None
            recovery_event = source.recovery_events[-1]
            if (
                recovery_event.event_type != "PROOF_RECOVERY_ATTESTED"
                or recovery_event.revision != source.command.latest_revision
                or recovery_event.record_sha256 != attestation.recovery_event_sha256
                or recovery_event.writer_owner_id != fence.owner_id
                or recovery_event.writer_fencing_token != fence.fencing_token
                or recovery_event.writer_fence_sha256 != fence.fence_sha256
                or fence.fencing_token <= source.proof_ready_event.writer_fencing_token
            ):
                return None
            return VerifiedDispatchRecoveryResolution(
                scope=proof.scope,
                permit_id=proof.permit_id,
                intent_id=proof.intent_id,
                intent_hash=proof.intent_hash,
                cause_id=proof.cause_id,
                claim_digest=claim.claim_digest,
                proof_sha256=proof.fingerprint,
                attestation_sha256=attestation.fingerprint,
                recovery_event_id=attestation.recovery_event_id,
                recovery_event_revision=attestation.recovery_event_revision,
                recovery_event_sha256=attestation.recovery_event_sha256,
                original_writer_owner_id=attestation.original_writer_owner_id,
                original_writer_fencing_token=attestation.original_writer_fencing_token,
                original_writer_fence_sha256=attestation.original_writer_fence_sha256,
                current_writer_owner_id=fence.owner_id,
                current_writer_fencing_token=fence.fencing_token,
                current_writer_fence_sha256=fence.fence_sha256,
            )
        except (RiskOrderJournalError, sqlite3.Error, KeyError, TypeError, ValueError):
            return None

    def commands_for_scope(self, scope: AccountScope) -> tuple[RiskOrderCommand, ...]:
        """Return immutable command snapshots for startup recovery."""

        with closing(self._connection()) as connection:
            rows = connection.execute(
                "SELECT * FROM risk_order_commands WHERE scope_key=? ORDER BY created_revision",
                (scope.key,),
            ).fetchall()
            return tuple(self._command_from_row(connection, row, scope) for row in rows)

    def append_resolution_observations(
        self,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str,
        intent_id: str,
        order_observation: Mapping[str, Any],
        fill_observation: Mapping[str, Any],
    ) -> tuple[RiskOrderJournalEvent, RiskOrderJournalEvent, str]:
        """Persist the exact normalized order/fill observations before proof."""

        command = self.get_command(fence.scope, principal_ref, intent_id)
        if command is None:
            raise RiskOrderJournalError("COMMAND_NOT_FOUND")
        order_payload = _bounded_observation(order_observation)
        fill_payload = _bounded_observation(fill_observation)
        order_event = self.append_event(
            fence,
            principal_ref=principal_ref,
            intent_id=intent_id,
            event_type="ORDER_OBSERVATION",
            payload=order_payload,
        )
        fill_event = self.append_event(
            fence,
            principal_ref=principal_ref,
            intent_id=intent_id,
            event_type="FILL_OBSERVATION",
            payload=fill_payload,
        )
        evidence_sha256 = sha256_text(
            canonical_json(
                {
                    "fill_event_sha256": fill_event.record_sha256,
                    "fill_revision": fill_event.revision,
                    "order_event_sha256": order_event.record_sha256,
                    "order_revision": order_event.revision,
                    "provider_contract_sha256": order_payload.get("provider_contract_sha256"),
                    "request_sha256": command.order_request_sha256,
                    "schema": "bt-api-risk-order-reconciliation-evidence-v1",
                }
            )
        )
        return order_event, fill_event, evidence_sha256


    def read_cancel_resolution_target_binding(
        self,
        fence: RiskOrderWriterFence,
        *,
        execution_scope_key: str,
        cancel_id: str,
    ) -> CancelResolutionTargetBindingV1:
        """Resolve the exact same-run Risk command named by a stored cancel."""

        self._assert_current(fence)
        source = self._read_cancel_resolution_source(
            fence.scope, execution_scope_key=execution_scope_key, cancel_id=cancel_id
        )
        command, _proof, _claim = self._read_cancel_target_risk_source(fence, source)
        return CancelResolutionTargetBindingV1(
            scope=fence.scope,
            execution_scope_key=source.scope.key,
            cancel_id=source.cancel_intent.cancel_id,
            target_intent_id=source.target_intent.intent_id,
            provider_order_id=source.cancel_intent.provider_order_id,
            principal_ref=command.principal_ref,
            risk_intent_id=command.risk_intent_id,
            permit_id=command.permit_id or "",
            order_request_sha256=command.order_request_sha256,
            wire_scope_sha256=sha256_text(
                canonical_json(dict(source.owner_batch_body["wire_scope"]))
            ),
        )

    def create_cancel_dispatch_resolution_proof(
        self,
        fence: RiskOrderWriterFence,
        *,
        claim: DispatchClaimBinding,
        target_claim: DispatchClaimBinding,
        target_order_proof: DispatchTrackedOrderProof,
        execution_scope_key: str,
        cancel_id: str,
    ) -> CancelDispatchResolutionProof:
        """Issue one proof from an exact terminal cancel and tracked target."""

        self._assert_current(fence)
        if type(claim) is not DispatchClaimBinding or claim.scope != fence.scope:
            raise RiskOrderJournalError("CANCEL_RESOLUTION_CLAIM_INVALID")
        source = self._read_cancel_resolution_source(
            fence.scope, execution_scope_key=execution_scope_key, cancel_id=cancel_id
        )
        _command, journal_target_proof, journal_target_claim = self._read_cancel_target_risk_source(
            fence, source
        )
        if (
            type(target_claim) is not DispatchClaimBinding
            or target_claim != journal_target_claim
            or type(target_order_proof) is not DispatchTrackedOrderProof
            or target_order_proof != journal_target_proof
        ):
            raise RiskOrderJournalError("CANCEL_TARGET_RISK_RECEIPT_MISMATCH")
        return self._build_cancel_dispatch_resolution_proof(
            fence,
            claim=claim,
            source=source,
            target_order_proof=journal_target_proof,
        )

    def verify_cancel_dispatch_resolution_source(
        self,
        proof: CancelDispatchResolutionProof,
        *,
        claim: DispatchClaimBinding,
    ) -> bool:
        """Read-only verification used when a terminal proof is replayed."""

        if (
            type(proof) is not CancelDispatchResolutionProof
            or type(claim) is not DispatchClaimBinding
            or proof.scope != claim.scope
            or proof.writer_fence_sha256
            != _fence_digest(proof.scope, proof.writer_owner_id, proof.writer_fencing_token)
        ):
            return False
        fence = _thread_fences().get(proof.scope.key)
        if fence is None or fence.scope != proof.scope:
            return False
        try:
            source = self._read_cancel_resolution_source(
                proof.scope,
                execution_scope_key=proof.execution_scope_key,
                cancel_id=proof.cancel_id,
            )
            _command, target_proof, _target_claim = self._read_cancel_target_risk_source(
                fence, source
            )
            expected = self._build_cancel_dispatch_resolution_proof(
                fence,
                claim=claim,
                source=source,
                target_order_proof=target_proof,
                writer_owner_id=proof.writer_owner_id,
                writer_fencing_token=proof.writer_fencing_token,
                writer_fence_sha256=proof.writer_fence_sha256,
            )
            self._assert_current(fence)
            return expected == proof
        except (RiskOrderJournalError, sqlite3.Error, KeyError, TypeError, ValueError):
            return False

    @contextmanager
    def cancel_dispatch_resolution_guard(
        self,
        proof: CancelDispatchResolutionProof,
        *,
        claim: DispatchClaimBinding,
    ) -> Iterator[VerifiedCancelDispatchResolution | None]:
        """Hold the current Risk writer fence while rereading cancel source."""

        if (
            type(proof) is not CancelDispatchResolutionProof
            or type(claim) is not DispatchClaimBinding
            or proof.scope != claim.scope
        ):
            yield None
            return
        fence = _thread_fences().get(proof.scope.key)
        if fence is None or fence.scope != proof.scope:
            yield None
            return
        attestation = self._attest_cancel_dispatch_resolution(proof, claim, fence)
        self._assert_current(fence)
        try:
            yield attestation
        finally:
            self._assert_current(fence)

    def _attest_cancel_dispatch_resolution(
        self,
        proof: CancelDispatchResolutionProof,
        claim: DispatchClaimBinding,
        fence: RiskOrderWriterFence,
    ) -> VerifiedCancelDispatchResolution | None:
        try:
            source = self._read_cancel_resolution_source(
                fence.scope,
                execution_scope_key=proof.execution_scope_key,
                cancel_id=proof.cancel_id,
            )
            _command, target_proof, _target_claim = self._read_cancel_target_risk_source(
                fence, source
            )
            expected = self._build_cancel_dispatch_resolution_proof(
                fence,
                claim=claim,
                source=source,
                target_order_proof=target_proof,
            )
            self._assert_current(fence)
            if expected != proof:
                return None
            return VerifiedCancelDispatchResolution(
                scope=proof.scope,
                permit_id=proof.permit_id,
                intent_id=proof.intent_id,
                intent_hash=proof.intent_hash,
                claim_digest=proof.claim_digest,
                proof_sha256=proof.fingerprint,
                cancel_event_id=proof.cancel_event_id,
                cancel_event_sequence=proof.cancel_event_sequence,
                cancel_event_sha256=proof.cancel_event_sha256,
                source_evidence_sha256=proof.source_evidence_sha256,
                target_postcondition=proof.target_postcondition,
                target_record_sha256=proof.target_record_sha256,
                target_event_id=proof.target_event_id,
                target_event_sequence=proof.target_event_sequence,
                target_event_sha256=proof.target_event_sha256,
                writer_owner_id=fence.owner_id,
                writer_fencing_token=fence.fencing_token,
                writer_fence_sha256=fence.fence_sha256,
            )
        except (RiskOrderJournalError, sqlite3.Error, KeyError, TypeError, ValueError):
            return None




    @contextmanager
    def dispatch_resolution_guard(
        self,
        proof: DispatchTrackedOrderProof | DispatchTerminalProof,
        *,
        claim: DispatchClaimBinding,
    ) -> Iterator[VerifiedDispatchResolution | None]:
        """Reread an exact terminal proof while the account writer fence is held."""

        if type(proof) not in (DispatchTrackedOrderProof, DispatchTerminalProof) or type(
            claim
        ) is not DispatchClaimBinding:
            yield None
            return
        fence = _thread_fences().get(proof.scope.key)
        if fence is None or fence.scope != proof.scope:
            yield None
            return
        if type(proof) is DispatchTerminalProof:
            attestation = self._attest_terminal_dispatch_resolution(proof, claim, fence)
        else:
            attestation = self._attest_dispatch_resolution(proof, claim, fence)
        self._assert_current(fence)
        try:
            yield attestation
        finally:
            self._assert_current(fence)

    def _attest_dispatch_resolution(
        self,
        proof: DispatchTrackedOrderProof,
        claim: DispatchClaimBinding,
        fence: RiskOrderWriterFence,
    ) -> VerifiedDispatchResolution | None:
        try:
            with closing(self._connection()) as connection:
                self._assert_current_in(connection, fence)
                command = connection.execute(
                    "SELECT * FROM risk_order_commands WHERE scope_key=? AND risk_intent_id=?",
                    (proof.scope.key, proof.intent_id),
                ).fetchone()
                if command is None:
                    return None
                row = connection.execute(
                    "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? AND revision=?",
                    (
                        proof.scope.key,
                        command["principal_ref"],
                        command["intent_id"],
                        proof.journal_revision,
                    ),
                ).fetchone()
                if row is None:
                    return None
                event = self._event_from_row(row, proof.scope)
                if not self._verify_event_chains(
                    connection, command, proof.scope, proof.journal_revision
                ):
                    return None
                payload = event.payload
                if (
                    event.event_type != "PROOF_READY"
                    or event.record_sha256 != proof.journal_record_sha256
                    or event.writer_fence_sha256 != fence.fence_sha256
                    or event.writer_owner_id != fence.owner_id
                    or event.writer_fencing_token != fence.fencing_token
                    or payload.get("permit_id") != proof.permit_id
                    or payload.get("risk_intent_id") != proof.intent_id
                    or payload.get("intent_hash") != proof.intent_hash
                    or payload.get("cause_id") != proof.cause_id
                    or payload.get("claim_digest") != proof.claim_digest
                    or payload.get("dispatch_attempt_count") != 1
                    or payload.get("evidence_class") != proof.evidence_class.value
                    or payload.get("accepted_request_sha256") != proof.accepted_request_sha256
                    or payload.get("provider_order_id") != proof.provider_order_id
                    or payload.get("exposure_reference_id") != proof.exposure_reservation_id
                    or payload.get("exposure_reference_sha256") != proof.exposure_reservation_sha256
                    or payload.get("reconciliation_evidence_sha256")
                    != proof.reconciliation_evidence_sha256
                    or payload.get("filled_quantity") != 0
                    or payload.get("trade_count") != 0
                    or payload.get("claim") != _claim_payload(claim)
                    or event.scope != claim.scope
                    or command["risk_intent_id"] != claim.intent_id
                    or command["payload_sha256"] == ""
                    or command["order_request_sha256"] != proof.accepted_request_sha256
                ):
                    return None
                exposure = connection.execute(
                    "SELECT * FROM risk_order_exposure_references WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                    (proof.scope.key, command["principal_ref"], command["intent_id"]),
                ).fetchone()
                if (
                    exposure is None
                    or exposure["reservation_id"] != proof.exposure_reservation_id
                    or exposure["reference_sha256"] != proof.exposure_reservation_sha256
                    or sha256_text(exposure["reference_json"]) != proof.exposure_reservation_sha256
                ):
                    return None
                reference = json.loads(exposure["reference_json"])
                if (
                    reference.get("schema") != "bt-api-risk-order-exposure-reference-v1"
                    or reference.get("scope_key") != proof.scope.key
                    or reference.get("intent_id") != proof.intent_id
                    or reference.get("intent_hash") != proof.intent_hash
                    or reference.get("permit_id") != proof.permit_id
                    or reference.get("claim_digest") != proof.claim_digest
                    or reference.get("accepted_request_sha256") != proof.accepted_request_sha256
                    or reference.get("provider_order_id") != proof.provider_order_id
                    or reference.get("observation_record_sha256")
                    != payload.get("observation_record_sha256")
                    or reference.get("observation_revision") != payload.get("observation_revision")
                    or reference.get("reconciliation_evidence_sha256")
                    != proof.reconciliation_evidence_sha256
                    or reference.get("writer_fence_sha256") != proof.writer_fence_sha256
                    or reference.get("dispatch_attempt_count") != 1
                    or reference.get("filled_quantity") != 0
                    or reference.get("trade_count") != 0
                    or reference.get("claim") != _claim_payload(claim)
                ):
                    return None
                for event_type, revision_key, digest_key in (
                    (
                        "ORDER_OBSERVATION",
                        "order_observation_revision",
                        "order_observation_record_sha256",
                    ),
                    (
                        "FILL_OBSERVATION",
                        "fill_observation_revision",
                        "fill_observation_record_sha256",
                    ),
                ):
                    observation_row = connection.execute(
                        "SELECT event_type, record_sha256 FROM risk_order_events "
                        "WHERE scope_key=? AND principal_ref=? AND intent_id=? AND revision=?",
                        (
                            proof.scope.key,
                            command["principal_ref"],
                            command["intent_id"],
                            reference.get(revision_key),
                        ),
                    ).fetchone()
                    if (
                        observation_row is None
                        or observation_row["event_type"] != event_type
                        or observation_row["record_sha256"] != reference.get(digest_key)
                    ):
                        return None
                if (
                    _fence_digest(fence.scope, fence.owner_id, fence.fencing_token)
                    != proof.writer_fence_sha256
                ):
                    return None
                return VerifiedDispatchResolution(
                    scope=proof.scope,
                    permit_id=proof.permit_id,
                    intent_id=proof.intent_id,
                    intent_hash=proof.intent_hash,
                    claim_digest=proof.claim_digest,
                    proof_sha256=proof.fingerprint,
                    journal_revision=proof.journal_revision,
                    journal_record_sha256=proof.journal_record_sha256,
                    writer_fence_sha256=proof.writer_fence_sha256,
                )
        except (RiskOrderJournalError, sqlite3.Error, KeyError, TypeError, ValueError):
            return None

    def _attest_terminal_dispatch_resolution(
        self,
        proof: DispatchTerminalProof,
        claim: DispatchClaimBinding,
        fence: RiskOrderWriterFence,
    ) -> VerifiedDispatchResolution | None:
        """Attest one hash-chained CTP order-specific zero-fill terminal proof."""

        try:
            with closing(self._connection()) as connection:
                self._assert_current_in(connection, fence)
                self._validate_terminal_dispatch_source_in(
                    connection,
                    fence,
                    principal_ref=None,
                    intent_id=None,
                    claim=claim,
                    proof=proof,
                    allow_ack=False,
                )
                return VerifiedDispatchResolution(
                    scope=proof.scope,
                    permit_id=proof.permit_id,
                    intent_id=proof.intent_id,
                    intent_hash=proof.intent_hash,
                    claim_digest=proof.claim_digest,
                    proof_sha256=proof.fingerprint,
                    journal_revision=proof.journal_revision,
                    journal_record_sha256=proof.journal_record_sha256,
                    writer_fence_sha256=proof.writer_fence_sha256,
                )
        except (
            RiskOrderJournalError,
            sqlite3.Error,
            KeyError,
            TypeError,
            ValueError,
            InvalidOperation,
        ):
            return None

    def _validate_terminal_dispatch_source_in(
        self,
        connection: sqlite3.Connection,
        fence: RiskOrderWriterFence,
        *,
        principal_ref: str | None,
        intent_id: str | None,
        claim: DispatchClaimBinding,
        proof: DispatchTerminalProof,
        allow_ack: bool,
    ) -> tuple[RiskOrderCommand, dict[str, list[RiskOrderJournalEvent]]]:
        """Validate the exact CTP no-fill event chain under one writer fence.

        This validates durable linkage and hashes only. The trusted caller must
        re-read the live CTP source evidence and Risk receipt before invoking
        the journal; a serialized evidence mapping is not external authority.
        """

        if (
            type(fence) is not RiskOrderWriterFence
            or type(claim) is not DispatchClaimBinding
            or type(proof) is not DispatchTerminalProof
            or proof.scope != fence.scope
            or claim.scope != fence.scope
            or proof.scope != claim.scope
            or proof.permit_id != claim.permit_id
            or proof.intent_id != claim.intent_id
            or proof.intent_hash != claim.intent_hash
            or proof.cause_id != claim.cause_id
            or proof.claim_digest != claim.claim_digest
            or proof.evidence_class is not DispatchEvidenceClass.NATIVE_PROVIDER_JOURNAL
            or proof.writer_fence_sha256 != fence.fence_sha256
            or proof.dispatch_attempt_count != 1
            or proof.fee_record_count != 0
            or proof.fee_history_complete is not True
            or proof.filled_quantity != 0
            or proof.trade_count != 0
        ):
            raise RiskOrderJournalError("TERMINAL_DISPATCH_PROOF_INVALID")

        if principal_ref is None and intent_id is None:
            command_row = connection.execute(
                "SELECT * FROM risk_order_commands WHERE scope_key=? AND risk_intent_id=?",
                (fence.scope.key, proof.intent_id),
            ).fetchone()
        elif type(principal_ref) is str and type(intent_id) is str:
            command_row = connection.execute(
                "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
                (fence.scope.key, principal_ref, intent_id),
            ).fetchone()
        else:
            raise RiskOrderJournalError("TERMINAL_DISPATCH_COMMAND_ID_INVALID")
        if command_row is None:
            raise RiskOrderJournalError("TERMINAL_DISPATCH_COMMAND_MISSING")
        command = self._command_from_row(connection, command_row, fence.scope)
        if (
            command.risk_intent_id != proof.intent_id
            or command.scope != fence.scope
            or command.payload_sha256 == ""
            or command.order_request_sha256 == ""
            or command.permit_id != proof.permit_id
            or (principal_ref is not None and command.principal_ref != principal_ref)
            or (intent_id is not None and command.intent_id != intent_id)
        ):
            raise RiskOrderJournalError("TERMINAL_DISPATCH_COMMAND_BINDING_INVALID")

        rows = connection.execute(
            "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? ORDER BY revision",
            (fence.scope.key, command.principal_ref, command.intent_id),
        ).fetchall()
        events = tuple(self._event_from_row(row, fence.scope) for row in rows)
        event_types = tuple(event.event_type for event in events)
        prefix = (
            "PREPARED",
            "RESERVED",
            "CLAIMED",
            "DISPATCHING",
            "ORDER_OBSERVATION",
            "FILL_OBSERVATION",
            "PROOF_READY",
        )
        allowed_with_ack = prefix + ("ACKED_TERMINAL",)
        if (
            event_types != prefix
            and not (allow_ack and event_types == allowed_with_ack)
        ):
            raise RiskOrderJournalError("TERMINAL_DISPATCH_EVENT_SEQUENCE_INVALID")
        if not self._verify_event_chains(
            connection,
            command_row,
            fence.scope,
            events[-1].revision,
            target_revision=proof.journal_revision,
        ):
            raise RiskOrderJournalError("TERMINAL_DISPATCH_EVENT_CHAIN_INVALID")
        if any(
            event.writer_owner_id != fence.owner_id
            or event.writer_fencing_token != fence.fencing_token
            or event.writer_fence_sha256 != fence.fence_sha256
            for event in events
        ):
            raise RiskOrderJournalError("TERMINAL_DISPATCH_WRITER_FENCE_INVALID")

        by_type: dict[str, list[RiskOrderJournalEvent]] = {}
        for event in events:
            by_type.setdefault(event.event_type, []).append(event)
        prepared, reserved, claimed, dispatching = events[:4]
        order_event, fill_event, proof_event = events[4:7]
        profile = self._risk_dispatch_profile(claim.scope.provider)
        if (
            set(prepared.payload)
            != {
                "canonical_payload",
                "client_order_id",
                "created_at_ns",
                "exchange_name",
                "order_request",
                "order_request_sha256",
                "provider_account_id",
                "risk_intent_id",
                "wire_scope",
                "updated_at_ns",
            }
            or set(reserved.payload)
            != {"permit_id", "risk_intent_id", "updated_at_ns"}
            or set(claimed.payload)
            != {"claim", "permit_id", "risk_intent_id", "updated_at_ns"}
            or set(dispatching.payload)
            != {
                "dispatch_attempt_count",
                "permit_id",
                "risk_intent_id",
                profile.binding_field,
                "updated_at_ns",
            }
            or prepared.payload.get("risk_intent_id") != command.risk_intent_id
            or prepared.payload.get("canonical_payload") != dict(command.canonical_payload)
            or sha256_text(canonical_json(dict(command.canonical_payload)))
            != command.payload_sha256
            or prepared.payload.get("client_order_id") != command.client_order_id
            or prepared.payload.get("order_request") != dict(command.order_request)
            or prepared.payload.get("order_request_sha256") != command.order_request_sha256
            or prepared.payload.get("provider_account_id") != command.provider_account_id
            or prepared.payload.get("exchange_name") != command.exchange_name
            or prepared.payload.get("wire_scope") != dict(command.wire_scope)
            or prepared.payload.get("created_at_ns") != command.created_at_ns
            or reserved.payload.get("risk_intent_id") != command.risk_intent_id
            or reserved.payload.get("permit_id") != claim.permit_id
            or claimed.payload.get("risk_intent_id") != command.risk_intent_id
            or claimed.payload.get("permit_id") != claim.permit_id
            or claimed.payload.get("claim") != _claim_payload(claim)
            or dispatching.payload.get("risk_intent_id") != command.risk_intent_id
            or dispatching.payload.get("permit_id") != claim.permit_id
            or dispatching.payload.get("dispatch_attempt_count") != 1
            or type(dispatching.payload.get("dispatch_attempt_count")) is not int
        ):
            raise RiskOrderJournalError("TERMINAL_DISPATCH_CLAIM_HISTORY_INVALID")

        binding = dispatching.payload.get(profile.binding_field)
        profile.validate_terminal_binding(
            binding, command, claim, fence, require_sha256=_require_sha256,
            journal_error_type=RiskOrderJournalError,
        )

        evidence = order_event.payload.get(profile.terminal_evidence_field)
        evidence_sha256 = profile.validate_terminal_evidence(
            evidence, binding, command, fence, journal_error_type=RiskOrderJournalError,
            hash_text=sha256_text, canonical_json=canonical_json, require_sha256=_require_sha256,
            sha256_length=_SHA256_LENGTH,
        )
        profile.validate_terminal_observations(
            order_event, fill_event, evidence_sha256, command, claim,
            claim_payload=_claim_payload, journal_error_type=RiskOrderJournalError,
        )

        expected_state = profile.terminal_state(evidence)
        if expected_state not in {
            DispatchTerminalState.CANCELED_NO_FILL.value,
            DispatchTerminalState.REJECTED_NO_FILL.value,
        }:
            raise RiskOrderJournalError("TERMINAL_DISPATCH_PROOF_SOURCE_MISMATCH")
        expected_proof_payload = {
            "schema": profile.terminal_proof_schema,
            "cause_id": claim.cause_id,
            "claim": _claim_payload(claim),
            "claim_digest": claim.claim_digest,
            "dispatch_attempt_count": 1,
            "evidence_class": DispatchEvidenceClass.NATIVE_PROVIDER_JOURNAL.value,
            "fee_history_complete": True,
            "fee_record_count": 0,
            "filled_quantity": 0,
            "intent_hash": claim.intent_hash,
            "intent_id": claim.intent_id,
            "permit_id": claim.permit_id,
            "risk_intent_id": command.risk_intent_id,
            "terminal_state": expected_state,
            "trade_count": 0,
            "reconciliation_evidence_sha256": evidence_sha256,
            "writer_fence_sha256": fence.fence_sha256,
            "order_observation_revision": order_event.revision,
            "order_observation_record_sha256": order_event.record_sha256,
            "fill_observation_revision": fill_event.revision,
            "fill_observation_record_sha256": fill_event.record_sha256,
        }
        proof_payload = dict(proof_event.payload)
        proof_updated_at_ns = proof_payload.pop("updated_at_ns", None)
        if (
            set(proof_event.payload) != set(expected_proof_payload) | {"updated_at_ns"}
            or
            proof_event.revision != proof.journal_revision
            or proof_event.record_sha256 != proof.journal_record_sha256
            or proof_payload != expected_proof_payload
            or type(proof_updated_at_ns) is not int
            or proof_updated_at_ns <= 0
            or proof.terminal_state.value != expected_state
            or proof.reconciliation_evidence_sha256 != evidence_sha256
        ):
            raise RiskOrderJournalError("TERMINAL_DISPATCH_PROOF_SOURCE_MISMATCH")

        if allow_ack:
            if command.state not in {"PROOF_READY", "ACKED_TERMINAL"}:
                raise RiskOrderJournalError("TERMINAL_DISPATCH_STATE_INVALID")
            if command.state == "ACKED_TERMINAL" and len(events) != 8:
                raise RiskOrderJournalError("TERMINAL_DISPATCH_ACK_INVALID")
        elif command.state != "PROOF_READY" or len(events) != 7:
            raise RiskOrderJournalError("TERMINAL_DISPATCH_STATE_INVALID")
        return command, by_type

    def _lock_path(self, scope: AccountScope) -> Path:
        digest = sha256_text(scope.key)
        return self._path.with_name(self._path.name + "." + digest + ".writer.lock")

    def _next_fencing_token(self, scope: AccountScope) -> int:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT fencing_token FROM risk_order_fences WHERE scope_key=?",
                (scope.key,),
            ).fetchone()
            token = 1 if row is None else int(row[0]) + 1
            connection.execute(
                "INSERT INTO risk_order_fences(scope_key, fencing_token) VALUES(?, ?) "
                "ON CONFLICT(scope_key) DO UPDATE SET fencing_token=excluded.fencing_token",
                (scope.key, token),
            )
            return token

    def _assert_current(self, fence: RiskOrderWriterFence) -> None:
        if type(fence) is not RiskOrderWriterFence:
            raise RiskOrderJournalError("WRITER_FENCE_REQUIRED")
        active = _thread_fences().get(fence.scope.key)
        if active is not fence:
            raise RiskOrderJournalError("WRITER_FENCE_NOT_HELD")
        with closing(self._connection()) as connection:
            self._assert_current_in(connection, fence)

    @staticmethod
    def _assert_current_in(connection: sqlite3.Connection, fence: RiskOrderWriterFence) -> None:
        row = connection.execute(
            "SELECT fencing_token FROM risk_order_fences WHERE scope_key=?",
            (fence.scope.key,),
        ).fetchone()
        if row is None or int(row[0]) != fence.fencing_token:
            raise RiskOrderJournalError("WRITER_FENCE_STALE")

    @staticmethod
    def _next_event_identity(
        connection: sqlite3.Connection,
        scope_key: str,
        principal_ref: str,
        intent_id: str,
    ) -> tuple[int, str, str]:
        account = connection.execute(
            "SELECT revision, record_sha256 FROM risk_order_events WHERE scope_key=? ORDER BY revision DESC LIMIT 1",
            (scope_key,),
        ).fetchone()
        command = connection.execute(
            "SELECT record_sha256 FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? ORDER BY revision DESC LIMIT 1",
            (scope_key, principal_ref, intent_id),
        ).fetchone()
        return (
            1 if account is None else int(account["revision"]) + 1,
            "0" * _SHA256_LENGTH if account is None else str(account["record_sha256"]),
            "0" * _SHA256_LENGTH if command is None else str(command["record_sha256"]),
        )

    @staticmethod
    def _event_from_body(
        fence: RiskOrderWriterFence,
        principal_ref: str,
        intent_id: str,
        revision: int,
        event_type: str,
        payload: Mapping[str, Any],
        previous_account: str,
        previous_command: str,
    ) -> RiskOrderJournalEvent:
        payload_json = canonical_json(dict(payload))
        record_material = canonical_json(
            {
                "event_type": event_type,
                "intent_id": intent_id,
                "payload": json.loads(payload_json),
                "previous_account_sha256": previous_account,
                "previous_command_sha256": previous_command,
                "principal_ref": principal_ref,
                "revision": revision,
                "scope_key": fence.scope.key,
                "writer_fence_sha256": fence.fence_sha256,
                "writer_fencing_token": fence.fencing_token,
                "writer_owner_id": fence.owner_id,
            }
        )
        return RiskOrderJournalEvent(
            scope=fence.scope,
            principal_ref=principal_ref,
            intent_id=intent_id,
            revision=revision,
            event_type=event_type,
            payload=json.loads(payload_json),
            previous_account_sha256=previous_account,
            previous_command_sha256=previous_command,
            record_sha256=sha256_text(record_material),
            writer_owner_id=fence.owner_id,
            writer_fencing_token=fence.fencing_token,
            writer_fence_sha256=fence.fence_sha256,
        )

    @staticmethod
    def _insert_event(
        connection: sqlite3.Connection,
        fence: RiskOrderWriterFence,
        event: RiskOrderJournalEvent,
    ) -> None:
        connection.execute(
            """INSERT INTO risk_order_events (
                scope_key, principal_ref, intent_id, revision, event_type,
                payload_json, previous_account_sha256, previous_command_sha256,
                record_sha256, writer_owner_id, writer_fencing_token, writer_fence_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                fence.scope.key,
                event.principal_ref,
                event.intent_id,
                event.revision,
                event.event_type,
                canonical_json(dict(event.payload)),
                event.previous_account_sha256,
                event.previous_command_sha256,
                event.record_sha256,
                event.writer_owner_id,
                event.writer_fencing_token,
                event.writer_fence_sha256,
            ),
        )

    def _command_from_row(
        self, connection: sqlite3.Connection, row: sqlite3.Row, scope: AccountScope
    ) -> RiskOrderCommand:
        events = connection.execute(
            "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? ORDER BY revision",
            (row["scope_key"], row["principal_ref"], row["intent_id"]),
        ).fetchall()
        if not events:
            raise RiskOrderJournalError("COMMAND_EVENT_MISSING")
        event = self._event_from_row(events[-1], scope)
        initial_payload = json.loads(events[0]["payload_json"])
        permit_id = next(
            (
                payload.get("permit_id")
                for payload in (json.loads(item["payload_json"]) for item in reversed(events))
                if type(payload.get("permit_id")) is str
            ),
            None,
        )
        return RiskOrderCommand(
            scope=scope,
            principal_ref=str(row["principal_ref"]),
            intent_id=str(row["intent_id"]),
            risk_intent_id=str(row["risk_intent_id"]),
            payload_sha256=str(row["payload_sha256"]),
            canonical_payload=json.loads(row["canonical_payload_json"]),
            wire_scope=json.loads(row["wire_scope_json"]),
            exchange_name=str(row["exchange_name"]),
            provider_account_id=str(row["provider_account_id"]),
            client_order_id=str(row["client_order_id"]),
            permit_id=permit_id,
            order_request=json.loads(row["order_request_json"]),
            order_request_sha256=str(row["order_request_sha256"]),
            created_revision=int(row["created_revision"]),
            created_record_sha256=str(row["created_record_sha256"]),
            created_at_ns=int(initial_payload.get("created_at_ns", 0)),
            updated_at_ns=int(event.payload.get("updated_at_ns", 0)),
            state=event.event_type,
            latest_revision=event.revision,
            latest_record_sha256=event.record_sha256,
            latest_event=event.payload,
        )

    def _event_from_row(self, row: sqlite3.Row, scope: AccountScope) -> RiskOrderJournalEvent:
        return RiskOrderJournalEvent(
            scope=scope,
            principal_ref=str(row["principal_ref"]),
            intent_id=str(row["intent_id"]),
            revision=int(row["revision"]),
            event_type=str(row["event_type"]),
            payload=json.loads(row["payload_json"]),
            previous_account_sha256=str(row["previous_account_sha256"]),
            previous_command_sha256=str(row["previous_command_sha256"]),
            record_sha256=str(row["record_sha256"]),
            writer_owner_id=str(row["writer_owner_id"]),
            writer_fencing_token=int(row["writer_fencing_token"]),
            writer_fence_sha256=str(row["writer_fence_sha256"]),
        )

    @staticmethod
    def _require_command(
        connection: sqlite3.Connection, scope_key: str, principal_ref: str, intent_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
            (scope_key, principal_ref, intent_id),
        ).fetchone()
        if row is None:
            raise RiskOrderJournalError("COMMAND_NOT_FOUND")
        return row

    @staticmethod
    def _validate_transition(current: str, following: str) -> None:
        allowed = {
            "PREPARED": {"RESERVED", "ADMISSION_DENIED", "UNKNOWN"},
            "RESERVED": {"CLAIMED", "NO_DISPATCH", "UNKNOWN", "ADMISSION_DENIED"},
            "CLAIMED": {"DISPATCHING", "UNKNOWN"},
            "DISPATCHING": {"ORDER_OBSERVATION", "UNKNOWN"},
            "ORDER_OBSERVATION": {"FILL_OBSERVATION", "UNKNOWN"},
            "FILL_OBSERVATION": {"PROOF_READY", "UNKNOWN", "PROVIDER_QUERY"},
            "PROOF_READY": {
                "ACKED_TRACKED",
                "ACKED_TERMINAL",
                "PROOF_RECOVERY_ATTESTED",
                "UNKNOWN",
            },
            "PROOF_RECOVERY_ATTESTED": {
                "ACKED_TRACKED",
                "PROOF_RECOVERY_ATTESTED",
                "UNKNOWN",
            },
            "ACKED_TRACKED": {"PROVIDER_QUERY", "UNKNOWN"},
            "PROVIDER_QUERY": {"PROVIDER_QUERY", "EXPOSURE_APPLIED", "UNKNOWN"},
            "EXPOSURE_APPLIED": {"PROVIDER_QUERY", "UNKNOWN"},
            "UNKNOWN": {
                "ORDER_OBSERVATION",
                "PROOF_RECOVERY_ATTESTED",
                "UNKNOWN",
                "PROVIDER_QUERY",
            },
            "ADMISSION_DENIED": set(),
            "NO_DISPATCH": set(),
            "ACKED_TERMINAL": set(),
        }
        if following not in allowed.get(current, set()):
            raise RiskOrderJournalError("JOURNAL_STATE_CONFLICT")

    @staticmethod
    def _verify_event_chains(
        connection: sqlite3.Connection,
        command_row: sqlite3.Row,
        scope: AccountScope,
        through_revision: int,
        *,
        target_revision: int | None = None,
    ) -> bool:
        if target_revision is None:
            target_revision = through_revision
        events = connection.execute(
            "SELECT * FROM risk_order_events WHERE scope_key=? AND revision<=? ORDER BY revision",
            (command_row["scope_key"], through_revision),
        ).fetchall()
        account_hash = "0" * _SHA256_LENGTH
        command_hashes: dict[tuple[str, str], str] = {}
        expected_revision = 1
        found_target = False
        for row in events:
            revision = int(row["revision"])
            event_key = (str(row["principal_ref"]), str(row["intent_id"]))
            previous_command = command_hashes.get(event_key, "0" * _SHA256_LENGTH)
            if (
                revision != expected_revision
                or row["previous_account_sha256"] != account_hash
                or row["previous_command_sha256"] != previous_command
            ):
                return False
            event = RiskOrderJournalEvent(
                scope=scope,
                principal_ref=event_key[0],
                intent_id=event_key[1],
                revision=revision,
                event_type=str(row["event_type"]),
                payload=json.loads(row["payload_json"]),
                previous_account_sha256=str(row["previous_account_sha256"]),
                previous_command_sha256=str(row["previous_command_sha256"]),
                record_sha256=str(row["record_sha256"]),
                writer_owner_id=str(row["writer_owner_id"]),
                writer_fencing_token=int(row["writer_fencing_token"]),
                writer_fence_sha256=str(row["writer_fence_sha256"]),
            )
            expected = RiskOrderJournal._event_from_body(
                RiskOrderWriterFence(
                    scope,
                    event.writer_owner_id,
                    event.writer_fencing_token,
                    event.writer_fence_sha256,
                ),
                event.principal_ref,
                event.intent_id,
                event.revision,
                event.event_type,
                event.payload,
                event.previous_account_sha256,
                event.previous_command_sha256,
            )
            if expected.record_sha256 != event.record_sha256:
                return False
            account_hash = event.record_sha256
            command_hashes[event_key] = event.record_sha256
            if event.revision == target_revision and event_key == (
                command_row["principal_ref"],
                command_row["intent_id"],
            ):
                found_target = True
            expected_revision += 1
        return found_target and expected_revision == through_revision + 1


def _claim_payload(claim: DispatchClaimBinding) -> dict[str, Any]:
    return {
        "cause_id": claim.cause_id,
        "claim_digest": claim.claim_digest,
        "claimed_at": claim.claimed_at,
        "intent_hash": claim.intent_hash,
        "intent_id": claim.intent_id,
        "permit_id": claim.permit_id,
        "scope_key": claim.scope.key,
    }


def _require_terminal_dispatch_receipt(
    receipt: DispatchTerminalResolutionReceipt,
    proof: DispatchTerminalProof,
) -> None:
    if (
        type(receipt) is not DispatchTerminalResolutionReceipt
        or receipt.status
        is not DispatchTerminalResolutionReceiptStatus.NO_FILL_TERMINAL_RESOLVED
        or type(proof) is not DispatchTerminalProof
        or receipt.proof != proof
        or receipt.proof_sha256 != proof.fingerprint
        or receipt.dispatch_latch_active is not False
        or type(receipt.fee_record_count) is not int
        or receipt.fee_record_count != 0
        or receipt.fee_history_complete is not True
        or receipt.group_claim is not None
    ):
        raise RiskOrderJournalError("TERMINAL_DISPATCH_RECEIPT_INVALID")
    if (
        receipt.claim.scope != proof.scope
        or receipt.claim.permit_id != proof.permit_id
        or receipt.claim.intent_id != proof.intent_id
        or receipt.claim.intent_hash != proof.intent_hash
        or receipt.claim.cause_id != proof.cause_id
        or receipt.claim.claim_digest != proof.claim_digest
    ):
        raise RiskOrderJournalError("TERMINAL_DISPATCH_RECEIPT_BINDING_INVALID")


def _terminal_dispatch_ack_payload(
    receipt: DispatchTerminalResolutionReceipt,
    proof: DispatchTerminalProof,
    events_by_type: Mapping[str, list[RiskOrderJournalEvent]],
    *, profile_for,
) -> dict[str, Any]:
    _require_terminal_dispatch_receipt(receipt, proof)
    proof_events = events_by_type.get("PROOF_READY", [])
    if len(proof_events) != 1:
        raise RiskOrderJournalError("TERMINAL_DISPATCH_PROOF_READY_INVALID")
    profile = profile_for(receipt.claim.scope.provider)

    return {
        "schema": profile.terminal_ack_schema,
        "status": receipt.status.value,
        "claim": _claim_payload(receipt.claim),
        "proof_sha256": receipt.proof_sha256,
        "proof_journal_revision": proof.journal_revision,
        "proof_journal_record_sha256": proof.journal_record_sha256,
        "terminal_state": proof.terminal_state.value,
        "reconciliation_evidence_sha256": proof.reconciliation_evidence_sha256,
        "writer_fence_sha256": proof.writer_fence_sha256,
        "dispatch_latch_active": False,
        "has_other_active_freezes": receipt.has_other_active_freezes,
        "fee_record_count": 0,
        "fee_history_complete": True,
    }


def _terminal_permit_id_from_history(
    events_by_type: Mapping[str, list[RiskOrderJournalEvent]],
    command_row: sqlite3.Row,
    *,
    expected_claim: DispatchClaimBinding | None = None,
) -> str:
    """Resolve the permit from immutable admission history, never a command column.

    ``risk_order_commands`` intentionally stores stable command identity and has no
    ``permit_id`` column.  The RESERVED event is the earliest durable permit binding;
    require CLAIMED and DISPATCHING to repeat that binding before accepting a later
    UNKNOWN or terminal exposure reference.
    """

    reserved = events_by_type.get("RESERVED", [])
    claimed = events_by_type.get("CLAIMED", [])
    dispatching = events_by_type.get("DISPATCHING", [])
    if len(reserved) != 1 or len(claimed) != 1 or len(dispatching) != 1:
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_DISPATCH_HISTORY_INVALID")
    risk_intent_id = str(command_row["risk_intent_id"])
    permit_id = reserved[0].payload.get("permit_id")
    reserve_payload = reserved[0].payload
    claim_payload = claimed[0].payload
    nested_claim = claim_payload.get("claim")
    dispatch_payload = dispatching[0].payload
    if (
        type(permit_id) is not str
        or not permit_id
        or reserve_payload.get("risk_intent_id") != risk_intent_id
        or claim_payload.get("permit_id") != permit_id
        or claim_payload.get("risk_intent_id") != risk_intent_id
        or type(nested_claim) is not dict
        or set(nested_claim)
        != {
            "cause_id",
            "claim_digest",
            "claimed_at",
            "intent_hash",
            "intent_id",
            "permit_id",
            "scope_key",
        }
        or nested_claim.get("permit_id") != permit_id
        or nested_claim.get("intent_id") != risk_intent_id
        or nested_claim.get("scope_key") != command_row["scope_key"]
        or dispatch_payload.get("permit_id") != permit_id
        or dispatch_payload.get("risk_intent_id") != risk_intent_id
        or dispatch_payload.get("dispatch_attempt_count") != 1
        or (expected_claim is not None and nested_claim != _claim_payload(expected_claim))
    ):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_DISPATCH_HISTORY_INVALID")
    return permit_id


def _terminal_exposure_lifecycle(
    command: RiskOrderCommand,
    command_row: sqlite3.Row,
    events: tuple[RiskOrderJournalEvent, ...],
    fence: RiskOrderWriterFence,
    *,
    expected_claim: DispatchClaimBinding | None = None,
) -> tuple[
    str,
    RiskOrderJournalEvent,
    RiskOrderJournalEvent,
    RiskOrderJournalEvent | None,
]:
    """Validate the terminal command suffix in both proof paths.

    OPEN still accepts only its original first-dispatch observation pair,
    optionally followed by one UNKNOWN.  CLOSE may be reconciled repeatedly
    after an uncertain dispatch: each query appends one complete order/fill
    pair and a nonterminal result may append UNKNOWN before the next query.
    Every CLOSE pair is independently source-validated and must monotonically
    extend the same order's cumulative fill history.  The returned pair is the
    latest pair, which is the exact pair named by the terminal CLOSE proof.
    """

    base_sequence = (
        "PREPARED",
        "RESERVED",
        "CLAIMED",
        "DISPATCHING",
        "ORDER_OBSERVATION",
        "FILL_OBSERVATION",
    )
    event_types = tuple(event.event_type for event in events)
    is_close = (
        isinstance(command, RiskOrderCommand)
        and command.canonical_payload.get("position_effect", "OPEN") == "CLOSE"
    )
    if is_close:
        order_event, fill_event, unknown_event = _terminal_close_observation_history(
            command,
            command_row,
            events,
        )
    elif event_types == base_sequence:
        order_event, fill_event, unknown_event = events[4], events[5], None
    elif event_types == (*base_sequence, "UNKNOWN"):
        order_event, fill_event, unknown_event = events[4], events[5], events[-1]
    else:
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_SEQUENCE_INVALID")

    if (
        type(command) is not RiskOrderCommand
        or type(command_row) is not sqlite3.Row
        or type(fence) is not RiskOrderWriterFence
        or not events
        or command.scope != fence.scope
        or command_row["scope_key"] != fence.scope.key
        or command_row["principal_ref"] != command.principal_ref
        or command_row["intent_id"] != command.intent_id
        or command_row["risk_intent_id"] != command.risk_intent_id
        or command.created_revision != events[0].revision
        or command.created_record_sha256 != events[0].record_sha256
        or command.latest_revision != events[-1].revision
        or command.latest_record_sha256 != events[-1].record_sha256
        or command.state != events[-1].event_type
        or dict(command.latest_event) != dict(events[-1].payload)
        or command.updated_at_ns != events[-1].payload.get("updated_at_ns")
    ):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_COMMAND_STATE_MISMATCH")

    if any(
        event.scope != fence.scope
        or event.principal_ref != command.principal_ref
        or event.intent_id != command.intent_id
        or (
            not is_close
            and (
                event.writer_owner_id != fence.owner_id
                or event.writer_fencing_token != fence.fencing_token
                or event.writer_fence_sha256 != fence.fence_sha256
            )
        )
        or type(event.revision) is not int
        or event.revision <= 0
        or type(event.payload.get("updated_at_ns")) is not int
        or event.payload["updated_at_ns"] <= 0
        for event in events
    ) or any(left.revision >= right.revision for left, right in zip(events, events[1:])):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_SEQUENCE_INVALID")

    initial_payload = events[0].payload
    if (
        initial_payload.get("risk_intent_id") != command.risk_intent_id
        or initial_payload.get("created_at_ns") != command.created_at_ns
        or initial_payload.get("canonical_payload") != dict(command.canonical_payload)
        or initial_payload.get("wire_scope") != dict(command.wire_scope)
        or initial_payload.get("exchange_name") != command.exchange_name
        or initial_payload.get("provider_account_id") != command.provider_account_id
        or initial_payload.get("client_order_id") != command.client_order_id
        or initial_payload.get("order_request") != dict(command.order_request)
        or initial_payload.get("order_request_sha256") != command.order_request_sha256
        or sha256_text(canonical_json(dict(command.canonical_payload)))
        != command.payload_sha256
        or sha256_text(
            canonical_json(
                {
                    "exchange_name": command.exchange_name,
                    "operation": "BtApi.make_order(normalized=True)",
                    "request": dict(command.order_request),
                }
            )
        )
        != command.order_request_sha256
    ):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_COMMAND_CREATION_MISMATCH")

    by_type: dict[str, list[RiskOrderJournalEvent]] = {}
    for event in events:
        by_type.setdefault(event.event_type, []).append(event)
    permit_id = _terminal_permit_id_from_history(
        by_type,
        command_row,
        expected_claim=expected_claim,
    )
    if command.permit_id != permit_id:
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_DISPATCH_HISTORY_INVALID")

    if (
        not _is_v2_order_event(order_event.payload)
        or not _is_v2_fill_event(fill_event.payload)
    ):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID")

    if unknown_event is not None:
        payload = unknown_event.payload
        reason_code = payload.get("reason_code")
        claimed_payload = events[2].payload.get("claim")
        has_claim = "claim" in payload or "claim_digest" in payload
        if (
            payload.get("permit_id") != permit_id
            or payload.get("dispatch_attempt_count") != 1
            or payload.get("public_state") != "UNKNOWN"
            or type(reason_code) is not str
            or not reason_code
            or len(reason_code) > 96
            or reason_code[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for char in reason_code)
            or (has_claim and (
                payload.get("claim") != claimed_payload
                or payload.get("claim_digest") != claimed_payload.get("claim_digest")
            ))
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_UNKNOWN_INVALID")

    return permit_id, order_event, fill_event, unknown_event


def _terminal_close_observation_history(
    command: RiskOrderCommand,
    command_row: sqlite3.Row,
    events: tuple[RiskOrderJournalEvent, ...],
) -> tuple[
    RiskOrderJournalEvent,
    RiskOrderJournalEvent,
    RiskOrderJournalEvent | None,
]:
    """Validate every source pair in a query-only CLOSE recovery history."""

    prefix = ("PREPARED", "RESERVED", "CLAIMED", "DISPATCHING")
    if (
        type(command) is not RiskOrderCommand
        or type(command_row) is not sqlite3.Row
        or len(events) < len(prefix) + 2
        or tuple(event.event_type for event in events[: len(prefix)]) != prefix
    ):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_SEQUENCE_INVALID")

    try:
        request_quantity = Decimal(str(command.order_request["quantity"]))
        request_instrument = command.order_request["symbol"]
        request_side = str(command.order_request["side"]).upper()
        permit_id = events[1].payload["permit_id"]
        claimed_payload = events[2].payload["claim"]
        claim_digest = claimed_payload["claim_digest"]
        dimensions = _position_dimensions_from_payload(command.canonical_payload)
    except (KeyError, TypeError, ValueError, InvalidOperation, RiskOrderJournalError):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID") from None
    if (
        not request_quantity.is_finite()
        or request_quantity <= 0
        or type(request_instrument) is not str
        or not request_instrument
        or request_side not in {"BUY", "SELL"}
        or type(permit_id) is not str
        or not permit_id
        or type(claim_digest) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", claim_digest)
        or type(claimed_payload) is not dict
    ):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID")

    cursor = len(prefix)
    unknown_event: RiskOrderJournalEvent | None = None

    def validate_unknown(event: RiskOrderJournalEvent) -> None:
        payload = event.payload
        allowed = {
            frozenset(
                {
                    "dispatch_attempt_count",
                    "permit_id",
                    "public_state",
                    "reason_code",
                    "updated_at_ns",
                }
            ),
            frozenset(
                {
                    "claim",
                    "claim_digest",
                    "dispatch_attempt_count",
                    "permit_id",
                    "public_state",
                    "reason_code",
                    "updated_at_ns",
                }
            ),
        }
        reason_code = payload.get("reason_code")
        has_claim = "claim" in payload or "claim_digest" in payload
        if (
            event.event_type != "UNKNOWN"
            or frozenset(payload) not in allowed
            or payload.get("permit_id") != permit_id
            or payload.get("dispatch_attempt_count") != 1
            or type(payload.get("dispatch_attempt_count")) is not int
            or payload.get("public_state") != "UNKNOWN"
            or type(reason_code) is not str
            or re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", reason_code) is None
            or (has_claim and (
                payload.get("claim") != claimed_payload
                or payload.get("claim_digest") != claim_digest
            ))
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_UNKNOWN_INVALID")

    # A lost initial acknowledgement can leave UNKNOWN before the first query.
    if cursor < len(events) and events[cursor].event_type == "UNKNOWN":
        validate_unknown(events[cursor])
        unknown_event = events[cursor]
        cursor += 1

    pairs: list[tuple[RiskOrderJournalEvent, RiskOrderJournalEvent]] = []
    previous_order_revision = 0
    previous_fill_watermark = 0
    previous_filled = Fraction(0)
    previous_state: str | None = None
    previous_order_record: Mapping[str, Any] | None = None
    previous_facts: dict[str, OrderFillFact] = {}
    previous_metadata_facts: str | None = None
    previous_provider_order_id: str | None = None

    while cursor < len(events):
        if (
            cursor + 1 >= len(events)
            or events[cursor].event_type != "ORDER_OBSERVATION"
            or events[cursor + 1].event_type != "FILL_OBSERVATION"
            or len(pairs) >= 256
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_SEQUENCE_INVALID")
        # A later query supersedes any preceding UNKNOWN projection.  Keep an
        # UNKNOWN only when it remains the suffix after the latest observation.
        unknown_event = None
        order_event, fill_event = events[cursor], events[cursor + 1]
        order, fills = order_event.payload, fill_event.payload
        if not _is_v2_order_event(order) or not _is_v2_fill_event(fills):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID")
        try:
            order_record = order["record"]
            if type(order_record) is not dict:
                raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID")
            order_filled = Fraction(Decimal(str(order["filled_quantity"])))
            fill_filled = Fraction(Decimal(str(fills["filled_quantity"])))
            quantity = Fraction(Decimal(str(order["quantity"])))
            record_filled = Fraction(Decimal(str(order_record.get("filled"))))
            order_revision = order["order_revision"]
            fill_watermark = fills["fill_watermark_revision"]
            state = order["exposure_state"]
            facts = _fill_facts_from_event(fills)
            facts_by_id = {fact.trade_id: fact for fact in facts}
            metadata_json = canonical_json(order["metadata_facts"])
        except (KeyError, TypeError, ValueError, InvalidOperation, RiskOrderJournalError):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID") from None
        if (
            len(facts_by_id) != len(facts)
            or order_filled != fill_filled
            or quantity != Fraction(request_quantity)
            or order_filled < 0
            or order_filled > quantity
            or sum((Fraction(fact.quantity) for fact in facts), Fraction(0))
            != fill_filled
            or type(order_revision) is not int
            or type(fill_watermark) is not int
            or fill_watermark < order_revision
            or order_revision < previous_order_revision
            or fill_watermark < previous_fill_watermark
            or fill_filled < previous_filled
            or state not in {item.value for item in OrderExposureState}
            or order.get("client_order_id") != command.client_order_id
            or fills.get("client_order_id") != command.client_order_id
            or order.get("provider_order_id") != order_record.get("order_id")
            or (
                previous_provider_order_id is not None
                and order.get("provider_order_id") != previous_provider_order_id
            )
            or order.get("account_id") != command.provider_account_id
            or fills.get("account_id") != command.provider_account_id
            or order.get("instrument") != request_instrument
            or str(order.get("side", "")).upper() != request_side
            or not _decimal_text_matches(order.get("quantity"), request_quantity)
            or not _decimal_text_matches(order_record.get("size"), request_quantity)
            or record_filled != order_filled
            or order.get("risk_intent_id") != command.risk_intent_id
            or fills.get("risk_intent_id") != command.risk_intent_id
            or order.get("claim_digest") != claim_digest
            or fills.get("claim_digest") != claim_digest
            or order.get("position_effect") != "CLOSE"
            or fills.get("position_effect") != "CLOSE"
            or order.get("reduce_only") is not True
            or not _position_dimensions_match(order, dimensions)
            or not _position_dimensions_match(fills, dimensions)
            or order.get("provider_contract_sha256")
            != fills.get("provider_contract_sha256")
            or metadata_json != canonical_json(fills.get("metadata_facts"))
            or (previous_metadata_facts is not None and metadata_json != previous_metadata_facts)
            or any(
                fact.side != request_side
                or fact.position_effect != "CLOSE"
                for fact in facts
            )
            or any(
                record.get("account_id") != command.provider_account_id
                or record.get("client_order_id") != command.client_order_id
                or record.get("order_id") != order.get("provider_order_id")
                or record.get("symbol") != request_instrument
                or str(record.get("side", "")).upper() != request_side
                for record in fills.get("records", ())
            )
            or any(
                facts_by_id.get(trade_id) != fact
                for trade_id, fact in previous_facts.items()
            )
            or (
                order_revision == previous_order_revision
                and previous_order_record is not None
                and order_record != previous_order_record
            )
            or (
                fill_watermark == previous_fill_watermark
                and previous_facts
                and facts_by_id != previous_facts
            )
            or (
                previous_state in {
                    OrderExposureState.FILLED.value,
                    OrderExposureState.CANCELLED.value,
                    OrderExposureState.REJECTED.value,
                }
                and (
                    state != previous_state
                    or order_record != previous_order_record
                    or facts_by_id != previous_facts
                )
            )
            or (
                state == OrderExposureState.ACKED.value and order_filled != 0
            )
            or (
                state == OrderExposureState.PARTIALLY_FILLED.value
                and not 0 < order_filled < quantity
            )
            or (
                state == OrderExposureState.FILLED.value and order_filled != quantity
            )
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_INVALID")

        pairs.append((order_event, fill_event))
        previous_order_revision = order_revision
        previous_fill_watermark = fill_watermark
        previous_filled = fill_filled
        previous_state = state
        previous_order_record = order_record
        previous_facts = facts_by_id
        previous_metadata_facts = metadata_json
        if order.get("provider_order_id") is not None:
            previous_provider_order_id = order["provider_order_id"]
        cursor += 2
        if cursor < len(events) and events[cursor].event_type == "UNKNOWN":
            validate_unknown(events[cursor])
            unknown_event = events[cursor]
            cursor += 1

    if not pairs:
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_SEQUENCE_INVALID")
    return pairs[-1][0], pairs[-1][1], unknown_event


def _terminal_exposure_source_projection(
    command: RiskOrderCommand,
    command_row: sqlite3.Row,
    events: tuple[RiskOrderJournalEvent, ...],
    current_fence: RiskOrderWriterFence,
) -> tuple[
    RiskOrderCommand,
    tuple[RiskOrderJournalEvent, ...],
    RiskOrderWriterFence,
    RiskOrderJournalEvent | None,
]:
    """Project immutable first-terminal source events across later writer leases.

    The provider observations are written under one lease. Recovery can append
    one UNKNOWN under that same lease and a later owner can append the durable
    ACK after re-attesting the persisted proof. The source rows must remain on
    their original fence; only a final ACK may carry a newer, valid fence.
    """

    if type(command) is not RiskOrderCommand or type(current_fence) is not RiskOrderWriterFence:
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_FENCE_INVALID")
    if not events:
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_SEQUENCE_INVALID")
    ack_event = events[-1] if events[-1].event_type == "ACKED_TRACKED" else None
    source_events = events[:-1] if ack_event is not None else events
    if not source_events:
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_SEQUENCE_INVALID")
    origin = source_events[0]
    source_fence = RiskOrderWriterFence(
        current_fence.scope,
        origin.writer_owner_id,
        origin.writer_fencing_token,
        origin.writer_fence_sha256,
    )
    is_close = command.canonical_payload.get("position_effect", "OPEN") == "CLOSE"
    if is_close:
        # CLOSE may be queried repeatedly, and each query is a new writer
        # lease.  Keep each immutable observation pair on one lease and allow
        # a lease advance only after the previous attempt durably ended UNKNOWN.
        _terminal_close_observation_history(command, command_row, source_events)
        _terminal_close_source_fences(source_events, current_fence)
    elif (
        source_fence.fence_sha256
        != _fence_digest(source_fence.scope, source_fence.owner_id, source_fence.fencing_token)
        or source_fence.fencing_token > current_fence.fencing_token
        or (
            source_fence.fencing_token == current_fence.fencing_token
            and (
                source_fence.owner_id != current_fence.owner_id
                or source_fence.fence_sha256 != current_fence.fence_sha256
            )
        )
        or any(
            event.writer_owner_id != source_fence.owner_id
            or event.writer_fencing_token != source_fence.fencing_token
            or event.writer_fence_sha256 != source_fence.fence_sha256
            for event in source_events
        )
    ):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_FENCE_INVALID")
    if ack_event is not None:
        ack_minimum_fence = (
            RiskOrderWriterFence(
                current_fence.scope,
                source_events[-1].writer_owner_id,
                source_events[-1].writer_fencing_token,
                source_events[-1].writer_fence_sha256,
            )
            if is_close
            else source_fence
        )
        if (
            ack_event.event_type != "ACKED_TRACKED"
            or ack_event.writer_fence_sha256
            != _fence_digest(
                current_fence.scope,
                ack_event.writer_owner_id,
                ack_event.writer_fencing_token,
            )
            or ack_event.writer_fencing_token < ack_minimum_fence.fencing_token
            or ack_event.writer_fencing_token > current_fence.fencing_token
            or (
                ack_event.writer_fencing_token == ack_minimum_fence.fencing_token
                and (
                    ack_event.writer_owner_id != ack_minimum_fence.owner_id
                    or ack_event.writer_fence_sha256 != ack_minimum_fence.fence_sha256
                )
            )
            or (
                ack_event.writer_fencing_token == current_fence.fencing_token
                and (
                    ack_event.writer_owner_id != current_fence.owner_id
                    or ack_event.writer_fence_sha256 != current_fence.fence_sha256
                )
            )
            or command.state != "ACKED_TRACKED"
            or command.latest_revision != ack_event.revision
            or command.latest_record_sha256 != ack_event.record_sha256
            or command.updated_at_ns != ack_event.payload.get("updated_at_ns")
            or dict(command.latest_event) != dict(ack_event.payload)
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_ACK_FENCE_INVALID")
    latest_source_event = source_events[-1]
    source_command = replace(
        command,
        updated_at_ns=latest_source_event.payload.get("updated_at_ns"),
        state=latest_source_event.event_type,
        latest_revision=latest_source_event.revision,
        latest_record_sha256=latest_source_event.record_sha256,
        latest_event=latest_source_event.payload,
    )
    return source_command, source_events, source_fence, ack_event




_DISPATCH_BASE_FIELDS = frozenset(
    {"dispatch_attempt_count", "permit_id", "risk_intent_id", "updated_at_ns"}
)




def _provider_dispatch_binding_claim_valid(
    value: object, *, claim: DispatchClaimBinding, risk_scope_key: str, profile_for
) -> bool:
    profile = profile_for(claim.scope.provider)
    return profile.validate_claim(
        value, claim=claim, risk_scope_key=risk_scope_key, require_sha256=_require_sha256
    )


def _provider_dispatch_payload_valid(payload, *, claim, risk_scope_key, profile_for):
    keys = set(payload)
    if keys == _DISPATCH_BASE_FIELDS:
        return True
    if not _DISPATCH_BASE_FIELDS < keys or len(keys) != len(_DISPATCH_BASE_FIELDS) + 1:
        return False
    profile = profile_for(claim.scope.provider)
    return keys == _DISPATCH_BASE_FIELDS | {profile.binding_field} and bool(
        profile.validate_claim(
            payload.get(profile.binding_field), claim=claim, risk_scope_key=risk_scope_key,
            require_sha256=_require_sha256,
        )
    )


def _provider_zero_fill_dispatch_history_valid(
    value: object, *, claim: DispatchClaimBinding, risk_scope_key: str,
    command: RiskOrderCommand, proof: DispatchTrackedOrderProof,
    reference: Mapping[str, Any], order_event: RiskOrderJournalEvent | None,
    fill_event: RiskOrderJournalEvent | None, profile_for,
) -> bool:
    """Delegate provider evidence matching while retaining journal and risk types."""
    profile = profile_for(claim.scope.provider)
    return profile.validate_zero_fill(
        value, claim=claim, risk_scope_key=risk_scope_key, command=command, proof=proof,
        reference=reference, order_event=order_event, fill_event=fill_event,
        journal_command_type=RiskOrderCommand, risk_tracked_proof_type=DispatchTrackedOrderProof,
        journal_event_type=RiskOrderJournalEvent, canonical_json=canonical_json,
        validate_claim_binding=partial(_provider_dispatch_binding_claim_valid, profile_for=profile_for),
    )




def _terminal_close_source_fences(
    events: tuple[RiskOrderJournalEvent, ...],
    current_fence: RiskOrderWriterFence,
) -> tuple[RiskOrderWriterFence, RiskOrderWriterFence]:
    """Check CLOSE observation leases as a monotonic UNKNOWN-delimited chain."""

    prefix = ("PREPARED", "RESERVED", "CLAIMED", "DISPATCHING")
    if (
        type(current_fence) is not RiskOrderWriterFence
        or len(events) < len(prefix) + 2
        or tuple(event.event_type for event in events[: len(prefix)]) != prefix
    ):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_FENCE_INVALID")

    def event_fence(event: RiskOrderJournalEvent) -> RiskOrderWriterFence:
        owner_id = event.writer_owner_id
        token = event.writer_fencing_token
        digest = event.writer_fence_sha256
        if (
            type(owner_id) is not str
            or not owner_id
            or type(token) is not int
            or token <= 0
            or type(digest) is not str
            or digest
            != _fence_digest(current_fence.scope, owner_id, token)
            or token > current_fence.fencing_token
            or (
                token == current_fence.fencing_token
                and (
                    owner_id != current_fence.owner_id
                    or digest != current_fence.fence_sha256
                )
            )
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_FENCE_INVALID")
        return RiskOrderWriterFence(current_fence.scope, owner_id, token, digest)

    first_fence = event_fence(events[0])
    prefix_fences = tuple(event_fence(event) for event in events[: len(prefix)])
    if any(item != first_fence for item in prefix_fences):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_FENCE_INVALID")

    cursor = len(prefix)
    previous_fence = first_fence
    previous_was_unknown = False
    if cursor < len(events) and events[cursor].event_type == "UNKNOWN":
        unknown_fence = event_fence(events[cursor])
        if unknown_fence != previous_fence:
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_FENCE_INVALID")
        previous_was_unknown = True
        cursor += 1

    while cursor < len(events):
        if (
            cursor + 1 >= len(events)
            or events[cursor].event_type != "ORDER_OBSERVATION"
            or events[cursor + 1].event_type != "FILL_OBSERVATION"
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_SEQUENCE_INVALID")
        order_fence = event_fence(events[cursor])
        fill_fence = event_fence(events[cursor + 1])
        if (
            order_fence != fill_fence
            or order_fence.fencing_token < previous_fence.fencing_token
            or (
                previous_was_unknown
                and order_fence.fencing_token <= previous_fence.fencing_token
            )
            or (
                order_fence.fencing_token == previous_fence.fencing_token
                and order_fence != previous_fence
            )
            or (
                order_fence.fencing_token > previous_fence.fencing_token
                and not previous_was_unknown
            )
        ):
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_FENCE_INVALID")
        cursor += 2
        previous_fence = order_fence
        previous_was_unknown = False
        if cursor < len(events) and events[cursor].event_type == "UNKNOWN":
            unknown_fence = event_fence(events[cursor])
            if unknown_fence != previous_fence:
                raise RiskOrderJournalError("TERMINAL_EXPOSURE_SOURCE_FENCE_INVALID")
            previous_was_unknown = True
            cursor += 1
        if cursor < len(events) and not previous_was_unknown:
            raise RiskOrderJournalError("TERMINAL_EXPOSURE_EVENT_SEQUENCE_INVALID")

    return first_fence, previous_fence


def _load_dispatch_proof_for_recovery_in(
    journal: RiskOrderJournal,
    connection: sqlite3.Connection,
    fence: RiskOrderWriterFence,
    *,
    principal_ref: str,
    intent_id: str,
    claim: DispatchClaimBinding,
) -> DispatchProofRecoverySource | None:
    if (
        type(principal_ref) is not str
        or not principal_ref
        or type(intent_id) is not str
        or not intent_id
        or type(claim) is not DispatchClaimBinding
        or claim.scope != fence.scope
    ):
        raise RiskOrderJournalError("RECOVERY_IDENTITY_INVALID")
    command_row = connection.execute(
        "SELECT * FROM risk_order_commands WHERE scope_key=? AND principal_ref=? AND intent_id=?",
        (fence.scope.key, principal_ref, intent_id),
    ).fetchone()
    if command_row is None:
        return None
    command_event_rows = connection.execute(
        "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? "
        "ORDER BY revision",
        (fence.scope.key, principal_ref, intent_id),
    ).fetchall()
    if not command_event_rows:
        raise RiskOrderJournalError("RECOVERY_EVENT_CHAIN_INVALID")
    command_events = tuple(journal._event_from_row(row, fence.scope) for row in command_event_rows)
    proof_events = tuple(event for event in command_events if event.event_type == "PROOF_READY")
    if not proof_events:
        return None
    if len(proof_events) != 1:
        raise RiskOrderJournalError("RECOVERY_PROOF_READY_AMBIGUOUS")
    proof_ready_event = proof_events[0]
    head = connection.execute(
        "SELECT revision FROM risk_order_events WHERE scope_key=? ORDER BY revision DESC LIMIT 1",
        (fence.scope.key,),
    ).fetchone()
    if head is None or not journal._verify_event_chains(
        connection,
        command_row,
        fence.scope,
        int(head["revision"]),
        target_revision=proof_ready_event.revision,
    ):
        raise RiskOrderJournalError("RECOVERY_EVENT_CHAIN_INVALID")
    command = journal._command_from_row(connection, command_row, fence.scope)
    if command.state not in {"PROOF_READY", "PROOF_RECOVERY_ATTESTED", "UNKNOWN"}:
        raise RiskOrderJournalError("RECOVERY_COMMAND_STATE_INVALID")
    if command.risk_intent_id != claim.intent_id or command.permit_id != claim.permit_id:
        raise RiskOrderJournalError("RECOVERY_CLAIM_COMMAND_MISMATCH")
    if command.created_revision != command_events[0].revision or (
        command.created_record_sha256 != command_events[0].record_sha256
    ):
        raise RiskOrderJournalError("RECOVERY_COMMAND_CREATION_MISMATCH")

    initial = command_events[0]
    initial_payload = dict(initial.payload)
    if (
        initial.event_type != "PREPARED"
        or initial.revision != command.created_revision
        or initial.record_sha256 != command.created_record_sha256
        or initial_payload.get("risk_intent_id") != command.risk_intent_id
        or initial_payload.get("canonical_payload") != dict(command.canonical_payload)
        or initial_payload.get("wire_scope") != dict(command.wire_scope)
        or initial_payload.get("exchange_name") != command.exchange_name
        or initial_payload.get("provider_account_id") != command.provider_account_id
        or initial_payload.get("client_order_id") != command.client_order_id
        or initial_payload.get("order_request") != dict(command.order_request)
        or initial_payload.get("order_request_sha256") != command.order_request_sha256
        or sha256_text(canonical_json(dict(command.canonical_payload))) != command.payload_sha256
        or sha256_text(
            canonical_json(
                {
                    "exchange_name": command.exchange_name,
                    "operation": "BtApi.make_order(normalized=True)",
                    "request": dict(command.order_request),
                }
            )
        )
        != command.order_request_sha256
    ):
        raise RiskOrderJournalError("RECOVERY_COMMAND_CREATION_MISMATCH")

    by_type: dict[str, list[RiskOrderJournalEvent]] = {}
    for event in command_events:
        by_type.setdefault(event.event_type, []).append(event)
    reserved = by_type.get("RESERVED", [])
    claimed = by_type.get("CLAIMED", [])
    dispatching = by_type.get("DISPATCHING", [])
    if len(reserved) != 1 or len(claimed) != 1 or len(dispatching) != 1:
        raise RiskOrderJournalError("RECOVERY_DISPATCH_HISTORY_INVALID")
    claimed_event = claimed[0]
    dispatch_event = dispatching[0]
    if (
        reserved[0].revision >= claimed_event.revision
        or claimed_event.revision >= dispatch_event.revision
        or dispatch_event.revision >= proof_ready_event.revision
        or reserved[0].payload.get("permit_id") != claim.permit_id
        or reserved[0].payload.get("risk_intent_id") != claim.intent_id
        or claimed_event.payload.get("permit_id") != claim.permit_id
        or claimed_event.payload.get("risk_intent_id") != claim.intent_id
        or claimed_event.payload.get("claim") != _claim_payload(claim)
        or dispatch_event.payload.get("permit_id") != claim.permit_id
        or dispatch_event.payload.get("risk_intent_id") != claim.intent_id
        or dispatch_event.payload.get("dispatch_attempt_count") != 1
    ):
        raise RiskOrderJournalError("RECOVERY_DISPATCH_HISTORY_INVALID")

    proof_payload = dict(proof_ready_event.payload)
    expected_proof_keys = {
        "accepted_request_sha256",
        "cause_id",
        "claim",
        "claim_digest",
        "dispatch_attempt_count",
        "evidence_class",
        "exposure_reference",
        "exposure_reference_id",
        "exposure_reference_sha256",
        "filled_quantity",
        "intent_hash",
        "intent_id",
        "observation_record_sha256",
        "observation_revision",
        "permit_id",
        "provider_order_id",
        "reconciliation_evidence_sha256",
        "risk_intent_id",
        "trade_count",
        "updated_at_ns",
        "writer_fence_sha256",
    }
    if set(proof_payload) != expected_proof_keys:
        raise RiskOrderJournalError("RECOVERY_PROOF_FIELDS_INVALID")
    if (
        proof_payload.get("claim") != _claim_payload(claim)
        or proof_payload.get("claim_digest") != claim.claim_digest
        or proof_payload.get("intent_hash") != claim.intent_hash
        or proof_payload.get("cause_id") != claim.cause_id
        or proof_payload.get("intent_id") != claim.intent_id
        or proof_payload.get("risk_intent_id") != command.risk_intent_id
        or proof_payload.get("permit_id") != claim.permit_id
        or proof_payload.get("dispatch_attempt_count") != 1
        or proof_payload.get("accepted_request_sha256") != command.order_request_sha256
        or proof_payload.get("filled_quantity") != 0
        or proof_payload.get("trade_count") != 0
        or proof_payload.get("writer_fence_sha256") != proof_ready_event.writer_fence_sha256
        or proof_ready_event.writer_fencing_token >= fence.fencing_token
        or proof_ready_event.writer_fence_sha256 == fence.fence_sha256
        or _fence_digest(
            fence.scope,
            proof_ready_event.writer_owner_id,
            proof_ready_event.writer_fencing_token,
        )
        != proof_ready_event.writer_fence_sha256
    ):
        raise RiskOrderJournalError("RECOVERY_PROOF_BINDING_INVALID")
    try:
        evidence_class = DispatchEvidenceClass(proof_payload["evidence_class"])
        proof = DispatchTrackedOrderProof(
            scope=fence.scope,
            permit_id=str(proof_payload["permit_id"]),
            intent_id=str(proof_payload["risk_intent_id"]),
            intent_hash=str(proof_payload["intent_hash"]),
            cause_id=str(proof_payload["cause_id"]),
            claim_digest=str(proof_payload["claim_digest"]),
            evidence_class=evidence_class,
            dispatch_attempt_count=proof_payload["dispatch_attempt_count"],
            journal_revision=proof_ready_event.revision,
            journal_record_sha256=proof_ready_event.record_sha256,
            reconciliation_evidence_sha256=str(proof_payload["reconciliation_evidence_sha256"]),
            writer_fence_sha256=proof_ready_event.writer_fence_sha256,
            provider_order_id=str(proof_payload["provider_order_id"]),
            accepted_request_sha256=str(proof_payload["accepted_request_sha256"]),
            exposure_reservation_id=str(proof_payload["exposure_reference_id"]),
            exposure_reservation_sha256=str(proof_payload["exposure_reference_sha256"]),
            filled_quantity=proof_payload["filled_quantity"],
            trade_count=proof_payload["trade_count"],
        )
    except (KeyError, TypeError, ValueError):
        raise RiskOrderJournalError("RECOVERY_PROOF_BINDING_INVALID") from None
    if proof.scope != claim.scope or proof.intent_id != claim.intent_id:
        raise RiskOrderJournalError("RECOVERY_PROOF_CLAIM_MISMATCH")

    exposure_row = connection.execute(
        "SELECT * FROM risk_order_exposure_references WHERE scope_key=? AND principal_ref=? AND intent_id=?",
        (fence.scope.key, principal_ref, intent_id),
    ).fetchone()
    if exposure_row is None:
        raise RiskOrderJournalError("RECOVERY_EXPOSURE_REFERENCE_MISSING")
    try:
        reference = json.loads(exposure_row["reference_json"])
    except (TypeError, ValueError):
        raise RiskOrderJournalError("RECOVERY_EXPOSURE_REFERENCE_INVALID") from None
    if type(reference) is not dict:
        raise RiskOrderJournalError("RECOVERY_EXPOSURE_REFERENCE_INVALID")
    reference_sha = sha256_text(str(exposure_row["reference_json"]))
    expected_exposure_id = (
        "risk-order-exposure:"
        + sha256_text(
            canonical_json(
                {
                    "intent_id": command.risk_intent_id,
                    "permit_id": claim.permit_id,
                    "provider_order_id": proof.provider_order_id,
                    "scope_key": fence.scope.key,
                }
            )
        )[:32]
    )
    if (
        str(exposure_row["reservation_id"]) != proof.exposure_reservation_id
        or proof.exposure_reservation_id != expected_exposure_id
        or str(exposure_row["reference_sha256"]) != reference_sha
        or reference_sha != proof.exposure_reservation_sha256
        or int(exposure_row["created_revision"]) != proof_ready_event.revision
        or str(exposure_row["record_sha256"]) != proof_ready_event.record_sha256
        or proof_payload.get("exposure_reference") != reference
        or reference.get("schema") != "bt-api-risk-order-exposure-reference-v1"
        or reference.get("scope_key") != fence.scope.key
        or reference.get("intent_id") != proof.intent_id
        or reference.get("intent_hash") != proof.intent_hash
        or reference.get("permit_id") != proof.permit_id
        or reference.get("claim_digest") != proof.claim_digest
        or reference.get("claim") != _claim_payload(claim)
        or reference.get("accepted_request_sha256") != proof.accepted_request_sha256
        or reference.get("provider_order_id") != proof.provider_order_id
        or reference.get("reconciliation_evidence_sha256") != proof.reconciliation_evidence_sha256
        or reference.get("writer_fence_sha256") != proof.writer_fence_sha256
        or reference.get("dispatch_attempt_count") != 1
        or reference.get("filled_quantity") != 0
        or reference.get("trade_count") != 0
        or reference.get("observation_revision") != proof_payload.get("observation_revision")
        or reference.get("observation_record_sha256")
        != proof_payload.get("observation_record_sha256")
    ):
        raise RiskOrderJournalError("RECOVERY_EXPOSURE_REFERENCE_INVALID")
    if (
        type(reference.get("order_observation_revision")) is not int
        or type(reference.get("fill_observation_revision")) is not int
    ):
        raise RiskOrderJournalError("RECOVERY_OBSERVATION_LINK_INVALID")
    order_row = connection.execute(
        "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? "
        "AND revision=?",
        (
            fence.scope.key,
            principal_ref,
            intent_id,
            reference["order_observation_revision"],
        ),
    ).fetchone()
    fill_row = connection.execute(
        "SELECT * FROM risk_order_events WHERE scope_key=? AND principal_ref=? AND intent_id=? "
        "AND revision=?",
        (
            fence.scope.key,
            principal_ref,
            intent_id,
            reference["fill_observation_revision"],
        ),
    ).fetchone()
    if (
        order_row is None
        or fill_row is None
        or str(order_row["event_type"]) != "ORDER_OBSERVATION"
        or str(fill_row["event_type"]) != "FILL_OBSERVATION"
        or int(order_row["revision"]) >= int(fill_row["revision"])
        or int(fill_row["revision"]) >= proof_ready_event.revision
        or str(order_row["record_sha256"]) != reference.get("order_observation_record_sha256")
        or str(fill_row["record_sha256"]) != reference.get("fill_observation_record_sha256")
        or int(fill_row["revision"]) != proof_payload.get("observation_revision")
        or str(fill_row["record_sha256"]) != proof_payload.get("observation_record_sha256")
    ):
        raise RiskOrderJournalError("RECOVERY_OBSERVATION_LINK_INVALID")
    order_event = journal._event_from_row(order_row, fence.scope)
    fill_event = journal._event_from_row(fill_row, fence.scope)
    reconciliation_sha = sha256_text(
        canonical_json(
            {
                "fill_event_sha256": fill_event.record_sha256,
                "fill_revision": fill_event.revision,
                "order_event_sha256": order_event.record_sha256,
                "order_revision": order_event.revision,
                "provider_contract_sha256": order_event.payload.get("provider_contract_sha256"),
                "request_sha256": command.order_request_sha256,
                "schema": "bt-api-risk-order-reconciliation-evidence-v1",
            }
        )
    )
    if (
        reconciliation_sha != proof.reconciliation_evidence_sha256
        or reference.get("order_observation_record_sha256") != order_event.record_sha256
        or reference.get("fill_observation_record_sha256") != fill_event.record_sha256
        or reference.get("observation_revision") != fill_event.revision
        or reference.get("observation_record_sha256") != fill_event.record_sha256
    ):
        raise RiskOrderJournalError("RECOVERY_RECONCILIATION_BINDING_INVALID")

    recovery_events: list[RiskOrderJournalEvent] = []
    proof_index = command_events.index(proof_ready_event)
    post_proof_events = command_events[proof_index + 1 :]
    for event in post_proof_events:
        if event.event_type == "PROOF_RECOVERY_ATTESTED":
            recovery_events.append(event)
        elif event.event_type == "UNKNOWN":
            if (
                event.payload.get("permit_id") != claim.permit_id
                or event.payload.get("dispatch_attempt_count") != 1
                or event.payload.get("public_state") != "UNKNOWN"
            ):
                raise RiskOrderJournalError("RECOVERY_UNKNOWN_EVENT_INVALID")
        else:
            # In particular, a provider query after PROOF_READY invalidates
            # automatic proof recovery. Only the immutable pre-query evidence
            # may be used to clear the latch.
            raise RiskOrderJournalError("RECOVERY_POST_PROOF_EVENT_UNSUPPORTED")
    if command.state == "PROOF_RECOVERY_ATTESTED" and (
        not recovery_events or recovery_events[-1].revision != command.latest_revision
    ):
        raise RiskOrderJournalError("RECOVERY_EVENT_MISSING")
    source = DispatchProofRecoverySource(
        command=command,
        claim=claim,
        proof=proof,
        proof_ready_event=proof_ready_event,
        order_observation_event=order_event,
        fill_observation_event=fill_event,
        exposure_reference=MappingProxyType(reference),
        exposure_reference_id=proof.exposure_reservation_id,
        exposure_reference_sha256=proof.exposure_reservation_sha256,
        recovery_events=tuple(recovery_events),
        recovery_attestations=(),
    )
    recovery_attestations = [
        _recovery_attestation_from_event(source, event) for event in recovery_events
    ]
    return DispatchProofRecoverySource(
        command=source.command,
        claim=source.claim,
        proof=source.proof,
        proof_ready_event=source.proof_ready_event,
        order_observation_event=source.order_observation_event,
        fill_observation_event=source.fill_observation_event,
        exposure_reference=source.exposure_reference,
        exposure_reference_id=source.exposure_reference_id,
        exposure_reference_sha256=source.exposure_reference_sha256,
        recovery_events=source.recovery_events,
        recovery_attestations=tuple(recovery_attestations),
    )


def _recovery_event_payload(
    source: DispatchProofRecoverySource,
    fence: RiskOrderWriterFence,
    *,
    recovery_event_id: str,
    recovery_event_revision: int,
) -> dict[str, Any]:
    proof = source.proof
    original = source.proof_ready_event
    return {
        "accepted_request_sha256": proof.accepted_request_sha256,
        "cause_id": proof.cause_id,
        "claim_digest": proof.claim_digest,
        "client_intent_id": source.command.intent_id,
        "current_writer_fence_sha256": fence.fence_sha256,
        "current_writer_fencing_token": fence.fencing_token,
        "current_writer_owner_id": fence.owner_id,
        "exposure_reservation_id": proof.exposure_reservation_id,
        "exposure_reservation_sha256": proof.exposure_reservation_sha256,
        "fill_observation_record_sha256": source.fill_observation_event.record_sha256,
        "fill_observation_revision": source.fill_observation_event.revision,
        "intent_hash": proof.intent_hash,
        "permit_id": proof.permit_id,
        "principal_ref": source.command.principal_ref,
        "proof_ready_record_sha256": original.record_sha256,
        "proof_ready_revision": original.revision,
        "proof_sha256": proof.fingerprint,
        "provider_order_id": proof.provider_order_id,
        "reconciliation_evidence_sha256": proof.reconciliation_evidence_sha256,
        "recovery_event_id": recovery_event_id,
        "recovery_event_revision": recovery_event_revision,
        "risk_intent_id": proof.intent_id,
        "schema": "bt-api-risk-order-recovery-attestation-v1",
        "scope_key": proof.scope.key,
        "order_observation_record_sha256": source.order_observation_event.record_sha256,
        "order_observation_revision": source.order_observation_event.revision,
        "original_writer_fence_sha256": original.writer_fence_sha256,
        "original_writer_fencing_token": original.writer_fencing_token,
        "original_writer_owner_id": original.writer_owner_id,
    }


def _recovery_attestation_from_event(
    source: DispatchProofRecoverySource,
    event: RiskOrderJournalEvent,
) -> DispatchRecoveryAttestation:
    payload = dict(event.payload)
    expected_keys = {
        "accepted_request_sha256",
        "cause_id",
        "claim_digest",
        "client_intent_id",
        "current_writer_fence_sha256",
        "current_writer_fencing_token",
        "current_writer_owner_id",
        "exposure_reservation_id",
        "exposure_reservation_sha256",
        "fill_observation_record_sha256",
        "fill_observation_revision",
        "intent_hash",
        "order_observation_record_sha256",
        "order_observation_revision",
        "original_writer_fence_sha256",
        "original_writer_fencing_token",
        "original_writer_owner_id",
        "permit_id",
        "principal_ref",
        "proof_ready_record_sha256",
        "proof_ready_revision",
        "proof_sha256",
        "provider_order_id",
        "reconciliation_evidence_sha256",
        "recovery_event_id",
        "recovery_event_revision",
        "risk_intent_id",
        "schema",
        "scope_key",
        "updated_at_ns",
    }
    expected_event_id = sha256_text(
        canonical_json(
            [
                source.proof.scope.key,
                source.command.principal_ref,
                source.command.intent_id,
                event.revision,
            ]
        )
    )
    proof = source.proof
    original = source.proof_ready_event
    if (
        event.event_type != "PROOF_RECOVERY_ATTESTED"
        or set(payload) != expected_keys
        or payload.get("schema") != "bt-api-risk-order-recovery-attestation-v1"
        or payload.get("scope_key") != proof.scope.key
        or payload.get("principal_ref") != source.command.principal_ref
        or payload.get("client_intent_id") != source.command.intent_id
        or payload.get("risk_intent_id") != proof.intent_id
        or payload.get("permit_id") != proof.permit_id
        or payload.get("intent_hash") != proof.intent_hash
        or payload.get("cause_id") != proof.cause_id
        or payload.get("claim_digest") != proof.claim_digest
        or payload.get("proof_sha256") != proof.fingerprint
        or payload.get("proof_ready_revision") != original.revision
        or payload.get("proof_ready_record_sha256") != original.record_sha256
        or payload.get("original_writer_owner_id") != original.writer_owner_id
        or payload.get("original_writer_fencing_token") != original.writer_fencing_token
        or payload.get("original_writer_fence_sha256") != original.writer_fence_sha256
        or payload.get("order_observation_revision") != source.order_observation_event.revision
        or payload.get("order_observation_record_sha256")
        != source.order_observation_event.record_sha256
        or payload.get("fill_observation_revision") != source.fill_observation_event.revision
        or payload.get("fill_observation_record_sha256")
        != source.fill_observation_event.record_sha256
        or payload.get("reconciliation_evidence_sha256") != proof.reconciliation_evidence_sha256
        or payload.get("accepted_request_sha256") != proof.accepted_request_sha256
        or payload.get("provider_order_id") != proof.provider_order_id
        or payload.get("exposure_reservation_id") != proof.exposure_reservation_id
        or payload.get("exposure_reservation_sha256") != proof.exposure_reservation_sha256
        or payload.get("recovery_event_id") != expected_event_id
        or payload.get("recovery_event_revision") != event.revision
        or payload.get("current_writer_owner_id") != event.writer_owner_id
        or payload.get("current_writer_fencing_token") != event.writer_fencing_token
        or payload.get("current_writer_fence_sha256") != event.writer_fence_sha256
        or _fence_digest(proof.scope, event.writer_owner_id, event.writer_fencing_token)
        != event.writer_fence_sha256
        or type(payload.get("updated_at_ns")) is not int
        or payload.get("updated_at_ns") <= 0
        or event.writer_fencing_token <= original.writer_fencing_token
        or event.writer_fence_sha256 == original.writer_fence_sha256
    ):
        raise RiskOrderJournalError("RECOVERY_ATTESTATION_EVENT_INVALID")
    try:
        return DispatchRecoveryAttestation(
            scope=proof.scope,
            permit_id=proof.permit_id,
            intent_id=proof.intent_id,
            intent_hash=proof.intent_hash,
            cause_id=proof.cause_id,
            claim_digest=proof.claim_digest,
            proof_sha256=proof.fingerprint,
            proof_ready_revision=original.revision,
            proof_ready_record_sha256=original.record_sha256,
            original_writer_owner_id=original.writer_owner_id,
            original_writer_fencing_token=original.writer_fencing_token,
            original_writer_fence_sha256=original.writer_fence_sha256,
            order_observation_revision=source.order_observation_event.revision,
            order_observation_record_sha256=source.order_observation_event.record_sha256,
            fill_observation_revision=source.fill_observation_event.revision,
            fill_observation_record_sha256=source.fill_observation_event.record_sha256,
            reconciliation_evidence_sha256=proof.reconciliation_evidence_sha256,
            accepted_request_sha256=proof.accepted_request_sha256,
            provider_order_id=proof.provider_order_id,
            exposure_reservation_id=proof.exposure_reservation_id,
            exposure_reservation_sha256=proof.exposure_reservation_sha256,
            recovery_event_id=expected_event_id,
            recovery_event_revision=event.revision,
            recovery_event_sha256=event.record_sha256,
            current_writer_owner_id=event.writer_owner_id,
            current_writer_fencing_token=event.writer_fencing_token,
            current_writer_fence_sha256=event.writer_fence_sha256,
        )
    except (TypeError, ValueError):
        raise RiskOrderJournalError("RECOVERY_ATTESTATION_EVENT_INVALID") from None


def _same_recovery_source_snapshot(
    left: DispatchProofRecoverySource, right: DispatchProofRecoverySource
) -> bool:
    return (
        left.command.scope == right.command.scope
        and left.command.principal_ref == right.command.principal_ref
        and left.command.intent_id == right.command.intent_id
        and left.command.state == right.command.state
        and left.command.latest_revision == right.command.latest_revision
        and left.command.latest_record_sha256 == right.command.latest_record_sha256
        and left.claim == right.claim
        and left.proof == right.proof
        and left.proof_ready_event == right.proof_ready_event
        and left.order_observation_event == right.order_observation_event
        and left.fill_observation_event == right.fill_observation_event
        and dict(left.exposure_reference) == dict(right.exposure_reference)
        and left.exposure_reference_id == right.exposure_reference_id
        and left.exposure_reference_sha256 == right.exposure_reference_sha256
        and left.recovery_events == right.recovery_events
        and left.recovery_attestations == right.recovery_attestations
    )


def _decimal_text(value: Decimal) -> str:
    if value == 0:
        return "0"
    result = format(value, "f")
    if "." in result:
        result = result.rstrip("0").rstrip(".")
    return result


_FINITE_DECIMAL_TEXT = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z")


def _decimal_text_matches(value: object, expected: object) -> bool:
    """Compare a serialized decimal to a typed Decimal without changing either.

    Provider-backed journal payloads preserve the decimal scale present in the
    normalized observation (for example ``"1.0"``). Risk proof DTOs compare by
    numeric value, so requiring the journal's canonical display spelling here
    would reject an otherwise exact value. Keep the persisted text and its hash
    untouched; reject booleans, malformed spellings, non-finite values, and
    non-Decimal proof operands.
    """

    if type(value) is not str or type(expected) is not Decimal:
        return False
    if _FINITE_DECIMAL_TEXT.fullmatch(value) is None or not expected.is_finite():
        return False
    try:
        actual = Decimal(value)
    except (InvalidOperation, ValueError):
        return False
    return actual.is_finite() and actual == expected


def _provider_observation_digest_matches(payload: Mapping[str, Any]) -> bool:
    digest = payload.get("provider_observation_sha256")
    if type(digest) is not str or len(digest) != _SHA256_LENGTH:
        return False
    projected = dict(payload)
    projected.pop("provider_observation_sha256", None)
    # The service adds this attempt count after hashing the provider's
    # normalized response; it is journal linkage, not provider source data.
    projected.pop("dispatch_attempt_count", None)
    projected.pop("updated_at_ns", None)
    try:
        return sha256_text(canonical_json(projected)) == digest
    except RiskOrderJournalError:
        return False


def _valid_exposure_applied_payload(
    payload: Mapping[str, Any], *, persisted: bool = False
) -> bool:
    required = {
        "dispatch_attempt_count",
        "filled_gross_notional",
        "filled_quantity",
        "journal_record_sha256",
        "journal_revision",
        "leaves_quantity",
        "notional_unit",
        "open_gross_notional",
        "order_revision",
        "permit_id",
        "proof_sha256",
        "provider_order_id",
        "public_state",
        "risk_intent_id",
        "trade_count",
    }
    keys = set(payload)
    allowed_keys = {frozenset(required), frozenset(required | {"reason_code"})}
    if persisted:
        # append_event owns this timestamp and adds it after validating the
        # caller-supplied body. Read-side validation accepts that exact stored
        # form without broadening the append API.
        allowed_keys.update(
            {
                frozenset(required | {"updated_at_ns"}),
                frozenset(required | {"reason_code", "updated_at_ns"}),
            }
        )
    if frozenset(keys) not in allowed_keys:
        return False
    if persisted and (
        type(payload.get("updated_at_ns")) is not int or payload["updated_at_ns"] <= 0
    ):
        return False
    if (
        payload.get("dispatch_attempt_count") != 1
        or type(payload.get("dispatch_attempt_count")) is not int
        or type(payload.get("journal_revision")) is not int
        or payload["journal_revision"] <= 0
        or type(payload.get("order_revision")) is not int
        or payload["order_revision"] <= 0
        or type(payload.get("trade_count")) is not int
        or payload["trade_count"] < 0
        or type(payload.get("permit_id")) is not str
        or not payload["permit_id"]
        or type(payload.get("risk_intent_id")) is not str
        or not payload["risk_intent_id"]
        or type(payload.get("provider_order_id")) is not str
        or not payload["provider_order_id"]
        or type(payload.get("notional_unit")) is not str
        or not payload["notional_unit"]
        or type(payload.get("public_state")) is not str
        or payload["public_state"] not in {state.value for state in OrderExposureState}
        or type(payload.get("proof_sha256")) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", payload["proof_sha256"])
        or type(payload.get("journal_record_sha256")) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", payload["journal_record_sha256"])
    ):
        return False
    for key in (
        "filled_gross_notional",
        "filled_quantity",
        "leaves_quantity",
        "open_gross_notional",
    ):
        value = payload.get(key)
        if type(value) is not str:
            return False
        try:
            decimal_value = Decimal(value)
        except InvalidOperation:
            return False
        if not decimal_value.is_finite() or decimal_value < 0:
            return False
    return type(payload.get("reason_code")) is str if "reason_code" in keys else True


def _exposure_application_matches_query(
    event: RiskOrderJournalEvent,
    query_event: RiskOrderJournalEvent,
    command: RiskOrderCommand,
) -> bool:
    payload = event.payload
    query = query_event.payload
    try:
        valuation_unit = query["metadata_facts"]["instrument_metadata"]["valuation_unit"]
    except (KeyError, TypeError):
        return False
    return (
        _valid_exposure_applied_payload(payload, persisted=True)
        and payload.get("updated_at_ns") is not None
        and type(payload.get("updated_at_ns")) is int
        and payload["updated_at_ns"] > 0
        and event.writer_owner_id == query_event.writer_owner_id
        and event.writer_fencing_token == query_event.writer_fencing_token
        and event.writer_fence_sha256 == query_event.writer_fence_sha256
        and payload.get("dispatch_attempt_count") == 1
        and payload.get("journal_revision") == query_event.revision
        and payload.get("journal_record_sha256") == query_event.record_sha256
        and payload.get("order_revision") == query.get("order_revision")
        and payload.get("permit_id") == command.permit_id
        and payload.get("provider_order_id") == query.get("provider_order_id")
        and payload.get("risk_intent_id") == command.risk_intent_id
        and payload.get("public_state") == query.get("exposure_state")
        and payload.get("filled_quantity") == query.get("filled_quantity")
        and payload.get("trade_count") == query.get("trade_count")
        and payload.get("notional_unit") == valuation_unit
    )


def _acknowledged_query_history_valid(
    events: tuple[RiskOrderJournalEvent, ...],
    *,
    ack_index: int,
    command: RiskOrderCommand,
    allow_pending_latest_query: bool,
) -> bool:
    """Validate append-only provider queries and Risk application receipts."""

    acknowledged_order_id = events[ack_index].payload.get("provider_order_id")
    if type(acknowledged_order_id) is not str or not acknowledged_order_id:
        return False
    pending_query: RiskOrderJournalEvent | None = None
    for event in events[ack_index + 1 :]:
        payload = event.payload
        if event.event_type == "UNKNOWN":
            if not _post_ack_unknown_payload_valid(
                payload,
                revision=event.revision,
                ack_revision=events[ack_index].revision,
                permit_id=command.permit_id,
            ):
                return False
            pending_query = None
            continue
        if event.event_type == "PROVIDER_QUERY":
            if (
                pending_query is not None
                or payload.get("permit_id") is not None
                or payload.get("dispatch_attempt_count") != 1
                or type(payload.get("dispatch_attempt_count")) is not int
                or payload.get("public_state") not in {"ACKED_TRACKED", "UNKNOWN"}
                or payload.get("provider_order_id") != acknowledged_order_id
                or payload.get("client_order_id") != command.client_order_id
                or payload.get("account_id") != command.provider_account_id
                or payload.get("complete") is not True
                or payload.get("source_alignment_valid") is not True
                or payload.get("fill_source_alignment_valid") is not True
                or type(payload.get("updated_at_ns")) is not int
                or payload.get("updated_at_ns") <= 0
                or not _provider_observation_digest_matches(payload)
            ):
                return False
            if payload.get("public_state") == "ACKED_TRACKED":
                record = payload.get("record")
                try:
                    zero_filled = Decimal(str(payload.get("filled_quantity"))) == 0
                    record_zero_filled = (
                        type(record) is dict and Decimal(str(record.get("filled"))) == 0
                    )
                except (InvalidOperation, ValueError):
                    return False
                if (
                    payload.get("record_count") != 0
                    or payload.get("trade_count") != 0
                    or payload.get("records") != []
                    or not zero_filled
                    or not record_zero_filled
                    or type(record) is not dict
                    or record.get("order_id") != acknowledged_order_id
                    or record.get("client_order_id") != command.client_order_id
                    or record.get("account_id") != command.provider_account_id
                    or record.get("status") != "accepted"
                ):
                    return False
            elif not (
                _is_v2_order_event(payload, combined_query=True)
                and _is_v2_fill_event(payload, combined_query=True)
            ):
                return False
            else:
                pending_query = event
            continue
        if event.event_type == "EXPOSURE_APPLIED":
            if (
                pending_query is None
                or event.revision != pending_query.revision + 1
                or not _exposure_application_matches_query(event, pending_query, command)
            ):
                return False
            pending_query = None
            continue
        return False
    if pending_query is not None:
        return (
            allow_pending_latest_query
            and events[-1] is pending_query
            and pending_query.event_type == "PROVIDER_QUERY"
        )
    return True


def _post_ack_unknown_payload_valid(
    payload: Mapping[str, Any],
    *,
    revision: int,
    ack_revision: int,
    permit_id: str | None,
) -> bool:
    """Require the exact journal-owned UNKNOWN shape after a resolved ACK."""

    expected_keys = {
        "dispatch_attempt_count",
        "permit_id",
        "public_state",
        "reason_code",
        "updated_at_ns",
    }
    reason_code = payload.get("reason_code") if isinstance(payload, Mapping) else None
    return (
        isinstance(payload, Mapping)
        and set(payload) == expected_keys
        and type(revision) is int
        and type(ack_revision) is int
        and revision > ack_revision
        and type(permit_id) is str
        and bool(permit_id)
        and type(payload.get("permit_id")) is str
        and payload.get("permit_id") == permit_id
        and type(payload.get("dispatch_attempt_count")) is int
        and payload.get("dispatch_attempt_count") == 1
        and payload.get("public_state") == "UNKNOWN"
        and type(reason_code) is str
        and re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", reason_code) is not None
        and type(payload.get("updated_at_ns")) is int
        and payload.get("updated_at_ns") > 0
    )


def _provenance_snapshot_matches(value: object, *, operation: str) -> bool:
    from bt_api_base.order_provenance_projection import provenance_snapshot_matches

    if type(value) is not dict or value.get("schema") not in (
        "bt-api-order-source-provenance-v6",
    ):
        return False
    return provenance_snapshot_matches(
        value, operation=operation, schema=value["schema"],
        canonical_json=canonical_json, sha256_text=sha256_text,
    )


def _observation_subparts(
    payload: Mapping[str, Any], *, combined_query: bool
) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    if not combined_query:
        return payload, payload
    provenance = payload.get("normalization_provenance")
    fields = payload.get("source_fields")
    values = payload.get("source_values")
    envelope_fields = payload.get("envelope_fields")
    envelope_values = payload.get("envelope_values")
    hashes = payload.get("source_sha256")
    if any(type(value) is not dict for value in (provenance, fields, values, envelope_fields, envelope_values, hashes)):
        return None
    try:
        order = {
            "normalization_provenance": provenance["order"],
            "source_fields": fields["order"],
            "source_values": values["order"],
            "envelope_fields": envelope_fields["order"],
            "envelope_values": envelope_values["order"],
            "source_sha256": hashes["order"],
        }
        fills = {
            "normalization_provenance": provenance["fills"],
            "source_fields": fields["fills"],
            "source_values": values["fills"],
            "envelope_fields": envelope_fields["fills"],
            "envelope_values": envelope_values["fills"],
            "source_sha256": hashes["fills"],
        }
    except (KeyError, TypeError):
        return None
    return order, fills


def _is_v2_order_event(
    payload: Mapping[str, Any], *, combined_query: bool = False
) -> bool:
    if not isinstance(payload, Mapping) or not _provider_observation_digest_matches(payload):
        return False
    parts = _observation_subparts(payload, combined_query=combined_query)
    if parts is None:
        return False
    order_part, _fill_part = parts
    order_provenance = order_part.get("normalization_provenance")
    if (
        not _provenance_snapshot_matches(order_provenance, operation="query_order")
        or order_provenance.get("schema") != payload.get("normalizer_schema")
    ):
        return False
    order_fields = (
        payload.get("complete") is True
        and payload.get("source_alignment_valid") is True
        and payload.get("source_row_count") == 1
        and type(payload.get("source_row_count")) is int
        and type(payload.get("provider_order_id")) is str
        and bool(payload.get("provider_order_id"))
        and type(payload.get("client_order_id")) is str
        and type(payload.get("account_id")) is str
        and type(payload.get("instrument")) is str
        and type(payload.get("order_revision")) is int
        and payload.get("order_revision") > 0
        and type(payload.get("metadata_facts")) is dict
        and type(payload.get("source_alias_map_sha256")) is str
        and type(payload.get("exposure_state")) is str
        and payload.get("provider_contract_sha256") == payload.get("metadata_facts", {}).get("provider_contract_sha256")
    )
    if combined_query:
        return order_fields and payload.get("operation") == "orders.query"
    return (
        order_fields
        and payload.get("operation") == "query_order"
        and payload.get("normalizer_schema") in ("bt-api-order-source-provenance-v6",)
        and payload.get("provider_contract_sha256") is not None
    )


def _is_v2_fill_event(
    payload: Mapping[str, Any], *, combined_query: bool = False
) -> bool:
    if not isinstance(payload, Mapping) or not _provider_observation_digest_matches(payload):
        return False
    parts = _observation_subparts(payload, combined_query=combined_query)
    if parts is None:
        return False
    order_part, fill_part = parts
    fill_provenance = fill_part.get("normalization_provenance")
    if (
        not _provenance_snapshot_matches(fill_provenance, operation="get_deals")
        or fill_provenance.get("schema") != payload.get("normalizer_schema")
    ):
        return False
    records = payload.get("records")
    row_provenance = payload.get("fill_row_provenance")
    if (
        type(records) is not list
        or type(row_provenance) is not list
        or len(records) != len(row_provenance)
        or payload.get("complete") is not True
        or payload.get("source_alignment_valid") is not True
        or payload.get("fill_source_alignment_valid", True) is not True
        or payload.get("fill_watermark_revision") is None
        or type(payload.get("fill_watermark_revision")) is not int
        or payload.get("fill_watermark_revision") <= 0
        or payload.get("record_count") != len(records)
        or payload.get("trade_count") != len(records)
        or payload.get("provider_contract_sha256") != payload.get("metadata_facts", {}).get("provider_contract_sha256")
    ):
        return False
    for record, provenance in zip(records, row_provenance, strict=True):
        if (
            type(record) is not dict
            or type(record.get("source_revision")) is not int
            or record["source_revision"] <= 0
            or record["source_revision"] > payload["fill_watermark_revision"]
            or not _provenance_snapshot_matches(provenance, operation="get_deals")
            or provenance.get("schema") != payload.get("normalizer_schema")
        ):
            return False
    if combined_query:
        return payload.get("operation") == "orders.query"
    return (
        payload.get("operation") == "get_deals"
        and payload.get("normalizer_schema") in ("bt-api-order-source-provenance-v6",)
    )


def _reconciliation_evidence_sha256(
    command: RiskOrderCommand,
    order_event: RiskOrderJournalEvent,
    fill_event: RiskOrderJournalEvent,
) -> str:
    if (
        type(command) is not RiskOrderCommand
        or type(order_event) is not RiskOrderJournalEvent
        or type(fill_event) is not RiskOrderJournalEvent
    ):
        raise RiskOrderJournalError("RECONCILIATION_SOURCE_INVALID")
    return sha256_text(
        canonical_json(
            {
                "fill_event_sha256": fill_event.record_sha256,
                "fill_revision": fill_event.revision,
                "order_event_sha256": order_event.record_sha256,
                "order_revision": order_event.revision,
                "provider_contract_sha256": order_event.payload.get("provider_contract_sha256"),
                "request_sha256": command.order_request_sha256,
                "schema": "bt-api-risk-order-reconciliation-evidence-v1",
            }
        )
    )


def _tracked_proof_from_events(
    command: RiskOrderCommand,
    claim: DispatchClaimBinding,
    proof_event: RiskOrderJournalEvent,
) -> DispatchTrackedOrderProof:
    if (
        type(command) is not RiskOrderCommand
        or type(claim) is not DispatchClaimBinding
        or type(proof_event) is not RiskOrderJournalEvent
        or proof_event.event_type != "PROOF_READY"
        or claim.scope != command.scope
        or proof_event.scope != command.scope
    ):
        raise RiskOrderJournalError("TRACKED_PROOF_SOURCE_INVALID")
    payload = proof_event.payload
    try:
        return DispatchTrackedOrderProof(
            scope=claim.scope,
            permit_id=claim.permit_id,
            intent_id=claim.intent_id,
            intent_hash=claim.intent_hash,
            cause_id=claim.cause_id,
            claim_digest=claim.claim_digest,
            evidence_class=DispatchEvidenceClass(payload["evidence_class"]),
            dispatch_attempt_count=payload["dispatch_attempt_count"],
            journal_revision=proof_event.revision,
            journal_record_sha256=proof_event.record_sha256,
            reconciliation_evidence_sha256=payload["reconciliation_evidence_sha256"],
            writer_fence_sha256=proof_event.writer_fence_sha256,
            provider_order_id=payload["provider_order_id"],
            accepted_request_sha256=payload["accepted_request_sha256"],
            exposure_reservation_id=payload["exposure_reference_id"],
            exposure_reservation_sha256=payload["exposure_reference_sha256"],
            filled_quantity=payload["filled_quantity"],
            trade_count=payload["trade_count"],
        )
    except (KeyError, TypeError, ValueError):
        raise RiskOrderJournalError("TRACKED_PROOF_SOURCE_INVALID") from None


def _dispatch_claim_from_payload(
    scope: AccountScope, payload: object
) -> DispatchClaimBinding:
    if (
        type(scope) is not AccountScope
        or type(payload) is not dict
        or set(payload)
        != {
            "cause_id",
            "claim_digest",
            "claimed_at",
            "intent_hash",
            "intent_id",
            "permit_id",
            "scope_key",
        }
        or payload.get("scope_key") != scope.key
        or type(payload.get("claimed_at")) not in (int, float)
        or type(payload.get("claimed_at")) is bool
    ):
        raise RiskOrderJournalError("CANCEL_TARGET_CLAIM_INVALID")
    try:
        return DispatchClaimBinding(
            scope=scope,
            permit_id=payload["permit_id"],
            intent_id=payload["intent_id"],
            intent_hash=payload["intent_hash"],
            cause_id=payload["cause_id"],
            claimed_at=payload["claimed_at"],
            claim_digest=payload["claim_digest"],
        )
    except (TypeError, ValueError):
        raise RiskOrderJournalError("CANCEL_TARGET_CLAIM_INVALID") from None












def _fill_facts_from_event(
    payload: Mapping[str, Any], *, combined_query: bool = False
) -> tuple[OrderFillFact, ...]:
    if not _is_v2_fill_event(payload, combined_query=combined_query):
        raise RiskOrderJournalError("FILL_FACT_SOURCE_INVALID")
    contract = payload["metadata_facts"].get("provider_contract")
    if type(contract) is not dict:
        raise RiskOrderJournalError("FILL_FACT_SOURCE_INVALID")
    revision_field = contract.get("fill_revision_field")
    fee_field = contract.get("fee_amount_field")
    fee_currency_field = contract.get("fee_currency_field")
    position_effect = payload.get("position_effect", "OPEN")
    if position_effect not in {"OPEN", "CLOSE"}:
        raise RiskOrderJournalError("FILL_FACT_SOURCE_INVALID")
    facts: list[OrderFillFact] = []
    for record, raw_provenance in zip(
        payload["records"], payload["fill_row_provenance"], strict=True
    ):
        values = raw_provenance["source_values"]
        try:
            source_record_sha256 = _fill_source_record_sha256(raw_provenance)
            if record.get("source_record_sha256") != source_record_sha256:
                raise RiskOrderJournalError("FILL_FACT_SOURCE_INVALID")
            fact = OrderFillFact(
                trade_id=record["trade_id"],
                quantity=Decimal(str(record["size"])),
                price=Decimal(str(record["price"])),
                side=str(record["side"]).upper(),
                position_effect=position_effect,
                fee_amount=Decimal(str(values[fee_field])),
                fee_currency=str(values[fee_currency_field]).upper(),
                source_record_sha256=source_record_sha256,
                source_revision=values[revision_field],
            )
        except (KeyError, TypeError, ValueError, InvalidOperation):
            raise RiskOrderJournalError("FILL_FACT_SOURCE_INVALID") from None
        facts.append(fact)
    return tuple(sorted(facts, key=lambda item: item.trade_id))


def _weighted_average_price(payload: Mapping[str, Any]) -> str:
    """Derive the executed average price from one immutable fill observation.

    The value is the quantity-weighted mean of the exact validated fill facts,
    so a terminal ACK can expose the provider-executed price without trusting a
    second provider read.  Non-positive totals are refused instead of returning
    a silent placeholder.
    """

    facts = _fill_facts_from_event(payload)
    quantity = sum((fact.quantity for fact in facts), Decimal(0))
    if not facts or quantity <= 0:
        raise RiskOrderJournalError("FILL_FACT_SOURCE_INVALID")
    gross = sum((fact.quantity * fact.price for fact in facts), Decimal(0))
    return _decimal_text(gross / quantity)


def _fill_source_record_sha256(provenance: Mapping[str, Any]) -> str:
    """Recompute the immutable explicit fill-row digest from normalized provenance."""

    if (
        type(provenance) is not dict
        or provenance.get("operation") != "get_deals"
        or provenance.get("schema") not in ("bt-api-order-source-provenance-v6",)
        or type(provenance.get("source_fields")) is not list
        or type(provenance.get("source_values")) is not dict
    ):
        raise RiskOrderJournalError("FILL_FACT_SOURCE_INVALID")
    return sha256_text(
        canonical_json(
            {
                "schema": "bt-api-provider-source-row-v1",
                "operation": "get_deals",
                "source_fields": provenance["source_fields"],
                "source_values": provenance["source_values"],
            }
        )
    )


def _terminal_ack_payload(
    receipt: DispatchExposureResolutionReceipt,
    reference: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        type(receipt) is not DispatchExposureResolutionReceipt
        or receipt.status not in {
            DispatchExposureResolutionReceiptStatus.TERMINAL_EXPOSURE_RESOLVED,
            DispatchExposureResolutionReceiptStatus.TERMINAL_CLOSE_RESOLVED,
        }
        or not isinstance(reference, Mapping)
    ):
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_RECEIPT_INVALID")
    payload = {
        "average_price": reference.get("average_price"),
        "dispatch_attempt_count": 1,
        "filled_quantity": _decimal_text(receipt.filled_quantity),
        "journal_revision": receipt.journal_revision,
        "order_revision": receipt.order_revision,
        "permit_id": receipt.claim.permit_id,
        "proof_sha256": receipt.proof_sha256,
        "provider_order_id": reference.get("provider_order_id"),
        "public_state": receipt.final_state.value,
        "reconciliation_evidence_sha256": reference.get("reconciliation_evidence_sha256"),
        "risk_intent_id": receipt.claim.intent_id,
        "trade_count": receipt.trade_count,
    }
    if receipt.position_effect == "CLOSE":
        payload.update(
            {
                "close_proof_sha256": receipt.exposure_proof_sha256,
                "close_reference_id": receipt.exposure_reservation_id,
                "close_reference_sha256": receipt.exposure_reservation_sha256,
                "position_effect": "CLOSE",
            }
        )
    else:
        payload.update(
            {
                "exposure_proof_sha256": receipt.exposure_proof_sha256,
                "exposure_reference_id": receipt.exposure_reservation_id,
                "exposure_reference_sha256": receipt.exposure_reservation_sha256,
            }
        )
    if type(payload["average_price"]) is not str or not payload["average_price"]:
        # A terminal positive-fill reference always carries the derived text;
        # refusing an absent value keeps the ACK from presenting a filled order
        # without its executed price.
        raise RiskOrderJournalError("TERMINAL_EXPOSURE_RECEIPT_INVALID")
    return payload


def _trade_identity_declaration_matches(
    proof: OrderExposureObservationProof, contract: object
) -> bool:
    """Require the declared DIM01 identity domain to match the stored contract.

    Undeclared proofs and undeclared contracts keep the legacy behavior.  Any
    other combination (declared on one side only, or different values) refuses
    the proof instead of inferring an identity domain from a profile version.
    """

    declared_domain = proof.trade_id_domain_ref
    declared_scope = proof.trade_id_scope
    stored_domain = contract.get("trade_id_domain_ref") if isinstance(contract, Mapping) else None
    stored_scope = contract.get("trade_id_scope") if isinstance(contract, Mapping) else None
    return declared_domain == stored_domain and declared_scope == stored_scope


def _terminal_exposure_source_matches(
    *,
    observation: OrderExposureObservationProof,
    claim: DispatchClaimBinding,
    command: RiskOrderCommand,
    order_event: RiskOrderJournalEvent,
    fill_event: RiskOrderJournalEvent,
    reference: Mapping[str, Any],
    reference_id: str,
    reference_sha256: str,
    fence: RiskOrderWriterFence,
    reconciliation_evidence_sha256: str,
) -> bool:
    order = order_event.payload
    fills = fill_event.payload
    try:
        source_facts = order["metadata_facts"]
        metadata = source_facts["instrument_metadata"]
        contract = source_facts["provider_contract"]
        facts = _fill_facts_from_event(fills)
        position_effect = str(command.canonical_payload.get("position_effect", "OPEN"))
        expected_reduce_only = position_effect == "CLOSE"
        accepted_order_request = command.order_request
        quote_currency, fx_rate = _verified_provider_fx_fact(
            source_facts, str(order.get("instrument"))
        )
        source_values = order["source_values"]
        source_price = Decimal(
            str(
                next(
                    source_values[name]
                    for name in ("price", "limit_price", "order_price", "Price")
                    if name in source_values
                )
            )
        )
        expected_observation = order.get("provider_observation_sha256")
        expected_fill_history = fills.get("provider_observation_sha256")
        requested = Decimal(str(order["quantity"]))
        filled = Decimal(str(fills["filled_quantity"]))
    except (KeyError, TypeError, ValueError, InvalidOperation, RiskOrderJournalError):
        return False
    quote_currency = contract.get("quote_currency_by_instrument", {}).get(order.get("instrument"))
    valuation_unit = metadata.get("valuation_unit")
    return all(
        (
            claim.scope == fence.scope == command.scope == observation.scope,
            claim.intent_id == command.risk_intent_id == observation.intent_id,
            claim.permit_id == command.permit_id == observation.permit_id,
            claim.intent_hash == observation.intent_hash,
            claim.claim_digest == observation.dispatch_claim_digest,
            order_event.writer_owner_id == fence.owner_id,
            order_event.writer_fencing_token == fence.fencing_token,
            order_event.writer_fence_sha256 == fence.fence_sha256,
            fill_event.writer_owner_id == fence.owner_id,
            fill_event.writer_fencing_token == fence.fencing_token,
            fill_event.writer_fence_sha256 == fence.fence_sha256,
            order.get("claim_digest") == claim.claim_digest,
            fills.get("claim_digest") == claim.claim_digest,
            order.get("risk_intent_id") == claim.intent_id,
            fills.get("risk_intent_id") == claim.intent_id,
            order.get("provider_contract_sha256") == source_facts.get("provider_contract_sha256"),
            _trade_identity_declaration_matches(observation, contract),
            reference.get("claim") == _claim_payload(claim),
            reference.get("claim_digest") == claim.claim_digest,
            position_effect in {"OPEN", "CLOSE"},
            order.get("position_effect", position_effect) == position_effect,
            fills.get("position_effect", position_effect) == position_effect,
            command.canonical_payload.get("reduce_only", expected_reduce_only)
            is expected_reduce_only,
            accepted_order_request.get("reduce_only") is expected_reduce_only,
            reference.get("reservation_id") == reference_id,
            reference.get("provider_order_id") == order.get("provider_order_id"),
            reference.get("accepted_request_sha256") == command.order_request_sha256,
            reference.get("reconciliation_evidence_sha256") == reconciliation_evidence_sha256,
            observation.provider_order_id == order.get("provider_order_id"),
            observation.accepted_request_sha256 == command.order_request_sha256,
            observation.exposure_reservation_id == reference_id,
            observation.exposure_reservation_sha256 == reference_sha256,
            observation.reconciliation_evidence_sha256 == reconciliation_evidence_sha256
            if hasattr(observation, "reconciliation_evidence_sha256")
            else True,
            observation.order_revision == order.get("order_revision"),
            observation.journal_revision == fill_event.revision,
            observation.journal_record_sha256 == fill_event.record_sha256,
            observation.state.value == order.get("exposure_state"),
            (
                position_effect != "CLOSE"
                or (
                    observation.state is OrderExposureState.FILLED
                    and filled == requested
                    and observation.leaves_quantity == 0
                )
            ),
            observation.requested_quantity == requested,
            observation.cumulative_filled_quantity == filled,
            observation.fill_trade_count == fills.get("trade_count"),
            observation.fills == facts,
            observation.observation_sha256 == expected_observation,
            observation.fill_history_sha256 == expected_fill_history,
            observation.source_alias_map_sha256 == order.get("source_alias_map_sha256"),
            observation.instrument_id == order.get("instrument"),
            observation.instrument_version == metadata.get("metadata_version"),
            observation.instrument_multiplier == Decimal(str(metadata.get("contract_multiplier"))),
            observation.instrument_metadata_sha256 == metadata.get("metadata_sha256"),
            observation.instrument_metadata_observed_at_ns == metadata.get("as_of_ns"),
            observation.instrument_metadata_valid_until_ns == metadata.get("expires_at_ns"),
            observation.quote_currency == quote_currency,
            observation.valuation_unit == valuation_unit,
            observation.notional_unit == valuation_unit,
            observation.order_side == str(order.get("side")).upper(),
            observation.position_effect == position_effect,
            observation.complete_order_snapshot is True,
            observation.complete_fill_history is True,
            observation.writer_owner_id == fence.owner_id,
            observation.writer_fencing_token == fence.fencing_token,
            observation.writer_fence_sha256 == fence.fence_sha256,
            _observation_fx_matches(observation, fx_rate),
            observation.leaves_valuation_price
            == (source_price if observation.leaves_quantity > 0 else None),
            observation.filled_gross_notional
            == sum(
                (fact.quantity * fact.price for fact in facts),
                Decimal(0),
            )
            * Decimal(str(metadata.get("contract_multiplier")))
            * (Decimal(1) if fx_rate is None else fx_rate.rate),
            observation.leaves_gross_notional
            == observation.leaves_quantity
            * source_price
            * Decimal(str(metadata.get("contract_multiplier")))
            * (Decimal(1) if fx_rate is None else fx_rate.rate),
            observation.valuation_facts_sha256
            == _valuation_facts_sha256(
                metadata=metadata,
                quote_currency=quote_currency,
                valuation_unit=valuation_unit,
                fill_facts=facts,
                leaves_valuation_price=source_price,
                fx_rate=fx_rate,
            ),
        )
    )


def _order_observation_source_matches(
    *,
    proof: OrderExposureObservationProof,
    command: RiskOrderCommand,
    claim: DispatchClaimBinding,
    tracked_order: DispatchTrackedOrderProof,
    query_event: RiskOrderJournalEvent,
    order_event: RiskOrderJournalEvent,
    fill_event: RiskOrderJournalEvent,
    fence: RiskOrderWriterFence,
) -> bool:
    payload = query_event.payload
    parts = _observation_subparts(payload, combined_query=True)
    if parts is None:
        return False
    order_part, fill_part = parts
    try:
        metadata_facts = payload["metadata_facts"]
        metadata = metadata_facts["instrument_metadata"]
        contract = metadata_facts["provider_contract"]
        quote_currency, fx_rate = _verified_provider_fx_fact(
            metadata_facts, str(payload.get("instrument"))
        )
        source_order_revision = order_part["normalization_provenance"]["source_values"][
            contract["order_revision_field"]
        ]
        source_values = order_part["normalization_provenance"]["source_values"]
        source_price_value = next(
            source_values[name]
            for name in ("price", "limit_price", "order_price", "Price")
            if name in source_values
        )
        source_price = Decimal(str(source_price_value))
        facts = _fill_facts_from_event(payload, combined_query=True)
    except (KeyError, TypeError, ValueError, InvalidOperation, RiskOrderJournalError):
        return False
    return all(
        (
            query_event.event_type == "PROVIDER_QUERY",
            query_event.scope == fence.scope == proof.scope,
            query_event.principal_ref == command.principal_ref,
            query_event.intent_id == command.intent_id,
            query_event.writer_owner_id == fence.owner_id,
            query_event.writer_fencing_token == fence.fencing_token,
            query_event.writer_fence_sha256 == fence.fence_sha256,
            _is_v2_order_event(payload, combined_query=True),
            _is_v2_fill_event(payload, combined_query=True),
            payload.get("public_state") == "UNKNOWN",
            payload.get("dispatch_attempt_count") == 1,
            payload.get("risk_intent_id") == claim.intent_id,
            payload.get("dispatch_claim_digest") == claim.claim_digest,
            payload.get("provider_order_id") == tracked_order.provider_order_id,
            payload.get("client_order_id") == command.client_order_id,
            payload.get("account_id") == command.provider_account_id,
            payload.get("quantity") == command.order_request.get("quantity"),
            proof.provider_order_id == tracked_order.provider_order_id,
            proof.accepted_request_sha256 == command.order_request_sha256,
            proof.dispatch_claim_digest == claim.claim_digest,
            proof.dispatch_proof_sha256 == tracked_order.fingerprint,
            proof.order_revision == source_order_revision,
            proof.state.value == payload.get("exposure_state"),
            proof.requested_quantity == Decimal(str(payload.get("quantity"))),
            proof.cumulative_filled_quantity == Decimal(str(payload.get("filled_quantity"))),
            proof.leaves_valuation_price
            == (source_price if proof.leaves_quantity > 0 else None),
            proof.fills == facts,
            proof.fill_trade_count == payload.get("trade_count"),
            proof.fill_watermark_revision == payload.get("fill_watermark_revision"),
            proof.observation_sha256 == payload.get("provider_observation_sha256"),
            proof.fill_history_sha256 == payload.get("provider_observation_sha256"),
            proof.source_alias_map_sha256 == payload.get("source_alias_map_sha256"),
            proof.instrument_id == payload.get("instrument"),
            proof.instrument_version == metadata.get("metadata_version"),
            proof.instrument_multiplier == Decimal(str(metadata.get("contract_multiplier"))),
            proof.instrument_metadata_sha256 == metadata.get("metadata_sha256"),
            proof.instrument_metadata_observed_at_ns == metadata.get("as_of_ns"),
            proof.instrument_metadata_valid_until_ns == metadata.get("expires_at_ns"),
            proof.quote_currency == contract.get("quote_currency_by_instrument", {}).get(payload.get("instrument")),
            proof.valuation_unit == metadata.get("valuation_unit"),
            proof.notional_unit == metadata.get("valuation_unit"),
            proof.position_effect == "OPEN",
            proof.complete_order_snapshot is True,
            proof.complete_fill_history is True,
            proof.writer_owner_id == fence.owner_id,
            proof.writer_fencing_token == fence.fencing_token,
            proof.writer_fence_sha256 == fence.fence_sha256,
            order_event.writer_fence_sha256 == tracked_order.writer_fence_sha256,
            fill_event.writer_fence_sha256 == tracked_order.writer_fence_sha256,
            metadata_facts.get("provider_contract_sha256") == contract.get("fingerprint"),
            _trade_identity_declaration_matches(proof, contract),
            proof.quote_currency == quote_currency,
            _observation_fx_matches(proof, fx_rate),
            proof.filled_gross_notional
            == sum((fact.quantity * fact.price for fact in facts), Decimal(0))
            * proof.instrument_multiplier
            * (Decimal(1) if fx_rate is None else fx_rate.rate),
            proof.leaves_gross_notional
            == proof.leaves_quantity
            * source_price
            * proof.instrument_multiplier
            * (Decimal(1) if fx_rate is None else fx_rate.rate),
            proof.valuation_facts_sha256
            == _valuation_facts_sha256(
                metadata=metadata,
                quote_currency=quote_currency,
                valuation_unit=str(metadata.get("valuation_unit")),
                fill_facts=facts,
                leaves_valuation_price=source_price,
                fx_rate=fx_rate,
            ),
        )
    )


def _verified_provider_fx_fact(
    metadata_facts: Mapping[str, Any], instrument: str
) -> tuple[str, InstrumentRiskFxRate | None]:
    """Validate the persisted provider/metadata binding for a cross-currency order."""

    expected_keys = {
        "provider_contract_sha256",
        "provider_contract",
        "instrument_metadata",
    }
    contract = metadata_facts.get("provider_contract")
    metadata = metadata_facts.get("instrument_metadata")
    if (
        type(metadata_facts) is not dict
        or type(contract) is not dict
        or type(metadata) is not dict
        or type(metadata_facts.get("provider_contract_sha256")) is not str
        or contract.get("fingerprint") != metadata_facts.get("provider_contract_sha256")
        or type(contract.get("quote_currency_by_instrument")) is not dict
    ):
        raise RiskOrderJournalError("PROVIDER_FX_SOURCE_INVALID")
    quote = contract["quote_currency_by_instrument"].get(instrument)
    valuation = metadata.get("valuation_unit")
    metadata_quote = metadata.get("quote_currency") or valuation
    if (
        type(quote) is not str
        or type(valuation) is not str
        or metadata_quote != quote
    ):
        raise RiskOrderJournalError("PROVIDER_FX_SOURCE_INVALID")
    if quote == valuation:
        if set(metadata_facts) != expected_keys or metadata.get("fx_source_ref") is not None:
            raise RiskOrderJournalError("PROVIDER_FX_SOURCE_INVALID")
        return quote, None
    fx_keys = {"instrument_fx_rate", "instrument_fx_rate_sha256"}
    if set(metadata_facts) != expected_keys | fx_keys:
        raise RiskOrderJournalError("PROVIDER_FX_SOURCE_INVALID")
    raw = metadata_facts.get("instrument_fx_rate")
    if (
        type(raw) is not dict
        or set(raw)
        != {
            "fx_pair",
            "instrument",
            "observed_at_ns",
            "quote_currency",
            "rate",
            "schema",
            "source_record_sha256",
            "source_ref",
            "source_revision",
            "valid_until_ns",
            "valuation_unit",
        }
        or type(raw.get("rate")) is not str
        or type(raw.get("observed_at_ns")) is not int
        or type(raw.get("valid_until_ns")) is not int
        or type(raw.get("source_revision")) is not str
        or raw.get("instrument") != instrument
        or raw.get("quote_currency") != quote
        or raw.get("valuation_unit") != valuation
        or raw.get("fx_pair") != quote + "/" + valuation
        or raw.get("source_ref") != metadata.get("fx_source_ref")
        or type(metadata_facts.get("instrument_fx_rate_sha256")) is not str
    ):
        raise RiskOrderJournalError("PROVIDER_FX_SOURCE_INVALID")
    try:
        fx_rate = InstrumentRiskFxRate(
            instrument=raw["instrument"],
            quote_currency=raw["quote_currency"],
            valuation_unit=raw["valuation_unit"],
            rate=Decimal(raw["rate"]),
            observed_at_ns=raw["observed_at_ns"],
            valid_until_ns=raw["valid_until_ns"],
            source_ref=raw["source_ref"],
            source_revision=raw["source_revision"],
            source_record_sha256=raw["source_record_sha256"],
        )
    except (KeyError, TypeError, ValueError, InvalidOperation):
        raise RiskOrderJournalError("PROVIDER_FX_SOURCE_INVALID") from None
    if (
        raw != fx_rate.to_payload()
        or metadata_facts.get("instrument_fx_rate_sha256") != fx_rate.digest
    ):
        raise RiskOrderJournalError("PROVIDER_FX_SOURCE_INVALID")
    return quote, fx_rate


def _observation_fx_matches(
    observation: OrderExposureObservationProof,
    fx_rate: InstrumentRiskFxRate | None,
) -> bool:
    from bt_api_risk.order_valuation import observation_fx_matches

    return observation_fx_matches(observation, fx_rate)


def _valuation_facts_sha256(
    *,
    metadata: Mapping[str, Any],
    quote_currency: str,
    valuation_unit: str,
    fill_facts: tuple[OrderFillFact, ...],
    leaves_valuation_price: Decimal,
    fx_rate: InstrumentRiskFxRate | None,
) -> str:
    from bt_api_risk.order_valuation import valuation_facts_sha256

    return valuation_facts_sha256(
        metadata=metadata, quote_currency=quote_currency, valuation_unit=valuation_unit,
        fill_facts=fill_facts, leaves_valuation_price=leaves_valuation_price, fx_rate=fx_rate,
        decimal_text=_decimal_text, canonical_json=canonical_json, sha256_text=sha256_text,
    )


def _fence_digest(scope: AccountScope, owner_id: str, fencing_token: int) -> str:
    return sha256_text(
        canonical_json(
            {
                "account_scope_key": scope.key,
                "fencing_token": fencing_token,
                "owner_id": owner_id,
                "schema": "bt-api-risk-order-writer-fence-v1",
            }
        )
    )


def _bounded_observation(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "account_revision",
        "acknowledgement",
        "collection_provenance",
        "provider_contract_sha256",
        "operation",
        "normalizer_schema",
        "normalization_provenance",
        "source_fields",
        "source_values",
        "envelope_fields",
        "envelope_values",
        "source_sha256",
        "response_fields",
        "response",
        "record",
        "records",
        "record_count",
        "order_observation_sha256",
        "fill_observation_sha256",
        "complete",
        "schema",
        "schema_version",
        "source_alignment_valid",
        "source_row_count",
        "watermark",
        "provider_order_id",
        "client_order_id",
        "query_client_order_id",
        "account_id",
        "instrument",
        "side",
        "status",
        "quantity",
        "filled_quantity",
        "trade_count",
        "provider_observation_sha256",
        "position_effect",
        "position_side",
        "position_bucket",
        "reduce_only",
        "public_state",
        "reason_code",
        "order_revision",
        "exposure_state",
        "fill_row_provenance",
        "fill_watermark_revision",
        "metadata_facts",
        "source_alias_map_sha256",
        "dispatch_claim_digest",
        "claim_digest",
        "risk_intent_id",
        "exposure_proof_sha256",
        "exposure_reference_id",
        "exposure_reference_sha256",
    }
    if not isinstance(value, Mapping) or set(value) - allowed:
        raise RiskOrderJournalError("OBSERVATION_FIELDS_INVALID")
    projected = dict(value)
    if len(canonical_json(projected).encode("utf-8")) > 256 * 1024:
        raise RiskOrderJournalError("OBSERVATION_TOO_LARGE")
    return projected


__all__ = [
    "DispatchProofRecoverySource",
    "RiskOrderCommand",
    "RiskOrderJournal",
    "RiskOrderJournalError",
    "RiskOrderJournalEvent",
    "RiskOrderWriterFence",
    "canonical_json",
    "sha256_text",
]
