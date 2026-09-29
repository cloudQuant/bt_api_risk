"""Fake-only tests for cancellation-action dispatch latch resolution."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from decimal import Decimal
from hashlib import sha256
from threading import Lock

import pytest

from bt_api_risk import (
    AccountScope,
    CancelDispatchResolutionProof,
    CancelDispatchSource,
    CancelDispatchTerminalState,
    CancelTargetPostcondition,
    DispatchEvidenceClass,
    DispatchTerminalProof,
    DispatchTerminalState,
    DurableRiskGate,
    IntentAction,
    PermitInvalidError,
    RiskIntent,
    RiskPolicy,
    VerifiedCancelDispatchResolution,
)


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


class FakeCancelJournalAuthority:
    """Test-only immutable journal and writer-fence model."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._accepted: dict[str, CancelDispatchResolutionProof] = {}
        self.guard_calls = 0

    def register(self, proof: CancelDispatchResolutionProof) -> None:
        self._accepted[proof.fingerprint] = proof

    @contextmanager
    def cancel_dispatch_resolution_guard(self, proof, *, claim):
        with self._lock:
            self.guard_calls += 1
            valid = (
                type(proof) is CancelDispatchResolutionProof
                and self._accepted.get(proof.fingerprint) == proof
                and proof.scope == claim.scope
                and proof.permit_id == claim.permit_id
                and proof.intent_id == claim.intent_id
                and proof.intent_hash == claim.intent_hash
                and proof.cause_id == claim.cause_id
                and proof.claim_digest == claim.claim_digest
            )
            if not valid:
                yield None
                return
            yield VerifiedCancelDispatchResolution(
                scope=claim.scope,
                permit_id=claim.permit_id,
                intent_id=claim.intent_id,
                intent_hash=claim.intent_hash,
                claim_digest=claim.claim_digest,
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
                writer_owner_id=proof.writer_owner_id,
                writer_fencing_token=proof.writer_fencing_token,
                writer_fence_sha256=proof.writer_fence_sha256,
            )


class BareBooleanCancelAuthority:
    @contextmanager
    def cancel_dispatch_resolution_guard(self, proof, *, claim):
        yield True


@pytest.fixture
def scope() -> AccountScope:
    return AccountScope(provider="fake", account_id="account-1", environment="sandbox")


@pytest.fixture
def policy() -> RiskPolicy:
    return RiskPolicy(
        policy_id="cancel-proof-policy",
        max_increase_notional=Decimal("100"),
        max_increase_count=3,
    )


def _claimed_cancel(
    tmp_path, scope, policy, *, authority=None, name="cancel", track_open_order=False
):
    gate = DurableRiskGate(tmp_path / f"{name}.db", policy, execution_journal_authority=authority)
    execution_scope_key = "simnow:account-1:strategy-a:day-1"
    cancel_id = name + "-id"
    cancel_fingerprint = _digest("cancel-intent:" + name)
    intent = RiskIntent(
        intent_id=f"cancel-admission:{execution_scope_key}:{cancel_id}",
        scope=scope,
        action=IntentAction.CANCEL,
        notional=Decimal("0"),
        payload_fingerprint=cancel_fingerprint,
    )
    permit = gate.reserve(intent)
    if track_open_order:
        gate.reserve(
            RiskIntent(
                intent_id="submit-intent-1",
                scope=scope,
                action=IntentAction.INCREASE,
                notional=Decimal("40"),
                payload_fingerprint="tracked-order-payload",
            )
        )
    gate.claim_for_dispatch(permit.permit_id, intent)
    binding = gate.dispatch_claim_binding(permit.permit_id)
    return gate, intent, permit, binding, execution_scope_key, cancel_id, cancel_fingerprint


def _cancel_proof(
    binding,
    *,
    execution_scope_key,
    cancel_id,
    cancel_fingerprint,
    terminal_state=CancelDispatchTerminalState.CANCELLED,
    **changes,
):
    cancelled = terminal_state is CancelDispatchTerminalState.CANCELLED
    values = {
        "scope": binding.scope,
        "permit_id": binding.permit_id,
        "intent_id": binding.intent_id,
        "intent_hash": binding.intent_hash,
        "cause_id": binding.cause_id,
        "claim_digest": binding.claim_digest,
        "evidence_class": DispatchEvidenceClass.SIMULATION_JOURNAL,
        "dispatch_attempt_count": 1,
        "cancel_intent_fingerprint": cancel_fingerprint,
        "execution_scope_key": execution_scope_key,
        "cancel_id": cancel_id,
        "target_intent_id": "submit-intent-1",
        "provider_order_id": "fake-order-9",
        "terminal_state": terminal_state,
        "cancel_event_id": "cancel-event-1",
        "cancel_event_sequence": 4,
        "cancel_event_sha256": _digest("cancel-event"),
        "cancel_source": CancelDispatchSource.PROVIDER,
        "source_evidence_sha256": _digest("source-evidence"),
        "target_postcondition": (
            CancelTargetPostcondition.TARGET_TERMINAL
            if cancelled
            else CancelTargetPostcondition.TARGET_REMAINS_OPEN
        ),
        "target_state": "CANCELLED" if cancelled else "PARTIALLY_FILLED",
        "target_filled_quantity": "2",
        "target_updated_at_ns": 1_700_000_000_000_000_000,
        "target_record_sha256": _digest("target-record"),
        "target_event_id": "target-event-1",
        "target_event_sequence": 7,
        "target_event_type": ("cancelled_by_cancel_intent" if cancelled else "order_observation"),
        "target_event_sha256": _digest("target-event"),
        "writer_owner_id": "writer-a",
        "writer_fencing_token": 12,
        "writer_fence_sha256": _digest("writer-fence"),
    }
    values.update(changes)
    return CancelDispatchResolutionProof(**values)


def _read_rows(database_path, table):
    statements = {
        "risk_dispatch_resolutions": "SELECT * FROM risk_dispatch_resolutions",
        "risk_cancel_dispatch_resolutions": "SELECT * FROM risk_cancel_dispatch_resolutions",
        "risk_reservations": "SELECT * FROM risk_reservations",
    }
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(statements[table]).fetchall()


def test_cancel_action_terminal_proof_settles_permit_and_clears_only_cancel_latch(
    tmp_path, scope, policy
):
    authority = FakeCancelJournalAuthority()
    gate, _intent, permit, binding, execution_scope_key, cancel_id, fingerprint = _claimed_cancel(
        tmp_path, scope, policy, authority=authority, track_open_order=True
    )
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]

    proof = _cancel_proof(
        binding,
        execution_scope_key=execution_scope_key,
        cancel_id=cancel_id,
        cancel_fingerprint=fingerprint,
    )
    authority.register(proof)
    gate.resolve_cancel_dispatch_freeze(proof)

    assert gate.active_freeze_reasons(scope) == []
    assert gate.snapshot(scope)["increase_count"] == 1
    assert gate.snapshot(scope)["increase_notional"] == Decimal("40")
    assert _read_rows(gate._database_path, "risk_dispatch_resolutions") == []
    row = _read_rows(gate._database_path, "risk_cancel_dispatch_resolutions")
    assert len(row) == 1
    reservations = _read_rows(gate._database_path, "risk_reservations")
    reservation = next(row for row in reservations if row["permit_id"] == permit.permit_id)
    assert reservation["status"] == DurableRiskGate._SETTLED
    assert reservation["action"] == IntentAction.CANCEL.value
    tracked_order = next(row for row in reservations if row["intent_id"] == "submit-intent-1")
    assert tracked_order["status"] == DurableRiskGate._ACTIVE
    assert tracked_order["notional"] == "40"

    # Exact replay is idempotent and the separate action proof stays immutable.
    gate.resolve_cancel_dispatch_freeze(proof)
    assert len(_read_rows(gate._database_path, "risk_cancel_dispatch_resolutions")) == 1
    assert authority.guard_calls == 1
    with sqlite3.connect(gate._database_path) as connection:
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute(
                "UPDATE risk_cancel_dispatch_resolutions SET terminal_state='REJECTED'"
            )
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("DELETE FROM risk_cancel_dispatch_resolutions")


def test_rejected_cancel_action_resolution_preserves_open_target_fact(tmp_path, scope, policy):
    authority = FakeCancelJournalAuthority()
    gate, _intent, _permit, binding, execution_scope_key, cancel_id, fingerprint = _claimed_cancel(
        tmp_path, scope, policy, authority=authority, name="reject"
    )
    proof = _cancel_proof(
        binding,
        execution_scope_key=execution_scope_key,
        cancel_id=cancel_id,
        cancel_fingerprint=fingerprint,
        terminal_state=CancelDispatchTerminalState.REJECTED,
    )
    authority.register(proof)
    gate.resolve_cancel_dispatch_freeze(proof)

    row = _read_rows(gate._database_path, "risk_cancel_dispatch_resolutions")[0]
    assert row["terminal_state"] == "REJECTED"
    assert row["target_postcondition"] == "TARGET_REMAINS_OPEN"
    assert row["target_state"] == "PARTIALLY_FILLED"
    assert row["target_filled_quantity"] == "2"
    assert gate.active_freeze_reasons(scope) == []


def test_generic_order_no_fill_proof_cannot_clear_cancel_action_latch(tmp_path, scope, policy):
    gate, _intent, permit, binding, _scope_key, _cancel_id, _fingerprint = _claimed_cancel(
        tmp_path, scope, policy, name="old-proof"
    )
    gate.settle(permit.permit_id)
    old_order_proof = DispatchTerminalProof(
        scope=scope,
        permit_id=permit.permit_id,
        intent_id=binding.intent_id,
        intent_hash=binding.intent_hash,
        cause_id=binding.cause_id,
        claim_digest=binding.claim_digest,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        terminal_state=DispatchTerminalState.CANCELED_NO_FILL,
        dispatch_attempt_count=1,
        journal_revision=1,
        journal_record_sha256=_digest("wrong-order-proof"),
        reconciliation_evidence_sha256=_digest("wrong-order-reconciliation"),
        writer_fence_sha256=_digest("wrong-order-fence"),
    )

    with pytest.raises(PermitInvalidError, match="cancellation-action evidence"):
        gate.resolve_dispatch_freeze(old_order_proof)
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]
    assert _read_rows(gate._database_path, "risk_dispatch_resolutions") == []
    assert _read_rows(gate._database_path, "risk_cancel_dispatch_resolutions") == []


@pytest.mark.parametrize(
    "change",
    [
        {"cancel_event_id": "other-event"},
        {"cancel_event_sequence": 5},
        {"cancel_event_sha256": _digest("other-cancel-event")},
        {"source_evidence_sha256": _digest("other-source")},
        {"target_record_sha256": _digest("other-record")},
        {"target_event_sha256": _digest("other-target-event")},
        {"writer_owner_id": "writer-b"},
        {"writer_fencing_token": 13},
        {"writer_fence_sha256": _digest("other-fence")},
    ],
)
def test_unattested_cancel_proof_mismatch_keeps_latch(tmp_path, scope, policy, change):
    authority = FakeCancelJournalAuthority()
    gate, _intent, _permit, binding, execution_scope_key, cancel_id, fingerprint = _claimed_cancel(
        tmp_path, scope, policy, authority=authority, name="mismatch"
    )
    accepted = _cancel_proof(
        binding,
        execution_scope_key=execution_scope_key,
        cancel_id=cancel_id,
        cancel_fingerprint=fingerprint,
    )
    changed = _cancel_proof(
        binding,
        execution_scope_key=execution_scope_key,
        cancel_id=cancel_id,
        cancel_fingerprint=fingerprint,
        **change,
    )
    authority.register(accepted)

    with pytest.raises(PermitInvalidError, match="did not attest"):
        gate.resolve_cancel_dispatch_freeze(changed)
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]
    assert _read_rows(gate._database_path, "risk_cancel_dispatch_resolutions") == []


def test_cancel_resolution_requires_exact_typed_journal_attestation(tmp_path, scope, policy):
    gate, _intent, _permit, binding, execution_scope_key, cancel_id, fingerprint = _claimed_cancel(
        tmp_path, scope, policy, authority=BareBooleanCancelAuthority(), name="bool"
    )
    proof = _cancel_proof(
        binding,
        execution_scope_key=execution_scope_key,
        cancel_id=cancel_id,
        cancel_fingerprint=fingerprint,
    )

    with pytest.raises(PermitInvalidError, match="did not attest"):
        gate.resolve_cancel_dispatch_freeze(proof)
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]


@pytest.mark.parametrize(
    "proof_changes",
    [
        {"terminal_state": "CANCELLED"},
        {"target_state": "PARTIALLY_FILLED"},
        {"target_postcondition": CancelTargetPostcondition.TARGET_REMAINS_OPEN},
    ],
)
def test_cancel_proof_constructor_rejects_nonterminal_or_contradictory_facts(
    tmp_path, scope, policy, proof_changes
):
    gate, _intent, _permit, binding, execution_scope_key, cancel_id, fingerprint = _claimed_cancel(
        tmp_path, scope, policy, name="invalid-shape"
    )
    with pytest.raises((TypeError, ValueError)):
        _cancel_proof(
            binding,
            execution_scope_key=execution_scope_key,
            cancel_id=cancel_id,
            cancel_fingerprint=fingerprint,
            **proof_changes,
        )
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]
