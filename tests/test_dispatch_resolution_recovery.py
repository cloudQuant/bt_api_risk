"""Focused tests for read-only dispatch receipts and new-fence recovery."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from threading import Lock

import pytest

from bt_api_risk import (
    AccountScope,
    DispatchEvidenceClass,
    DispatchRecoveryAttestation,
    DispatchResolutionReceiptStatus,
    DispatchTrackedOrderProof,
    DurableRiskGate,
    IntentAction,
    PermitInvalidError,
    RiskIntent,
    RiskPolicy,
    VerifiedDispatchRecoveryResolution,
    VerifiedDispatchResolution,
)


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _scope(account_id="account-recovery") -> AccountScope:
    return AccountScope(provider="fake", account_id=account_id, environment="sandbox")


def _policy() -> RiskPolicy:
    return RiskPolicy(
        policy_id="dispatch-recovery-test",
        max_increase_notional=Decimal("100"),
        max_increase_count=5,
    )


def _make_gate(tmp_path: Path, authority=None, name="recovery") -> DurableRiskGate:
    return DurableRiskGate(
        tmp_path / (name + ".sqlite"),
        _policy(),
        execution_journal_authority=authority,
    )


def _claim_and_settle(gate: DurableRiskGate, scope: AccountScope, intent_id="intent-1"):
    intent = RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal("40"),
        payload_fingerprint="accepted-test-intent",
    )
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)
    claim = gate.dispatch_claim_binding(permit.permit_id)
    gate.settle(permit.permit_id)
    return intent, permit, claim


def _proof(claim, *, journal_revision=10) -> DispatchTrackedOrderProof:
    return DispatchTrackedOrderProof(
        scope=claim.scope,
        permit_id=claim.permit_id,
        intent_id=claim.intent_id,
        intent_hash=claim.intent_hash,
        cause_id=claim.cause_id,
        claim_digest=claim.claim_digest,
        evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        dispatch_attempt_count=1,
        journal_revision=journal_revision,
        journal_record_sha256=_digest("proof-ready-row:" + claim.intent_id),
        reconciliation_evidence_sha256=_digest("reconciliation-row:" + claim.intent_id),
        writer_fence_sha256=_digest("old-writer-fence"),
        provider_order_id="synthetic-provider-order",
        accepted_request_sha256=_digest("accepted-order-request"),
        exposure_reservation_id="exposure-ref-1",
        exposure_reservation_sha256=_digest("exposure-ref-row"),
    )


def _attestation(proof) -> DispatchRecoveryAttestation:
    return DispatchRecoveryAttestation(
        scope=proof.scope,
        permit_id=proof.permit_id,
        intent_id=proof.intent_id,
        intent_hash=proof.intent_hash,
        cause_id=proof.cause_id,
        claim_digest=proof.claim_digest,
        proof_sha256=proof.fingerprint,
        proof_ready_revision=proof.journal_revision,
        proof_ready_record_sha256=proof.journal_record_sha256,
        original_writer_owner_id="original-owner",
        original_writer_fencing_token=3,
        original_writer_fence_sha256=proof.writer_fence_sha256,
        order_observation_revision=proof.journal_revision - 3,
        order_observation_record_sha256=_digest("order-observation-row"),
        fill_observation_revision=proof.journal_revision - 2,
        fill_observation_record_sha256=_digest("fill-observation-row"),
        reconciliation_evidence_sha256=proof.reconciliation_evidence_sha256,
        accepted_request_sha256=proof.accepted_request_sha256,
        provider_order_id=proof.provider_order_id,
        exposure_reservation_id=proof.exposure_reservation_id,
        exposure_reservation_sha256=proof.exposure_reservation_sha256,
        recovery_event_id=_digest("scope/principal/intent/recovery-revision"),
        recovery_event_revision=proof.journal_revision + 1,
        recovery_event_sha256=_digest("recovery-event-row"),
        current_writer_owner_id="recovery-owner",
        current_writer_fencing_token=4,
        current_writer_fence_sha256=_digest("current-writer-fence"),
    )


def _verified(proof, attestation, claim):
    return VerifiedDispatchRecoveryResolution(
        scope=claim.scope,
        permit_id=claim.permit_id,
        intent_id=claim.intent_id,
        intent_hash=claim.intent_hash,
        cause_id=claim.cause_id,
        claim_digest=claim.claim_digest,
        proof_sha256=proof.fingerprint,
        attestation_sha256=attestation.fingerprint,
        recovery_event_id=attestation.recovery_event_id,
        recovery_event_revision=attestation.recovery_event_revision,
        recovery_event_sha256=attestation.recovery_event_sha256,
        original_writer_owner_id=attestation.original_writer_owner_id,
        original_writer_fencing_token=attestation.original_writer_fencing_token,
        original_writer_fence_sha256=attestation.original_writer_fence_sha256,
        current_writer_owner_id=attestation.current_writer_owner_id,
        current_writer_fencing_token=attestation.current_writer_fencing_token,
        current_writer_fence_sha256=attestation.current_writer_fence_sha256,
    )


class FakeRecoveryJournalAuthority:
    """Synthetic historical-journal verifier and account-fence holder."""

    def __init__(self, *, accepted=True, tamper=None):
        self._lock = Lock()
        self.accepted = accepted
        self.tamper = tamper
        self.guard_calls = 0

    @contextmanager
    def dispatch_resolution_guard(self, proof, *, claim):
        yield VerifiedDispatchResolution(
            scope=claim.scope,
            permit_id=claim.permit_id,
            intent_id=claim.intent_id,
            intent_hash=claim.intent_hash,
            claim_digest=claim.claim_digest,
            proof_sha256=proof.fingerprint,
            journal_revision=proof.journal_revision,
            journal_record_sha256=proof.journal_record_sha256,
            writer_fence_sha256=proof.writer_fence_sha256,
        )

    @contextmanager
    def recovered_dispatch_resolution_guard(self, proof, attestation, *, claim):
        with self._lock:
            self.guard_calls += 1
            if not self.accepted:
                yield None
                return
            verified = _verified(proof, attestation, claim)
            if self.tamper == "fence":
                verified = replace(
                    verified,
                    current_writer_fencing_token=verified.current_writer_fencing_token + 1,
                )
            yield verified


class FakeOriginalJournalAuthority:
    @contextmanager
    def dispatch_resolution_guard(self, proof, *, claim):
        yield VerifiedDispatchResolution(
            scope=claim.scope,
            permit_id=claim.permit_id,
            intent_id=claim.intent_id,
            intent_hash=claim.intent_hash,
            claim_digest=claim.claim_digest,
            proof_sha256=proof.fingerprint,
            journal_revision=proof.journal_revision,
            journal_record_sha256=proof.journal_record_sha256,
            writer_fence_sha256=proof.writer_fence_sha256,
        )


def _durable_state(gate: DurableRiskGate, permit_id: str):
    with gate._connection() as connection:
        reservation = dict(
            connection.execute(
                "SELECT status, action FROM risk_reservations WHERE permit_id = ?",
                (permit_id,),
            ).fetchone()
        )
        claim = dict(
            connection.execute(
                "SELECT * FROM risk_dispatch_claims WHERE permit_id = ?", (permit_id,)
            ).fetchone()
        )
        freezes = [
            tuple(row)
            for row in connection.execute(
                "SELECT cause_id, active FROM risk_freezes ORDER BY cause_id"
            ).fetchall()
        ]
        resolutions = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM risk_dispatch_resolutions ORDER BY permit_id"
            ).fetchall()
        ]
        audits = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM risk_dispatch_recovery_audits ORDER BY permit_id"
            ).fetchall()
        ]
    return reservation, claim, freezes, resolutions, audits


def test_unresolved_receipt_binds_exact_claim_and_reports_other_freeze(tmp_path):
    scope = _scope()
    gate = _make_gate(tmp_path)
    _, permit, claim = _claim_and_settle(gate, scope)
    gate.freeze(scope, "operator-hold", "operator hold")

    receipt = gate.dispatch_resolution_receipt(permit.permit_id)

    assert receipt.status is DispatchResolutionReceiptStatus.UNRESOLVED_ACTIVE
    assert receipt.claim == claim
    assert (receipt.scope, receipt.permit_id, receipt.intent_id) == (
        scope,
        permit.permit_id,
        claim.intent_id,
    )
    assert receipt.dispatch_latch_active is True
    assert receipt.has_other_active_freezes is True
    assert receipt.proof is None
    assert receipt.recovery_attestation is None


def test_receipt_rejects_absent_unsettled_wrong_cause_and_inactive_without_resolution(
    tmp_path,
):
    scope = _scope()
    gate = _make_gate(tmp_path)
    with pytest.raises(PermitInvalidError) as absent:
        gate.dispatch_resolution_receipt("missing-permit")
    assert absent.value.code == "PERMIT_UNKNOWN"

    intent = RiskIntent(
        intent_id="unsettled-intent",
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal("40"),
        payload_fingerprint="unsettled",
    )
    unsettled = gate.reserve(intent)
    gate.claim_for_dispatch(unsettled.permit_id, intent)
    with pytest.raises(PermitInvalidError) as not_settled:
        gate.dispatch_resolution_receipt(unsettled.permit_id)
    assert not_settled.value.code == "PERMIT_NOT_SETTLED"

    other_scope = _scope("account-recovery-other")
    _, permit, claim = _claim_and_settle(gate, other_scope, "bad-cause")
    with gate._transaction() as connection:
        connection.execute(
            "UPDATE risk_dispatch_claims SET cause_id = ? WHERE permit_id = ?",
            ("dispatch-inflight:other-intent", permit.permit_id),
        )
    with pytest.raises(PermitInvalidError) as wrong_cause:
        gate.dispatch_resolution_receipt(permit.permit_id)
    assert wrong_cause.value.code == "DISPATCH_CLAIM_CONFLICT"

    gate2 = _make_gate(tmp_path, name="inactive-without-resolution")
    _, permit2, claim2 = _claim_and_settle(
        gate2, _scope("account-recovery-inactive"), "inactive-latch"
    )
    with gate2._transaction() as connection:
        connection.execute(
            "UPDATE risk_freezes SET active = 0 WHERE scope_key = ? AND cause_id = ?",
            (claim2.scope.key, claim2.cause_id),
        )
    with pytest.raises(PermitInvalidError) as inactive:
        gate2.dispatch_resolution_receipt(permit2.permit_id)
    assert inactive.value.code == "DISPATCH_RESOLUTION_STATE_CONFLICT"


def test_receipt_rejects_unknown_resolution_kind_instead_of_acknowledging(tmp_path):
    scope = _scope()
    gate = _make_gate(tmp_path, FakeOriginalJournalAuthority())
    _, permit, claim = _claim_and_settle(gate, scope, "unknown-resolution")
    proof = _proof(claim)
    gate.resolve_dispatch_freeze(proof)
    with gate._transaction() as connection:
        connection.execute(
            "UPDATE risk_dispatch_resolutions SET proof_kind = 'UNKNOWN' WHERE permit_id = ?",
            (permit.permit_id,),
        )

    with pytest.raises(PermitInvalidError) as invalid:
        gate.dispatch_resolution_receipt(permit.permit_id)
    assert invalid.value.code == "DISPATCH_RESOLUTION_STATE_CONFLICT"


def test_resolved_receipt_recovers_exact_proof_without_mutation(tmp_path):
    scope = _scope()
    gate = _make_gate(tmp_path, FakeOriginalJournalAuthority(), "resolved-receipt")
    _, permit, claim = _claim_and_settle(gate, scope)
    gate.freeze(scope, "operator-hold", "operator hold")
    proof = _proof(claim)
    gate.resolve_dispatch_freeze(proof)
    before = _durable_state(gate, permit.permit_id)

    restarted = _make_gate(tmp_path, name="resolved-receipt")
    receipt = restarted.dispatch_resolution_receipt(permit.permit_id)

    assert receipt.status is DispatchResolutionReceiptStatus.ACKED_TRACKED_RESOLVED
    assert receipt.proof == proof
    assert receipt.proof_sha256 == proof.fingerprint
    assert receipt.dispatch_latch_active is False
    assert receipt.has_other_active_freezes is True
    assert receipt.recovery_attestation is None
    assert _durable_state(restarted, permit.permit_id) == before


def test_recovered_resolution_is_atomic_audited_and_receiptable_after_restart(tmp_path):
    scope = _scope()
    authority = FakeRecoveryJournalAuthority()
    gate = _make_gate(tmp_path, authority, "recovered")
    _, permit, claim = _claim_and_settle(gate, scope)
    gate.freeze(scope, "operator-hold", "unrelated hold")
    proof = _proof(claim)
    attestation = _attestation(proof)

    gate.resolve_dispatch_freeze_recovered(proof, attestation)

    receipt = gate.dispatch_resolution_receipt(permit.permit_id)
    assert receipt.status is DispatchResolutionReceiptStatus.ACKED_TRACKED_RESOLVED
    assert receipt.proof == proof
    assert receipt.proof_sha256 == proof.fingerprint
    assert receipt.recovery_attestation == attestation
    assert receipt.has_other_active_freezes is True
    assert gate.active_freeze_reasons(scope) == ["unrelated hold"]
    assert gate.snapshot(scope)["increase_count"] == 1
    with gate._connection() as connection:
        reservation = connection.execute(
            "SELECT status FROM risk_reservations WHERE permit_id = ?", (permit.permit_id,)
        ).fetchone()
        assert reservation["status"] == "settled"
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM risk_dispatch_resolutions WHERE permit_id = ?",
                (permit.permit_id,),
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM risk_dispatch_recovery_audits WHERE permit_id = ?",
                (permit.permit_id,),
            ).fetchone()[0]
            == 1
        )
    committed = _durable_state(gate, permit.permit_id)

    restarted = _make_gate(tmp_path, name="recovered")
    replay_receipt = restarted.dispatch_resolution_receipt(permit.permit_id)
    assert replay_receipt == receipt
    assert _durable_state(restarted, permit.permit_id) == committed
    with (
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
        restarted._transaction() as connection,
    ):
        connection.execute(
            "UPDATE risk_dispatch_recovery_audits SET recorded_at = 0 WHERE permit_id = ?",
            (permit.permit_id,),
        )
    with (
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
        restarted._transaction() as connection,
    ):
        connection.execute(
            "DELETE FROM risk_dispatch_recovery_audits WHERE permit_id = ?",
            (permit.permit_id,),
        )


@pytest.mark.parametrize("failure", ["proof-mismatch", "authority-reject", "tampered-fence"])
def test_recovery_failures_leave_reservation_latch_and_audit_unchanged(tmp_path, failure):
    scope = _scope()
    authority = FakeRecoveryJournalAuthority(
        accepted=failure != "authority-reject",
        tamper="fence" if failure == "tampered-fence" else None,
    )
    gate = _make_gate(tmp_path, authority, failure)
    _, permit, claim = _claim_and_settle(gate, scope)
    proof = _proof(claim)
    attestation = _attestation(proof)
    if failure == "proof-mismatch":
        attestation = replace(attestation, provider_order_id="different-order")
    before = _durable_state(gate, permit.permit_id)

    with pytest.raises(PermitInvalidError) as rejected:
        gate.resolve_dispatch_freeze_recovered(proof, attestation)

    if failure == "proof-mismatch":
        assert rejected.value.code == "DISPATCH_RECOVERY_ATTESTATION_MISMATCH"
    else:
        assert rejected.value.code == "DISPATCH_RECOVERY_ATTESTATION_REJECTED"
    assert _durable_state(gate, permit.permit_id) == before
    assert gate.active_freeze_reasons(scope) == [claim.cause_id]


def test_recovery_replay_and_old_resolver_remain_rejected(tmp_path):
    scope = _scope()
    authority = FakeRecoveryJournalAuthority()
    gate = _make_gate(tmp_path, authority, "replay")
    _, permit, claim = _claim_and_settle(gate, scope)
    proof = _proof(claim)
    attestation = _attestation(proof)
    gate.resolve_dispatch_freeze_recovered(proof, attestation)
    committed = _durable_state(gate, permit.permit_id)

    with pytest.raises(PermitInvalidError) as recovery_replay:
        gate.resolve_dispatch_freeze_recovered(proof, attestation)
    assert recovery_replay.value.code == "DISPATCH_PROOF_REPLAYED"
    with pytest.raises(PermitInvalidError) as old_path_replay:
        gate.resolve_dispatch_freeze(proof)
    assert old_path_replay.value.code == "DISPATCH_PROOF_REPLAYED"
    assert _durable_state(gate, permit.permit_id) == committed


def test_recovery_commit_failure_rolls_back_resolution_and_audit(tmp_path):
    scope = _scope()
    authority = FakeRecoveryJournalAuthority()
    gate = _make_gate(tmp_path, authority, "recovery-commit-failure")
    _, permit, claim = _claim_and_settle(gate, scope, "commit-failure")
    proof = _proof(claim)
    attestation = _attestation(proof)
    with gate._connection() as connection:
        connection.execute(
            """
            CREATE TRIGGER fail_dispatch_latch_clear
            BEFORE UPDATE OF active ON risk_freezes
            WHEN OLD.scope_key = NEW.scope_key
                 AND OLD.cause_id = NEW.cause_id
                 AND OLD.cause_id = 'dispatch-inflight:commit-failure'
                 AND NEW.active = 0
            BEGIN
                SELECT RAISE(ABORT, 'forced recovery transaction failure');
            END
            """
        )
    before = _durable_state(gate, permit.permit_id)

    with pytest.raises(sqlite3.IntegrityError, match="forced recovery transaction failure"):
        gate.resolve_dispatch_freeze_recovered(proof, attestation)

    assert _durable_state(gate, permit.permit_id) == before
    assert gate.active_freeze_reasons(scope) == [claim.cause_id]
