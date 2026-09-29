"""Unit tests for the provider-independent durable risk admission boundary."""

from __future__ import annotations

import re
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from threading import Barrier, Lock
from typing import Optional

import pytest

from bt_api_risk import (
    AccountScope,
    DispatchEvidenceClass,
    DispatchTerminalProof,
    DispatchTerminalState,
    DispatchTrackedOrderProof,
    DurableRiskGate,
    IntentAction,
    PermitInvalidError,
    RiskDeniedError,
    RiskIntent,
    RiskPolicy,
    VerifiedDispatchResolution,
)


class MutableClock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


@pytest.fixture
def scope() -> AccountScope:
    return AccountScope(provider="fake", account_id="account-1", environment="sandbox")


@pytest.fixture
def policy() -> RiskPolicy:
    return RiskPolicy(
        policy_id="unit-policy",
        max_increase_notional=Decimal("100"),
        max_increase_count=3,
        permit_ttl_seconds=10.0,
    )


def make_intent(
    scope: AccountScope,
    intent_id: str,
    action: IntentAction = IntentAction.INCREASE,
    notional: str = "40",
) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=action,
        notional=Decimal(notional),
        payload_fingerprint="deterministic-test-payload",
    )


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


class FakeVerifiedExecutionJournalAuthority:
    """Test-only journal+fence model; never a provider or CTP authority."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._rows: dict[str, dict[str, object]] = {}
        self.guard_calls = 0

    def register(
        self, proof, *, current_revision=None, attempts=None, durable_exposure=True
    ) -> None:
        row: dict[str, object] = {
            "scope": proof.scope,
            "permit_id": proof.permit_id,
            "intent_id": proof.intent_id,
            "intent_hash": proof.intent_hash,
            "cause_id": proof.cause_id,
            "claim_digest": proof.claim_digest,
            "evidence_class": proof.evidence_class,
            "revision": proof.journal_revision
            if current_revision is None
            else current_revision,
            "attempts": proof.dispatch_attempt_count if attempts is None else attempts,
            "reconciliation_sha256": proof.reconciliation_evidence_sha256,
            "writer_fence_sha256": proof.writer_fence_sha256,
            "filled_quantity": proof.filled_quantity,
            "trade_count": proof.trade_count,
            "kind": "terminal" if type(proof) is DispatchTerminalProof else "tracked",
        }
        if type(proof) is DispatchTerminalProof:
            row["terminal_state"] = proof.terminal_state
        else:
            row.update(
                provider_order_id=proof.provider_order_id,
                accepted_request_sha256=proof.accepted_request_sha256,
                exposure_reservation_id=proof.exposure_reservation_id,
                exposure_reservation_sha256=proof.exposure_reservation_sha256,
                durable_exposure=durable_exposure,
            )
        self._rows[proof.journal_record_sha256] = row

    @contextmanager
    def dispatch_resolution_guard(self, proof, *, claim):
        # Holding this lock across `yield` models holding an external account
        # writer fence for the complete risk database commit.
        with self._lock:
            self.guard_calls += 1
            row = self._rows.get(proof.journal_record_sha256)
            valid = row is not None and all(
                (
                    row["scope"] == claim.scope == proof.scope,
                    row["permit_id"] == claim.permit_id == proof.permit_id,
                    row["intent_id"] == claim.intent_id == proof.intent_id,
                    row["intent_hash"] == claim.intent_hash == proof.intent_hash,
                    row["cause_id"] == claim.cause_id == proof.cause_id,
                    row["claim_digest"] == claim.claim_digest == proof.claim_digest,
                    row["evidence_class"] is proof.evidence_class,
                    row["revision"] == proof.journal_revision,
                    row["attempts"] == proof.dispatch_attempt_count == 1,
                    row["reconciliation_sha256"]
                    == proof.reconciliation_evidence_sha256,
                    row["writer_fence_sha256"] == proof.writer_fence_sha256,
                    row["filled_quantity"] == proof.filled_quantity == 0,
                    row["trade_count"] == proof.trade_count == 0,
                )
            )
            if valid and type(proof) is DispatchTerminalProof:
                valid = (
                    row["kind"] == "terminal"
                    and row["terminal_state"] is proof.terminal_state
                )
            elif valid and type(proof) is DispatchTrackedOrderProof:
                valid = all(
                    (
                        row["kind"] == "tracked",
                        row["durable_exposure"] is True,
                        row["provider_order_id"] == proof.provider_order_id,
                        row["accepted_request_sha256"] == proof.accepted_request_sha256,
                        row["exposure_reservation_id"] == proof.exposure_reservation_id,
                        row["exposure_reservation_sha256"]
                        == proof.exposure_reservation_sha256,
                    )
                )
            if valid is True:
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
            else:
                yield None


class BareBooleanJournalAuthority:
    """A naked boolean cannot stand in for an exact typed journal attestation."""

    @contextmanager
    def dispatch_resolution_guard(self, proof, *, claim):
        yield True


class TamperedReceiptJournalAuthority:
    """Yield one well-typed but incorrectly bound resolution receipt."""

    def __init__(self, inner, field):
        self.inner = inner
        self.field = field

    @contextmanager
    def dispatch_resolution_guard(self, proof, *, claim):
        with self.inner.dispatch_resolution_guard(proof, claim=claim) as attestation:
            if not isinstance(attestation, VerifiedDispatchResolution):
                yield attestation
                return
            replacements = {
                "scope": AccountScope("fake", "other-account", "sandbox"),
                "claim_digest": _digest("wrong-claim"),
                "journal_revision": attestation.journal_revision + 1,
                "journal_record_sha256": _digest("wrong-journal-row"),
                "writer_fence_sha256": _digest("wrong-writer-fence"),
            }
            yield replace(attestation, **{self.field: replacements[self.field]})


def _claimed_gate(tmp_path, scope, policy, authority=None, name="resolve"):
    gate = DurableRiskGate(
        tmp_path / f"{name}.db", policy, execution_journal_authority=authority
    )
    intent = make_intent(scope, name)
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)
    binding = gate.dispatch_claim_binding(permit.permit_id)
    gate.settle(permit.permit_id)
    return gate, intent, permit, binding


def _terminal_proof(binding, **changes):
    values = {
        "scope": binding.scope,
        "permit_id": binding.permit_id,
        "intent_id": binding.intent_id,
        "intent_hash": binding.intent_hash,
        "cause_id": binding.cause_id,
        "claim_digest": binding.claim_digest,
        "evidence_class": DispatchEvidenceClass.SIMULATION_JOURNAL,
        "terminal_state": DispatchTerminalState.REJECTED_NO_FILL,
        "dispatch_attempt_count": 1,
        "journal_revision": 1,
        "journal_record_sha256": _digest("journal-row"),
        "reconciliation_evidence_sha256": _digest("reconciliation"),
        "writer_fence_sha256": _digest("writer-fence"),
    }
    values.update(changes)
    return DispatchTerminalProof(**values)


def _tracked_proof(binding, **changes):
    values = {
        "scope": binding.scope,
        "permit_id": binding.permit_id,
        "intent_id": binding.intent_id,
        "intent_hash": binding.intent_hash,
        "cause_id": binding.cause_id,
        "claim_digest": binding.claim_digest,
        "evidence_class": DispatchEvidenceClass.SIMULATION_JOURNAL,
        "dispatch_attempt_count": 1,
        "journal_revision": 1,
        "journal_record_sha256": _digest("tracked-journal-row"),
        "reconciliation_evidence_sha256": _digest("tracked-reconciliation"),
        "writer_fence_sha256": _digest("tracked-writer-fence"),
        "provider_order_id": "fake-order-17",
        "accepted_request_sha256": _digest("accepted-request"),
        "exposure_reservation_id": "reservation-17",
        "exposure_reservation_sha256": _digest("durable-exposure-reservation"),
    }
    values.update(changes)
    return DispatchTrackedOrderProof(**values)


def test_reservation_is_idempotent_and_enforces_shared_limit(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    clock = MutableClock()
    database = tmp_path / "risk.db"
    first_gate = DurableRiskGate(database, policy, clock=clock)
    second_gate = DurableRiskGate(database, policy, clock=clock)

    first = first_gate.reserve(make_intent(scope, "intent-1"))
    duplicate = second_gate.reserve(make_intent(scope, "intent-1"))
    assert duplicate.permit_id == first.permit_id

    second_gate.reserve(make_intent(scope, "intent-2", notional="60"))
    with pytest.raises(RiskDeniedError, match="notional limit") as error:
        first_gate.reserve(make_intent(scope, "intent-3", notional="1"))
    assert error.value.code == "ACCOUNT_LIMIT_EXHAUSTED"
    assert first_gate.snapshot(scope)["increase_notional"] == Decimal("100")


def test_reused_id_with_different_payload_is_rejected(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    gate.reserve(make_intent(scope, "intent-1", notional="20"))

    with pytest.raises(RiskDeniedError) as error:
        gate.reserve(make_intent(scope, "intent-1", notional="21"))
    assert error.value.code == "INTENT_ID_REUSED"


def test_freeze_blocks_increase_but_not_cancel_or_reduce(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    gate.freeze(scope, "market-data-stale", "market data is stale")

    with pytest.raises(RiskDeniedError) as error:
        gate.reserve(make_intent(scope, "open", IntentAction.INCREASE))
    assert error.value.code == "FROZEN"

    cancel = gate.reserve(
        make_intent(scope, "cancel", IntentAction.CANCEL, notional="0")
    )
    reduce = gate.reserve(
        make_intent(scope, "reduce", IntentAction.REDUCE, notional="0")
    )
    assert cancel.action is IntentAction.CANCEL
    assert reduce.action is IntentAction.REDUCE

    gate.resolve_freeze(scope, "market-data-stale")
    assert gate.active_freeze_reasons(scope) == []
    assert (
        gate.reserve(make_intent(scope, "open-after", IntentAction.INCREASE)).intent_id
        == "open-after"
    )


def test_freeze_after_reservation_invalidates_increase_at_dispatch(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    intent = make_intent(scope, "open")
    permit = gate.reserve(intent)
    gate.freeze(scope, "operator", "operator freeze")

    with pytest.raises(RiskDeniedError) as error:
        gate.validate_permit(permit.permit_id, intent)
    assert error.value.code == "FROZEN"


def test_expired_and_policy_changed_permits_cannot_dispatch(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    clock = MutableClock()
    database = tmp_path / "risk.db"
    initial_gate = DurableRiskGate(database, policy, clock=clock)
    intent = make_intent(scope, "open")
    permit = initial_gate.reserve(intent)

    changed_policy = RiskPolicy(
        policy_id="changed", max_increase_notional=Decimal("100"), max_increase_count=2
    )
    changed_gate = DurableRiskGate(database, changed_policy, clock=clock)
    with pytest.raises(PermitInvalidError) as policy_error:
        changed_gate.validate_permit(permit.permit_id, intent)
    assert policy_error.value.code == "POLICY_CHANGED"

    clock.value += 11.0
    with pytest.raises(PermitInvalidError) as expiry_error:
        initial_gate.validate_permit(permit.permit_id, intent)
    assert expiry_error.value.code == "PERMIT_NOT_ACTIVE"


def test_settle_and_release_only_allow_pending_permits(
    tmp_path, scope: AccountScope, policy: RiskPolicy
) -> None:
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    settled = gate.reserve(make_intent(scope, "settle"))
    with pytest.raises(PermitInvalidError) as unclaimed:
        gate.settle(settled.permit_id)
    assert unclaimed.value.code == "PERMIT_NOT_DISPATCH_CLAIMED"
    gate.claim_for_dispatch(settled.permit_id, make_intent(scope, "settle"))
    gate.settle(settled.permit_id)
    with pytest.raises(PermitInvalidError):
        gate.release(settled.permit_id, "cannot release dispatched request")

    release_scope = AccountScope("fake", "account-release", "sandbox")
    released = gate.reserve(make_intent(release_scope, "release"))
    gate.release(released.permit_id, "provider was never contacted")
    with pytest.raises(PermitInvalidError):
        gate.validate_permit(released.permit_id)


def test_dispatch_claimed_permit_cannot_be_released(tmp_path, scope, policy):
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    intent = make_intent(scope, "claimed")
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)

    with pytest.raises(PermitInvalidError) as caught:
        gate.release(permit.permit_id, "dispatch outcome is uncertain")

    assert caught.value.code == "PERMIT_DISPATCH_CLAIMED"
    snapshot = gate.snapshot(scope)
    assert snapshot["increase_count"] == 1
    assert snapshot["increase_notional"] == Decimal("40")


def test_ensure_settled_requires_exact_dispatch_claim_and_keeps_latch(
    tmp_path, scope, policy
):
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    intent = make_intent(scope, "ensure-settled")
    permit = gate.reserve(intent)

    with pytest.raises(PermitInvalidError) as unclaimed:
        gate.ensure_settled(permit.permit_id)
    assert unclaimed.value.code == "PERMIT_NOT_DISPATCH_CLAIMED"

    gate.claim_for_dispatch(permit.permit_id, intent)
    first = gate.ensure_settled(permit.permit_id)
    second = gate.ensure_settled(permit.permit_id)

    assert first.permit_id == second.permit_id == permit.permit_id
    assert gate.active_freeze_reasons(scope) == ["dispatch-inflight:ensure-settled"]
    with pytest.raises(PermitInvalidError) as blocked:
        gate.resolve_freeze(scope, "dispatch-inflight:ensure-settled")
    assert blocked.value.code == "DISPATCH_FREEZE_REQUIRES_RECONCILIATION"


def test_dispatch_claim_is_single_use_and_duplicate_does_not_create_permission(
    tmp_path, scope, policy
):
    gate = DurableRiskGate(tmp_path / "single-claim.db", policy)
    intent = make_intent(scope, "single-claim")
    permit = gate.reserve(intent)
    gate.claim_for_dispatch(permit.permit_id, intent)

    with pytest.raises(PermitInvalidError) as duplicate:
        gate.claim_for_dispatch(permit.permit_id, intent)

    assert duplicate.value.code == "DISPATCH_CLAIM_ALREADY_ISSUED"
    assert gate.active_freeze_reasons(scope) == ["dispatch-inflight:single-claim"]
    assert gate.snapshot(scope)["increase_count"] == 1


def test_dispatch_resolution_requires_injected_authority_and_exact_no_fill_proof(
    tmp_path, scope, policy
):
    gate, _, permit, binding = _claimed_gate(
        tmp_path, scope, policy, name="no-authority"
    )
    proof = _terminal_proof(binding)

    with pytest.raises(PermitInvalidError) as missing:
        gate.resolve_dispatch_freeze(proof)
    assert missing.value.code == "DISPATCH_RESOLUTION_AUTHORITY_REQUIRED"
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]
    assert gate.snapshot(scope)["increase_notional"] == permit.notional


def test_bare_boolean_authority_is_not_a_dispatch_attestation(tmp_path, scope, policy):
    gate, _, _, binding = _claimed_gate(
        tmp_path, scope, policy, BareBooleanJournalAuthority(), name="bare-boolean"
    )
    proof = _terminal_proof(binding)

    with pytest.raises(PermitInvalidError) as rejected:
        gate.resolve_dispatch_freeze(proof)

    assert rejected.value.code == "DISPATCH_RESOLUTION_PROOF_REJECTED"
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]


@pytest.mark.parametrize(
    "field",
    ["scope", "claim_digest", "journal_revision", "journal_record_sha256", "writer_fence_sha256"],
)
def test_well_typed_but_mismatched_resolution_receipt_keeps_dispatch_latch(
    tmp_path, scope, policy, field
):
    journal = FakeVerifiedExecutionJournalAuthority()
    authority = TamperedReceiptJournalAuthority(journal, field)
    gate, _, _, binding = _claimed_gate(
        tmp_path, scope, policy, authority, name="tampered-receipt-" + field
    )
    proof = _terminal_proof(binding)
    journal.register(proof)

    with pytest.raises(PermitInvalidError) as rejected:
        gate.resolve_dispatch_freeze(proof)

    assert rejected.value.code == "DISPATCH_RESOLUTION_PROOF_REJECTED"
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]
    assert gate.snapshot(scope)["increase_count"] == 1
    assert gate.snapshot(scope)["increase_notional"] == Decimal("40")


@pytest.mark.parametrize(
    "terminal_state",
    [DispatchTerminalState.REJECTED_NO_FILL, DispatchTerminalState.CANCELED_NO_FILL],
)
def test_exact_terminal_proof_clears_only_matching_latch_and_releases_no_fill_capacity(
    tmp_path, scope, policy, terminal_state
):
    authority = FakeVerifiedExecutionJournalAuthority()
    gate, _, _, binding = _claimed_gate(
        tmp_path,
        scope,
        policy,
        authority,
        name="terminal-" + terminal_state.value.lower(),
    )
    proof = _terminal_proof(
        binding,
        terminal_state=terminal_state,
        journal_record_sha256=_digest("terminal-" + terminal_state.value),
    )
    authority.register(proof)

    gate.resolve_dispatch_freeze(proof)

    assert gate.active_freeze_reasons(scope) == []
    assert gate.snapshot(scope)["increase_count"] == 0
    assert gate.snapshot(scope)["increase_notional"] == Decimal("0")
    assert gate.reserve(
        make_intent(scope, "after-no-fill", notional="100")
    ).notional == Decimal("100")


def test_acked_tracked_proof_clears_uncertainty_but_keeps_risk_capacity_reserved(
    tmp_path, scope, policy
):
    authority = FakeVerifiedExecutionJournalAuthority()
    gate, _, permit, binding = _claimed_gate(
        tmp_path, scope, policy, authority, name="acked-tracked"
    )
    proof = _tracked_proof(binding)
    authority.register(proof)

    gate.resolve_dispatch_freeze(proof)

    assert gate.active_freeze_reasons(scope) == []
    assert gate.snapshot(scope)["increase_count"] == 1
    assert gate.snapshot(scope)["increase_notional"] == permit.notional
    with pytest.raises(RiskDeniedError) as over_limit:
        gate.reserve(make_intent(scope, "capacity-stays-held", notional="61"))
    assert over_limit.value.code == "ACCOUNT_LIMIT_EXHAUSTED"


def test_acked_tracked_transfer_requires_exact_durable_exposure_and_no_synthetic_fill(
    tmp_path, scope, policy
):
    authority = FakeVerifiedExecutionJournalAuthority()
    gate, _, _, binding = _claimed_gate(
        tmp_path, scope, policy, authority, name="acked-no-exposure"
    )
    with pytest.raises(ValueError, match="synthetic or partial fills"):
        _tracked_proof(binding, filled_quantity=1)
    proof = _tracked_proof(binding)
    authority.register(proof, durable_exposure=False)

    with pytest.raises(PermitInvalidError) as rejected:
        gate.resolve_dispatch_freeze(proof)

    assert rejected.value.code == "DISPATCH_RESOLUTION_PROOF_REJECTED"
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]
    assert gate.snapshot(scope)["increase_notional"] == Decimal("40")


@pytest.mark.parametrize("mismatch", ["account", "intent"])
def test_dispatch_proof_wrong_account_or_intent_is_rejected_before_authority(
    tmp_path, scope, policy, mismatch
):
    authority = FakeVerifiedExecutionJournalAuthority()
    gate, _, _, binding = _claimed_gate(
        tmp_path, scope, policy, authority, name="wrong-" + mismatch
    )
    proof = _terminal_proof(binding)
    if mismatch == "account":
        proof = _terminal_proof(
            binding,
            scope=AccountScope("fake", "other-account", "sandbox"),
        )
    else:
        proof = _terminal_proof(
            binding,
            intent_id="other-intent",
            cause_id="dispatch-inflight:other-intent",
        )

    with pytest.raises(PermitInvalidError) as caught:
        gate.resolve_dispatch_freeze(proof)

    assert caught.value.code == "DISPATCH_RESOLUTION_PROOF_SCOPE_MISMATCH"
    assert authority.guard_calls == 0
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]


@pytest.mark.parametrize("case", ["unknown-row", "stale-revision", "duplicate-attempt"])
def test_dispatch_proof_unknown_stale_or_duplicate_attempt_stays_frozen(
    tmp_path, scope, policy, case
):
    authority = FakeVerifiedExecutionJournalAuthority()
    gate, _, _, binding = _claimed_gate(
        tmp_path, scope, policy, authority, name="invalid-" + case
    )
    if case == "duplicate-attempt":
        with pytest.raises(ValueError, match="exactly one dispatch attempt"):
            _terminal_proof(binding, dispatch_attempt_count=2)
        proof = _terminal_proof(binding)
        authority.register(proof, attempts=2)
    else:
        proof = _terminal_proof(binding)
        if case == "stale-revision":
            authority.register(proof, current_revision=proof.journal_revision + 1)

    with pytest.raises(PermitInvalidError) as rejected:
        gate.resolve_dispatch_freeze(proof)

    assert rejected.value.code == "DISPATCH_RESOLUTION_PROOF_REJECTED"
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]


def test_dispatch_proof_rejects_fills_unknown_state_and_simulation_ctp_scope(
    tmp_path, scope, policy
):
    authority = FakeVerifiedExecutionJournalAuthority()
    gate, _, _, binding = _claimed_gate(
        tmp_path, scope, policy, authority, name="invalid-fill"
    )
    with pytest.raises(ValueError, match="zero filled quantity"):
        _terminal_proof(binding, filled_quantity=1)
    with pytest.raises(ValueError):
        _terminal_proof(binding, terminal_state="UNKNOWN")
    with pytest.raises(ValueError, match="non-simulation provider"):
        _terminal_proof(
            binding,
            scope=AccountScope("ctp", "account-1", "simulation"),
            evidence_class=DispatchEvidenceClass.SIMULATION_JOURNAL,
        )
    with pytest.raises(ValueError, match="fake or fixture"):
        _terminal_proof(
            binding, evidence_class=DispatchEvidenceClass.NATIVE_PROVIDER_JOURNAL
        )

    proof = _terminal_proof(binding)
    with pytest.raises(PermitInvalidError) as unknown:
        gate.resolve_dispatch_freeze(proof)
    assert unknown.value.code == "DISPATCH_RESOLUTION_PROOF_REJECTED"
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]


def test_dispatch_proof_replay_is_rejected_after_restart(tmp_path, scope, policy):
    authority = FakeVerifiedExecutionJournalAuthority()
    gate, _, _, binding = _claimed_gate(
        tmp_path, scope, policy, authority, name="proof-restart"
    )
    proof = _terminal_proof(binding)
    authority.register(proof)
    gate.resolve_dispatch_freeze(proof)

    # `_claimed_gate` owns this path by convention; a fresh gate instance
    # models process restart while the proof row remains durable.
    restarted = DurableRiskGate(
        tmp_path / "proof-restart.db", policy, execution_journal_authority=authority
    )
    with pytest.raises(PermitInvalidError) as replay:
        restarted.resolve_dispatch_freeze(proof)
    assert replay.value.code == "DISPATCH_PROOF_REPLAYED"


def test_concurrent_duplicate_dispatch_proofs_commit_only_once(tmp_path, scope, policy):
    authority = FakeVerifiedExecutionJournalAuthority()
    gate, _, _, binding = _claimed_gate(
        tmp_path, scope, policy, authority, name="proof-concurrent"
    )
    proof = _terminal_proof(binding)
    authority.register(proof)
    second_gate = DurableRiskGate(
        tmp_path / "proof-concurrent.db", policy, execution_journal_authority=authority
    )
    barrier = Barrier(2)

    def resolve(candidate_gate):
        barrier.wait()
        try:
            candidate_gate.resolve_dispatch_freeze(proof)
            return "resolved"
        except PermitInvalidError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(resolve, (gate, second_gate)))

    assert results.count("resolved") == 1
    assert (
        sum(
            result in {"DISPATCH_PROOF_REPLAYED", "DISPATCH_ALREADY_RECONCILED"}
            for result in results
        )
        == 1
    )
    assert gate.active_freeze_reasons(scope) == []
    with gate._connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM risk_dispatch_resolutions"
        ).fetchone()[0]
    assert count == 1


def test_dispatch_latch_namespace_cannot_be_created_or_cleared_generically(
    tmp_path, scope, policy
):
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    with pytest.raises(ValueError, match="reserved"):
        gate.freeze(scope, "dispatch-inflight:forged", "forged reason")
    with pytest.raises(PermitInvalidError) as blocked:
        gate.resolve_freeze(scope, "dispatch-inflight:forged")
    assert blocked.value.code == "DISPATCH_FREEZE_REQUIRES_RECONCILIATION"


def test_dispatch_claim_rolls_back_claim_and_latch_after_partial_failure(
    tmp_path, scope, policy, monkeypatch
):
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    intent = make_intent(scope, "rollback-claim")
    permit = gate.reserve(intent)
    freeze = gate._freeze_in_transaction

    def fail_after_freeze(connection, claim_scope, cause_id, reason, updated_at):
        freeze(connection, claim_scope, cause_id, reason, updated_at)
        raise RuntimeError("injected failure after both claim mutations")

    monkeypatch.setattr(gate, "_freeze_in_transaction", fail_after_freeze)
    with pytest.raises(RuntimeError, match="injected failure"):
        gate.claim_for_dispatch(permit.permit_id, intent)
    assert gate.active_freeze_reasons(scope) == []

    monkeypatch.setattr(gate, "_freeze_in_transaction", freeze)
    gate.claim_for_dispatch(permit.permit_id, intent)
    assert gate.active_freeze_reasons(scope) == ["dispatch-inflight:rollback-claim"]


def test_foreign_keys_are_enabled_on_every_connection(tmp_path, scope, policy):
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    with gate._connection() as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO risk_dispatch_claims
                    (permit_id, intent_id, intent_hash, scope_key, cause_id, claimed_at)
                VALUES ('missing-permit', 'intent', 'hash', ?, 'cause', 0)
                """,
                (scope.key,),
            )


@pytest.mark.parametrize(
    "value", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity"), True]
)
def test_nonfinite_and_boolean_amounts_are_not_risk_limits_or_intents(value, scope):
    with pytest.raises(ValueError):
        RiskPolicy("unsafe", value, 1)
    with pytest.raises(ValueError):
        RiskIntent("unsafe", scope, IntentAction.INCREASE, value)


@pytest.mark.parametrize("count", [float("nan"), float("inf"), 1.5, True])
def test_increase_count_cannot_disable_limit_using_nan_or_fraction(count):
    with pytest.raises(ValueError, match="integer"):
        RiskPolicy("unsafe", Decimal("100"), count)


@pytest.mark.parametrize("ttl", [float("nan"), float("inf"), True])
def test_permit_expiry_must_be_finite(ttl):
    with pytest.raises(ValueError):
        RiskPolicy("unsafe", Decimal("100"), 1, ttl)


def test_exact_retry_after_freeze_does_not_return_an_admitted_increase(
    tmp_path, scope, policy
):
    gate = DurableRiskGate(tmp_path / "risk.db", policy)
    intent = make_intent(scope, "same")
    gate.reserve(intent)
    gate.freeze(scope, "disconnect", "connection lost")
    gate.freeze(scope, "operator", "operator hold")
    gate.resolve_freeze(scope, "disconnect")
    with pytest.raises(RiskDeniedError) as denied:
        gate.reserve(intent)
    assert denied.value.code == "FROZEN"
    assert gate.active_freeze_reasons(scope) == ["operator hold"]


def test_concurrent_connections_cannot_oversubscribe_account_budget(
    tmp_path, scope, policy
):
    database = tmp_path / "risk.db"
    gates = [DurableRiskGate(database, policy), DurableRiskGate(database, policy)]
    barrier = Barrier(8)

    def reserve(index):
        barrier.wait(timeout=10)
        try:
            gates[index % 2].reserve(make_intent(scope, "concurrent-" + str(index)))
            return "admitted"
        except RiskDeniedError as denied:
            return denied.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve, range(8)))
    assert results.count("admitted") == 2
    assert results.count("ACCOUNT_LIMIT_EXHAUSTED") == 6
    reopened = DurableRiskGate(database, policy)
    assert reopened.snapshot(scope)["increase_notional"] == Decimal("80")


def test_public_exports_are_defined():
    import bt_api_risk

    assert all(hasattr(bt_api_risk, name) for name in bt_api_risk.__all__)
    assert "DurableRiskGate" in bt_api_risk.__all__
    assert "StrategyAllocationSnapshot" in bt_api_risk.__all__


def test_public_version_matches_project_metadata():
    import bt_api_risk

    project_root = Path(__file__).resolve().parents[1]
    metadata = (project_root / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', metadata)

    assert version is not None
    assert bt_api_risk.__version__ == version.group(1)


def test_risk_payload_binding_is_immutable(scope):
    from dataclasses import FrozenInstanceError

    intent = make_intent(scope, "immutable")
    fingerprint = intent.fingerprint
    with pytest.raises(FrozenInstanceError):
        intent.payload_fingerprint = "changed"
    with pytest.raises(ValueError, match="immutable"):
        RiskIntent(
            "mutable", scope, IntentAction.INCREASE, Decimal("1"), {"quantity": 1}
        )
    assert intent.fingerprint == fingerprint


def test_separate_processes_share_the_same_account_budget(tmp_path, scope, policy):
    database = tmp_path / "risk.db"
    gate = DurableRiskGate(database, policy)
    program = """
import socket
import sys
def no_network(*args, **kwargs):
    raise AssertionError('risk worker attempted external I/O')
socket.create_connection = no_network
socket.socket.connect = no_network
from decimal import Decimal
from bt_api_risk import AccountScope, DurableRiskGate, IntentAction, RiskDeniedError, RiskIntent, RiskPolicy
gate = DurableRiskGate(sys.argv[1], RiskPolicy('unit-policy', Decimal('100'), 3, 10.0))
intent = RiskIntent(sys.argv[2], AccountScope('fake', 'account-1', 'sandbox'), IntentAction.INCREASE, Decimal('40'))
try:
    gate.reserve(intent)
except RiskDeniedError as error:
    print(error.code)
else:
    print('admitted')
"""

    def run_worker(index):
        result = subprocess.run(  # noqa: S603 -- fixed local Python worker, no shell.
            [sys.executable, "-c", program, str(database), "process-" + str(index)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(run_worker, range(4)))
    assert results.count("admitted") == 2
    assert results.count("ACCOUNT_LIMIT_EXHAUSTED") == 2
    assert gate.snapshot(scope)["increase_notional"] == Decimal("80")


def test_atomic_dispatch_claim_fences_two_prevalidated_processes(
    tmp_path, scope, policy
):
    """A check-then-freeze race must admit at most one provider boundary.

    Both permits are intentionally reserved before either child begins.  The
    assertion therefore exercises the dispatch-time transaction rather than
    the easier reservation-time freeze check.
    """

    database = tmp_path / "risk.db"
    gate = DurableRiskGate(database, policy)
    first = gate.reserve(make_intent(scope, "dispatch-process-1", notional="10"))
    second = gate.reserve(make_intent(scope, "dispatch-process-2", notional="10"))
    program = """
import socket
import sys
def no_network(*args, **kwargs):
    raise AssertionError('risk worker attempted external I/O')
socket.create_connection = no_network
socket.socket.connect = no_network
from decimal import Decimal
from bt_api_risk import AccountScope, DurableRiskGate, IntentAction, RiskDeniedError, RiskIntent, RiskPolicy
gate = DurableRiskGate(sys.argv[1], RiskPolicy('unit-policy', Decimal('100'), 3, 10.0))
intent = RiskIntent(
    sys.argv[2],
    AccountScope('fake', 'account-1', 'sandbox'),
    IntentAction.INCREASE,
    Decimal('10'),
    'deterministic-test-payload',
)
try:
    gate.claim_for_dispatch(sys.argv[3], intent)
except RiskDeniedError as error:
    print(error.code)
else:
    print('claimed')
"""

    def claim(intent_id: str, permit_id: str) -> str:
        result = subprocess.run(  # noqa: S603 -- fixed local Python worker, no shell.
            [sys.executable, "-c", program, str(database), intent_id, permit_id],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda values: claim(*values),
                (
                    ("dispatch-process-1", first.permit_id),
                    ("dispatch-process-2", second.permit_id),
                ),
            )
        )

    assert results.count("claimed") == 1
    assert results.count("FROZEN") == 1
    active = gate.active_freeze_reasons(scope)
    assert len(active) == 1
    assert active[0] in {
        "dispatch-inflight:dispatch-process-1",
        "dispatch-inflight:dispatch-process-2",
    }


def _allocation_policy(
    *, account_limit: str = "1000", count_limit: int = 20
) -> RiskPolicy:
    return RiskPolicy(
        "allocation-policy",
        Decimal(account_limit),
        count_limit,
        30.0,
        require_strategy_allocation=True,
        notional_unit="USD",
    )


def _allocation_intent(
    scope: AccountScope,
    intent_id: str,
    *,
    notional: str = "1",
    version: str = "v1",
    quantity: Optional[str] = None,  # noqa: UP045 -- Python 3.9 is supported.
    instrument: str = "fixture/contract",
    quantity_unit: str = "contract",
    action: IntentAction = IntentAction.INCREASE,
) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=action,
        notional=Decimal(notional),
        payload_fingerprint="allocation-payload:" + intent_id,
        strategy_id="strategy-1",
        allocation_version=version,
        instrument=instrument if quantity is not None else None,
        quantity=Decimal(quantity) if quantity is not None else None,
        quantity_unit=quantity_unit if quantity is not None else None,
        notional_unit="USD",
    )


def test_account_and_strategy_allowance_have_distinct_exhaustion_codes(tmp_path, scope):
    account_gate = DurableRiskGate(
        tmp_path / "account-budget.db", _allocation_policy(account_limit="50")
    )
    account_gate.set_strategy_allocation(
        scope, "strategy-1", "v1", max_notional=Decimal("100")
    )
    account_gate.reserve(_allocation_intent(scope, "account-used", notional="40"))
    with pytest.raises(RiskDeniedError) as account_exhausted:
        account_gate.reserve(_allocation_intent(scope, "account-over", notional="20"))
    assert account_exhausted.value.code == "ACCOUNT_LIMIT_EXHAUSTED"

    strategy_gate = DurableRiskGate(
        tmp_path / "strategy-budget.db", _allocation_policy(account_limit="1000")
    )
    strategy_gate.set_strategy_allocation(
        scope, "strategy-1", "v1", max_notional=Decimal("50")
    )
    strategy_gate.reserve(_allocation_intent(scope, "strategy-used", notional="40"))
    with pytest.raises(RiskDeniedError) as strategy_exhausted:
        strategy_gate.reserve(_allocation_intent(scope, "strategy-over", notional="20"))
    assert strategy_exhausted.value.code == "STRATEGY_ALLOCATION_EXHAUSTED"


def test_separate_processes_share_strategy_allocation_budget(tmp_path, scope):
    database = tmp_path / "strategy-processes.db"
    policy = _allocation_policy()
    gate = DurableRiskGate(database, policy)
    gate.set_strategy_allocation(scope, "strategy-1", "v1", max_notional=Decimal("60"))
    program = """
import socket
import sys
def no_network(*args, **kwargs):
    raise AssertionError('risk worker attempted external I/O')
socket.create_connection = no_network
socket.socket.connect = no_network
from decimal import Decimal
from bt_api_risk import AccountScope, DurableRiskGate, IntentAction, RiskDeniedError, RiskIntent, RiskPolicy
gate = DurableRiskGate(sys.argv[1], RiskPolicy('allocation-policy', Decimal('1000'), 20, 30.0, require_strategy_allocation=True, notional_unit='USD'))
intent = RiskIntent(sys.argv[2], AccountScope('fake', 'account-1', 'sandbox'), IntentAction.INCREASE, Decimal('40'), 'allocation-payload', strategy_id='strategy-1', allocation_version='v1', notional_unit='USD')
try:
    gate.reserve(intent)
except RiskDeniedError as error:
    print(error.code)
else:
    print('admitted')
"""

    def run_worker(index: int) -> str:
        result = subprocess.run(  # noqa: S603 -- fixed local Python worker, no shell.
            [sys.executable, "-c", program, str(database), "process-" + str(index)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run_worker, range(2)))
    assert sorted(results) == ["STRATEGY_ALLOCATION_EXHAUSTED", "admitted"]
    assert gate.snapshot(scope)["increase_notional"] == Decimal("40")


def test_two_strategies_contend_for_one_account_cap_across_processes(tmp_path, scope):
    database = tmp_path / "allocation-account-cap.db"
    gate = DurableRiskGate(database, _allocation_policy(account_limit="1000"))
    for strategy_id in ("strategy-1", "strategy-2"):
        gate.set_strategy_allocation(
            scope,
            strategy_id,
            "v1",
            max_notional=Decimal("600"),
            notional_unit="USD",
        )
    ready_dir = tmp_path / "workers-ready"
    ready_dir.mkdir()
    go_file = tmp_path / "workers-go"
    program = r"""
import socket
import sys
import time
from pathlib import Path
def no_network(*args, **kwargs):
    raise AssertionError('risk worker attempted external I/O')
socket.create_connection = no_network
socket.socket.connect = no_network
ready = Path(sys.argv[2])
go = Path(sys.argv[3])
ready.write_text('ready', encoding='ascii')
deadline = time.monotonic() + 15
while not go.exists():
    if time.monotonic() >= deadline:
        raise TimeoutError('process barrier was not released')
    time.sleep(0.01)
from decimal import Decimal
from bt_api_risk import AccountScope, DurableRiskGate, IntentAction, RiskDeniedError, RiskIntent, RiskPolicy
gate = DurableRiskGate(sys.argv[1], RiskPolicy('allocation-policy', Decimal('1000'), 20, 30.0, require_strategy_allocation=True, notional_unit='USD'))
intent = RiskIntent(sys.argv[4], AccountScope('fake', 'account-1', 'sandbox'), IntentAction.INCREASE, Decimal('600'), 'account-cap-payload', strategy_id=sys.argv[5], allocation_version='v1', notional_unit='USD')
try:
    gate.reserve(intent)
except RiskDeniedError as error:
    print(error.code)
else:
    print('admitted')
"""

    def run_worker(index: int) -> str:
        result = subprocess.run(  # noqa: S603 -- fixed local Python worker, no shell.
            [
                sys.executable,
                "-c",
                program,
                str(database),
                str(ready_dir / ("ready-" + str(index))),
                str(go_file),
                "account-contention-" + str(index),
                "strategy-" + str(index + 1),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    with ThreadPoolExecutor(max_workers=2) as pool:
        workers = [pool.submit(run_worker, index) for index in range(2)]
        deadline = time.monotonic() + 15
        while not all((ready_dir / ("ready-" + str(i))).exists() for i in range(2)):
            if time.monotonic() >= deadline:
                go_file.touch()
                pytest.fail("separate processes did not reach the reservation barrier")
            time.sleep(0.01)
        go_file.touch()
        results = [worker.result(timeout=30) for worker in workers]

    assert sorted(results) == ["ACCOUNT_LIMIT_EXHAUSTED", "admitted"]
    assert gate.snapshot(scope)["increase_notional"] == Decimal("600")


def test_allocation_revision_invalidates_old_permit_and_never_reuses_version(
    tmp_path, scope
):
    gate = DurableRiskGate(tmp_path / "allocation-revision.db", _allocation_policy())
    gate.set_strategy_allocation(
        scope,
        "strategy-1",
        "v1",
        max_notional=Decimal("100"),
        max_position=Decimal("5"),
        position_instrument="fixture/contract",
        position_unit="contract",
    )
    old_intent = _allocation_intent(
        scope, "old-permit", notional="30", quantity="3", version="v1"
    )
    old_permit = gate.reserve(old_intent)
    gate.set_strategy_allocation(
        scope,
        "strategy-1",
        "v2",
        max_notional=Decimal("100"),
        max_position=Decimal("5"),
        position_instrument="fixture/contract",
        position_unit="contract",
    )
    with pytest.raises(PermitInvalidError) as stale:
        gate.claim_for_dispatch(old_permit.permit_id, old_intent)
    assert stale.value.code == "STRATEGY_ALLOCATION_VERSION_CHANGED"

    # Old-version reservation still counts against the aggregate allowance.
    with pytest.raises(RiskDeniedError) as exhausted:
        gate.reserve(
            _allocation_intent(
                scope, "new-too-much", notional="1", quantity="3", version="v2"
            )
        )
    assert exhausted.value.code == "STRATEGY_ALLOCATION_EXHAUSTED"

    gate.set_strategy_allocation(
        scope,
        "strategy-1",
        "v2",
        max_notional=Decimal("100"),
        max_position=Decimal("5"),
        position_instrument="fixture/contract",
        position_unit="contract",
    )
    with pytest.raises(ValueError, match="cannot be reused"):
        gate.set_strategy_allocation(
            scope,
            "strategy-1",
            "v1",
            max_notional=Decimal("100"),
            max_position=Decimal("5"),
            position_instrument="fixture/contract",
            position_unit="contract",
        )
    with pytest.raises(ValueError, match="changed limits"):
        gate.set_strategy_allocation(
            scope, "strategy-1", "v2", max_notional=Decimal("99")
        )


def test_lowered_position_cap_keeps_old_reservations_and_reduce_does_not_release(
    tmp_path, scope
):
    gate = DurableRiskGate(tmp_path / "lowered-position.db", _allocation_policy())
    gate.set_strategy_allocation(
        scope,
        "strategy-1",
        "v1",
        max_notional=Decimal("100"),
        max_position=Decimal("5"),
        position_instrument="fixture/contract",
        position_unit="contract",
    )
    gate.reserve(_allocation_intent(scope, "held", notional="30", quantity="3"))
    gate.reserve(
        _allocation_intent(scope, "reduce", notional="0", action=IntentAction.REDUCE)
    )
    gate.set_strategy_allocation(
        scope,
        "strategy-1",
        "v2",
        max_notional=Decimal("100"),
        max_position=Decimal("2"),
        position_instrument="fixture/contract",
        position_unit="contract",
    )
    with pytest.raises(RiskDeniedError) as exhausted:
        gate.reserve(
            _allocation_intent(
                scope, "still-full", notional="1", quantity="0.1", version="v2"
            )
        )
    assert exhausted.value.code == "STRATEGY_ALLOCATION_EXHAUSTED"


def test_strategy_snapshot_reports_only_same_unit_local_ledger(tmp_path, scope):
    from dataclasses import FrozenInstanceError

    policy = _allocation_policy(account_limit="50")
    gate = DurableRiskGate(tmp_path / "allocation-snapshot.db", policy)
    gate.set_strategy_allocation(scope, "strategy-1", "v1", max_notional=Decimal("100"))
    intent = _allocation_intent(scope, "snapshot", notional="20")
    permit = gate.reserve(intent)

    pending = gate.get_strategy_allocation(scope, "strategy-1")
    assert pending.revision == "v1"
    assert pending.allocated_notional == Decimal("100")
    assert pending.used_notional == Decimal("0")
    assert pending.reserved_notional == Decimal("20")
    assert pending.available_notional == Decimal("30")
    assert pending.notional_unit == "USD"
    assert pending.source == "local_risk_reservation_ledger"
    assert pending.completeness == "LOCAL_LEDGER_COMPLETE"
    with pytest.raises(FrozenInstanceError):
        pending.available_notional = Decimal("50")

    gate.claim_for_dispatch(permit.permit_id, intent)
    gate.settle(permit.permit_id)
    settled = gate.get_strategy_allocation(scope, "strategy-1")
    assert settled.used_notional == Decimal("20")
    assert settled.reserved_notional == Decimal("0")
    assert settled.available_notional == Decimal("30")


def test_strategy_snapshot_is_read_only_and_keeps_expired_active_usage_conservative(
    tmp_path, scope
):
    clock = MutableClock()
    policy = RiskPolicy(
        "allocation-policy",
        Decimal("1000"),
        20,
        1.0,
        require_strategy_allocation=True,
        notional_unit="USD",
    )
    database = tmp_path / "snapshot-read-only.db"
    gate = DurableRiskGate(database, policy, clock=clock)
    gate.set_strategy_allocation(scope, "strategy-1", "v1", max_notional=Decimal("100"))
    gate.reserve(_allocation_intent(scope, "expiring", notional="20"))
    clock.value += 10

    snapshot = gate.get_strategy_allocation(scope, "strategy-1")

    assert snapshot.reserved_notional == Decimal("20")
    with sqlite3.connect(database) as connection:
        status = connection.execute(
            "SELECT status FROM risk_reservations WHERE intent_id = 'expiring'"
        ).fetchone()[0]
    assert status == "active"


def test_required_allocation_rejects_unbound_and_mixed_notional_units(tmp_path, scope):
    unbound = DurableRiskGate(
        tmp_path / "unit-unbound.db",
        RiskPolicy(
            "allocation-policy",
            Decimal("1000"),
            20,
            30.0,
            require_strategy_allocation=True,
        ),
    )
    with pytest.raises(RiskDeniedError) as missing_policy_unit:
        unbound.reserve(_allocation_intent(scope, "missing-unit"))
    assert missing_policy_unit.value.code == "NOTIONAL_UNIT_UNBOUND"

    gate = DurableRiskGate(tmp_path / "unit-mixed.db", _allocation_policy())
    gate.set_strategy_allocation(scope, "strategy-1", "v1", max_notional=Decimal("100"))
    with pytest.raises(RiskDeniedError) as mismatch:
        gate.reserve(
            RiskIntent(
                "wrong-unit",
                scope,
                IntentAction.INCREASE,
                Decimal("1"),
                "wrong-unit-payload",
                strategy_id="strategy-1",
                allocation_version="v1",
                notional_unit="EUR",
            )
        )
    assert mismatch.value.code == "NOTIONAL_UNIT_MISMATCH"


def test_failed_allocation_revision_rolls_back_its_version_number(tmp_path, scope):
    database = tmp_path / "allocation-rollback.db"
    gate = DurableRiskGate(database, _allocation_policy())
    with sqlite3.connect(database) as connection:
        connection.execute(
            """CREATE TRIGGER reject_strategy_revision
               BEFORE INSERT ON risk_strategy_allocations
               BEGIN SELECT RAISE(ABORT, 'forced allocation failure'); END"""
        )
    with pytest.raises(sqlite3.IntegrityError, match="forced allocation failure"):
        gate.set_strategy_allocation(
            scope, "strategy-1", "v1", max_notional=Decimal("100")
        )
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER reject_strategy_revision")
    gate.set_strategy_allocation(scope, "strategy-1", "v1", max_notional=Decimal("100"))
    assert gate.get_strategy_allocation(scope, "strategy-1").revision == "v1"


def test_different_gate_policies_and_legacy_unit_rows_cannot_reinterpret_usage(
    tmp_path, scope, policy
):
    database = tmp_path / "policy-unit-change.db"
    legacy_gate = DurableRiskGate(database, policy)
    legacy_permit = legacy_gate.reserve(
        make_intent(scope, "legacy-unknown-unit", notional="10")
    )

    required_cny = RiskPolicy(
        "allocation-cny",
        Decimal("1000"),
        20,
        30.0,
        require_strategy_allocation=True,
        notional_unit="CNY",
    )
    cny_gate = DurableRiskGate(database, required_cny)
    with pytest.raises(RiskDeniedError) as no_strategy_mapping:
        cny_gate.set_strategy_allocation(
            scope, "strategy-1", "v1", max_notional=Decimal("100")
        )
    assert no_strategy_mapping.value.code == "RISK_POLICY_BINDING_MISMATCH"
    with pytest.raises(PermitInvalidError) as policy_changed:
        cny_gate.validate_permit(legacy_permit.permit_id)
    assert policy_changed.value.code == "POLICY_CHANGED"

    # A differently denominated view of the same account cannot use its old
    # untyped reservation as either USD or CNY capacity.
    usd_gate = DurableRiskGate(database, _allocation_policy())
    with pytest.raises(RiskDeniedError) as policy_unknown:
        usd_gate.reserve(_allocation_intent(scope, "usd-after-legacy", notional="1"))
    assert policy_unknown.value.code == "RISK_POLICY_BINDING_MISMATCH"

    isolated_database = tmp_path / "two-policy-views.db"
    cny_gate = DurableRiskGate(isolated_database, required_cny)
    cny_gate.set_strategy_allocation(
        scope, "strategy-1", "v1", max_notional=Decimal("100")
    )
    cny_intent = RiskIntent(
        "cny-open",
        scope,
        IntentAction.INCREASE,
        Decimal("20"),
        "cny-payload",
        strategy_id="strategy-1",
        allocation_version="v1",
        notional_unit="CNY",
    )
    cny_permit = cny_gate.reserve(cny_intent)
    usd_gate = DurableRiskGate(isolated_database, _allocation_policy())
    mismatched_snapshot = usd_gate.get_strategy_allocation(scope, "strategy-1")
    assert mismatched_snapshot.available_notional is None
    assert mismatched_snapshot.completeness == "LOCAL_LEDGER_INCOMPLETE"
    assert mismatched_snapshot.reason == "RISK_POLICY_BINDING_MISMATCH"
    with pytest.raises(PermitInvalidError) as old_policy_permit:
        usd_gate.validate_permit(cny_permit.permit_id)
    assert old_policy_permit.value.code == "POLICY_CHANGED"
    with pytest.raises(RiskDeniedError) as allocation_policy_drift:
        usd_gate.set_strategy_allocation(
            scope, "strategy-1", "v1", max_notional=Decimal("100")
        )
    assert allocation_policy_drift.value.code == "RISK_POLICY_BINDING_MISMATCH"
    with pytest.raises(RiskDeniedError) as mixed_account_ledger:
        usd_gate.reserve(_allocation_intent(scope, "usd-open", notional="1"))
    assert mixed_account_ledger.value.code == "RISK_POLICY_BINDING_MISMATCH"


def test_account_policy_binding_rejects_cap_toggle_and_missing_unit_drift(
    tmp_path, scope
):
    database = tmp_path / "policy-binding.db"
    strict = DurableRiskGate(database, _allocation_policy(account_limit="100"))
    strict.set_strategy_allocation(
        scope,
        "strategy-1",
        "v1",
        max_notional=Decimal("100"),
        notional_unit="USD",
    )
    intent = _allocation_intent(scope, "policy-bound-60", notional="60")
    permit = strict.reserve(intent)
    strict.claim_for_dispatch(permit.permit_id, intent)

    drifted = DurableRiskGate(
        database,
        RiskPolicy(
            "allocation-policy",
            Decimal("1000"),
            20,
            30.0,
            require_strategy_allocation=False,
            notional_unit="USD",
        ),
    )
    with pytest.raises(RiskDeniedError) as widened_cap:
        drifted.reserve(make_intent(scope, "policy-bypass-wide", notional="900"))
    assert widened_cap.value.code == "RISK_POLICY_BINDING_MISMATCH"
    with pytest.raises(RiskDeniedError) as changed_allocation:
        drifted.set_strategy_allocation(
            scope, "strategy-1", "v2", max_notional=Decimal("1000")
        )
    assert changed_allocation.value.code == "RISK_POLICY_BINDING_MISMATCH"
    snapshot = drifted.get_strategy_allocation(scope, "strategy-1")
    assert snapshot.available_notional is None
    assert snapshot.reason == "RISK_POLICY_BINDING_MISMATCH"
    assert snapshot.completeness == "LOCAL_LEDGER_INCOMPLETE"
    with pytest.raises(PermitInvalidError) as claimed_binding:
        drifted.dispatch_claim_binding(permit.permit_id)
    assert claimed_binding.value.code == "RISK_POLICY_BINDING_MISMATCH"

    toggle_only = DurableRiskGate(
        database,
        RiskPolicy(
            "allocation-policy",
            Decimal("100"),
            20,
            30.0,
            require_strategy_allocation=False,
            notional_unit="USD",
        ),
    )
    with pytest.raises(RiskDeniedError) as toggled_gate:
        toggle_only.reserve(make_intent(scope, "policy-bypass-toggle", notional="1"))
    assert toggled_gate.value.code == "RISK_POLICY_BINDING_MISMATCH"

    unbound_unit = DurableRiskGate(
        database,
        RiskPolicy(
            "allocation-policy",
            Decimal("100"),
            20,
            30.0,
            require_strategy_allocation=False,
            notional_unit=None,
        ),
    )
    with pytest.raises(RiskDeniedError) as removed_unit:
        unbound_unit.reserve(make_intent(scope, "policy-bypass-unit", notional="1"))
    assert removed_unit.value.code == "RISK_POLICY_BINDING_MISMATCH"


def test_same_policy_legacy_rows_with_unknown_unit_fail_closed(tmp_path, scope):
    database = tmp_path / "legacy-unknown-unit.db"
    gate = DurableRiskGate(database, _allocation_policy())
    gate.set_strategy_allocation(scope, "strategy-1", "v1", max_notional=Decimal("100"))
    gate.reserve(_allocation_intent(scope, "legacy-unit-row", notional="10"))
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE risk_reservations SET notional_unit = NULL WHERE intent_id = ?",
            ("legacy-unit-row",),
        )
    with pytest.raises(RiskDeniedError) as unknown_unit:
        gate.reserve(_allocation_intent(scope, "after-legacy-unit", notional="1"))
    assert unknown_unit.value.code == "NOTIONAL_UNIT_USAGE_UNAVAILABLE"


def test_allocation_update_and_dispatch_claim_are_serialized(tmp_path, scope):
    gate = DurableRiskGate(tmp_path / "allocation-cutpoint.db", _allocation_policy())
    gate.set_strategy_allocation(scope, "strategy-1", "v1", max_notional=Decimal("100"))
    intent = _allocation_intent(scope, "cutpoint", notional="10", version="v1")
    permit = gate.reserve(intent)
    barrier = Barrier(2)

    def claim() -> str:
        barrier.wait(timeout=5)
        try:
            gate.claim_for_dispatch(permit.permit_id, intent)
            return "claimed"
        except PermitInvalidError as error:
            return error.code

    def update() -> str:
        barrier.wait(timeout=5)
        try:
            gate.set_strategy_allocation(
                scope, "strategy-1", "v2", max_notional=Decimal("100")
            )
            return "updated"
        except RiskDeniedError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (pool.submit(claim), pool.submit(update))
        outcomes = {future.result(timeout=10) for future in futures}
    assert outcomes in (
        {"claimed", "STRATEGY_ALLOCATION_DISPATCH_IN_FLIGHT"},
        {"updated", "STRATEGY_ALLOCATION_VERSION_CHANGED"},
    )
