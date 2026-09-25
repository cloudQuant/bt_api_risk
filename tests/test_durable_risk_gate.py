"""Unit tests for the provider-independent durable risk admission boundary."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from decimal import Decimal
from hashlib import sha256
from threading import Barrier, Lock

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
            "revision": proof.journal_revision if current_revision is None else current_revision,
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
                    row["reconciliation_sha256"] == proof.reconciliation_evidence_sha256,
                    row["writer_fence_sha256"] == proof.writer_fence_sha256,
                    row["filled_quantity"] == proof.filled_quantity == 0,
                    row["trade_count"] == proof.trade_count == 0,
                )
            )
            if valid and type(proof) is DispatchTerminalProof:
                valid = row["kind"] == "terminal" and row["terminal_state"] is proof.terminal_state
            elif valid and type(proof) is DispatchTrackedOrderProof:
                valid = all(
                    (
                        row["kind"] == "tracked",
                        row["durable_exposure"] is True,
                        row["provider_order_id"] == proof.provider_order_id,
                        row["accepted_request_sha256"] == proof.accepted_request_sha256,
                        row["exposure_reservation_id"] == proof.exposure_reservation_id,
                        row["exposure_reservation_sha256"] == proof.exposure_reservation_sha256,
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


def _claimed_gate(tmp_path, scope, policy, authority=None, name="resolve"):
    gate = DurableRiskGate(tmp_path / f"{name}.db", policy, execution_journal_authority=authority)
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
    assert error.value.code == "INCREASE_NOTIONAL_LIMIT"
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

    cancel = gate.reserve(make_intent(scope, "cancel", IntentAction.CANCEL, notional="0"))
    reduce = gate.reserve(make_intent(scope, "reduce", IntentAction.REDUCE, notional="0"))
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


def test_ensure_settled_requires_exact_dispatch_claim_and_keeps_latch(tmp_path, scope, policy):
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
    gate, _, permit, binding = _claimed_gate(tmp_path, scope, policy, name="no-authority")
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
    "terminal_state",
    [DispatchTerminalState.REJECTED_NO_FILL, DispatchTerminalState.CANCELED_NO_FILL],
)
def test_exact_terminal_proof_clears_only_matching_latch_and_releases_no_fill_capacity(
    tmp_path, scope, policy, terminal_state
):
    authority = FakeVerifiedExecutionJournalAuthority()
    gate, _, _, binding = _claimed_gate(
        tmp_path, scope, policy, authority, name="terminal-" + terminal_state.value.lower()
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
    assert gate.reserve(make_intent(scope, "after-no-fill", notional="100")).notional == Decimal(
        "100"
    )


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
    assert over_limit.value.code == "INCREASE_NOTIONAL_LIMIT"


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
    gate, _, _, binding = _claimed_gate(tmp_path, scope, policy, authority, name="invalid-" + case)
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
    gate, _, _, binding = _claimed_gate(tmp_path, scope, policy, authority, name="invalid-fill")
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
        _terminal_proof(binding, evidence_class=DispatchEvidenceClass.NATIVE_PROVIDER_JOURNAL)

    proof = _terminal_proof(binding)
    with pytest.raises(PermitInvalidError) as unknown:
        gate.resolve_dispatch_freeze(proof)
    assert unknown.value.code == "DISPATCH_RESOLUTION_PROOF_REJECTED"
    assert gate.active_freeze_reasons(scope) == [binding.cause_id]


def test_dispatch_proof_replay_is_rejected_after_restart(tmp_path, scope, policy):
    authority = FakeVerifiedExecutionJournalAuthority()
    gate, _, _, binding = _claimed_gate(tmp_path, scope, policy, authority, name="proof-restart")
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
    gate, _, _, binding = _claimed_gate(tmp_path, scope, policy, authority, name="proof-concurrent")
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
        count = connection.execute("SELECT COUNT(*) FROM risk_dispatch_resolutions").fetchone()[0]
    assert count == 1


def test_dispatch_latch_namespace_cannot_be_created_or_cleared_generically(tmp_path, scope, policy):
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


@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity"), True])
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


def test_exact_retry_after_freeze_does_not_return_an_admitted_increase(tmp_path, scope, policy):
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


def test_concurrent_connections_cannot_oversubscribe_account_budget(tmp_path, scope, policy):
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
    assert results.count("INCREASE_NOTIONAL_LIMIT") == 6
    reopened = DurableRiskGate(database, policy)
    assert reopened.snapshot(scope)["increase_notional"] == Decimal("80")


def test_public_exports_are_defined():
    import bt_api_risk

    assert all(hasattr(bt_api_risk, name) for name in bt_api_risk.__all__)
    assert "DurableRiskGate" in bt_api_risk.__all__


def test_risk_payload_binding_is_immutable(scope):
    from dataclasses import FrozenInstanceError

    intent = make_intent(scope, "immutable")
    fingerprint = intent.fingerprint
    with pytest.raises(FrozenInstanceError):
        intent.payload_fingerprint = "changed"
    with pytest.raises(ValueError, match="immutable"):
        RiskIntent("mutable", scope, IntentAction.INCREASE, Decimal("1"), {"quantity": 1})
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
    assert results.count("INCREASE_NOTIONAL_LIMIT") == 2
    assert gate.snapshot(scope)["increase_notional"] == Decimal("80")


def test_atomic_dispatch_claim_fences_two_prevalidated_processes(tmp_path, scope, policy):
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
