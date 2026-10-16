"""A CANCEL permit cannot claim dispatch after an SQLite writer-lock wait."""

from __future__ import annotations

from decimal import Decimal
from threading import Event, Thread

import pytest

from bt_api_risk import AccountScope, DurableRiskGate, IntentAction, PermitInvalidError, RiskIntent, RiskPolicy


class _ObservedClock:
    def __init__(self, value: float) -> None:
        self.value = value
        self.observe = False
        self.first_claim_sample = Event()

    def __call__(self) -> float:
        if self.observe:
            self.first_claim_sample.set()
        return self.value


def test_cancel_claim_rechecks_ttl_after_reservations_only_sqlite_wait(tmp_path) -> None:
    clock = _ObservedClock(1_700_000_000.0)
    scope = AccountScope(provider="fake", account_id="account-cancel", environment="sandbox")
    gate = DurableRiskGate(
        tmp_path / "cancel-claim-expiry.sqlite3",
        RiskPolicy(
            "cancel-claim-expiry-v1",
            Decimal("100"),
            max_increase_count=1,
            permit_ttl_seconds=1.0,
        ),
        clock=clock,
    )
    intent = RiskIntent(
        intent_id="cancel-expiring-under-lock",
        scope=scope,
        action=IntentAction.CANCEL,
        notional=Decimal("0"),
        payload_fingerprint="cancel-expiry-payload",
    )
    permit = gate.reserve(intent)
    writer_locked = Event()
    release_writer = Event()
    writer_errors: list[BaseException] = []
    outcome: dict[str, object] = {}

    def hold_writer_lock() -> None:
        try:
            with gate._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                writer_locked.set()
                if not release_writer.wait(5):
                    raise TimeoutError("test did not release its SQLite writer lock")
                connection.execute("ROLLBACK")
        except BaseException as error:  # surfaced after joining the test thread
            writer_errors.append(error)

    def claim() -> None:
        try:
            outcome["permit"] = gate.claim_for_dispatch(permit.permit_id, intent)
        except BaseException as error:  # asserted by the owning test thread
            outcome["error"] = error

    writer = Thread(target=hold_writer_lock, daemon=True)
    writer.start()
    assert writer_locked.wait(2), "synthetic writer did not acquire the SQLite lock"
    clock.observe = True
    operation = Thread(target=claim, daemon=True)
    operation.start()
    try:
        assert clock.first_claim_sample.wait(2), "claim did not sample its pre-transaction clock"
        # The claim is now blocked at BEGIN IMMEDIATE. Advance the same fake
        # clock past the permit TTL before the owner acquires the transaction.
        clock.value += 2.0
    finally:
        release_writer.set()
    operation.join(5)
    writer.join(5)

    assert not operation.is_alive(), "claim stayed blocked after writer release"
    assert not writer.is_alive(), "synthetic writer did not stop"
    assert writer_errors == []
    error = outcome.get("error")
    assert isinstance(error, PermitInvalidError)
    assert error.code == "PERMIT_NOT_ACTIVE"
    assert "permit" not in outcome
    with gate._connection() as connection:
        claim_row = connection.execute(
            "SELECT 1 FROM risk_dispatch_claims WHERE permit_id = ?", (permit.permit_id,)
        ).fetchone()
    assert claim_row is None
    assert gate.active_freeze_reasons(scope) == []
    gate.close()
