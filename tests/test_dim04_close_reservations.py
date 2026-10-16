"""DIM04 increment 1: per-strategy closable-position reservations.

A bound close is a REDUCE intent carrying the full attribution binding
(``strategy_id`` + ``allocation_version``, ``instrument``, ``quantity``,
``quantity_unit``).  Only bound closes engage the declare/reserve/attribute
ledger installed through ``set_closable_position``; a REDUCE without the
full binding keeps the established behavior exactly, which test 7 proves by
replaying one legacy scenario against both this worktree and the ``e2bedb3``
head revision of ``admission.py`` and comparing the canonical JSON output
byte for byte.

Everything here is synthetic local SQLite at package level: the real
``DurableRiskGate``, real transactions, a controllable clock, no provider,
no network, and no monkeypatching of gate internals.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from decimal import Decimal
from hashlib import sha256
from pathlib import Path

import bt_api_base
import pytest

import bt_api_risk
from bt_api_risk import (
    AccountScope,
    DurableRiskGate,
    IntentAction,
    RiskDeniedError,
    RiskIntent,
    RiskPolicy,
)
from bt_api_risk.core.admission import ClosablePositionSnapshot

_FACTS_OBSERVED_NS = 100_000_000_000
_FACTS_VALID_UNTIL_NS = 1_000_000_000_000
_HEAD_REVISION = "e2bedb3"


class _Clock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _sha(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _gate(
    tmp_path,
    *,
    strategies: tuple[str, ...] = (),
    ttl: float = 5.0,
    database: str = "close-reservations.sqlite3",
) -> tuple[DurableRiskGate, AccountScope, _Clock]:
    clock = _Clock()
    scope = AccountScope("fixture", "account-1", "sandbox")
    gate = DurableRiskGate(
        tmp_path / database,
        RiskPolicy(
            "close-position-policy",
            Decimal("1000"),
            32,
            permit_ttl_seconds=ttl,
            require_strategy_allocation=True,
            notional_unit="USD",
        ),
        clock=clock,
    )
    for strategy_id in strategies:
        gate.set_strategy_allocation(
            scope,
            strategy_id,
            "allocation-v1",
            max_notional=Decimal("1000"),
            notional_unit="USD",
        )
    return gate, scope, clock


def _declare(
    gate: DurableRiskGate,
    scope: AccountScope,
    instrument: str,
    strategy_id: str,
    version: str,
    quantity: str,
    *,
    unit: str = "contract",
) -> None:
    gate.set_closable_position(
        scope,
        instrument,
        strategy_id,
        version,
        closable_quantity=Decimal(quantity),
        quantity_unit=unit,
    )


def _increase(
    scope: AccountScope,
    intent_id: str,
    *,
    strategy_id: str = "strategy-a",
    instrument: str = "venue/increase-a",
    quantity: str = "1",
    notional: str = "10",
) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal(notional),
        payload_fingerprint=_sha("increase|" + intent_id),
        strategy_id=strategy_id,
        allocation_version="allocation-v1",
        instrument=instrument,
        quantity=Decimal(quantity),
        quantity_unit="contract",
        notional_unit="USD",
        exposure_profile_fingerprint=_sha("profile|" + instrument),
        instrument_facts_observed_at_ns=_FACTS_OBSERVED_NS,
        instrument_facts_valid_until_ns=_FACTS_VALID_UNTIL_NS,
    )


def _bound_close(
    scope: AccountScope,
    intent_id: str,
    *,
    instrument: str,
    quantity: str = "1",
    quantity_unit: str = "contract",
    strategy_id: str = "strategy-a",
) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.REDUCE,
        notional=Decimal("0"),
        payload_fingerprint=_sha("bound-close|" + intent_id),
        strategy_id=strategy_id,
        allocation_version="allocation-v1",
        instrument=instrument,
        quantity=Decimal(quantity),
        quantity_unit=quantity_unit,
        notional_unit="USD",
        exposure_profile_fingerprint=_sha("profile|" + instrument),
        instrument_facts_observed_at_ns=_FACTS_OBSERVED_NS,
        instrument_facts_valid_until_ns=_FACTS_VALID_UNTIL_NS,
    )


def _legacy_reduce(scope: AccountScope, intent_id: str) -> RiskIntent:
    """The only legacy REDUCE shape the established suite uses: no binding."""

    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.REDUCE,
        notional=Decimal("0"),
        payload_fingerprint="deterministic-test-payload",
    )


def _row(gate: DurableRiskGate, permit_id: str) -> dict:
    with gate._connection() as connection:
        row = connection.execute(
            "SELECT * FROM risk_reservations WHERE permit_id = ?", (permit_id,)
        ).fetchone()
    return dict(row)


def _count(gate: DurableRiskGate) -> int:
    with gate._connection() as connection:
        return connection.execute("SELECT COUNT(*) FROM risk_reservations").fetchone()[0]


def test_net_share_two_strategies_cannot_cross_declared_shares(tmp_path):
    gate, scope, _ = _gate(tmp_path, strategies=("strategy-a", "strategy-b"))
    instrument = "venue/net-share"
    _declare(gate, scope, instrument, "strategy-a", "share-v1", "4")
    _declare(gate, scope, instrument, "strategy-b", "share-v1", "3")

    first = gate.reserve(_bound_close(scope, "close-a-3", instrument=instrument, quantity="3"))
    row_first = _row(gate, first.permit_id)
    assert row_first["action"] == "reduce"
    assert row_first["close_position_version"] == "share-v1"

    snapshot_a = gate.get_closable_position(scope, instrument, "strategy-a")
    assert isinstance(snapshot_a, ClosablePositionSnapshot)
    assert snapshot_a.revision == "share-v1"
    assert snapshot_a.declared_quantity == Decimal("4")
    assert snapshot_a.used_quantity == Decimal("3")
    assert snapshot_a.available_quantity == Decimal("1")
    assert snapshot_a.quantity_unit == "contract"
    assert snapshot_a.completeness == "LOCAL_LEDGER_COMPLETE"
    assert snapshot_a.source == "local_closable_position_ledger"
    assert snapshot_a.as_of == 100.0

    # Equality with the declared share is admitted...
    second = gate.reserve(_bound_close(scope, "close-a-1", instrument=instrument, quantity="1"))
    assert second.intent_id == "close-a-1"
    snapshot_a = gate.get_closable_position(scope, instrument, "strategy-a")
    assert snapshot_a.used_quantity == Decimal("4")
    assert snapshot_a.available_quantity == Decimal("0")

    # ...but one more step is denied with CLOSE_QUANTITY_EXHAUSTED even though
    # the account's combined declared share across both strategies is 7: the
    # per-strategy key is the hard boundary, never the account total.
    before = _count(gate)
    with pytest.raises(RiskDeniedError) as exhausted:
        gate.reserve(_bound_close(scope, "close-a-over", instrument=instrument, quantity="0.01"))
    assert exhausted.value.code == "CLOSE_QUANTITY_EXHAUSTED"
    assert _count(gate) == before

    # Strategy B's independent share starts fully available and is never
    # widened or reduced by strategy A's usage.
    b_first = gate.reserve(
        _bound_close(scope, "close-b-3", instrument=instrument, quantity="3", strategy_id="strategy-b")
    )
    assert _row(gate, b_first.permit_id)["close_position_version"] == "share-v1"
    snapshot_b = gate.get_closable_position(scope, instrument, "strategy-b")
    assert snapshot_b.declared_quantity == Decimal("3")
    assert snapshot_b.used_quantity == Decimal("3")
    assert snapshot_b.available_quantity == Decimal("0")
    before = _count(gate)
    with pytest.raises(RiskDeniedError) as b_over:
        gate.reserve(
            _bound_close(
                scope, "close-b-over", instrument=instrument, quantity="0.01", strategy_id="strategy-b"
            )
        )
    assert b_over.value.code == "CLOSE_QUANTITY_EXHAUSTED"
    assert _count(gate) == before
    gate.close()


def test_declaration_versions_are_immutable_and_gate_future_reservations(tmp_path):
    gate, scope, _ = _gate(tmp_path, strategies=("strategy-a",))
    instrument = "venue/versions"
    _declare(gate, scope, instrument, "strategy-a", "decl-v1", "2")
    # Identical facts under the same current version are an idempotent no-op.
    _declare(gate, scope, instrument, "strategy-a", "decl-v1", "2")
    # The same version with changed facts is rejected.
    with pytest.raises(ValueError, match="changed facts"):
        _declare(gate, scope, instrument, "strategy-a", "decl-v1", "3")

    occupancy = gate.reserve(
        _bound_close(scope, "close-v1-full", instrument=instrument, quantity="2")
    )
    assert _row(gate, occupancy.permit_id)["close_position_version"] == "decl-v1"

    # A raised revision gates future reservations only: the outstanding row
    # keeps its face-value occupation, so exactly one more contract fits.
    _declare(gate, scope, instrument, "strategy-a", "decl-v2", "3")
    # A retired version can never be replayed, even with identical facts.
    with pytest.raises(ValueError, match="cannot be reused"):
        _declare(gate, scope, instrument, "strategy-a", "decl-v1", "2")
    snapshot = gate.get_closable_position(scope, instrument, "strategy-a")
    assert snapshot.revision == "decl-v2"
    assert snapshot.used_quantity == Decimal("2")
    assert snapshot.available_quantity == Decimal("1")

    extra = gate.reserve(_bound_close(scope, "close-v2-extra", instrument=instrument, quantity="1"))
    assert _row(gate, extra.permit_id)["close_position_version"] == "decl-v2"
    with pytest.raises(RiskDeniedError) as over:
        gate.reserve(_bound_close(scope, "close-v2-over", instrument=instrument, quantity="0.01"))
    assert over.value.code == "CLOSE_QUANTITY_EXHAUSTED"
    gate.close()


def test_bound_close_requires_declaration_and_matching_unit(tmp_path):
    gate, scope, _ = _gate(tmp_path, strategies=("strategy-a",))
    instrument = "venue/configured"

    # No declaration for (scope, instrument, strategy): fail closed, write nothing.
    before = _count(gate)
    with pytest.raises(RiskDeniedError) as unconfigured:
        gate.reserve(_bound_close(scope, "close-unconfigured", instrument=instrument))
    assert unconfigured.value.code == "CLOSE_POSITION_UNCONFIGURED"
    assert _count(gate) == before
    with pytest.raises(RiskDeniedError) as read_denied:
        gate.get_closable_position(scope, instrument, "strategy-a")
    assert read_denied.value.code == "CLOSE_POSITION_UNCONFIGURED"

    _declare(gate, scope, instrument, "strategy-a", "decl-v1", "5")

    # A quantity unit that does not match the declaration fails closed too.
    with pytest.raises(RiskDeniedError) as unit_mismatch:
        gate.reserve(_bound_close(scope, "close-unit", instrument=instrument, quantity_unit="lot"))
    assert unit_mismatch.value.code == "CLOSE_POSITION_UNIT_MISMATCH"
    assert _count(gate) == before

    admitted = gate.reserve(_bound_close(scope, "close-ok", instrument=instrument))
    row = _row(gate, admitted.permit_id)
    assert row["quantity_unit"] == "contract"
    assert row["close_position_version"] == "decl-v1"
    gate.close()


def test_late_fill_consumes_credit_permanently_and_expiry_returns_credit(tmp_path):
    gate, scope, clock = _gate(tmp_path, strategies=("strategy-a", "strategy-c"))

    # --- late fill: claimed + settled permanently consumes the credit ---
    late_instrument = "venue/late-fill"
    _declare(gate, scope, late_instrument, "strategy-a", "decl-v1", "2")
    late_intent = _bound_close(scope, "close-late", instrument=late_instrument, quantity="2")
    claimed = gate.reserve(late_intent)
    gate.claim_for_dispatch(claimed.permit_id, late_intent)
    clock.value += 10.0  # the outcome arrives long after the permit TTL

    # A claimed row never expires (no fill can exist without a claim, but a
    # claim may already be in flight), so the full share stays occupied and a
    # second reservation cannot re-credit it.
    with pytest.raises(RiskDeniedError) as exhausted:
        gate.reserve(
            _bound_close(scope, "close-late-second", instrument=late_instrument, quantity="0.01")
        )
    assert exhausted.value.code == "CLOSE_QUANTITY_EXHAUSTED"
    assert _row(gate, claimed.permit_id)["status"] == "active"

    gate.settle(claimed.permit_id)
    row = _row(gate, claimed.permit_id)
    assert row["status"] == "settled"
    assert row["close_position_version"] == "decl-v1"
    # The late settle stays consumed forever: still no credit returns.
    with pytest.raises(RiskDeniedError) as still_exhausted:
        gate.reserve(
            _bound_close(scope, "close-late-third", instrument=late_instrument, quantity="0.01")
        )
    assert still_exhausted.value.code == "CLOSE_QUANTITY_EXHAUSTED"
    late_snapshot = gate.get_closable_position(scope, late_instrument, "strategy-a")
    assert late_snapshot.used_quantity == Decimal("2")
    assert late_snapshot.available_quantity == Decimal("0")

    # --- unclaimed active: expires at the TTL and returns its credit ---
    expiring_instrument = "venue/expiring"
    _declare(gate, scope, expiring_instrument, "strategy-c", "decl-v1", "2")
    first = gate.reserve(
        _bound_close(
            scope, "close-expiring-first", instrument=expiring_instrument, quantity="2",
            strategy_id="strategy-c",
        )
    )
    assert (
        gate.get_closable_position(scope, expiring_instrument, "strategy-c").used_quantity
        == Decimal("2")
    )
    clock.value += 10.0
    second = gate.reserve(
        _bound_close(
            scope, "close-expiring-second", instrument=expiring_instrument, quantity="2",
            strategy_id="strategy-c",
        )
    )
    assert _row(gate, first.permit_id)["status"] == "expired"
    assert _row(gate, second.permit_id)["status"] == "active"
    expired_snapshot = gate.get_closable_position(scope, expiring_instrument, "strategy-c")
    assert expired_snapshot.used_quantity == Decimal("2")  # only the new active row
    assert expired_snapshot.available_quantity == Decimal("0")
    gate.close()


def test_self_trade_conflict_both_directions(tmp_path):
    gate, scope, clock = _gate(tmp_path, strategies=("strategy-a",))
    instrument = "venue/self-trade"
    _declare(gate, scope, instrument, "strategy-a", "decl-v1", "5")

    increase_permit = gate.reserve(_increase(scope, "increase-self", instrument=instrument))

    # Direction 1: a bound close is refused while any ACTIVE increase exists.
    before = _count(gate)
    with pytest.raises(RiskDeniedError) as close_conflict:
        gate.reserve(_bound_close(scope, "close-against-increase", instrument=instrument))
    assert close_conflict.value.code == "SELF_TRADE_CONFLICT"
    assert _count(gate) == before

    # The guard is binding-gated: a legacy REDUCE without the full binding is
    # admitted exactly as before, even with the active increase present.
    legacy = gate.reserve(_legacy_reduce(scope, "legacy-reduce-self"))
    assert legacy.action is IntentAction.REDUCE
    assert _row(gate, legacy.permit_id)["close_position_version"] is None

    # Once the increase expires at the TTL, the same bound close shape is admitted.
    clock.value += 10.0
    bounding = gate.reserve(_bound_close(scope, "close-after-expiry", instrument=instrument))
    assert _row(gate, increase_permit.permit_id)["status"] == "expired"

    # Direction 2: a new increase is refused while an ACTIVE bound close exists.
    before = _count(gate)
    with pytest.raises(RiskDeniedError) as increase_conflict:
        gate.reserve(_increase(scope, "increase-against-close", instrument=instrument))
    assert increase_conflict.value.code == "SELF_TRADE_CONFLICT"
    assert _count(gate) == before

    # The guard is scoped to one account instrument: another instrument never conflicts.
    other = gate.reserve(_increase(scope, "increase-other-instrument", instrument="venue/other"))
    assert other.intent_id == "increase-other-instrument"

    # The bound close's own TTL clears direction two as well.
    clock.value += 10.0
    retry = gate.reserve(_increase(scope, "increase-retry", instrument=instrument))
    assert _row(gate, bounding.permit_id)["status"] == "expired"
    assert retry.intent_id == "increase-retry"
    gate.close()


def test_strategy_batch_release_scopes_claims_and_ownership(tmp_path):
    gate, scope, _ = _gate(tmp_path, strategies=("strategy-a", "strategy-b"))
    a_instrument = "venue/release-a"
    b_instrument = "venue/release-b"
    _declare(gate, scope, a_instrument, "strategy-a", "decl-v1", "2")
    _declare(gate, scope, b_instrument, "strategy-b", "decl-v1", "2")

    a_close = gate.reserve(_bound_close(scope, "batch-a-close", instrument=a_instrument, quantity="1"))
    b_close = gate.reserve(
        _bound_close(
            scope, "batch-b-close", instrument=b_instrument, quantity="1", strategy_id="strategy-b"
        )
    )
    a_open = gate.reserve(_increase(scope, "batch-a-open", instrument="venue/a-open"))

    # The batch releases exactly this strategy's ACTIVE unclaimed rows.
    released = gate.release_strategy_unclaimed(scope, "strategy-a", "owner-batch-cancel")
    assert released == tuple(sorted((a_close.permit_id, a_open.permit_id)))
    assert _row(gate, a_close.permit_id)["status"] == "released"
    assert _row(gate, a_open.permit_id)["status"] == "released"
    # Another strategy's rows are never touched.
    assert _row(gate, b_close.permit_id)["status"] == "active"
    a_snapshot = gate.get_closable_position(scope, a_instrument, "strategy-a")
    assert a_snapshot.used_quantity == Decimal("0")
    assert a_snapshot.available_quantity == Decimal("2")
    b_snapshot = gate.get_closable_position(scope, b_instrument, "strategy-b")
    assert b_snapshot.used_quantity == Decimal("1")

    # A claimed, unresolved own row keeps the whole batch fail-closed.
    still_instrument = "venue/still-a"
    _declare(gate, scope, still_instrument, "strategy-a", "decl-v1", "1")
    claimed_intent = _bound_close(scope, "batch-a-claimed", instrument=a_instrument, quantity="2")
    claimed = gate.reserve(claimed_intent)
    gate.claim_for_dispatch(claimed.permit_id, claimed_intent)
    still = gate.reserve(_bound_close(scope, "batch-a-still", instrument=still_instrument, quantity="1"))

    with pytest.raises(RiskDeniedError) as unresolved:
        gate.release_strategy_unclaimed(scope, "strategy-a", "owner-batch-cancel")
    assert unresolved.value.code == "STRATEGY_CLAIM_UNRESOLVED"
    assert _row(gate, still.permit_id)["status"] == "active"  # nothing was released
    assert _row(gate, claimed.permit_id)["status"] == "active"
    assert _row(gate, b_close.permit_id)["status"] == "active"

    # Once the claimed row resolves, the batch releases exactly the remaining
    # unclaimed row and never rewrites the resolved one.
    gate.settle(claimed.permit_id)
    released_after = gate.release_strategy_unclaimed(scope, "strategy-a", "owner-batch-cancel-retry")
    assert released_after == (still.permit_id,)
    assert _row(gate, still.permit_id)["status"] == "released"
    assert _row(gate, claimed.permit_id)["status"] == "settled"
    assert _row(gate, b_close.permit_id)["status"] == "active"

    # An empty batch is a no-op.
    assert gate.release_strategy_unclaimed(scope, "strategy-a", "owner-batch-cancel") == ()

    # Strategy B's batch reaches only strategy B.
    released_b = gate.release_strategy_unclaimed(scope, "strategy-b", "owner-b-batch")
    assert released_b == (b_close.permit_id,)
    assert gate.get_closable_position(scope, b_instrument, "strategy-b").used_quantity == Decimal("0")

    with pytest.raises(ValueError):
        gate.release_strategy_unclaimed(scope, "bad strategy!", "reason")
    with pytest.raises(ValueError):
        gate.release_strategy_unclaimed(scope, "strategy-a", "   ")
    gate.close()


_LEGACY_PARITY_PROBE = r'''
import hashlib
import json
import sys
from decimal import Decimal

from bt_api_risk import (
    AccountScope,
    DurableRiskGate,
    IntentAction,
    RiskIntent,
    RiskPolicy,
)


def _sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def run(db_path):
    scope = AccountScope("fixture", "account-1", "sandbox")
    gate = DurableRiskGate(
        db_path,
        RiskPolicy(
            "legacy-parity-policy",
            Decimal("1000"),
            8,
            permit_ttl_seconds=5.0,
            require_strategy_allocation=True,
            notional_unit="USD",
        ),
        clock=lambda: 100.0,
    )
    try:
        gate.set_strategy_allocation(
            scope,
            "strategy-a",
            "allocation-v1",
            max_notional=Decimal("1000"),
            notional_unit="USD",
        )
        increase = RiskIntent(
            intent_id="parity-increase",
            scope=scope,
            action=IntentAction.INCREASE,
            notional=Decimal("10"),
            payload_fingerprint=_sha("parity-increase"),
            strategy_id="strategy-a",
            allocation_version="allocation-v1",
            instrument="venue/parity",
            quantity=Decimal("1"),
            quantity_unit="contract",
            notional_unit="USD",
            exposure_profile_fingerprint=_sha("parity-profile"),
            instrument_facts_observed_at_ns=100_000_000_000,
            instrument_facts_valid_until_ns=1_000_000_000_000,
        )
        increase_permit = gate.reserve(increase)
        reduce_intent = RiskIntent(
            intent_id="parity-reduce",
            scope=scope,
            action=IntentAction.REDUCE,
            notional=Decimal("0"),
            payload_fingerprint="deterministic-test-payload",
        )
        reduce_permit = gate.reserve(reduce_intent)
        replay = gate.reserve(reduce_intent)
        gate.claim_for_dispatch(reduce_permit.permit_id, reduce_intent)
        gate.settle(reduce_permit.permit_id)
        with gate._connection() as connection:
            rows = [
                {
                    key: row[key]
                    for key in row.keys()
                    if key not in ("permit_id", "close_position_version")
                }
                for row in connection.execute(
                    "SELECT * FROM risk_reservations ORDER BY intent_id"
                ).fetchall()
            ]
        return {
            "increase_permit_intent": increase_permit.intent_id,
            "reduce_permit_intent": reduce_permit.intent_id,
            "replay_same_permit": replay.permit_id == reduce_permit.permit_id,
            "rows": rows,
            "snapshot": gate.snapshot(scope),
        }
    finally:
        gate.close()


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1]), sort_keys=True, separators=(",", ":"), default=str))
'''


def test_legacy_reduce_without_binding_matches_head_revision(tmp_path):
    gate, scope, _ = _gate(tmp_path, strategies=("strategy-a",))

    # Make the closable ledger real and fully occupied, and add an active
    # increase on another instrument: any accidental engagement of the new
    # machinery would deny or rewrite this legacy REDUCE, and none may.
    instrument = "venue/legacy-occupied"
    _declare(gate, scope, instrument, "strategy-a", "decl-v1", "1")
    gate.reserve(_bound_close(scope, "legacy-occupant", instrument=instrument, quantity="1"))
    gate.reserve(_increase(scope, "legacy-increase", instrument="venue/legacy-increase"))

    legacy_intent = _legacy_reduce(scope, "legacy-reduce")
    permit = gate.reserve(legacy_intent)
    row = _row(gate, permit.permit_id)
    assert row["action"] == "reduce"
    assert row["strategy_id"] is None
    assert row["instrument"] is None
    assert row["quantity"] is None
    assert row["close_position_version"] is None
    # The dispatch lifecycle is unchanged as well.
    gate.claim_for_dispatch(permit.permit_id, legacy_intent)
    settled = gate.settle(permit.permit_id)
    assert settled.action is IntentAction.REDUCE

    # Byte-level control against the head revision: run one identical legacy
    # scenario against e2bedb3's admission.py in a subprocess and against this
    # worktree in-process; the canonical JSON must match exactly.
    package_dir = Path(bt_api_risk.__file__).resolve().parent
    probe_path = tmp_path / "legacy_parity_probe.py"
    probe_path.write_text(_LEGACY_PARITY_PROBE, encoding="utf-8")
    try:
        located = subprocess.run(
            ["git", "-C", str(package_dir), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
        )
    except OSError:
        pytest.skip("git is not available; the head-parity comparison cannot run")
    if located.returncode != 0:
        pytest.skip("not a git checkout; the head-parity comparison cannot run")
    head_show = subprocess.run(
        [
            "git",
            "-C",
            located.stdout.strip(),
            "show",
            _HEAD_REVISION + ":src/bt_api_risk/core/admission.py",
        ],
        capture_output=True,
    )
    if head_show.returncode != 0:
        pytest.skip("the head revision of admission.py is unavailable")

    head_source = tmp_path / "head-source"
    if head_source.exists():
        shutil.rmtree(head_source)
    shutil.copytree(
        package_dir,
        head_source / "bt_api_risk",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    (head_source / "bt_api_risk" / "core" / "admission.py").write_bytes(head_show.stdout)

    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(head_source), str(Path(bt_api_base.__file__).resolve().parent.parent)]
    )
    completed = subprocess.run(
        [sys.executable, str(probe_path), str(tmp_path / "head-parity.sqlite3")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=environment,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr

    spec = importlib.util.spec_from_file_location("legacy_parity_probe", probe_path)
    assert spec is not None and spec.loader is not None
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    worktree_result = probe.run(str(tmp_path / "worktree-parity.sqlite3"))
    canonical = json.dumps(worktree_result, sort_keys=True, separators=(",", ":"), default=str)
    assert completed.stdout.strip() == canonical

    head_result = json.loads(completed.stdout)
    assert head_result["replay_same_permit"] is True
    assert head_result["reduce_permit_intent"] == "parity-reduce"
    legacy_rows = [row for row in worktree_result["rows"] if row["intent_id"] == "parity-reduce"]
    assert len(legacy_rows) == 1
    assert legacy_rows[0]["strategy_id"] is None
    gate.close()
