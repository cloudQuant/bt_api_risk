"""Shared-collateral domain admission is one durable, trusted risk budget."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from threading import Barrier

import pytest
from bt_api_base.account_protocol import AccountResourceKey

from bt_api_risk import (
    AccountScope,
    DurableRiskGate,
    ExposureAccountingMode,
    GrossExposureBaselineProof,
    IntentAction,
    OrderExposureState,
    PermitInvalidError,
    RiskDeniedError,
    RiskGroupLegIntent,
    RiskIntent,
    RiskPolicy,
)
from test_live_gross_exposure import (
    SyntheticJournalAuthority as _SyntheticJournalAuthority,
    _NOW as _ORDER_NOW,
    _NOW_NS as _ORDER_NOW_NS,
    _observation as _order_observation,
    _sha as _order_sha,
    _tracked_order as _track_order,
)


_RESOURCE_A = AccountResourceKey(product_type="futures", margin_pool="cross-domain")
_RESOURCE_B = AccountResourceKey(product_type="options", margin_pool="cross-domain")


def _policy() -> RiskPolicy:
    return RiskPolicy(
        "shared-collateral-policy",
        Decimal("1000"),
        16,
        permit_ttl_seconds=5.0,
        require_strategy_allocation=True,
        notional_unit="USD",
    )


def _gate(path: Path, scopes: tuple[AccountScope, ...]) -> DurableRiskGate:
    gate = DurableRiskGate(path, _policy(), clock=lambda: 100.0)
    for scope in scopes:
        gate.set_strategy_allocation(
            scope,
            "strategy-1",
            "allocation-v1",
            max_notional=Decimal("1000"),
            notional_unit="USD",
        )
    return gate


def _intent(
    scope: AccountScope,
    intent_id: str,
    notional: str,
    *,
    resource: AccountResourceKey | None,
    action: IntentAction = IntentAction.INCREASE,
) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=action,
        notional=Decimal(notional),
        payload_fingerprint=hashlib.sha256(intent_id.encode("utf-8")).hexdigest(),
        strategy_id="strategy-1",
        allocation_version="allocation-v1",
        notional_unit="USD" if action is IntentAction.INCREASE else None,
        resource=resource,
    )


def _group_intent(
    scope: AccountScope,
    intent_id: str,
    notional: str,
    *,
    resource: AccountResourceKey,
    facts_observed_at_ns: int = 100_000_000_000,
    facts_valid_until_ns: int = 1_000_000_000_000,
) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal(notional),
        payload_fingerprint=hashlib.sha256(intent_id.encode("utf-8")).hexdigest(),
        strategy_id="strategy-1",
        allocation_version="allocation-v1",
        instrument="venue/contract-" + intent_id,
        quantity=Decimal("1"),
        quantity_unit="contract",
        notional_unit="USD",
        exposure_profile_fingerprint=hashlib.sha256(
            ("profile/" + intent_id).encode("utf-8")
        ).hexdigest(),
        instrument_facts_observed_at_ns=facts_observed_at_ns,
        instrument_facts_valid_until_ns=facts_valid_until_ns,
        resource=resource,
    )


def _counts(gate: DurableRiskGate) -> tuple[int, int]:
    with gate._connection() as connection:
        return (
            int(connection.execute("SELECT COUNT(*) FROM risk_reservations").fetchone()[0]),
            int(connection.execute("SELECT COUNT(*) FROM risk_dispatch_claims").fetchone()[0]),
        )


def _database_snapshot(gate: DurableRiskGate) -> tuple[object, ...]:
    """Capture every SQLite schema object and table row before denied admission."""

    with gate._connection() as connection:
        schema = tuple(
            tuple(row)
            for row in connection.execute(
                """SELECT type, name, sql FROM sqlite_schema
                   WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"""
            )
        )
        table_names = tuple(
            str(row[0])
            for row in connection.execute(
                """SELECT name FROM sqlite_schema
                   WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"""
            )
        )
        tables = tuple(
            (
                name,
                tuple(
                    sorted(
                        (tuple(row) for row in connection.execute(f'SELECT * FROM "{name}"')),
                        key=repr,
                    )
                ),
            )
            for name in table_names
        )
    return schema, tables


def _live_order_intent(
    scope: AccountScope,
    intent_id: str,
    notional: str,
    resource: AccountResourceKey,
) -> RiskIntent:
    return RiskIntent(
        intent_id=intent_id,
        scope=scope,
        action=IntentAction.INCREASE,
        notional=Decimal(notional),
        payload_fingerprint=hashlib.sha256(intent_id.encode("utf-8")).hexdigest(),
        strategy_id="strategy-1",
        allocation_version="allocation-v1",
        instrument="BTC-USDT",
        quantity=Decimal("5"),
        quantity_unit="BTC",
        notional_unit="USD",
        resource=resource,
    )


def _live_gate(path: Path, scopes: tuple[AccountScope, ...]) -> DurableRiskGate:
    policy = RiskPolicy(
        "shared-collateral-live-gross-policy",
        Decimal("1000"),
        16,
        permit_ttl_seconds=10.0,
        require_strategy_allocation=True,
        notional_unit="USD",
        exposure_accounting_mode=ExposureAccountingMode.LIVE_GROSS,
        max_gross_occupancy_notional=Decimal("1000"),
        max_gross_occupancy_intent_count=16,
        max_exposure_facts_age_seconds=3600,
    )
    authority = _SyntheticJournalAuthority()
    gate = DurableRiskGate(
        path,
        policy,
        clock=lambda: _ORDER_NOW,
        execution_journal_authority=authority,
        gross_exposure_authority=authority,
    )
    for index, scope in enumerate(scopes):
        resource = _RESOURCE_A if index == 0 else _RESOURCE_B
        gate.set_strategy_allocation(
            scope,
            "strategy-1",
            "allocation-v1",
            max_notional=Decimal("1000"),
            notional_unit="USD",
            max_gross_occupancy_notional=Decimal("1000"),
            max_gross_occupancy_intent_count=16,
        )
        gate.set_margin_pool_limit(
            scope,
            resource.product_type,
            resource.margin_pool,
            "allocation-v1",
            max_notional=Decimal("300"),
        )
        gate.install_gross_exposure_baseline(
            GrossExposureBaselineProof(
                scope=scope,
                account_revision=1,
                notional_unit="USD",
                account_gross_notional=Decimal("0"),
                account_active_increase_intent_count=0,
                strategy_baselines=(),
                unmanaged_open_order_count=0,
                complete_positions=True,
                complete_open_orders=True,
                source_snapshot_sha256=_order_sha(f"baseline-{index}"),
                positions_sha256=_order_sha(f"positions-{index}"),
                open_orders_sha256=_order_sha(f"orders-{index}"),
                valuation_facts_sha256=_order_sha(f"valuation-{index}"),
                source_schema_version="fixture-baseline-v1",
                observed_at_ns=_ORDER_NOW_NS,
                valid_until_ns=_ORDER_NOW_NS + 3_600_000_000_000,
                writer_owner_id="synthetic-writer",
                writer_fencing_token=1,
                writer_fence_sha256=_order_sha("fence"),
            )
        )
    return gate


def _seed_unknown_increase(
    gate: DurableRiskGate, scope: AccountScope, resource: AccountResourceKey
):
    intent = _live_order_intent(scope, "preexisting-unknown-increase", "100", resource)
    permit, tracked = _track_order(gate, scope, intent)
    unknown = _order_observation(
        scope,
        tracked,
        state=OrderExposureState.UNKNOWN,
        order_revision=1,
        journal_revision=3,
        cumulative_filled_quantity="0",
        leaves_quantity="5",
        filled_gross_notional="0",
        leaves_gross_notional="0",
        complete=False,
        observed_at_ns=_ORDER_NOW_NS - 7_200_000_000_000,
        valid_until_ns=_ORDER_NOW_NS - 3_600_000_000_000,
    )
    snapshot = gate.apply_order_exposure_observation(unknown)
    assert snapshot.state is OrderExposureState.UNKNOWN
    return permit


def _declare(
    gate: DurableRiskGate,
    scopes: tuple[AccountScope, ...],
    members: tuple[tuple[AccountScope, AccountResourceKey], ...],
    *,
    ledger_identity: str | None,
    complete: bool = True,
    cap: str | None = "300",
    revision: str = "domain-v1",
) -> bool:
    return gate.declare_shared_collateral_domain(
        "shared-collateral-main",
        revision,
        scopes,
        members,
        max_notional=None if cap is None else Decimal(cap),
        ledger_identity_ref=ledger_identity,
        manifest_complete=complete,
    )


def test_incomplete_or_ownerless_domain_quarantines_increases_before_any_write(tmp_path):
    scope_a = AccountScope("fixture", "account-a", "sandbox")
    scope_b = AccountScope("fixture", "account-b", "sandbox")
    isolated = AccountScope("fixture", "account-isolated", "sandbox")
    gate = _gate(tmp_path / "risk.sqlite3", (scope_a, scope_b, isolated))
    try:
        legacy_intent = _intent(scope_a, "preexisting-increase", "10", resource=None)
        legacy = gate.reserve(legacy_intent)
        ready = _declare(
            gate,
            (scope_a, scope_b),
            ((scope_a, _RESOURCE_A),),
            ledger_identity=None,
            complete=False,
            cap=None,
        )
        assert ready is False
        before = _database_snapshot(gate)
        assert _counts(gate) == (1, 0)

        with pytest.raises(RiskDeniedError) as keyless:
            gate.reserve(_intent(scope_a, "keyless-increase", "10", resource=None))
        assert keyless.value.code == "SHARED_COLLATERAL_DOMAIN_UNREADY"
        assert _database_snapshot(gate) == before

        with pytest.raises(RiskDeniedError) as mapped:
            gate.reserve(_intent(scope_b, "mapped-increase", "10", resource=_RESOURCE_B))
        assert mapped.value.code == "SHARED_COLLATERAL_DOMAIN_UNREADY"
        assert _database_snapshot(gate) == before
        with pytest.raises(PermitInvalidError) as dispatch:
            gate.claim_for_dispatch(legacy.permit_id, legacy_intent)
        assert dispatch.value.code == "SHARED_COLLATERAL_DOMAIN_UNREADY"
        assert _database_snapshot(gate) == before

        # A declared shared domain does not disable existing risk-reducing
        # behavior or change an unrelated isolated account's legacy path.
        reduce = gate.reserve(
            _intent(scope_a, "existing-reduce-path", "0", resource=None, action=IntentAction.REDUCE)
        )
        assert reduce.action is IntentAction.REDUCE
        cancel = gate.reserve(
            _intent(scope_a, "existing-cancel-path", "0", resource=None, action=IntentAction.CANCEL)
        )
        assert cancel.action is IntentAction.CANCEL
        isolated_permit = gate.reserve(
            _intent(isolated, "isolated-increase", "10", resource=None)
        )
        assert isolated_permit.intent_id == "isolated-increase"
        gate.release(legacy.permit_id, "owner-stopped-before-dispatch")
        with gate._connection() as connection:
            terminal = connection.execute(
                "SELECT status FROM risk_reservations WHERE permit_id = ?",
                (legacy.permit_id,),
            ).fetchone()
        assert terminal["status"] == DurableRiskGate._RELEASED
    finally:
        gate.close()


def test_complete_shared_domain_without_one_ledger_identity_stays_fail_closed(tmp_path):
    scope_a = AccountScope("fixture", "account-a", "sandbox")
    scope_b = AccountScope("fixture", "account-b", "sandbox")
    gate = _gate(tmp_path / "risk.sqlite3", (scope_a, scope_b))
    try:
        ready = _declare(
            gate,
            (scope_a, scope_b),
            ((scope_a, _RESOURCE_A), (scope_b, _RESOURCE_B)),
            ledger_identity=None,
        )
        assert ready is False
        before = _database_snapshot(gate)
        assert _counts(gate) == (0, 0)
        for scope, intent_id, resource in (
            (scope_a, "ownerless-a", _RESOURCE_A),
            (scope_b, "ownerless-b", _RESOURCE_B),
        ):
            with pytest.raises(RiskDeniedError) as denied:
                gate.reserve(_intent(scope, intent_id, "10", resource=resource))
            assert denied.value.code == "SHARED_COLLATERAL_DOMAIN_UNREADY"
            assert _database_snapshot(gate) == before
    finally:
        gate.close()


def test_two_account_keys_and_products_share_one_unknown_and_group_budget(tmp_path):
    scope_a = AccountScope("fixture", "account-a", "sandbox")
    scope_b = AccountScope("fixture", "account-b", "sandbox")
    scopes = (scope_a, scope_b)
    gate = _live_gate(tmp_path / "risk.sqlite3", scopes)
    try:
        first = _seed_unknown_increase(gate, scope_a, _RESOURCE_A)
        with gate._connection() as connection:
            occupied = connection.execute(
                """SELECT reservation.status, exposure.state
                   FROM risk_reservations AS reservation
                   JOIN risk_order_exposures AS exposure
                     ON exposure.permit_id = reservation.permit_id
                   WHERE reservation.permit_id = ?""",
                (first.permit_id,),
            ).fetchone()
        assert occupied["status"] == DurableRiskGate._SETTLED
        assert occupied["state"] == OrderExposureState.UNKNOWN.value

        assert _declare(
            gate,
            scopes,
            ((scope_a, _RESOURCE_A), (scope_b, _RESOURCE_B)),
            ledger_identity=gate.ledger_identity_ref,
        )
        with gate._connection() as connection:
            bound = connection.execute(
                """SELECT shared_collateral_domain_id,
                          shared_collateral_domain_revision
                   FROM risk_reservations WHERE permit_id = ?""",
                (first.permit_id,),
            ).fetchone()
        assert bound["shared_collateral_domain_id"] == "shared-collateral-main"
        assert bound["shared_collateral_domain_revision"] == "domain-v1"

        # The same settled permit has an actual UNKNOWN order-exposure row.
        # It must block both cap growth by revision and new credit, while the
        # reservation is counted once rather than once per matching condition.
        before_revision = _database_snapshot(gate)
        with pytest.raises(ValueError, match="active, settled, or unknown increases"):
            _declare(
                gate,
                scopes,
                ((scope_a, _RESOURCE_A), (scope_b, _RESOURCE_B)),
                ledger_identity=gate.ledger_identity_ref,
                cap="400",
                revision="domain-v2",
            )
        assert _database_snapshot(gate) == before_revision

        # A different AccountKey and product type still sees the same ceiling;
        # the failed vector writes neither leg nor group row or policy/limit row.
        before = _database_snapshot(gate)
        with pytest.raises(RiskDeniedError) as denied:
            gate.reserve_group_vector(
                scope_b,
                "options-group",
                (
                    RiskGroupLegIntent(
                        "option-leg",
                        _group_intent(
                            scope_b,
                            "options-increase",
                            "250",
                            resource=_RESOURCE_B,
                            facts_observed_at_ns=_ORDER_NOW_NS,
                            facts_valid_until_ns=_ORDER_NOW_NS + 3_600_000_000_000,
                        ),
                    ),
                ),
                deadline_ns=_ORDER_NOW_NS + 1_200_000_000_000,
            )
        assert denied.value.code == "SHARED_COLLATERAL_LIMIT_EXHAUSTED"
        assert _database_snapshot(gate) == before
        with pytest.raises(RiskDeniedError) as absent:
            gate.query_group_vector(scope_b, "options-group")
        assert absent.value.code == "GROUP_NOT_FOUND"

        # A distinct account/product may consume exactly the remaining 200;
        # the unknown + settled reservation is therefore projected once.
        at_ceiling_intent = _live_order_intent(
            scope_b, "options-at-shared-ceiling", "200", _RESOURCE_B
        )
        at_ceiling = gate.reserve(at_ceiling_intent)
        before_exhausted = _database_snapshot(gate)
        with pytest.raises(RiskDeniedError) as exhausted:
            gate.reserve(
                _live_order_intent(scope_b, "one-over-shared-ceiling", "1", _RESOURCE_B)
            )
        assert exhausted.value.code == "SHARED_COLLATERAL_LIMIT_EXHAUSTED"
        assert _database_snapshot(gate) == before_exhausted
        gate.release(at_ceiling.permit_id, "owner-stopped-before-dispatch")

        receipt = gate.reserve_group_vector(
            scope_b,
            "options-group-within-cap",
            (
                RiskGroupLegIntent(
                    "option-leg-a",
                    _group_intent(
                        scope_b,
                        "options-increase-a",
                        "40",
                        resource=_RESOURCE_B,
                        facts_observed_at_ns=_ORDER_NOW_NS,
                        facts_valid_until_ns=_ORDER_NOW_NS + 3_600_000_000_000,
                    ),
                ),
                RiskGroupLegIntent(
                    "option-leg-b",
                    _group_intent(
                        scope_b,
                        "options-increase-b",
                        "50",
                        resource=_RESOURCE_B,
                        facts_observed_at_ns=_ORDER_NOW_NS,
                        facts_valid_until_ns=_ORDER_NOW_NS + 3_600_000_000_000,
                    ),
                ),
            ),
            deadline_ns=_ORDER_NOW_NS + 1_200_000_000_000,
        )
        assert len(receipt.legs) == 2
        with gate._connection() as connection:
            group_bindings = connection.execute(
                """SELECT shared_collateral_domain_id,
                          shared_collateral_domain_revision
                   FROM risk_reservations WHERE group_id = ? ORDER BY group_leg_id""",
                ("options-group-within-cap",),
            ).fetchall()
        assert [row["shared_collateral_domain_id"] for row in group_bindings] == [
            "shared-collateral-main",
            "shared-collateral-main",
        ]
        assert [row["shared_collateral_domain_revision"] for row in group_bindings] == [
            "domain-v1",
            "domain-v1",
        ]
    finally:
        gate.close()


def test_two_gate_instances_on_one_ledger_serialize_last_shared_credit(tmp_path):
    scope_a = AccountScope("fixture", "account-a", "sandbox")
    scope_b = AccountScope("fixture", "account-b", "sandbox")
    database = tmp_path / "shared-ledger.sqlite3"
    gate_a = _gate(database, (scope_a, scope_b))
    gate_b = DurableRiskGate(database, _policy(), clock=lambda: 100.0)
    try:
        assert gate_a.ledger_identity_ref == gate_b.ledger_identity_ref
        assert _declare(
            gate_a,
            (scope_a, scope_b),
            ((scope_a, _RESOURCE_A), (scope_b, _RESOURCE_B)),
            ledger_identity=gate_a.ledger_identity_ref,
            cap="200",
        )
        barrier = Barrier(2)

        def attempt(gate, scope, intent_id, resource):
            barrier.wait(timeout=10)
            try:
                gate.reserve(_intent(scope, intent_id, "150", resource=resource))
            except RiskDeniedError as exc:
                return (False, exc.code)
            return (True, None)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = [
                pool.submit(attempt, gate_a, scope_a, "race-a", _RESOURCE_A),
                pool.submit(attempt, gate_b, scope_b, "race-b", _RESOURCE_B),
            ]
            resolved = [future.result(timeout=20) for future in outcomes]
        assert sum(1 for granted, _ in resolved if granted) == 1
        assert sum(1 for granted, _ in resolved if not granted) == 1
        assert next(code for granted, code in resolved if not granted) == (
            "SHARED_COLLATERAL_LIMIT_EXHAUSTED"
        )
        assert _counts(gate_a) == (1, 0)
    finally:
        gate_b.close()
        gate_a.close()


def test_ledger_identity_from_another_database_stays_quarantined(tmp_path):
    scope_a = AccountScope("fixture", "account-a", "sandbox")
    scope_b = AccountScope("fixture", "account-b", "sandbox")
    gate_a = _gate(tmp_path / "ledger-a.sqlite3", (scope_a, scope_b))
    gate_b = _gate(tmp_path / "ledger-b.sqlite3", (scope_a, scope_b))
    try:
        assert gate_a.ledger_identity_ref != gate_b.ledger_identity_ref
        assert not _declare(
            gate_b,
            (scope_a, scope_b),
            ((scope_a, _RESOURCE_A), (scope_b, _RESOURCE_B)),
            ledger_identity=gate_a.ledger_identity_ref,
        )
        before = _database_snapshot(gate_b)
        assert _counts(gate_b) == (0, 0)
        with pytest.raises(RiskDeniedError) as denied:
            gate_b.reserve(_intent(scope_b, "other-ledger", "10", resource=_RESOURCE_B))
        assert denied.value.code == "SHARED_COLLATERAL_DOMAIN_UNREADY"
        assert _database_snapshot(gate_b) == before
    finally:
        gate_b.close()
        gate_a.close()


def test_resource_membership_is_unique_and_failed_activation_is_atomic(tmp_path):
    scope_a = AccountScope("fixture", "account-a", "sandbox")
    scope_b = AccountScope("fixture", "account-b", "sandbox")
    gate = _gate(tmp_path / "risk.sqlite3", (scope_a, scope_b))
    try:
        # A pre-domain keyless reservation cannot be omitted from the new
        # manifest's accounting, so activation fails without partial rows.
        legacy = gate.reserve(_intent(scope_a, "legacy-occupied", "50", resource=None))
        with pytest.raises(ValueError, match="unclassified occupied increases"):
            _declare(
                gate,
                (scope_a, scope_b),
                ((scope_a, _RESOURCE_A), (scope_b, _RESOURCE_B)),
                ledger_identity=gate.ledger_identity_ref,
            )
        with gate._connection() as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM risk_shared_collateral_domains"
            ).fetchone()[0] == 0
            assert connection.execute(
                "SELECT COUNT(*) FROM risk_shared_collateral_domain_scopes"
            ).fetchone()[0] == 0

        # The same trusted resource cannot be allocated to two independent
        # domain budgets, which would otherwise credit it twice.
        gate.release(
            legacy.permit_id, "owner-stopped-before-dispatch"
        )
        for scope, resource in ((scope_a, _RESOURCE_A), (scope_b, _RESOURCE_B)):
            gate.set_margin_pool_limit(
                scope,
                resource.product_type,
                resource.margin_pool,
                "allocation-v1",
                max_notional=Decimal("300"),
            )
        legacy_mapped = gate.reserve(
            _intent(scope_a, "legacy-mapped-occupied", "50", resource=_RESOURCE_A)
        )
        assert _declare(
            gate,
            (scope_a, scope_b),
            ((scope_a, _RESOURCE_A), (scope_b, _RESOURCE_B)),
            ledger_identity=gate.ledger_identity_ref,
        )
        with gate._connection() as connection:
            bound = connection.execute(
                """SELECT shared_collateral_domain_id,
                          shared_collateral_domain_revision
                   FROM risk_reservations WHERE permit_id = ?""",
                (legacy_mapped.permit_id,),
            ).fetchone()
        assert bound["shared_collateral_domain_id"] == "shared-collateral-main"
        assert bound["shared_collateral_domain_revision"] == "domain-v1"
        with pytest.raises(ValueError, match="only one shared-collateral domain"):
            gate.declare_shared_collateral_domain(
                "shared-collateral-other",
                "other-v1",
                (scope_a, scope_b),
                ((scope_a, _RESOURCE_A), (scope_b, _RESOURCE_B)),
                max_notional=Decimal("300"),
                ledger_identity_ref=gate.ledger_identity_ref,
                manifest_complete=True,
            )
        with gate._connection() as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM risk_shared_collateral_domains"
            ).fetchone()[0] == 1
    finally:
        gate.close()


def test_domain_revision_cannot_recredit_a_scope_with_unresolved_claim(tmp_path):
    scope_a = AccountScope("fixture", "account-a", "sandbox")
    scope_b = AccountScope("fixture", "account-b", "sandbox")
    gate = _gate(tmp_path / "risk.sqlite3", (scope_a, scope_b))
    try:
        members = ((scope_a, _RESOURCE_A), (scope_b, _RESOURCE_B))
        assert _declare(
            gate, (scope_a, scope_b), members, ledger_identity=gate.ledger_identity_ref
        )
        intent = _intent(scope_a, "claimed-increase", "100", resource=_RESOURCE_A)
        permit = gate.reserve(intent)
        gate.claim_for_dispatch(permit.permit_id, intent)

        with pytest.raises(ValueError, match="active, settled, or unknown increases"):
            _declare(
                gate,
                (scope_a, scope_b),
                members,
                ledger_identity=gate.ledger_identity_ref,
                cap="500",
                revision="domain-v2",
            )
        assert _counts(gate) == (1, 1)
        with gate._connection() as connection:
            current = connection.execute(
                "SELECT revision FROM risk_shared_collateral_domains WHERE domain_id = ?",
                ("shared-collateral-main",),
            ).fetchone()
        assert current["revision"] == "domain-v1"
    finally:
        gate.close()
