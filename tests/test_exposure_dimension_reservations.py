"""Focused acceptance for source-bound concentration and Greek reservations."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import hashlib
import sqlite3
from types import SimpleNamespace

import pytest

from bt_api_risk import (
    AccountScope,
    DurableRiskGate,
    ExposureAccountingMode,
    GrossExposureBaselineProof,
    InstrumentRiskAdmissionMapper,
    InstrumentRiskGreeks,
    InstrumentRiskMetadata,
    InstrumentRiskRegistry,
    OrderExposureState,
    PositionSnapshotCoverage,
    RiskDeniedError,
    RiskExposureKind,
    RiskExposureLimit,
    RiskGroupLegIntent,
    RiskPolicy,
)
from test_live_gross_exposure import (
    SyntheticJournalAuthority,
    _NOW,
    _NOW_NS,
    _observation,
    _sha,
    _tracked_order,
)


_SCOPE = AccountScope("fixture", "account-a", "sandbox")


def _metadata(instrument: str, *, underlying_ref: str = "BTC") -> InstrumentRiskMetadata:
    return InstrumentRiskMetadata(
        instrument=instrument,
        metadata_version="metadata-v1",
        as_of_ns=_NOW_NS - 1_000,
        expires_at_ns=_NOW_NS + 3_600_000_000_000,
        tick_size=Decimal("0.1"),
        quantity_step=Decimal("1"),
        contract_multiplier=Decimal("1"),
        max_gross_notional=Decimal("10000"),
        taker_fee_bps=Decimal("0"),
        fixed_fee=Decimal("0"),
        max_slippage_bps=Decimal("0"),
        quantity_unit="BTC",
        valuation_unit="USD",
        underlying_ref=underlying_ref,
    )


def _greeks(
    instrument: str,
    *,
    observed_at_ns: int = _NOW_NS,
    valid_until_ns: int = _NOW_NS + 3_600_000_000_000,
) -> InstrumentRiskGreeks:
    return InstrumentRiskGreeks(
        instrument=instrument,
        underlying_ref="BTC",
        delta_per_contract=Decimal("0.5"),
        delta_unit="BTC",
        gamma_per_contract=Decimal("0.02"),
        gamma_unit="BTC-PER-USD",
        vega_per_contract=Decimal("1.25"),
        vega_unit="USD-PER-VOL-POINT",
        observed_at_ns=observed_at_ns,
        valid_until_ns=valid_until_ns,
        source_ref="fixture-greeks-feed",
        source_revision="revision-1",
        source_record_sha256=_sha("greeks-record/" + instrument),
    )


def _limit(kind: RiskExposureKind, key: str, unit: str, ceiling: str) -> RiskExposureLimit:
    return RiskExposureLimit(kind, key, unit, Decimal(ceiling))


def _execution(
    metadata: InstrumentRiskMetadata,
    intent_id: str,
    *,
    quantity: str = "5",
    side: str = "BUY",
) -> SimpleNamespace:
    execution_scope = SimpleNamespace(
        provider="fixture",
        account_ref=_SCOPE.account_id,
        environment=_SCOPE.environment,
        strategy_id="strategy-a",
        trading_day="2026-10-16",
    )
    return SimpleNamespace(
        intent_id=intent_id,
        instrument=metadata.instrument,
        quantity=Decimal(quantity),
        price=Decimal("20"),
        metadata_version=metadata.metadata_version,
        tags={"instrument_metadata_digest": metadata.digest},
        position_effect=SimpleNamespace(value="OPEN"),
        side=SimpleNamespace(value=side),
        scope=execution_scope,
        fingerprint=hashlib.sha256(intent_id.encode("utf-8")).hexdigest(),
    )


def _mapper(
    gate: DurableRiskGate,
    metadata: tuple[InstrumentRiskMetadata, ...],
    limits: tuple[RiskExposureLimit, ...],
    *,
    greeks: tuple[InstrumentRiskGreeks, ...] = (),
) -> InstrumentRiskAdmissionMapper:
    registry = InstrumentRiskRegistry(metadata)
    return InstrumentRiskAdmissionMapper(
        _SCOPE,
        registry,
        clock_ns=lambda: _NOW_NS,
        allocation_reader=lambda requested: gate.get_strategy_allocation(
            _SCOPE, requested.strategy_id
        ),
        exposure_dimension_limits=limits,
        greeks_by_instrument=greeks,
    )


def _policy(limits: tuple[RiskExposureLimit, ...], *, live_gross: bool = True) -> RiskPolicy:
    return RiskPolicy(
        "dimension-policy",
        Decimal("10000"),
        16,
        permit_ttl_seconds=10.0,
        require_strategy_allocation=live_gross,
        notional_unit="USD",
        exposure_accounting_mode=(
            ExposureAccountingMode.LIVE_GROSS
            if live_gross
            else ExposureAccountingMode.RESERVATIONS_ONLY
        ),
        max_gross_occupancy_notional=Decimal("10000") if live_gross else None,
        max_gross_occupancy_intent_count=16 if live_gross else None,
        max_exposure_facts_age_seconds=3600 if live_gross else None,
        exposure_dimension_limits=limits,
    )


def _open_simple_gate(path, limits):
    _, gate = _open_live_gate(path, limits)
    return gate


def _open_live_gate(path, limits):
    authority = SyntheticJournalAuthority()
    policy = _policy(limits, live_gross=True)

    def open_gate():
        gate = DurableRiskGate(
            path,
            policy,
            clock=lambda: _NOW,
            execution_journal_authority=authority,
            gross_exposure_authority=authority,
        )
        gate.set_strategy_allocation(
            _SCOPE,
            "strategy-a",
            "allocation-v1",
            max_notional=Decimal("10000"),
            notional_unit="USD",
            max_gross_occupancy_notional=Decimal("10000"),
            max_gross_occupancy_intent_count=16,
        )
        gate.install_gross_exposure_baseline(
            GrossExposureBaselineProof(
                scope=_SCOPE,
                account_revision=1,
                notional_unit="USD",
                account_gross_notional=Decimal("0"),
                account_active_increase_intent_count=0,
                strategy_baselines=(),
                unmanaged_open_order_count=0,
                complete_positions=True,
                complete_open_orders=True,
                source_snapshot_sha256=_sha("dimension-baseline"),
                positions_sha256=_sha("dimension-positions"),
                open_orders_sha256=_sha("dimension-orders"),
                valuation_facts_sha256=_sha("dimension-valuation"),
                source_schema_version="fixture-baseline-v1",
                observed_at_ns=_NOW_NS,
                valid_until_ns=_NOW_NS + 3_600_000_000_000,
                writer_owner_id="synthetic-writer",
                writer_fencing_token=1,
                writer_fence_sha256=_sha("fence"),
                position_coverage=PositionSnapshotCoverage(
                    scope=_SCOPE,
                    account_revision=1,
                    source_schema_version="fixture-baseline-v1",
                    query_scope="ALL_ACCOUNT_POSITIONS",
                    filters=(),
                    permission_scope="ACCOUNT_FULL",
                    permission_revision="permission-v1",
                    pagination_exhausted=True,
                    page_count=1,
                    snapshot_version="snapshot-v1",
                    observed_at_ns=_NOW_NS,
                    valid_until_ns=_NOW_NS + 3_600_000_000_000,
                ),
            )
        )
        return gate

    return open_gate, open_gate()


def test_underlying_concentration_is_reserved_across_contracts_in_one_transaction(
    tmp_path,
) -> None:
    limits = (
        _limit(RiskExposureKind.UNDERLYING_NOTIONAL, "BTC", "USD", "150"),
    )
    gate = _open_simple_gate(tmp_path / "concentration.sqlite3", limits)
    metadata_a = _metadata("BTC-USDT")
    metadata_b = _metadata("BTC-USD-PERP")
    mapper_a = _mapper(gate, (metadata_a, metadata_b), limits)
    mapper_b = mapper_a
    try:
        first_intent = mapper_a(_execution(metadata_a, "concentration-a"))
        permit = gate.reserve(first_intent)
        second_intent = mapper_b(_execution(metadata_b, "concentration-b"))

        assert first_intent.exposure_dimensions[0].dimension_key == "BTC"
        assert first_intent.exposure_dimensions[0].exposure == Decimal("100")
        with pytest.raises(RiskDeniedError) as denied:
            gate.reserve(second_intent)
        assert denied.value.code == "RISK_EXPOSURE_DIMENSION_LIMIT_EXHAUSTED"
        with gate._connection() as connection:
            rows = connection.execute(
                "SELECT permit_id, dimension_key, exposure FROM risk_reservation_dimensions"
            ).fetchall()
            reservations = connection.execute(
                "SELECT permit_id FROM risk_reservations"
            ).fetchall()
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE risk_reservation_dimensions SET exposure = '1' WHERE permit_id = ?",
                    (permit.permit_id,),
                )
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    "DELETE FROM risk_reservation_dimensions WHERE permit_id = ?",
                    (permit.permit_id,),
                )
        assert [tuple(row[:2]) for row in rows] == [(permit.permit_id, "BTC")]
        assert Decimal(rows[0]["exposure"]) == Decimal("100")
        assert [str(row["permit_id"]) for row in reservations] == [permit.permit_id]
    finally:
        gate.close()


def test_legacy_active_reservation_without_dimension_rows_fails_closed_after_upgrade(
    tmp_path,
) -> None:
    limits = (
        _limit(RiskExposureKind.UNDERLYING_NOTIONAL, "BTC", "USD", "150"),
    )
    database = tmp_path / "legacy-active-without-dimensions.sqlite3"
    gate = _open_simple_gate(database, limits)
    try:
        metadata = _metadata("BTC-USDT")
        initial = _mapper(gate, (metadata,), limits)(
            _execution(metadata, "legacy-active-dimension-source")
        )
        permit = gate.reserve(initial)
        with gate._connection() as connection:
            before = connection.execute(
                "SELECT status FROM risk_reservations WHERE permit_id = ?",
                (permit.permit_id,),
            ).fetchone()
            before_dimensions = connection.execute(
                "SELECT COUNT(*) FROM risk_reservation_dimensions WHERE permit_id = ?",
                (permit.permit_id,),
            ).fetchone()[0]
        assert before is not None
        assert before["status"] == DurableRiskGate._ACTIVE
        assert before_dimensions == 1
    finally:
        gate.close()

    # Model a database written before the dimension child table existed. The
    # parent ACTIVE reservation and its policy binding remain untouched; the
    # next gate opening recreates the new table without inventing old facts.
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE risk_reservation_dimensions")
        connection.commit()

    reopened = DurableRiskGate(database, _policy(limits), clock=lambda: _NOW)
    try:
        with reopened._connection() as connection:
            legacy = connection.execute(
                "SELECT status FROM risk_reservations WHERE permit_id = ?",
                (permit.permit_id,),
            ).fetchone()
            no_legacy_dimensions = connection.execute(
                "SELECT COUNT(*) FROM risk_reservation_dimensions WHERE permit_id = ?",
                (permit.permit_id,),
            ).fetchone()[0]
        assert legacy["status"] == DurableRiskGate._ACTIVE
        assert no_legacy_dimensions == 0

        candidate = _mapper(reopened, (metadata,), limits)(
            _execution(metadata, "candidate-after-legacy-upgrade", quantity="1")
        )
        with pytest.raises(RiskDeniedError) as denied:
            reopened.reserve(candidate)
        assert denied.value.code == "RISK_EXPOSURE_DIMENSION_HISTORY_UNAVAILABLE"
        with reopened._connection() as connection:
            reservations = connection.execute(
                "SELECT COUNT(*) FROM risk_reservations"
            ).fetchone()[0]
            original = connection.execute(
                "SELECT permit_id, status FROM risk_reservations WHERE permit_id = ?",
                (permit.permit_id,),
            ).fetchone()
            dimensions = connection.execute(
                "SELECT COUNT(*) FROM risk_reservation_dimensions"
            ).fetchone()[0]
        assert reservations == 1
        assert original is not None
        assert str(original["permit_id"]) == permit.permit_id
        assert original["status"] == DurableRiskGate._ACTIVE
        assert dimensions == 0
    finally:
        reopened.close()


def test_legacy_baseline_without_position_coverage_fails_closed_after_upgrade(tmp_path) -> None:
    limits = (
        _limit(RiskExposureKind.UNDERLYING_NOTIONAL, "BTC", "USD", "150"),
    )
    database = tmp_path / "legacy-baseline-without-position-coverage.sqlite3"
    _, gate = _open_live_gate(database, limits)
    gate.close()

    # Recreate the pre-position-dimensions shape. Migration must add the new
    # column/table without inferring coverage or dimension values for this row.
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE risk_gross_baseline_dimensions")
        connection.execute(
            "ALTER TABLE risk_gross_exposure_baselines DROP COLUMN position_coverage_sha256"
        )
        connection.commit()

    reopened = DurableRiskGate(database, _policy(limits), clock=lambda: _NOW)
    try:
        with reopened._connection() as connection:
            legacy = connection.execute(
                "SELECT position_coverage_sha256 FROM risk_gross_exposure_baselines"
            ).fetchone()
            dimensions = connection.execute(
                "SELECT COUNT(*) FROM risk_gross_baseline_dimensions"
            ).fetchone()[0]
        assert legacy is not None
        assert legacy["position_coverage_sha256"] is None
        assert dimensions == 0

        metadata = _metadata("BTC-USDT")
        candidate = _mapper(reopened, (metadata,), limits)(
            _execution(metadata, "candidate-after-baseline-upgrade", quantity="1")
        )
        with pytest.raises(RiskDeniedError) as denied:
            reopened.reserve(candidate)
        assert denied.value.code == "GROSS_EXPOSURE_POSITION_COVERAGE_UNAVAILABLE"
        with reopened._connection() as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM risk_reservations"
            ).fetchone()[0] == 0
    finally:
        reopened.close()


def test_group_vector_checks_sibling_legs_before_commit_and_rolls_back_whole_vector(
    tmp_path,
) -> None:
    limits = (
        _limit(RiskExposureKind.UNDERLYING_NOTIONAL, "BTC", "USD", "150"),
    )
    gate = _open_simple_gate(tmp_path / "group-dimensions.sqlite3", limits)
    metadata = (_metadata("BTC-USDT"), _metadata("BTC-USD-PERP"))
    mapper = _mapper(gate, metadata, limits)
    legs = tuple(
        RiskGroupLegIntent(
            leg_id=f"leg-{index}",
                intent=mapper.map_group_intent(
                    _execution(item, f"group-dimension-{index}")
                ),
        )
        for index, item in enumerate(metadata)
    )
    try:
        with pytest.raises(RiskDeniedError) as denied:
            gate.reserve_group_vector(
                _SCOPE,
                "shared-underlying-vector",
                legs,
                deadline_ns=_NOW_NS + 30_000_000_000,
            )
        assert denied.value.code == "RISK_EXPOSURE_DIMENSION_LIMIT_EXHAUSTED", str(denied.value)
        with gate._connection() as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM risk_reservations"
            ).fetchone()[0] == 0
            assert connection.execute(
                "SELECT COUNT(*) FROM risk_reservation_dimensions"
            ).fetchone()[0] == 0
    finally:
        gate.close()


def test_group_child_rejects_a_changed_underlying_or_greek_source_profile(tmp_path) -> None:
    limits = (
        _limit(RiskExposureKind.UNDERLYING_NOTIONAL, "BTC", "USD", "1000"),
        _limit(RiskExposureKind.DELTA, "BTC", "BTC", "100"),
    )
    gate = _open_simple_gate(tmp_path / "group-greek-profile.sqlite3", limits)
    metadata = _metadata("BTC-USDT-OPTION")
    reserved_fact = _greeks(metadata.instrument)
    reserving_mapper = _mapper(
        gate,
        (metadata,),
        limits,
        greeks=(reserved_fact,),
    )
    reserved_intent = reserving_mapper.map_group_intent(
        _execution(metadata, "greek-profile-leg", quantity="5")
    )
    try:
        receipt = gate.reserve_group_vector(
            _SCOPE,
            "greek-profile-group",
            (RiskGroupLegIntent("leg-a", reserved_intent),),
            deadline_ns=_NOW_NS + 30_000_000_000,
        )
        changed_fact = replace(
            reserved_fact,
            delta_per_contract=Decimal("0.6"),
            source_revision="revision-2",
        )
        changed_mapper = _mapper(
            gate,
            (metadata,),
            limits,
            greeks=(changed_fact,),
        )
        actual_child = changed_mapper.map_group_intent(
            _execution(metadata, "greek-profile-leg", quantity="1")
        )
        with pytest.raises(RiskDeniedError) as mismatch:
            gate.claim_group_leg(
                _SCOPE,
                "greek-profile-group",
                "leg-a",
                receipt.legs[0].permit_id,
                actual_child,
                expected_group_fingerprint=receipt.group_fingerprint,
                expected_deadline_ns=receipt.deadline_ns,
            )
        assert mismatch.value.code == "GROUP_LEG_PROFILE_MISMATCH"
        with gate._connection() as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM risk_dispatch_claims"
            ).fetchone()[0] == 0
    finally:
        gate.close()


def test_greeks_require_fresh_source_bound_facts_and_reserve_signed_dimensions(
    tmp_path,
) -> None:
    metadata = _metadata("BTC-USDT-OPTION")
    limits = (
        _limit(RiskExposureKind.DELTA, "BTC", "BTC", "100"),
        _limit(RiskExposureKind.GAMMA, "BTC", "BTC-PER-USD", "10"),
        _limit(RiskExposureKind.VEGA, "BTC", "USD-PER-VOL-POINT", "100"),
    )
    gate = _open_simple_gate(tmp_path / "greeks.sqlite3", limits)
    try:
        missing = _mapper(gate, (metadata,), limits)
        with pytest.raises(RiskDeniedError) as missing_facts:
            missing(_execution(metadata, "missing-greeks", side="SELL"))
        assert missing_facts.value.code == "INSTRUMENT_GREEKS_REQUIRED"

        unbound_underlying = _metadata("BTC-USDT-NO-UNDERLYING", underlying_ref=None)
        unbound_mapper = _mapper(
            gate,
            (unbound_underlying,),
            limits,
            greeks=(_greeks(unbound_underlying.instrument),),
        )
        with pytest.raises(RiskDeniedError) as missing_underlying:
            unbound_mapper(_execution(unbound_underlying, "missing-underlying", side="SELL"))
        assert missing_underlying.value.code == "INSTRUMENT_GREEK_UNDERLYING_UNAVAILABLE"

        stale = _mapper(
            gate,
            (metadata,),
            limits,
            greeks=(
                _greeks(
                    metadata.instrument,
                    observed_at_ns=_NOW_NS - 7_200_000_000_000,
                    valid_until_ns=_NOW_NS - 1,
                ),
            ),
        )
        with pytest.raises(RiskDeniedError) as stale_facts:
            stale(_execution(metadata, "stale-greeks", side="SELL"))
        assert stale_facts.value.code == "INSTRUMENT_GREEKS_STALE"

        fact = _greeks(metadata.instrument)
        mapper = _mapper(gate, (metadata,), limits, greeks=(fact,))
        mapped = mapper(_execution(metadata, "fresh-greeks", side="SELL"))
        observed = {dimension.kind: dimension for dimension in mapped.exposure_dimensions}
        assert observed[RiskExposureKind.DELTA].exposure == Decimal("-2.5")
        assert observed[RiskExposureKind.GAMMA].exposure == Decimal("-0.10")
        assert observed[RiskExposureKind.VEGA].exposure == Decimal("-6.25")
        assert all(dimension.source_sha256 == fact.digest for dimension in observed.values())

        limited_path = tmp_path / "greek-limit.sqlite3"
        limited_limits = tuple(
            _limit(kind, "BTC", unit, ceiling)
            for kind, unit, ceiling in (
                (RiskExposureKind.DELTA, "BTC", "2"),
                (RiskExposureKind.GAMMA, "BTC-PER-USD", "10"),
                (RiskExposureKind.VEGA, "USD-PER-VOL-POINT", "100"),
            )
        )
        limited_gate = _open_simple_gate(limited_path, limited_limits)
        try:
            limited_mapper = _mapper(
                limited_gate,
                (metadata,),
                limited_limits,
                greeks=(fact,),
            )
            with pytest.raises(RiskDeniedError) as greek_limit:
                limited_gate.reserve(
                    limited_mapper(_execution(metadata, "over-delta-cap", side="SELL"))
                )
            assert greek_limit.value.code == "RISK_EXPOSURE_DIMENSION_LIMIT_EXHAUSTED"
            with limited_gate._connection() as connection:
                assert connection.execute(
                    "SELECT COUNT(*) FROM risk_reservations"
                ).fetchone()[0] == 0
        finally:
            limited_gate.close()

        permit = gate.reserve(mapped)
        reopened = DurableRiskGate(
            tmp_path / "greeks.sqlite3", _policy(limits), clock=lambda: _NOW
        )
        try:
            with reopened._connection() as connection:
                rows = connection.execute(
                    """SELECT dimension_kind, dimension_key, unit, exposure,
                              source_sha256, observed_at_ns, valid_until_ns
                       FROM risk_reservation_dimensions WHERE permit_id = ?
                       ORDER BY dimension_kind""",
                    (permit.permit_id,),
                ).fetchall()
            assert len(rows) == 3
            assert {str(row["dimension_kind"]): str(row["exposure"]) for row in rows} == {
                "delta": "-2.5",
                "gamma": "-0.10",
                "vega": "-6.25",
            }
            assert {str(row["source_sha256"]) for row in rows} == {fact.digest}
        finally:
            reopened.close()
    finally:
        gate.close()


def test_unknown_order_dimension_is_persisted_and_counted_once_after_reopen(
    tmp_path,
) -> None:
    limits = (
        _limit(RiskExposureKind.UNDERLYING_NOTIONAL, "BTC", "USD", "150"),
        _limit(RiskExposureKind.DELTA, "BTC", "BTC", "100"),
        _limit(RiskExposureKind.GAMMA, "BTC", "BTC-PER-USD", "10"),
        _limit(RiskExposureKind.VEGA, "BTC", "USD-PER-VOL-POINT", "100"),
    )
    open_gate, gate = _open_live_gate(tmp_path / "unknown-dimensions.sqlite3", limits)
    metadata_a = _metadata("BTC-USDT")
    metadata_b = _metadata("BTC-USD-PERP")
    gate_closed = False
    try:
        mapper_a = _mapper(
            gate,
            (metadata_a,),
            limits,
            greeks=(_greeks(metadata_a.instrument),),
        )
        initial = mapper_a(_execution(metadata_a, "unknown-dimension-source"))
        permit, tracked = _tracked_order(gate, _SCOPE, initial)
        unknown = _observation(
            _SCOPE,
            tracked,
            state=OrderExposureState.UNKNOWN,
            order_revision=1,
            journal_revision=3,
            cumulative_filled_quantity="0",
            leaves_quantity="5",
            filled_gross_notional="0",
            leaves_gross_notional="0",
            complete=False,
            observed_at_ns=_NOW_NS - 7_200_000_000_000,
            valid_until_ns=_NOW_NS - 3_600_000_000_000,
        )
        snapshot = gate.apply_order_exposure_observation(unknown)
        assert snapshot.state is OrderExposureState.UNKNOWN

        gate.close()
        gate_closed = True
        reopened = open_gate()
        try:
            mapper_b = _mapper(
                reopened,
                (metadata_b,),
                limits,
                greeks=(_greeks(metadata_b.instrument),),
            )
            candidate = mapper_b(
                _execution(metadata_b, "candidate-within-cap", quantity="1")
            )
            larger = mapper_b(
                _execution(metadata_b, "candidate-over-cap", quantity="3")
            )
            with reopened._connection() as connection:
                row = connection.execute(
                    """SELECT reservation.status, exposure.state
                       FROM risk_reservations AS reservation
                       JOIN risk_order_exposures AS exposure
                         ON exposure.permit_id = reservation.permit_id
                       WHERE reservation.permit_id = ?""",
                    (permit.permit_id,),
                ).fetchone()
                dimensions = connection.execute(
                    "SELECT COUNT(*) FROM risk_reservation_dimensions WHERE permit_id = ?",
                    (permit.permit_id,),
                ).fetchone()[0]
            assert row["status"] == DurableRiskGate._SETTLED
            assert row["state"] == OrderExposureState.UNKNOWN.value
            assert dimensions == 4

            with reopened._transaction() as connection:
                # The persisted UNKNOWN row contributes once: 100 + 20 stays
                # below 150; a 60-unit candidate pushes the total above it.
                reopened._assert_exposure_dimension_limits(connection, candidate)
            with pytest.raises(RiskDeniedError) as denied:
                with reopened._transaction() as connection:
                    reopened._assert_exposure_dimension_limits(connection, larger)
            assert denied.value.code == "RISK_EXPOSURE_DIMENSION_LIMIT_EXHAUSTED"
            with reopened._connection() as connection:
                assert connection.execute(
                    "SELECT COUNT(*) FROM risk_reservations"
                ).fetchone()[0] == 1
                assert connection.execute(
                    "SELECT COUNT(*) FROM risk_reservation_dimensions"
                ).fetchone()[0] == 4
        finally:
            reopened.close()
    finally:
        if not gate_closed:
            gate.close()
