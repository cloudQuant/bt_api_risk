"""Bind neutral account orders to the durable risk admission gate.

This module is the risk-side adapter for an account owner's order entry.  The
caller supplies the owner-configured mapper that derives a trusted
``RiskIntent`` from its immutable order contract.  The adapter keeps risk
optional for the execution package: it imports neither execution nor gateway
and performs no provider or network I/O.

The adapter is admission only.  A successful dispatch claim installs the
gate's durable account freeze; settlement does not clear that freeze.  Order
observation and evidence-bound freeze resolution remain the account owner's
responsibility.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from typing import Any, NoReturn

from .core.admission import (
    AccountScope,
    DurableRiskGate,
    PermitInvalidError,
    RiskDeniedError,
    RiskGroupLegClaimReceipt,
    RiskGroupLegIntent,
    RiskGroupReservationReceipt,
    RiskIntent,
    RiskPermit,
)

_RISK_DENIAL_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,95}$")


class RiskAdmissionAdapterError(ValueError):
    """Finite composition error raised before the durable gate is called."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RiskAdmissionDeniedError(PermissionError):
    """Finite, risk-neutral projection for an expected admission rejection."""

    def __init__(self, code: str) -> None:
        if type(code) is not str or not _RISK_DENIAL_CODE.fullmatch(code):
            raise ValueError("invalid risk admission denial code")
        self.code = code
        super().__init__(code)


class DurableRiskAdmissionAdapter:
    """Expose ``DurableRiskGate`` through an account owner's order port.

    ``map_intent`` belongs to the trusted account-service composition.  It
    binds order identity, account scope, position effect, trusted instrument
    facts, and any configured strategy allocation into one ``RiskIntent``.
    The neutral order object is deliberately accepted by structural contract,
    so installing this adapter does not add an execution-package dependency.

    The incoming order's provider, environment, and account reference must
    match the scope produced by the mapper on every operation.  This prevents
    a correctly configured account adapter from silently re-binding an order
    routed for a different account.
    """

    def __init__(
        self,
        gate: DurableRiskGate,
        map_intent: Callable[[Any], RiskIntent],
    ) -> None:
        if type(gate) is not DurableRiskGate:
            raise RiskAdmissionAdapterError("INVALID_RISK_GATE")
        if not callable(map_intent):
            raise RiskAdmissionAdapterError("INTENT_MAPPER_REQUIRED")
        self._gate = gate
        self._map_intent = map_intent

    def reserve(self, intent: Any) -> RiskPermit:
        """Durably reserve capacity for one immutable account order."""

        try:
            return self._gate.reserve(self._map_order(intent))
        except (RiskDeniedError, PermitInvalidError) as error:
            self._raise_neutral_denial(error)

    def validate(self, permit_reference: str, intent: Any) -> RiskPermit:
        """Revalidate a pending permit against the same immutable order."""

        try:
            return self._gate.validate_permit(permit_reference, self._map_order(intent))
        except (RiskDeniedError, PermitInvalidError) as error:
            self._raise_neutral_denial(error)

    def claim_for_dispatch(self, permit_reference: str, intent: Any) -> RiskPermit:
        """Atomically claim the single dispatch attempt immediately before I/O."""

        try:
            return self._gate.claim_for_dispatch(permit_reference, self._map_order(intent))
        except (RiskDeniedError, PermitInvalidError) as error:
            self._raise_neutral_denial(error)

    def settle(self, permit_reference: str) -> RiskPermit:
        """Consume a claimed permit after the account owner records its outcome."""

        return self._gate.settle(permit_reference)

    def ensure_settled(self, permit_reference: str) -> RiskPermit:
        """Prove recovery settlement after the owner records a known outcome."""

        return self._gate.ensure_settled(permit_reference)

    def release(self, permit_reference: str, reason: str) -> None:
        """Release only an unclaimed reservation the owner did not dispatch."""

        self._gate.release(permit_reference, reason)

    def reserve_group_vector(
        self,
        scope: AccountScope,
        group_id: str,
        members: Sequence[tuple[str, Any]],
        *,
        deadline_ns: int,
    ) -> RiskGroupReservationReceipt:
        """Map a complete trusted leg vector and reserve it in one gate txn."""

        try:
            if type(scope) is not AccountScope:
                raise RiskDeniedError("GROUP_SCOPE_MISMATCH", "a trusted account scope is required")
            if isinstance(members, (str, bytes)) or not isinstance(members, Sequence):
                raise RiskDeniedError(
                    "GROUP_INVALID_LEG", "a complete sequence of raw order members is required"
                )
            mapped_members: list[RiskGroupLegIntent] = []
            for member in members:
                if type(member) is not tuple or len(member) != 2:
                    raise RiskDeniedError(
                        "GROUP_INVALID_LEG", "each group member must be (leg_id, order)"
                    )
                leg_id, order = member
                mapped = self._map_group_order(order)
                if mapped.scope != scope:
                    raise RiskDeniedError(
                        "GROUP_SCOPE_MISMATCH", "every mapped order must use the requested account"
                    )
                try:
                    mapped_members.append(RiskGroupLegIntent(leg_id=leg_id, intent=mapped))
                except (TypeError, ValueError):
                    raise RiskDeniedError(
                        "GROUP_INVALID_LEG", "group leg identity or mapping is invalid"
                    ) from None
            return self._gate.reserve_group_vector(
                scope, group_id, tuple(mapped_members), deadline_ns=deadline_ns
            )
        except (RiskDeniedError, PermitInvalidError) as error:
            self._raise_neutral_denial(error)

    def query_group_vector(self, scope: AccountScope, group_id: str) -> RiskGroupReservationReceipt:
        """Read the durable full-vector receipt for one exact account/group."""

        try:
            return self._gate.query_group_vector(scope, group_id)
        except (RiskDeniedError, PermitInvalidError) as error:
            self._raise_neutral_denial(error)

    def release_group_unclaimed(
        self, scope: AccountScope, group_id: str, reason: str
    ) -> RiskGroupReservationReceipt:
        """Release only the unclaimed siblings permitted by durable group rules."""

        try:
            return self._gate.release_group_unclaimed(scope, group_id, reason)
        except (RiskDeniedError, PermitInvalidError) as error:
            self._raise_neutral_denial(error)

    def claim_group_leg(
        self,
        intent: Any,
        *,
        group_id: str,
        leg_id: str,
        permit_reference: str,
        group_fingerprint: str,
        deadline_ns: int,
    ) -> RiskGroupLegClaimReceipt:
        """Claim one mapper-verified child order under its reserved group leg."""

        try:
            mapped = self._map_group_order(intent)
            return self._gate.claim_group_leg(
                mapped.scope,
                group_id,
                leg_id,
                permit_reference,
                mapped,
                expected_group_fingerprint=group_fingerprint,
                expected_deadline_ns=deadline_ns,
            )
        except (RiskDeniedError, PermitInvalidError) as error:
            self._raise_neutral_denial(error)

    @staticmethod
    def _raise_neutral_denial(error: Exception) -> NoReturn:
        """Project only exact, coded gate decisions into the order-port contract."""

        if type(error) not in (RiskDeniedError, PermitInvalidError):
            raise error
        code = getattr(error, "code", None)
        if type(code) is not str or not _RISK_DENIAL_CODE.fullmatch(code):
            raise error
        raise RiskAdmissionDeniedError(code) from None

    def _map_order(self, intent: Any) -> RiskIntent:
        return self._bind_mapped_order(intent, self._map_intent(intent))

    def _map_group_order(self, intent: Any) -> RiskIntent:
        mapper = self._map_intent
        group_mapper = getattr(mapper, "map_group_intent", None)
        if not callable(group_mapper):
            owner = getattr(mapper, "__self__", None)
            group_mapper = getattr(owner, "map_group_intent", None)
        mapped = group_mapper(intent) if callable(group_mapper) else mapper(intent)
        mapped = self._bind_mapped_order(intent, mapped)
        if mapped.exposure_profile_fingerprint is None:
            raise RiskDeniedError(
                "GROUP_PROFILE_UNAVAILABLE",
                "group orders require a trusted mapper-owned exposure profile",
            )
        return mapped

    def _bind_mapped_order(self, intent: Any, mapped: Any) -> RiskIntent:
        if type(mapped) is not RiskIntent:
            raise RiskAdmissionAdapterError("MAPPED_RISK_INTENT_REQUIRED")

        order_intent_id = getattr(intent, "intent_id", None)
        if type(order_intent_id) is not str or mapped.intent_id != order_intent_id:
            raise RiskDeniedError(
                "ORDER_INTENT_ID_MISMATCH",
                "mapped risk intent does not match the order intent identity",
            )

        order_scope = getattr(intent, "scope", None)
        try:
            input_scope = AccountScope(
                provider=order_scope.provider,
                account_id=order_scope.account_ref,
                environment=order_scope.environment,
            )
        except (AttributeError, TypeError, ValueError):
            raise RiskDeniedError(
                "ACCOUNT_SCOPE_UNPROVEN",
                "order does not carry a valid account scope",
            ) from None

        if mapped.scope != input_scope:
            raise RiskDeniedError(
                "ACCOUNT_SCOPE_MISMATCH",
                "mapped risk scope does not match the order account scope",
            )
        strategy_id = getattr(order_scope, "strategy_id", None)
        if mapped.strategy_id is not None and mapped.strategy_id != strategy_id:
            raise RiskDeniedError(
                "STRATEGY_SCOPE_MISMATCH",
                "mapped strategy allocation does not match the order strategy scope",
            )
        return mapped


__all__ = [
    "DurableRiskAdmissionAdapter",
    "RiskAdmissionAdapterError",
    "RiskAdmissionDeniedError",
]
