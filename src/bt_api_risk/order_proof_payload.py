"""Serialize risk CLOSE proof facts without granting source authority.

The caller must verify its journal/source bindings and retain its writer fence.
"""
from __future__ import annotations

from dataclasses import fields
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any

from .core.admission import (
    AccountScope, DispatchClaimBinding, DispatchEvidenceClass, DispatchExposureResolutionProof,
)
from .core.exposure import OrderExposureObservationProof, OrderExposureState, OrderFillFact


class RiskOrderProofPayloadError(RuntimeError):
    """Finite error for an invalid or mismatched Risk proof payload."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def terminal_close_proof_payload(
    proof: DispatchExposureResolutionProof, *, decimal_text,
) -> dict[str, Any]:
    """Serialize a typed CLOSE proof so UNKNOWN recovery reuses identical facts."""

    if (
        type(proof) is not DispatchExposureResolutionProof
        or proof.observation.position_effect != "CLOSE"
    ):
        raise RiskOrderProofPayloadError("TERMINAL_CLOSE_PROOF_REQUIRED")
    observation = proof.observation
    observation_payload: dict[str, Any] = {}
    include_position_dimensions = (
        observation.position_side != "NET" or observation.position_bucket != "ALL"
    )
    for item in fields(OrderExposureObservationProof):
        name = item.name
        value = getattr(observation, name)
        if name in {"position_side", "position_bucket"} and not include_position_dimensions:
            continue
        if name == "scope":
            observation_payload["scope_key"] = value.key
        elif name == "fills":
            observation_payload[name] = [
                {
                    fill_field.name: (
                        decimal_text(fill_value)
                        if isinstance(fill_value, Decimal)
                        else fill_value.value
                        if isinstance(fill_value, Enum)
                        else fill_value
                    )
                    for fill_field in fields(OrderFillFact)
                    for fill_value in (getattr(fill, fill_field.name),)
                }
                for fill in value
            ]
        elif isinstance(value, Decimal):
            observation_payload[name] = decimal_text(value)
        elif isinstance(value, Enum):
            observation_payload[name] = value.value
        else:
            observation_payload[name] = value
    return {
        "claim": {
            "cause_id": proof.claim.cause_id,
            "claim_digest": proof.claim.claim_digest,
            "claimed_at": proof.claim.claimed_at,
            "intent_hash": proof.claim.intent_hash,
            "intent_id": proof.claim.intent_id,
            "permit_id": proof.claim.permit_id,
            "scope": {
                "account_id": proof.claim.scope.account_id,
                "environment": proof.claim.scope.environment,
                "provider": proof.claim.scope.provider,
            },
            "scope_key": proof.claim.scope.key,
        },
        "dispatch_attempt_count": proof.dispatch_attempt_count,
        "evidence_class": proof.evidence_class.value,
        "exposure_proof_sha256": observation.fingerprint,
        "observation": observation_payload,
        "proof_sha256": proof.fingerprint,
        "reconciliation_evidence_sha256": proof.reconciliation_evidence_sha256,
        "schema": "bt-api-risk-order-terminal-close-proof-v1",
    }


def terminal_close_proof_from_payload(
    payload: object,
    *,
    scope: AccountScope,
) -> DispatchExposureResolutionProof:
    """Restore only the exact finite JSON representation emitted above."""

    outer_keys = {
        "claim",
        "dispatch_attempt_count",
        "evidence_class",
        "exposure_proof_sha256",
        "observation",
        "proof_sha256",
        "reconciliation_evidence_sha256",
        "schema",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != outer_keys
        or payload.get("schema") != "bt-api-risk-order-terminal-close-proof-v1"
    ):
        raise RiskOrderProofPayloadError("TERMINAL_CLOSE_PROOF_PAYLOAD_INVALID")
    claim_payload = payload.get("claim")
    if (
        not isinstance(claim_payload, dict)
        or set(claim_payload)
        != {
            "cause_id",
            "claim_digest",
            "claimed_at",
            "intent_hash",
            "intent_id",
            "permit_id",
            "scope",
            "scope_key",
        }
        or claim_payload.get("scope_key") != scope.key
        or claim_payload.get("scope")
        != {
            "account_id": scope.account_id,
            "environment": scope.environment,
            "provider": scope.provider,
        }
    ):
        raise RiskOrderProofPayloadError("TERMINAL_CLOSE_PROOF_CLAIM_INVALID")
    try:
        claim = DispatchClaimBinding(
            scope=scope,
            permit_id=claim_payload["permit_id"],
            intent_id=claim_payload["intent_id"],
            intent_hash=claim_payload["intent_hash"],
            cause_id=claim_payload["cause_id"],
            claimed_at=claim_payload["claimed_at"],
            claim_digest=claim_payload["claim_digest"],
        )
        raw_observation = payload["observation"]
        expected_observation_keys = {
            *(item.name for item in fields(OrderExposureObservationProof) if item.name != "scope"),
            "scope_key",
        }
        legacy_observation_keys = expected_observation_keys - {
            "position_side",
            "position_bucket",
        }
        raw_observation_keys = (
            frozenset(raw_observation) if isinstance(raw_observation, dict) else frozenset()
        )
        if (
            not isinstance(raw_observation, dict)
            or raw_observation_keys
            not in {frozenset(expected_observation_keys), frozenset(legacy_observation_keys)}
            or raw_observation.get("scope_key") != scope.key
        ):
            raise ValueError("observation fields")
        observation_values = dict(raw_observation)
        observation_values.pop("scope_key")
        observation_values.setdefault("position_side", "NET")
        observation_values.setdefault("position_bucket", "ALL")
        observation_values["scope"] = scope
        raw_fills = observation_values.get("fills")
        if type(raw_fills) is not list:
            raise ValueError("fill facts")
        fill_keys = {item.name for item in fields(OrderFillFact)}
        decimal_fill_fields = {"quantity", "price", "fee_amount"}
        fills: list[OrderFillFact] = []
        for raw_fill in raw_fills:
            if not isinstance(raw_fill, dict) or set(raw_fill) != fill_keys:
                raise ValueError("fill fact fields")
            values = dict(raw_fill)
            for name in decimal_fill_fields:
                values[name] = Decimal(str(values[name]))
            fills.append(OrderFillFact(**values))
        observation_values["fills"] = tuple(fills)
        observation_values["state"] = OrderExposureState(observation_values["state"])
        decimal_observation_fields = {
            "requested_quantity",
            "cumulative_filled_quantity",
            "leaves_quantity",
            "filled_gross_notional",
            "leaves_gross_notional",
            "instrument_multiplier",
        }
        for name in decimal_observation_fields:
            observation_values[name] = Decimal(str(observation_values[name]))
        for name in ("leaves_valuation_price", "fx_rate"):
            value = observation_values[name]
            observation_values[name] = None if value is None else Decimal(str(value))
        observation = OrderExposureObservationProof(**observation_values)
        proof = DispatchExposureResolutionProof(
            claim=claim,
            evidence_class=DispatchEvidenceClass(payload["evidence_class"]),
            dispatch_attempt_count=payload["dispatch_attempt_count"],
            reconciliation_evidence_sha256=payload[
                "reconciliation_evidence_sha256"
            ],
            observation=observation,
        )
    except (KeyError, TypeError, ValueError, InvalidOperation):
        raise RiskOrderProofPayloadError("TERMINAL_CLOSE_PROOF_PAYLOAD_INVALID") from None
    if (
        proof.fingerprint != payload.get("proof_sha256")
        or proof.observation.fingerprint != payload.get("exposure_proof_sha256")
    ):
        raise RiskOrderProofPayloadError("TERMINAL_CLOSE_PROOF_DIGEST_MISMATCH")
    return proof


__all__ = ("RiskOrderProofPayloadError", "terminal_close_proof_payload", "terminal_close_proof_from_payload")
