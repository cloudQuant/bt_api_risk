"""Ledger-backed policy versions (D64-12).

The effective policy is the highest version row in ``risk_pretrade_policy_versions``;
publishing appends a row (compare-and-set on the current version). Loading
re-validates the stored document with the current trusted rule allowlist and
the stored digest; any mismatch leaves the service without a policy
(``risk_policy_unavailable``), never with a guessed one.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ledger import PretradeLedger
from .policy import CustomRuleSpec, RiskPolicy, RiskPolicyError, validate_policy_document
from .rules import RiskRule, RuleConfigError, RuleRegistry


@dataclass(frozen=True)
class ActivePolicy:
    version: int
    policy: RiskPolicy
    r04: tuple[RiskRule, int]
    custom: tuple[tuple[CustomRuleSpec, RiskRule, int], ...]

    @property
    def label(self) -> str:
        return str(self.version)


def activate(version: int, policy: RiskPolicy, registry: RuleRegistry) -> ActivePolicy:
    """Bind a validated policy to trusted rule instances (raises RuleConfigError)."""
    custom = tuple(
        (spec, *registry.instantiate(spec.rule_id, spec.implementation, spec.version))
        for spec in policy.rules
    )
    return ActivePolicy(version, policy, registry.builtin_r04(), custom)


class PolicyStore:
    """Reads the effective policy version from the ledger."""

    def __init__(self, ledger: PretradeLedger) -> None:
        if type(ledger) is not PretradeLedger:
            raise RuleConfigError("POLICY_STORE_LEDGER_REQUIRED")
        self._ledger = ledger
        self.load_error: str | None = None

    @property
    def ledger(self) -> PretradeLedger:
        return self._ledger

    def load(self, registry: RuleRegistry) -> ActivePolicy | None:
        self.load_error = None
        with self._ledger.transaction() as txn:
            row = txn.latest_policy()
        if row is None:
            return None
        try:
            policy = validate_policy_document(
                row["document_json"],
                exchange_rules_text=row["exchange_rules_text"],
                rule_allowlist=registry.allowlist,
            )
            if policy.digest != row["digest"] or policy.policy_id != row["policy_id"]:
                self.load_error = "policy_store_digest_mismatch"
                return None
            return activate(int(row["version"]), policy, registry)
        except RiskPolicyError as error:
            self.load_error = error.code
        except RuleConfigError as error:
            self.load_error = error.code
        return None


__all__ = ["ActivePolicy", "PolicyStore", "activate"]
