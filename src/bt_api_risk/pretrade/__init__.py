"""Pre-trade core of the independent Risk service (iteration 64, freeze 64.01).

``bt_api_risk.pretrade`` judges, records and forwards; it never connects to a
provider, holds a session or credentials, changes order fields or holds kill
switch state (INV64-01). It does not import ``bt_api_py``, the Gateway or
Execution packages (INV64-02); the SDK Risk service host implements the ports.
Evidence level of this package alone: unit tests with fake ports only.
"""

from __future__ import annotations

from .controls import DATED_BUCKET_VENUES, crosses, derive_effect
from .engine import (
    NOT_SENT_STATES,
    PolicyPublishResult,
    PretradeEngine,
    RiskAdminError,
    RiskEngineConfigError,
    RiskParentResult,
    RiskRequestError,
    proves_not_sent,
    reserve_refused,
)
from .facts import (
    AccountSnapshot,
    InstrumentFacts,
    MarginRateFact,
    ObservedExecutionEvent,
    PriceFact,
    RiskFactError,
    StrategyFinancialFact,
)
from .ledger import SCHEMA_VERSION, PretradeLedger
from .policy import (
    POLICY_SCHEMA,
    RiskPolicy,
    RiskPolicyError,
    classify_change,
    parse_exchange_rules,
    validate_policy_document,
)
from .policy_store import ActivePolicy, PolicyStore
from .ports import (
    CallerIdentity,
    ControlReply,
    FactsPort,
    GatewayControlPort,
    GatewayOrderPort,
    GatewayReply,
    PortValueError,
    instrument_scope_value,
)
from .rules import (
    BreachRequest,
    OrderCountStopNewRule,
    RiskRule,
    RuleConfigError,
    RuleContext,
    RuleDecision,
    RuleRegistry,
)

__all__ = [
    "AccountSnapshot",
    "ActivePolicy",
    "BreachRequest",
    "CallerIdentity",
    "ControlReply",
    "DATED_BUCKET_VENUES",
    "FactsPort",
    "GatewayControlPort",
    "GatewayOrderPort",
    "GatewayReply",
    "InstrumentFacts",
    "MarginRateFact",
    "NOT_SENT_STATES",
    "ObservedExecutionEvent",
    "OrderCountStopNewRule",
    "POLICY_SCHEMA",
    "PolicyPublishResult",
    "PolicyStore",
    "PortValueError",
    "PretradeEngine",
    "PretradeLedger",
    "PriceFact",
    "RiskAdminError",
    "RiskEngineConfigError",
    "RiskFactError",
    "RiskParentResult",
    "RiskPolicy",
    "RiskPolicyError",
    "RiskRequestError",
    "RiskRule",
    "RuleConfigError",
    "RuleContext",
    "RuleDecision",
    "RuleRegistry",
    "SCHEMA_VERSION",
    "StrategyFinancialFact",
    "classify_change",
    "crosses",
    "derive_effect",
    "instrument_scope_value",
    "parse_exchange_rules",
    "proves_not_sent",
    "reserve_refused",
    "validate_policy_document",
]
