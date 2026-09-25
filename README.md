# bt_api_risk

[![Python 3.9-3.14](https://img.shields.io/badge/python-3.9--3.14-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

Intelligent risk management and compliance monitoring system for 73+ exchanges. Provides real-time risk assessment, ML-driven anomaly detection, and regulatory compliance support.

## Features

### Core Risk Management
- **RiskManager** — Central risk management orchestrator for pre-trade, in-trade, and post-trade risk controls
- **RiskAssessor** — Real-time risk scoring and limit enforcement

### Machine Learning Models
- **RiskEnsembleModel** — Ensemble model combining Random Forest, Neural Network, and XGBoost for risk prediction
- **AnomalyDetector** — Behavioral pattern recognition and outlier detection for suspicious trading activity

### Risk Containers
- **RiskEvent** — Structured event type for risk-triggered incidents
- **RiskEventType** — Enum of event types (POSITION_LIMIT, MARGIN_CALL, etc.)
- **RiskLevel** — Enum of risk levels (LOW, MEDIUM, HIGH, CRITICAL)
- **RiskMetrics** — Container for aggregated risk metrics

### Provider-independent admission primitives

`DurableRiskGate` and the instrument admission types provide deterministic,
local contracts for offline fake-client smoke tests. They do not source trusted
account, position, exchange metadata, or policy facts, and do not constitute a
real-account risk approval or enable a provider write route. A production
composition must independently supply and verify those authorities.

A successful dispatch claim leaves a `dispatch-inflight:<intent_id>` account
freeze. `settle` and `ensure_settled` require the matching durable claim and do
not clear that latch. The generic `resolve_freeze` method refuses dispatch
latches. `resolve_dispatch_freeze` requires an injected journal authority that
holds the account-wide writer fence while it verifies an exact current journal
row, the single dispatch attempt, and the account/intent/permit/claim binding,
then yields a typed `VerifiedDispatchResolution` bound to the proof digest. A
bare boolean cannot clear the latch; the receipt itself is not a signature or
proof of provider truth outside that injected authority.
The allowed resolutions are a rejected or canceled zero-fill terminal, or an
`ACKED_TRACKED` transfer to an exact durable order exposure reservation. The
tracked order's settled notional remains counted as risk capacity; this API
does not clear positions, margins, fills, or later order lifecycle state.
No authority is installed by default. The Iteration 41 CTP reconciliation
observation alone is not sufficient: its independent native queries do not
prove a common atomic snapshot or an account-wide writer fence. A verifier
that cannot prove those facts must keep the latch active. Fake simulation
evidence is restricted to `fake`/`fixture` scopes and cannot bind a native CTP
scope.

### Compliance Standards
- Market Manipulation Detection (spoofing, layering, front-running)
- Anti-Money Laundering (AML) and Know Your Customer (KYC)
- MiFID II and SEC Rule 606 trade reporting
- Position limits and concentration risk limits
- Credit risk and margin management

## Installation

```bash
pip install bt_api_risk
```

## Requirements

- Python >= 3.9
- numpy >= 1.26.0
- pydantic >= 2.0.0

## Quick Start

```python
from bt_api_risk import RiskManager, RiskAssessor, RiskLevel, RiskEvent, RiskEventType

# Initialize the risk manager
risk_mgr = RiskManager()

# Create a risk assessment
assessor = RiskAssessor()
risk_score = assessor.assess_position(
    exchange="BINANCE___SPOT",
    symbol="BTCUSDT",
    position_value=100000.0,
    account_equity=500000.0,
)
print(f"Risk level: {risk_score.level}")  # RiskLevel.MEDIUM

# Emit a risk event
event = RiskEvent(
    event_type=RiskEventType.POSITION_LIMIT,
    level=RiskLevel.HIGH,
    exchange="BINANCE___SPOT",
    symbol="BTCUSDT",
    message="Position exceeds single-symbol limit",
)
risk_mgr.emit(event)
```

### Anomaly Detection

```python
from bt_api_risk import AnomalyDetector

detector = AnomalyDetector(threshold=0.8)
is_anomalous = detector.is_anomalous(
    features={
        "trade_frequency": 150,
        "order_size_ratio": 0.95,
        "price_impact": 0.12,
    }
)
```

### ML Ensemble Risk Model

```python
from bt_api_risk import RiskEnsembleModel

model = RiskEnsembleModel()
risk_prob = model.predict_risk(
    features={
        "position_concentration": 0.75,
        "leverage_ratio": 2.5,
        "daily_volatility": 0.04,
        "liquidity_score": 0.6,
    }
)
print(f"Risk probability: {risk_prob:.3f}")
```

## API Reference

| Class | Description |
|--------|-------------|
| `RiskManager` | Central orchestrator for risk controls |
| `RiskAssessor` | Real-time risk scoring engine |
| `RiskEnsembleModel` | ML ensemble for risk prediction |
| `AnomalyDetector` | Behavioral anomaly detection |
| `RiskEvent` | Risk incident event container |
| `RiskEventType` | Enum of risk event types |
| `RiskLevel` | Enum of risk severity levels |
| `RiskMetrics` | Aggregated risk metrics container |

## Compliance Standards

| Standard | Description |
|----------|-------------|
| MiFID II | EU markets instrument directive |
| SEC Rule 606 | US trade reporting |
| AML/KYC | Anti-money laundering / Know your customer |
| Basel III | Banking capital requirements |
| MAR | EU market abuse regulation |

## Documentation

Full documentation available at [bt_api_py documentation](https://cloudquant.github.io/bt_api_py/).

## License

MIT License
