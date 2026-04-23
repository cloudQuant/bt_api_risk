---
title: Home | bt_api_risk
---

# bt_api_risk Documentation

Intelligent risk management and compliance monitoring system for 73+ exchanges. Provides real-time risk assessment, ML-driven anomaly detection, and regulatory compliance support.

## Overview

`bt_api_risk` provides comprehensive risk management with:

- **RiskManager / RiskAssessor** — Central risk orchestration and real-time scoring
- **ML Models** — RiskEnsembleModel (RF + NN + XGBoost), AnomalyDetector
- **Risk Containers** — RiskEvent, RiskEventType, RiskLevel, RiskMetrics
- **Compliance** — MiFID II, SEC Rule 606, AML/KYC, Basel III, MAR

## Key Benefits

- Pre-trade, in-trade, and post-trade risk controls
- Machine learning-driven risk prediction
- Behavioral anomaly detection for suspicious activity
- Support for 10+ regulatory standards
- Ensemble model combining multiple ML algorithms

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
print(f"Risk level: {risk_score.level}")
```

### Anomaly Detection

```python
from bt_api_risk import AnomalyDetector

detector = AnomalyDetector(threshold=0.8)
is_anomalous = detector.is_anomalous(
    features={"trade_frequency": 150, "order_size_ratio": 0.95, "price_impact": 0.12}
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
```

## Installation

```bash
pip install bt_api_risk
```

## Dependencies

- numpy >= 1.26.0
- pydantic >= 2.0.0

## Compliance Standards

| Standard | Description |
|----------|-------------|
| MiFID II | EU markets instrument directive |
| SEC Rule 606 | US trade reporting |
| AML/KYC | Anti-money laundering / Know your customer |
| Basel III | Banking capital requirements |
| MAR | EU market abuse regulation |

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

## Documentation

Full documentation available at [bt_api_py documentation](https://cloudquant.github.io/bt_api_py/).
