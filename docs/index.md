---
title: Home | bt_api_risk
---

# bt_api_risk Documentation

`bt_api_risk` holds three separate things. Only the first two take part in
order admission; the package performs no provider or network I/O and makes no
regulatory-compliance claim. Evidence levels: UNIT/FAKE (local synthetic tests),
INTEGRATION_SIM (local multi-process simulation), PACKAGE (installed wheel),
real (venue account). Nothing here is accepted at the real level.

## 1. Admission primitives (iteration-60 managed path)

`DurableRiskGate` keeps reservations, dispatch claims, STOP_NEW causes
(`stop_new`, `activate_stop_new_once`, `resolve_stop_new`,
`resolve_stop_new_exact`; refusal `STOP_NEW_ACTIVE`) and dispatch in-flight
latches (`dispatch-inflight:<intent_id>`; `resolve_dispatch_inflight`,
`resolve_cancel_dispatch_inflight`, `resolve_dispatch_inflight_recovered`) in
the SQLite table `risk_entry_blocks`. Ledgers that still have the pre-iteration-64
table `risk_freezes` are migrated in one transaction when opened; a conflict or
failure refuses to open (`RISK_ENTRY_BLOCK_TABLE_CONFLICT`,
`RISK_ENTRY_BLOCK_MIGRATION_FAILED`). Evidence: UNIT/FAKE and INTEGRATION_SIM.

## 2. Pre-trade service catalog (`bt_api_risk.pretrade`, iteration 64)

Controls R-01 to R-11 for the independent Risk service, implemented in
`bt_api_risk.pretrade`. Status REVIEW_PENDING, evidence UNIT/FAKE. See the
package README for the control list.

## 3. Analytics and ML (not admission)

`RiskAssessor`, `RiskCalculator`, `PolicyEngine`, `AnomalyDetector` and
`RiskEnsembleModel` with the containers `RiskEvent`, `RiskEventType`,
`RiskLevel` and `RiskMetrics`. They never gate an order. The former
`RiskManager` and `LimitsManager` were deleted in iteration 64 (D64-06).
Evidence: UNIT/FAKE only.

## Installation

```bash
pip install bt_api_risk                # base: bt_api_base, pydantic, typing-extensions
pip install "bt_api_risk[analytics]"   # adds numpy
pip install "bt_api_risk[ml]"          # adds numpy and scikit-learn
```
