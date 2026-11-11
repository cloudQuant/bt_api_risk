# bt_api_risk

[![Python 3.9-3.13](https://img.shields.io/badge/python-3.9--3.13-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

`bt_api_risk` holds three separate things: durable pre-trade admission
primitives, the iteration-64 pre-trade service catalog, and optional analytics.
Only the first two take part in order admission. The package performs no
provider or network I/O, does not source or independently verify account,
position or instrument facts, and makes no regulatory-compliance claim. A local
or fake permit is not a live-account approval and enables no provider write
route.

Evidence levels used below: **UNIT/FAKE** (local tests with synthetic data),
**INTEGRATION_SIM** (local multi-process simulation with fake providers),
**PACKAGE** (installed wheel), **real** (a venue account). Nothing in this
package is accepted at the real level; source existence is not acceptance.

Base dependencies are `bt_api_base`, `pydantic` and `typing-extensions`.
`numpy` is only needed by the optional `analytics` extra, and `numpy` plus
`scikit-learn` by the optional `ml` extra.

[Trading system architecture overview](https://github.com/cloudQuant/backtrader/blob/dev/docs/TRADING_SYSTEM_ARCHITECTURE.md).

## 1. Admission primitives (iteration-60 managed path)

`DurableRiskGate` (`core/admission.py`) is a SQLite ledger of reservations,
dispatch claims, STOP_NEW causes and dispatch in-flight latches for one trusted
account owner. The iteration-60 in-process managed path (`RiskOrderEntryService`,
the Execution facade and the SDK registry) keeps using it as a compatibility
core; the iteration-64 Risk service does not (section 2).

- **STOP_NEW causes.** `stop_new`, `activate_stop_new_once`, `resolve_stop_new`
  and `resolve_stop_new_exact` record and clear independent account-scope
  causes. While one is active, new risk-increasing reservations and claims are
  refused with `STOP_NEW_ACTIVE`; reductions, cancels and settlement continue.
- **Dispatch in-flight latch.** A successful dispatch claim leaves a
  `dispatch-inflight:<intent_id>` latch, which also blocks new increases of the
  account. `settle` and `ensure_settled` do not clear it, and the generic
  `resolve_stop_new` refuses it (`DISPATCH_INFLIGHT_REQUIRES_RECONCILIATION`).
  `resolve_dispatch_inflight`, `resolve_cancel_dispatch_inflight` and
  `resolve_dispatch_inflight_recovered` require an injected journal authority
  that holds the account-wide writer fence while it verifies an exact current
  journal row, the single dispatch attempt and the account/intent/permit/claim
  binding. The allowed resolutions are a rejected or canceled zero-fill
  terminal, or an `ACKED_TRACKED` transfer to an exact durable order exposure
  reservation. No authority is installed by default; a verifier that cannot
  prove those facts must keep the latch active.
- **Ledger table.** STOP_NEW causes and in-flight latches share the table
  `risk_entry_blocks`. A ledger written before iteration 64 has `risk_freezes`;
  opening it renames the table in one write transaction (rows, indexes and
  triggers move with it). A ledger that holds both names refuses to open with
  `RISK_ENTRY_BLOCK_TABLE_CONFLICT`; any other migration failure rolls back and
  refuses with `RISK_ENTRY_BLOCK_MIGRATION_FAILED` (`RiskLedgerSchemaError`).
- **Increase limits.** `RiskPolicy.max_increase_notional/count` count ACTIVE and
  SETTLED reservations over the ledger's lifetime, not per trading day.
- The result field `has_other_active_freezes` and the receipt fields
  `dispatch_latch_active` keep their historical names because Execution and
  Monitor receipts persisted them.

Supporting modules owned here (source migrations; behavior, old-data and
distribution acceptance remain open): the risk-only order journal and its
SQLite/OS-lock storage (`risk_order_journal*`; v6 provider-scoped order
provenance only), CLOSE proof payloads (`order_proof_payload`), position and
instrument payload decoding (`position_payload`), order valuation digests
(`order_valuation`), position-risk revaluation (`position_baseline`), and the
CTP path budget (`ctp_budget`, `ctp_budget_journal_projection`; historical
SimNow budget path, its CNY constants are not used by section 2). The SDK
composes provider evidence, Gateway receipt verification and writer fencing
around them.

Evidence: UNIT/FAKE in this package and INTEGRATION_SIM in the SDK host tests;
no real-account acceptance.

## 2. Pre-trade service catalog (`bt_api_risk.pretrade`, iteration 64)

The independent Risk service (one process per account, hosted by the SDK)
uses a new pre-trade ledger and rule engine implemented in
`bt_api_risk.pretrade`. Status: **REVIEW_PENDING**; evidence: **UNIT/FAKE**.

| ID | Control |
| --- | --- |
| R-01 | Single-order quantity cap per writing principal x instrument, required, OPEN and CLOSE |
| R-01b | Optional single-order notional cap (quantity x price x multiplier) |
| R-02 | Optional price band against a reference price; when enabled, market orders are refused |
| R-03 | Optional worst-case position limits (filled plus in flight, UNKNOWN counted) |
| R-03b | Close capacity: this close <= account closable - other in-flight closes |
| R-04 | Order/cancel counts per account x instrument x trading day |
| R-05 | Self-trade prevention against the account's own active opposite orders |
| R-06 | Duplicate-order window |
| R-07 | Optional daily loss and drawdown limits |
| R-08 | Optional margin pre-check (off unless configured) |
| R-09 | No new control: trading-permission facts stay with iteration 62 checks |
| R-10 | Emergency-control requests through the Gateway control port |
| R-11 | Single-account exchange-rule file limits |

The authoritative semantics, finite refusal codes and open gaps are in the
iteration-64 plan and design-freeze documents; a control listed here is not
accepted until those documents say so.

## 3. Analytics and ML (not admission)

`RiskAssessor`, `RiskCalculator` and `PolicyEngine` (`core/`), and the
`AnomalyDetector` / `RiskEnsembleModel` models (`ml_models/`, `ml` extra) are
analysis helpers. They never gate an order and are not part of sections 1 or 2.
`RiskEvent`, `RiskEventType`, `RiskLevel` and `RiskMetrics` are their data
containers. The former `RiskManager` and its `LimitsManager` facade were
deleted in iteration 64 (D64-06) because they defaulted to allowing orders.

Evidence: UNIT/FAKE only.

## Installation

```bash
pip install bt_api_risk                # admission primitives and service catalog
pip install "bt_api_risk[analytics]"   # adds numpy for RiskCalculator
pip install "bt_api_risk[ml]"          # adds numpy and scikit-learn for the ML models
```

## License

MIT License
