# Risk portfolio metrics V1 source round

Repository: `bt_api/bt_api_risk`, branch `dev`, parent `adb6ec58308149faa93c02920b72f98ac3796056`. The scoped round contains this record and the following two source paths:

- `src/bt_api_risk/portfolio_metrics_v1.py` — 20,497 bytes, SHA-256 `55a56d84fd314966f6e61fa6098bb7b5ae5cea27fac6df0ae01b562c3d4da23f`.
- `tests/test_portfolio_metrics_v1.py` — 12,431 bytes, SHA-256 `57517b596527b8831cbe4fd76aec28bdfc64a5e069042e2f9e7d4f4684d992ad`.

The V1 numeric component calculates supplied spot net/gross exposure, peak-to-trough drawdown, nearest-rank historical-loss VaR with fractional-tail ES, and multiplicative spot price/FX scenario PnL. A `-100%` price return produces zero stressed value; lower factors are rejected, while FX factors must remain strictly positive. Stress reports carry the common validated UTC cut. The hand-calculated scenario covers EUR long and GBP short rows and reconciles each row and their totals in USD.

Root's sole focused QA ran `tests/test_portfolio_metrics_v1.py`: 16 passed in 0.52 seconds, exit 0, empty stderr and no warnings. The 11 raw files are in `D:/temp/iteration10-risk-portfolio-metrics-root-20261016-r1/`; `result.json` is 806 bytes, SHA-256 `3ed7d25670c18fa29abeacfe2aa01876e3530cc92f4039a03a5fd558768492a7`, and records 137 source pins unchanged and both Risk/Base HEADs unchanged (`adb6ec58308149faa93c02920b72f98ac3796056` / `b4aabd1e17b9c7252fa7b4d266932087d99b5517`). No QA was rerun for delivery.

The original independent static review is `D:/bt_api_py/.codex-tmp/risk-portfolio-metrics-v1-static-review-20261016.md`, SHA-256 `72992985de8d858b337e3edbe683d9f392ea8ffec9588dc4d0d5f6fffdca1fe3`; it reviewed earlier pins of 20,451 bytes (`51e23273a18f92bcf98d2f9ff6968d8246fd4a594b205819e3fdea468fb28aa1`) and 10,561 bytes (`17952f127954414f037fd415f2c02c3f24c7493afbb672dadd0086d22b417ef8`). A separate incremental review returned `GO_STATIC` on the exact current pins above, covering the price-factor boundary, report cut, and two-row currency/side reconciliation.

Evidence level: `OFFLINE_SUPPLIED_FACTS_NUMERIC_METRICS_ONLY`. This source/QA round does not prove FX source authenticity, account completeness, SDK or AFI wiring, or AFI04 acceptance. Formal progress remains 37/68. The independent review's existing Python 3.9 package-metadata compatibility caveat remains open.

The Root postcommit receipt records the resulting commit hash and preservation checks.
