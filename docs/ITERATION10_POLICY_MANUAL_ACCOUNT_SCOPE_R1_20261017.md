# Iteration 10 manual account-policy scope R1

- Repository/branch: `bt_api/bt_api_risk`, `dev`.
- Base: `47d12a3f30bfcf491eed41b25a7bc27926014f37`.
- Scope: `src/bt_api_risk/policy_admission.py` and the new
  `tests/test_policy_admission_manual_scope.py`.
- Change: ordinary account-policy resolution now accepts the single-account
  `WireScope` shape used by a trusted manual-book target. It continues to reject
  strategy/run/group/leg and multi-account scopes, and rejects a manual-book
  scope mixed with a portfolio. The existing account-plus-portfolio form is
  unchanged. Catalog receipt matching remains exact across every scope field.
- Acceptance: the new focused SQLite/catalog/confirmed-store/Risk-gate test
  passed (`1 passed`, Python 3.12, AFI backend virtual environment). It checks
  published resolution, gate binding before persistent confirmation, offline
  restart readback, and wrong account/manual-book or expanded-scope rejection.
- Boundary: this is a local source/unit slice. It does not establish SDK
  `RiskOrderTarget` equality, AFI HTTP/Host integration, budget generation
  behavior, or formal AFI05/06 acceptance. The SDK owner-binding change is a
  separate selected patch pending its index slot.
