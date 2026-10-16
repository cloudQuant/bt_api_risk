# Iteration 10 Durable Risk Policy Binding R1

Repository: `bt_api/bt_api_risk`, branch `dev`.

This source round closes the API dependency required by the trusted account-policy startup resolver. `DurableRiskGate.bind_policy(scope)` accepts only an exact `AccountScope`, persists or verifies the configured immutable policy binding in the existing SQLite ledger, and returns a typed readback containing the scope, policy ID, policy fingerprint, and ledger identity. Rebinding the same policy is idempotent across restart. A different policy is denied without changing an existing active reservation. This binding is startup readback evidence; it does not by itself claim that an account consumer is effective.

The exact selected paths are:

- `src/bt_api_risk/core/admission.py`
- `src/bt_api_risk/core/__init__.py`
- `src/bt_api_risk/__init__.py`
- `tests/test_durable_policy_binding.py`

Base source is Risk `5434184d35a10418b2fc53e5ec7f805ee5edc884`. The admission-file change is the policy-binding class, `bind_policy` method, and public export only; unrelated DIM03/DIM04 work in the live checkout is excluded from this round.

Focused acceptance used the fixed Risk/Base source export and two real SQLite tests: same-policy restart/readback with an active reservation, replacement-policy rejection with unchanged rows, and invalid-scope rejection before binding creation. Result: **2 passed**. The fixed AFI candidate then cold-imported `bt_api_risk`, `bt_api_risk.core`, `core.admission`, and `policy_admission` from the candidate export, and its unique AFI partial-effective selector collected successfully: **1 test collected**. The exact fixed-source spec was `D:\temp\iteration10-afi05-06-ordinary-policy-partial-effective-fixed-source-cdd822-bb14-r543-r3-20261017\fixed-source-root-spec-r3.json` (SHA-256 `5507307e93215087e0b00ca8447f6bededdbf4182071c053e1cd176d86b88704`); its 2,938 file pins resolve within that candidate export, with Risk binding source overlaid on the pinned 5434184 base. That collection check did not execute the HTTP/Host test body. No external provider or real account was used; this round does not establish formal AFI05/AFI06 acceptance or `consumer_effective=true`.
