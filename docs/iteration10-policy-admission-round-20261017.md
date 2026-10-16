# Iteration 10 account policy document admission round

- Repository/branch: `bt_api/bt_api_risk`, `dev`.
- Base: `888745c48aceb9ff4c60d2db720684ef075ef1d3`.
- Scope: `service_component.py` confirmed-document persistence, new `policy_admission.py`, and `test_policy_admission.py`.
- Acceptance: focused pytest passed 3 tests; Ruff and compileall passed; `git diff --check` is clean. One existing pytest asyncio configuration warning was reported.
- Independent review: GO_STATIC for the exact implementation. The final test-only change removed one trailing blank line after review; no behavior changed.
- Evidence: synthetic SQLite/catalog and Risk gate tests cover gate-bind-before-confirm, exact published document and receipt persistence, offline restart resolution without catalog/latest lookup, legacy receipt-only fail-closed document resolution, and preservation of an active old reservation when a new policy binding is incompatible.
- Boundary: trusted composition code must derive principal and account scope from the trusted account-owner binding. This round does not wire the resolver into AFI HTTP/SDK Host or establish real-account or formal AFI05/06 acceptance. The child commit hash is recorded by the parent SDK round note to avoid a self-referential hash in this file.
