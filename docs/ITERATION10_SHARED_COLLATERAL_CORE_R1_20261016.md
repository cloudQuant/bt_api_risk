# Iteration 10: shared collateral core

Accepted scope: shared collateral domain declarations, exact resource membership, local ledger identity, revision binding, and aggregate admission accounting across AccountScope/product resources. ACTIVE, SETTLED and UNKNOWN occupancy is counted once per reservation. Incomplete declarations quarantine increases; REDUCE/CANCEL and terminal release remain available. A local ledger identity does not prove a sole deployment owner; trusted composer wiring remains pending.

Root QA R1: 6 passed, 1 failed, 1 existing pytest configuration warning, 2.46s. The failed new UNKNOWN fixture supplied an unsupported notional_unit keyword to set_margin_pool_limit. Only that keyword was removed; the policy already supplies USD. Root R2 ran only that failed node: 1 passed, 1 existing warning, 1.05s. This is seven unique accepted cases across two calls, not a single seven-case green run. Both calls preserved 147 source/runtime pins and Risk/base HEADs. Independent incremental static review accepted the UNKNOWN, no-double-count, deny-without-admission-side-effects and release cases.

Evidence is CORE_SHARED_COLLATERAL_LOCAL_SQLITE_ONLY. The concurrency test uses two Gate instances and threads on one SQLite ledger; it does not establish cross-process deployment ownership or formal DIM03 PASS. Source exports exclude the separate analytics worker WIP. The parent SDK R217 evidence archive retains both original calls without rerunning accepted cases.

Repository: existing bt_api_risk/dev; parent dc30c1c118cf587538150fc5016c8956e30c60a9. Commit hash is recorded by the scoped postcommit receipt and parent SDK round record. This commit contains only the two source/test files and this note.
