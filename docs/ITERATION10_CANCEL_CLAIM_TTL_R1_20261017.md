# CANCEL permit expiry under SQLite lock wait — R1

- Repository: `bt_api/bt_api_risk`, branch `dev`. Base: `d936a6ccc8e283d8d71eab68790574e30e007fa3`.
- Scope: the three `DurableRiskGate.claim_for_dispatch` hunks that refresh the clock after `BEGIN IMMEDIATE`, expire/revalidate CANCEL immediately before the claim insert, and recheck its expiry before commit; plus `tests/test_cancel_claim_expiry_lock_wait.py`.
- Acceptance: the focused local SQLite/fake-clock node passed 1 test (one existing pytest configuration warning). Independent static review returned GO. The test holds a real SQLite writer transaction, advances the injected clock beyond the one-second CANCEL permit TTL, then verifies `PERMIT_NOT_ACTIVE`, no persisted dispatch claim, and no freeze.
- Evidence level: local synthetic SQLite/clock only; no real provider or account. No other exposure modes, policy, or close behavior is changed by this round.
- The parent repository will record the resulting child commit SHA when it updates the SDK gitlink.
