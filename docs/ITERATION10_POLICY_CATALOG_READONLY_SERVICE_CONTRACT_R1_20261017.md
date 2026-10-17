# Iteration 10 Risk policy catalog read contract

Date: 2026-10-17
Repository: `bt_api/bt_api/bt_api_risk`, branch `dev`
Base HEAD: `489ef3d9a319356e72ccab4082540a63d3692d2f`.

This source round adds the two read operations required by the AFI policy-control HTTP view: `policy.inspect` and `policy.confirmation.read`. Inspection returns one policy version and canonical content only inside its exact owner scope. Confirmation status reports persisted owner-confirmation facts and validates the saved document against the receipt digest. Both operations require exactly `{policy_ref}` and remain read-only. A missing confirmation store fails closed; neither response claims account-gate effectiveness.

The fixed candidate uses the R3 Risk source at base commit `5434184d35a10418b2fc53e5ec7f805ee5edc884`, with its recorded `risk_policy_binding` overlay, plus only the selected read-contract patch. The patch was extracted from a mixed live file and excludes unrelated approval/publication hunks.

- Selected patch: 4,234 bytes, SHA-256 `c3fceb24525cd9e2d409963bf467be36bda105fd8bb819c60ba73fd3837d358a`.
- Candidate `service_component.py`: 153,921 bytes, SHA-256 `bfca1e082cb70eba2b144f3fd7e0e5b8f50bbcac8c9e374db52daafd6ab4d3a2`.
- Final test: 9,580 bytes, SHA-256 `5e66238881c03b67856fb0a86f6488d6e2438ed5de70a069d2e12c765bb62b8a`.
- Candidate manifest: SHA-256 `88e872a6a3267d7c437204fbbcb224e28e873721db61a87d68cc8076ee056465`.
- Focused spec: SHA-256 `2b25f86a9c70d9fdee4be56f612b3048813237a08357b1406de6c451fb74a10c`.

The focused run used the AFI Python 3.12.10 environment, cold imports from the fixed Risk and Base trees, plugin autoload disabled, `--noconftest`, and only the two SQLite contract tests. R2 passed 2/2, with 0 skips, failures, or errors; all 146 pinned sources remained unchanged and stderr was empty. The R2 spec is `D:\temp\iteration10-risk-policy-readonly-contract-source-r2-20261017\focused-source-spec.json`; raw output is in `D:\temp\iteration10-risk-policy-readonly-contract-root-20261017-r2`. R1 evidence remains preserved in its separate `*-r1` directories. Independent static review approved the production contract and the R2 cleanup-only test delta.

Evidence level: fixed-source local SQLite service-contract tests. This round does not rerun or erase the prior AFI Host startup failure, establish an AFI HTTP/Host pass or `consumer_effective`, or establish formal AFI05/06 acceptance.