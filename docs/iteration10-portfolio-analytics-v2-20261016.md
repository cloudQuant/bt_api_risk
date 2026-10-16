# Portfolio analytics V2 service round

Repository: `bt_api/bt_api_risk`, branch `dev`, parent `6c81653e2a586f47c17cba5f898f23a247b1905d`. This child-repository round contains the three accepted source paths below and this record:

- `src/bt_api_risk/portfolio_analytics_v2.py` — 44,071 bytes, SHA-256 `12f5d467eca0bd40a2b7992fc297f1402e39b03becd1d49d13287fc4d504de9b`.
- `src/bt_api_risk/service_analytics.py` — 43,916 bytes, SHA-256 `f2109a69b4c5f21a5181b970f34457cc3b4e92a003fd545de035e33d0d2ba5ac`.
- `tests/test_portfolio_analytics_v2.py` — 11,096 bytes, SHA-256 `0d60f87b1291478a9bf61d94fc057f3cbf5fda92ef70b8c9cef04ee040cbe4e7`.

The service accepts a strict typed V2 facts/request codec and dispatches V2 jobs through the existing risk-analysis task store while retaining its V1 payload and execution path. V2 reports preserve per-dataset availability, provenance and cuts, reuse the accepted numeric kernels, and bind input/request/report hashes. It imports no optional ML extras. The data in this round is supplied synthetic typed facts; it does not establish provider, real-account or FX-source authenticity.

Root focused QA passed six unit/compatibility tests in 1.11 seconds and one independent-process integration test in 5.34 seconds. The first run selected the five new V2 unit tests and the existing V1 service-store fail-closed test. The second used the SDK composition to upload, submit and query through separate Risk ServiceHost and SDK client processes. Both runs had exit code zero, empty stderr and no warnings; each recorded 24 unchanged source pins and unchanged SDK/Risk/Base/ZMQ repository HEADs. Raw QA outputs are archived by the parent SDK delivery.

Independent static review returned `GO_STATIC` for the exact four current implementation/test pins before Root QA. The review noted one non-blocking assertion opportunity: the process test checks provenance cuts but does not directly assert every metric result's own timestamp fields; the source binds those fields to their dataset cuts. The review message is summarized in the parent evidence archive; no separate raw reviewer artifact file was supplied.

Evidence level: `OFFLINE_V2_INDEPENDENT_RISK_SERVICE_HOST_AND_SDK_CLIENT_PROCESS_INTEGRATION_ONLY` for the cross-process path and `OFFLINE_TYPED_FACTS_RISK_V2_UNIT_AND_V1_TASK_SERVICE_COMPATIBILITY_ONLY` for the unit path. This accepts a V2 service/wire component only. It does not establish hard execution-deadline enforcement, cancellation semantics, AFI04 formal PASS, account-backed analytics, or trusted FX provenance. The deadline/cancel worker round remains separate.
