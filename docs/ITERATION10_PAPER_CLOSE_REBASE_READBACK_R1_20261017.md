# Iteration 10 Paper close-rebase readback R1

This round adds a typed, read-only Risk readback for the latest persisted NET/ALL closable-position rebase and binds absorbed close references to their verified terminal claim, claim row, and reservation intent. It enables the Execution owner to recognize and verify an exact same-cursor replay after restart without inventing a new proof or changing Risk state. Changed code is limited to `src/bt_api_risk/core/admission.py` and `tests/test_closable_position_rebase.py`.

The source candidate was built against Risk `dev` HEAD `66144a30f06ceda8c06e7fae28b70bce9ccace11`, using the committed NET/ALL storage schema. Final reviewed pins: `admission.py` 639,927 bytes, SHA-256 `658d0265536169444e10b85b6d78563fff7e1d93ac20ce4fc276404be02197b5`; `test_closable_position_rebase.py` 24,758 bytes, SHA-256 `af8e1067660dad7b65307c385c6b6a13133834289dd80bd6c3cfaf200d74fcca`; selected patch 21,894 bytes, SHA-256 `114689f31311acda62533206e5532068b3bea28b417a5bf0e513f936e8c29a95`.

The new selector `test_persisted_rebase_readback_same_cut_replay_is_read_only` passed once on the fixed-HEAD overlay: `1 passed, 1 warning`, exit 0. The warning is the existing unknown `asyncio_default_fixture_loop_scope` pytest option. The test compares SQLite dumps before and after readback and same-cut replay. The run was recorded in the author console only; no JUnit or separate raw-result artifact was produced. Independent static review returned GO_STATIC for these exact pins and confirmed the intent/cut/receipt bindings and database-state assertion.

This is a local Risk-store component round. It does not establish a Root Host restart result or formal AFI13 acceptance. Other Risk worktree changes were excluded from the selected patch and remain untouched.
