# Risk local operator Web API, version 1

This is the reference of the HTTP interface in `bt_api_risk.web.app` (iteration 64,
step 64.13, interface part) and of the login routes added by the built-in local host
`bt_api_py.risk_web_local_host`. It describes the code as it is. It is not evidence
that a Risk service, a Gateway, an account or a deployment has been checked: the
tests behind it use a fake admin caller and a fake SDK runtime (UNIT/FAKE). No page
is part of this interface; the page is delivered by iteration 69 (D63-64) and uses
this API like any other client.

## 1. What the interface is

- An optional, local-only HTTP adapter in front of the Risk service's operator port
  `service.risk_admin` (client mount `application.risk_admin`). It reads the Risk
  service's status, policy, latches, UNKNOWN permits, counts and audit records,
  publishes a policy, releases one latch, and requests and reads an operator cancel.
  Each route sends exactly one operation of
  `bt_api_base.risk_service_protocol.RISK_ADMIN_OPERATIONS`.
- It has no authority and no state of its own. The host supplies one admin caller
  bound to the operator's own authenticated CURVE registration (`application_client`
  role, the operator's principal and actor, no delegate). The Risk service's
  Registry and its handlers authorize, validate, execute and audit every call for
  that principal, exactly as for the operator's own SDK client.
- The API is independent of any page (D63-47). The same routes, with the same
  session token, serve a browser page, a script, or a future ai-for-investor
  adapter; nothing in the Risk service depends on this API, its host or a page
  being up. Stopping or crashing the Web host closes only its own registration.
- Install with the `web` extra: `pip install "bt_api_risk[web]"` (FastAPI,
  pydantic, uvicorn). `import bt_api_risk`, `bt_api_risk.pretrade` and
  `bt_api_risk.web` work without FastAPI; only `bt_api_risk.web.app` needs it.

## 2. Transport rules (every request)

| Rule | Failure |
| --- | --- |
| The TCP peer must be a loopback address. | 403 `{"error": "LOCAL_ACCESS_REQUIRED"}` |
| The `Host` header must equal the configured origin's host and port. | 403 `{"error": "HOST_DENIED"}` |
| Only `GET` and `POST` pass. | 405 `{"error": "METHOD_DENIED"}` |
| A `POST` must carry `Origin` equal to the configured origin; a `GET` that carries an `Origin` must carry that one. | 403 `{"error": "ORIGIN_DENIED"}` |
| A `POST` must carry a decimal `Content-Length` of at most 8192 bytes (524288 for `POST /api/v1/risk/policy`); a chunked body without it is refused. | 413 `{"error": "BODY_SIZE_INVALID"}` |
| A `POST` under `/api/v1/risk/` must be `Content-Type: application/json`. | 415 `{"error": "CONTENT_TYPE_DENIED"}` |

The configured origin of the app must be `http` or `https` on `localhost` or a
loopback IP; the built-in host accepts only `http://127.0.0.1:<port>` and
`run_local` listens only on 127.0.0.1, with proxy headers ignored. Every answer
carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` and `Content-Security-Policy: default-src 'none';
frame-ancestors 'none'`. No CORS header is ever sent, so another site's page can
neither read an answer nor send the session header without a preflight, and the
preflight (`OPTIONS`) is refused.

## 3. Authentication and authorisation

- The host authenticates every request; the adapter never reads an identity, an
  account or a strategy from a body, a query or a path. The built-in host expects
  `X-Risk-Session: <64 lowercase hex>` from `POST /login` (section 8). Without a
  valid session every route answers 401 `{"error": "AUTHENTICATION_REQUIRED"}`.
  Authentication runs before any request validation: an unauthenticated malformed
  request is still 401.
- Every `POST` under `/api/v1/risk/` also needs `X-CSRF-Token` equal to the
  `csrf_token` of `GET /api/v1/risk/session`: 403 `{"error": "CSRF_DENIED"}`.
- A session carries the operator operations its host may send (`operations` of
  `GET /api/v1/risk/session`). A route whose operation is not in that set answers
  403 `{"error": "OPERATION_NOT_GRANTED"}` and sends nothing. This only narrows: the
  Risk service still decides. Its Registry refusal of the call (section 6.2) and its
  handler's refusal `risk_unauthorized` are passed on as `REQUEST_REJECTED`.
- After authentication the request is validated strictly (unknown body fields,
  unknown or repeated query parameters, wrong JSON types including booleans for
  integers, duplicate JSON keys, `NaN`/`Infinity`, ids or reasons with surrounding
  spaces or control characters): 422 `{"error": "REQUEST_INVALID"}`. The answer never
  echoes the input, a field name or a value.

## 4. Routes

| Method | Path | Risk operation | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/v1/risk/session` | — | CSRF token, operations and storage namespace of this session (no Risk call) |
| `GET` | `/api/v1/risk/status` | `risk.admin.status` | Availability, policy version, latches, counts, observation state |
| `GET` | `/api/v1/risk/policy` | `risk.policy.read` | Effective policy document and version |
| `POST` | `/api/v1/risk/policy` | `risk.policy.publish` | Publish a new policy version (compare-and-set) |
| `GET` | `/api/v1/risk/latches` | `risk.latch.list` | Local breach latches; `?active_only=true\|false` (default `false`) |
| `POST` | `/api/v1/risk/latches/{latch_id}/release` | `risk.latch.release` | Release one latch (compare-and-set) |
| `GET` | `/api/v1/risk/unknown` | `risk.unknown.list` | Permits whose outcome is UNKNOWN |
| `GET` | `/api/v1/risk/counts/{trading_day}` | `risk.counts.export` | Day counts; `?format=json\|csv` (default `json`) |
| `GET` | `/api/v1/risk/audit` | `risk.audit.read` | Audit records; `?after=<int ≥ 0>&limit=<1..1000>` (defaults 0, 100) |
| `POST` | `/api/v1/risk/cancel` | `risk.cancel.request` | Request an operator cancel by scope |
| `GET` | `/api/v1/risk/cancel/{operation_id}` | `risk.cancel.status` | State of an operator cancel |

`risk.order.*` and `risk.parent.*` have no route and are never sent by the host's
caller; the route set equals `RISK_ADMIN_OPERATIONS` (checked when the module loads).

## 5. Requests and answers

A successful answer is the Risk service's reply, copied after validation (wire
`OBSERVED` or `NOT_FOUND`). The arguments sent to Risk are exactly those listed.

- `GET status` → Risk `{}`. Answer `{"status": "OBSERVED", "summary": {...}}`.
- `GET policy` → Risk `{}`. Answer `{"status": "OBSERVED", "version": int,
  "policy_id": str, "digest": str, "document": {...}, "exchange_rules_digest":
  str|null}`.
- `POST policy`, body `{"expected_version": int ≥ 0, "document": {...}, "reason":
  str, "exchange_rules_text": str|null}` (`exchange_rules_text` optional, default
  null; `reason` required, 1–1024 printable characters). Risk receives the same four
  fields. Answer `{"status": "OBSERVED", "version": int ≥ 1, "policy_id", "digest",
  "classification": {"tightened": [str], "loosened": [str], "unchanged": [str]}}`.
  The adapter bounds the document (depth 32, 100000 nodes) and checks only its JSON
  shape; the Risk service validates its content (`policy_*` codes).
- `GET latches` → Risk `{"active_only": bool}`. Answer `{"status": "OBSERVED",
  "latches": [latch]}`, each latch exactly `latch_id, control, scope_kind,
  scope_value, reason, trading_day, version, active, released_by, released_at`;
  `active` is shown as a boolean. With `active_only=true` a released latch in the
  reply makes it invalid.
- `POST latches/{latch_id}/release`, body `{"expected_version": int ≥ 0, "reason":
  str}` → Risk `{"latch_id", "expected_version", "reason"}`. Answer `{"status":
  "OBSERVED", "latch": latch}`; the latch must be the one named in the path and no
  longer active.
- `GET unknown` → Risk `{}`. Answer `{"status": "OBSERVED", "permits": [permit]}`,
  each exactly `request_key, strategy_ref, permit_id, reservation_id, state,
  instrument, side, offset, quantity, since`.
- `GET counts/{trading_day}` (`YYYYMMDD`, a calendar date) → Risk
  `{"trading_day", "format"}`. Answer `{"status": "OBSERVED", "format": str,
  "content": str}`, `format` equal to the request's.
- `GET audit` → Risk `{"after": int, "limit": int}`. Answer `{"status": "OBSERVED",
  "records": [{...}], "next_after": int}` with at most `limit` records and
  `next_after ≥ after`.
- `POST cancel`, body `{"operation_id": str, "scope_kind": "account"|"instrument",
  "scope_value": str}` (`scope_value` may be empty; the Risk service decides which
  values a scope allows). Answer `{"status": "OBSERVED", "operation_id", "state"}`
  for the same `operation_id`.
- `GET cancel/{operation_id}` → Risk `{"operation_id"}`. Answer `{"status":
  "OBSERVED", "operation_id", "state", "gateway": {...}|null}`, or 404
  `{"status": "NOT_FOUND", "operation_id"}`, always for the requested id.

Ids in a path or body (`latch_id`, `operation_id`) are 1–256 UTF-8 bytes,
printable, without surrounding spaces; an id containing `/` cannot be addressed
in a path.

## 6. Status values and codes

| Value | HTTP | Meaning |
| --- | --- | --- |
| `OBSERVED` | 200 | The Risk service answered; the body is its validated reply. |
| `NOT_FOUND` | 404 | `GET cancel/{operation_id}` only: Risk has no record under this id. |
| `REQUEST_REJECTED` | 409 or 422 | Risk refused this call with the finite `code`; this call changed nothing. 422 when Risk refused the request's content (`risk_request_invalid`, `risk_admin_reason_*`, `policy_*` other than the two below), 409 otherwise (state conflicts such as `policy_version_conflict`, `policy_loosening_latched`, `latch_version_conflict`, `latch_not_active`, `latch_not_found`, `risk_request_conflict`, `risk_unauthorized`, `risk_policy_unavailable`, and the Registry refusals of 6.2). Act on `code`, not on the HTTP status. |
| `NOT_SENT` | 503 | The host proved that the request never left the Web host (6.3). Nothing changed. |
| `UNKNOWN` | 502 or 504 | No provable outcome; a write may or may not have been applied (6.4). |

Adapter refusals, `{"error": "<code>"}`: `LOCAL_ACCESS_REQUIRED` (403),
`HOST_DENIED` (403), `METHOD_DENIED` (405), `ORIGIN_DENIED` (403),
`BODY_SIZE_INVALID` (413), `CONTENT_TYPE_DENIED` (415), `AUTHENTICATION_REQUIRED`
(401), `CSRF_DENIED` (403), `OPERATION_NOT_GRANTED` (403), `REQUEST_INVALID` (422).
Nothing is sent to Risk for any of them.

### 6.1 Codes of the Risk handlers

Lower-case finite codes of `{"status": "REQUEST_REJECTED", "code": ...}` replies,
for example `policy_version_conflict`, `latch_version_conflict`, `latch_not_found`,
`risk_admin_reason_required`, `risk_request_invalid`, `risk_unauthorized` and the
`policy_*` validation codes. The adapter accepts any code of the form
`[a-z][a-z0-9_]{0,63}`; another shape is `RISK_REPLY_INVALID`.

### 6.2 Refusals by the Risk service's Registry

Returned before any handler ran, in the service's own reply to this call; passed on
as 409 `REQUEST_REJECTED`: `CAPABILITY_UNAVAILABLE`, `CLOSED`, `DENIED`,
`NOT_REGISTERED`, `POLICY_REQUIREMENT_UNMET`, `SCOPE_DENIED`, `STALE_EPOCH`. Any
other code from the transport stays `UNKNOWN`.

### 6.3 `NOT_SENT` codes

`ROUTE_UNAVAILABLE` (no running, healthy registration of this operator on the
configured Risk service, peer and account, holding the operation), `NOT_READY`,
`QUEUE_FULL`, `TIMEOUT_BEFORE_START`, `CLOSED_BEFORE_START`, `REQUEST_NOT_SENT`,
`WRONG_PROCESS`, `OWNER_THREAD_REENTRY`, `INVALID_ARGUMENTS`. Any other not-sent
reason a host reports is shown as `REQUEST_NOT_SENT`.

### 6.4 `UNKNOWN` codes

`RISK_TIMEOUT` (504: no reply in time after the request may have left),
`RISK_OUTCOME_UNKNOWN` (502: transport failure, lost reply, handler failure, a
reply that crossed a re-registration), `RISK_REPLY_INVALID` (502: the reply does
not have the shape of section 5, has a credential-like key such as `token`,
`secret`, `password` or `auth_code`, or a non-finite number). No exception text,
argument or reply value is ever part of an error answer.

## 7. Client rules

1. `GET /api/v1/risk/session` first; keep `csrf_token`. Keep client-side state under
   `namespace` (a hash of the operator identity).
2. The adapter sends every request once and never retries. A client must not retry
   a write automatically either, whatever the HTTP method looks like.
3. On `UNKNOWN`, a lost reply or a closed tab, resolve by reading, never by
   repeating blindly:
   - publish: `GET policy`; the write happened if `version` and `digest` are the
     new ones. A repeat with the old `expected_version` is refused
     `policy_version_conflict` once the first one was applied.
   - latch release: `GET latches`; the latch shows `active: false` with a higher
     `version` if it was released. A repeat with the old version is refused.
   - cancel: `GET cancel/{operation_id}` with the same id. Choose the
     `operation_id` before the first request and keep it; a repeat with the same id
     and scope is the same cancel at the Risk service.
4. `NOT_SENT` is safe to send again after the cause is fixed (for example after the
   Web host was restarted). `REQUEST_REJECTED` describes this call only.
5. A released latch does not mean that trading is ready, and it never releases a
   Gateway control. Nothing resumes by itself.

## 8. Built-in host

`python -m bt_api_py.risk_web_local_host --config <absolute owner-only JSON>`
(`main()` in `bt_api_py.risk_web_local_host`). One host serves one operator
principal; a second operator runs a second host with its own principal and keys.

The configuration file must be absolute, a regular file owned by the user, mode
0600 or stricter, not a symlink at any path component. A detectable change ends
every session until the host is restarted. Keys (all required, no others):

```json
{"schema_version": 1, "origin": "http://127.0.0.1:8710",
 "operator": {"principal_ref": "...", "actor_ref": "...",
   "login_token_sha256": "<SHA-256 hex of a 64-hex random login token>",
   "execution_domain_ref": "...", "account_ref": "...", "scope_ref": "...",
   "service_id": "...", "service_principal_ref": "...", "instance_id": "...",
   "endpoint": "tcp://...", "server_public_key": "<Z85>",
   "client_public_key": "<Z85>", "client_secret_key": "<Z85>",
   "operations": ["risk.admin.status", "risk.policy.read"]}}
```

`operations` is a non-empty subset of `RISK_ADMIN_OPERATIONS`; it is requested on
mount `application.risk_admin` and the Risk service's Registry must grant it, or
`start()` fails with `RISK_ADMIN_UNAVAILABLE` and nothing is served.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/login` | Form body `token=<64 hex>`; answers `{"session": "<64 hex>"}` |
| `POST` | `/logout` | Header `X-Risk-Session`; answers `{"status": "SIGNED_OUT"}` |

Both follow the transport rules of section 2 (so `POST /login` needs the `Origin`).
A wrong token answers 401 `{"error": "AUTHENTICATION_REQUIRED"}`; more than 128
live sessions answer 503 `{"error": "SESSION_CAPACITY"}`. A session lasts at most
30 minutes. The host sets no cookie and serves no page. Revoking a login in the Web
host is not a Risk revocation: revoke the principal or its grant in the Risk
service's Registry.

## 9. What this API never does

- It never places, changes, reserves, dispatches or releases an order, and never
  calls `risk.order.*` or `risk.parent.*`.
- It never bypasses the Gateway: it talks only to the Risk service, which applies
  its own rules and forwards to the Gateway; it never calls a Gateway port.
- It never releases a latch, publishes a policy or requests a cancel except on an
  explicit request, never retries, never resumes trading and never clears an
  `UNKNOWN` permit.
- It never holds risk state, policy or latches of its own; browser storage and Web
  host memory are not an audit record. The Risk service writes the audit.
- It never accepts an identity, account or strategy from a request, never uses a
  shared or more privileged identity, and never grants a Risk operation.
- It never listens on a non-loopback address, follows proxy headers, sends CORS
  headers or sets cookies.
- It never starts, stops or reconfigures the Risk service; a page that is closed,
  broken or absent changes nothing there.

## 10. Evidence and open items

- Evidence: UNIT/FAKE only (`bt_api_risk/tests/test_risk_web_api.py`,
  `tests/unit/test_iter64_risk_web_local_host.py` of bt_api_py). No real Risk
  service, CURVE transport, Gateway, browser or account was used.
- The reply shapes of section 5 are the frozen wire of 64.01 section 10; the Risk
  host must project its ledger rows to them (for example `version`, `released_at`,
  `instrument`, `since`). A reply with other keys is `RISK_REPLY_INVALID`.
- Not delivered here: the page (iteration 69), ai-for-investor integration, and an
  INTEGRATION_SIM run against an actual Risk service host.
