# SRS/SDD Implementation Checklist

This checklist records implementation and verification status for the current M1 code. The authoritative SRS and SDD remain unchanged. “Verified” distinguishes automated tests/build checks from live integration and manual end-to-end checks; each verification is stated in its row.

## Functional requirements

| SRS | Status | Implementation / limit |
|---|---|---|
| FR-01 Authentication | Implemented | Password login, bearer JWT, current-user endpoint, protected API dependencies, active-user checks, and server-side logout revocation using hashed token fingerprints with TTL expiry. |
| FR-02 Role authorization | Implemented | Exactly Administrator and Normal User; server-side role and owner checks. |
| FR-03 User administration | Partial | Administrator creates, disables, and assigns roles. A separate settings/rule-management UI is not in the SRS endpoint list and is not implemented. |
| FR-04 PCAP upload | Implemented | Authenticated upload accepts `.pcap` and `.pcapng`. |
| FR-05 Upload validation | Implemented with request limits | Extension and capture magic, empty/malformed parse, pre-parser request-body cap, exact streamed file-size checks, safe errors, processing packet/time bounds, and staging cleanup. |
| FR-06 Analysis tracking | Implemented with recovery limits | Persisted queued, running, completed, and failed job states; detail endpoint supports polling. Detailed findings are stored in the separate `analysis_findings` collection and are visible only for the matching fenced completion token. Bounded workers reclaim queued jobs and running jobs after lease expiry if required indexes and staged files are available. Active execution is interrupted by restart; recovery is not a distributed durable queue. |
| FR-07 Performance | Measured on synthetic captures | Synthetic captures of approximately 1 MB (863 packets), 10 MB (8,624 packets), 20 MB (17,247 packets), and 24 MB (20,696 packets) completed below the SRS target of under two minutes. The 24 MB capture completed in 24 seconds based on the UI timestamps. A 50 MB capture was rejected by the configured 25 MB upload limit. Representative real-world capture performance remains unverified. |
| FR-08 Feature extraction | Implemented | Packet protocol and directional flow counts, bytes, duration, endpoints, and ports are derived without payload retention. |
| FR-09 Signature detection | Implemented | `SIG-NET-001` TCP SYN port scan and `SIG-NET-002` high-rate SYN burst; stable versions, severity, rationale, and evidence. |
| FR-10 ML scoring | Not available | No approved model artifact, compatible feature schema, or provenance-documented dataset was present. Jobs explicitly record scoring as skipped. |
| FR-11 Alert creation | Implemented | Persistent alert IDs, timestamp, severity, method, rule reference, evidence, job/user ownership, and workflow status. |
| FR-12 Threat context | Partial | Optional local JSON indicator matching is implemented. No local IOC list or external provider is bundled/configured. |
| FR-13 Alert review | Implemented | Scoped list/detail, text/severity/method/status/time filters, pagination; Administrators can update alert state. |
| FR-14 Dashboard | Implemented | Real Mongo-backed job/alert metrics, ownership scoping, and severity/method/time filters. |
| FR-15 Audit trail | Implemented | Login, role/user changes, upload/launch, denied access, and alert-state changes record safe metadata. |
| FR-16 Export | Implemented | Owner/Admin-scoped analysis-summary and filtered-alert CSV exports. API exports stream rows; the current browser helper buffers the returned Blob. |
| FR-17 Error reporting | Implemented | Consistent validation/auth/database errors; generic unhandled responses; payloads and secrets are not returned. |
| FR-18 Reproducible demo | Implemented | README workflow, safe synthetic capture generator, and known-result integration test. |

## Analysis finding storage verification

- One bounded MongoDB document is stored per finding, with a maximum encoded size of 8 MiB.
- The unique compound index is `(job_id, claim_token, finding_index)`. Idempotent upserts preserve deterministic per-claim indexes on retry.
- Findings are queried only through the job's `completed_claim_token`; pagination and CSV export read the separate collection in bounded batches.
- Finding writes check current claim ownership at bounded checkpoints. Since standalone MongoDB cannot atomically validate a job in one collection and write a finding in another, a narrow stale-write race remains possible. Such records are not visible and the bounded orphan sweeper eventually removes them.
- Real MongoDB 9.0.4 standalone verification used isolated database `intrusion_detection_results_cleanup_integration_test`; the database was removed after successful checks. It verified stale claim rejection, the post-validation race, bounded removal of 242 invalid rows in eight data batches (plus an exhaustion check), and preservation of completed findings. No transaction was used and the production database was not modified.
- A second isolated MongoDB 9.0.4 standalone check verified that cleanup preserves an active claim, removes it after lease expiry/reclaim, and keeps the replacement completed result visible. It used and then dropped only `intrusion_detection_results_cleanup_active_integration_test`. It also exercised MongoDB's naive-UTC datetime decoding.
- Final production-readiness audit: 87 backend tests passed with one Starlette/httpx TestClient deprecation warning; 8 frontend dependency-free tests passed; Vite production build, Python `compileall`, and `git diff --check` passed. Browser automation is disabled in the current Work settings, so no browser visual/accessibility session is claimed.

## Backend query and token lifecycle verification

- Analysis and alert lists apply ownership, filtering, stable descending timestamp/ID ordering, skip, and limit in MongoDB queries. Substring search uses escaped case-insensitive MongoDB regular expressions.
- Dashboard totals and grouped status/severity/method counts are computed with MongoDB aggregation (`$group` and `$facet`) while preserving the existing response keys and role scopes.
- Logout stores only a SHA-256 fingerprint and token expiration in `token_revocations`; expired tokens are rejected by JWT validation, disabled accounts remain rejected by the user check, revoked tokens are rejected by the revocation lookup, and expiry is handled by a TTL index plus bounded cleanup.
- Aggregation and revocation tests pass. MongoDB 9.0.4 standalone verification used only the isolated `intrusion_detection_scale_auth_integration_test2` database, which was dropped after success; no production database was modified and no transaction was used.
- The final audit repeated the full backend suite and also exercised real MongoDB 9.0.4 using only isolated database `intrusion_detection_prod_audit_20261113_a7c4`; required indexes, outbox uniqueness, live authentication, controlled PCAP detection, ownership, duplicate alert delivery, export, revocation, and staged-file cleanup passed. The isolated database was removed after success; no production database was accessed or changed.

## Nonfunctional requirements

| SRS | Status | Verification / limit |
|---|---|---|
| NFR-01 Security | Implemented | Protected API dependencies and ownership checks are tested. |
| NFR-02 Password safety | Implemented | Salted PBKDF2 password hashes; JWT key is environment-only and requires at least 32 characters; sample environment file uses placeholders. |
| NFR-03 Transport | Partial | README requires HTTPS outside local demos; TLS termination is deployment-owned and not configured here. |
| NFR-04 Input safety | Implemented with operational caps | Upload bodies are limited before multipart parsing, file size/type/parse are validated, and processing has configurable packet and elapsed-time budgets. CPU detection is bounded by packet count and checked against the deadline after the rule pass rather than forcibly interrupted mid-rule. |
| NFR-05 Privacy | Implemented | Packet payloads are not included in normalized records; staging files are deleted after processing and stale files are cleaned at startup. |
| NFR-06 Usability | Partial | Responsive sign-in, upload, job, alert, and admin views with empty/loading/error states exist; no evaluator usability session has been measured. |
| NFR-07 Performance | Partial | Synthetic PCAPs of approximately 1 MB, 10 MB, 20 MB, and 24 MB completed below the two-minute target. The 24 MB capture contained 20,696 packets and completed in 24 seconds based on the UI timestamps. The 50 MB capture was rejected by the 25 MB upload limit. Representative real-world traffic and performance on other machines remain unverified. |
| NFR-08 Reliability | Partial | Malformed input and processing-failure paths are covered; index/readiness guards, leases, startup recovery, shutdown cancellation, and bounded orphan cleanup are implemented. Restarts interrupt active work; recovery waits for lease expiry, and a missing/lost staging volume prevents recovery. |
| NFR-09 Maintainability | Implemented | API, adapters, feature extraction, rule catalog, persistence, and React views are separated. |
| NFR-10 Explainability | Implemented | Findings identify signature/rule/version, severity, description, and evidence. |
| NFR-11 Compatibility | Partial | Vite production build passes; no Chromium/browser matrix test was run. |
| NFR-12 Accessibility | Partial | Forms have labels, controls are keyboard-operable, status text is explicit, and responsive styles exist; no formal contrast/accessibility audit was run. |

## Acceptance criteria

| SRS | Status | Verification |
|---|---|---|
| AC-01 | Verified | Existing authentication tests cover unauthenticated protected access. |
| AC-02 | Verified | Role, user, analysis, and alert owner-access tests cover allowed and denied actions. |
| AC-03 | Verified | Synthetic PCAP test confirms completed job and `SIG-NET-001` evidence. |
| AC-04 | Verified | Tests cover invalid extension, empty, malformed, and oversized uploads. |
| AC-05 | Verified | Alert persistence, detail, evidence, method, severity, and state are tested. |
| AC-06 | Verified | Dashboard ownership and severity/time filters plus alert filters are tested. |
| AC-07 | Verified | A processing failure is persisted as failed and health remains available. |
| AC-08 | Partial | The documented local setup, live MongoDB workflow, backend tests, frontend tests, and production build were verified in the existing development environment. A clean-machine reproduction and independent Python dependency installation were not run during the final audit. |

## Design deviations and operational limits

- The SDD's replaceable processing interface is implemented with FastAPI background tasks plus MongoDB lease-based recovery. Active execution is not checkpointed; after restart, queued work is dispatched and running work is eligible after lease expiry if its staged file remains available.
- The analyzer is a small, explicit signature demonstration. It does not claim broad attack coverage, and no ML scores are fabricated in the absence of an approved artifact.
- Optional local intelligence requires an authorized file provided by the operator. External lookups are not implemented.
- Automated tests use an in-memory Mongo-compatible test double.
- Live MongoDB connectivity was verified through the database health endpoint. Analysis history was confirmed to persist after a backend restart.
- Synthetic capture timings were measured on the current test machine. The largest successful tested capture was approximately 24 MB, containing 20,696 packets, which completed in 24 seconds. The 50 MB capture was rejected by the 25 MB upload limit. Representative real-world capture performance remains unverified. FR-07 and NFR-07 report the same timing evidence; neither should be considered full verification of real-world performance.
- The existing SRS and SDD were read-only during implementation.
- Security hardening in the final audit rejects wildcard CORS origins, rejects malformed or excessive PBKDF2 parameters in stored hashes, protects CSV text from common spreadsheet formula prefixes, bounds packet count and processing time, and keeps database readiness false if MongoDB is unconfigured. The sample JWT and admin password values cannot be used as production credentials.
- Local browser automation was unavailable because Codex Work settings disabled browser controls. React text rendering was statically checked for unsafe HTML sinks; no rendered browser, keyboard, responsive, contrast, or assistive-technology audit is claimed.
- Backend Python dependency versions remain unpinned. MongoDB auth/TLS, production secrets, HTTPS, reverse-proxy request limits/security headers, and deployment-host configuration remain external prerequisites.
- The browser stores bearer tokens in `localStorage`, login rate limiting is deployment-gateway-owned, and the Administrator account list is unpaginated; these fit the current small-project scope but need attention before broad public or large-directory deployment.
