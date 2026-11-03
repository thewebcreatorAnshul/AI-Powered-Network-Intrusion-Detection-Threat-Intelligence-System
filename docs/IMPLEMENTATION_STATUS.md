# SRS/SDD implementation checklist

This checklist records implementation and verification status for the current M1 code. The authoritative SRS and SDD remain unchanged. “Verified” refers to automated tests/build checks in this repository; it does not imply a live MongoDB or deployment test.

## Functional requirements

| SRS | Status | Implementation / limit |
| --- | --- | --- |
| FR-01 Authentication | Implemented | Password login, bearer JWT, current-user endpoint, logout action, and protected API dependencies. |
| FR-02 Role authorization | Implemented | Exactly Administrator and Normal User; server-side role and owner checks. |
| FR-03 User administration | Partial | Administrator creates, disables, and assigns roles. A separate settings/rule-management UI is not in the SRS endpoint list and is not implemented. |
| FR-04 PCAP upload | Implemented | Authenticated upload accepts `.pcap` and `.pcapng`. |
| FR-05 Upload validation | Implemented | Extension and capture magic, empty/malformed parse, and streamed size checks; safe errors and staging cleanup. |
| FR-06 Analysis tracking | Implemented | Persisted queued, running, completed, and failed job states; detail endpoint supports polling. |
| FR-07 Source adapters | Implemented | `SourceAdapter` boundary with PCAP/PCAPNG adapter; no additional sources are claimed. |
| FR-08 Feature extraction | Implemented | Packet protocol and directional flow counts, bytes, duration, endpoints, and ports are derived without payload retention. |
| FR-09 Signature detection | Implemented | `SIG-NET-001` TCP SYN port scan and `SIG-NET-002` high-rate SYN burst; stable versions, severity, rationale, and evidence. |
| FR-10 ML scoring | Not available | No approved model artifact, compatible feature schema, or provenance-documented dataset was present. Jobs explicitly record scoring as skipped. |
| FR-11 Alert creation | Implemented | Persistent alert IDs, timestamp, severity, method, rule reference, evidence, job/user ownership, and workflow status. |
| FR-12 Threat context | Partial | Optional local JSON indicator matching is implemented. No local IOC list or external provider is bundled/configured. |
| FR-13 Alert review | Implemented | Scoped list/detail, text/severity/method/status/time filters, pagination; Administrators can update alert state. |
| FR-14 Dashboard | Implemented | Real Mongo-backed job/alert metrics, ownership scoping, and severity/method/time filters. |
| FR-15 Audit trail | Implemented | Login, role/user changes, upload/launch, denied access, and alert-state changes record safe metadata. |
| FR-16 Export | Implemented | Owner/Admin-scoped CSV export of analysis summary. |
| FR-17 Error reporting | Implemented | Consistent validation/auth/database errors; generic unhandled responses; payloads and secrets are not returned. |
| FR-18 Reproducible demo | Implemented | README workflow, safe synthetic capture generator, and known-result integration test. |

## Nonfunctional requirements

| SRS | Status | Verification / limit |
| --- | --- | --- |
| NFR-01 Security | Implemented | Protected API dependencies and ownership checks are tested. |
| NFR-02 Password safety | Implemented | Salted PBKDF2 password hashes; JWT key is environment-only and requires at least 32 characters; sample environment file uses placeholders. |
| NFR-03 Transport | Partial | README requires HTTPS outside local demos; TLS termination is deployment-owned and not configured here. |
| NFR-04 Input safety | Implemented | Uploads are size/type/parse validated; captures are parsed as data and never executed. |
| NFR-05 Privacy | Implemented | Packet payloads are not included in normalized records; staging files are deleted after processing and stale files are cleaned at startup. |
| NFR-06 Usability | Partial | Responsive sign-in, upload, job, alert, and admin views with empty/loading/error states exist; no evaluator usability session has been measured. |
| NFR-07 Performance | Not measured | The SRS target is under two minutes for the documented capture; no representative-machine benchmark was available. |
| NFR-08 Reliability | Implemented | Malformed input and processing-failure paths are covered; failed jobs do not block health routes in tests. |
| NFR-09 Maintainability | Implemented | API, adapters, feature extraction, rule catalog, persistence, and React views are separated. |
| NFR-10 Explainability | Implemented | Findings identify signature/rule/version, severity, description, and evidence. |
| NFR-11 Compatibility | Partial | Vite production build passes; no Chromium/browser matrix test was run. |
| NFR-12 Accessibility | Partial | Forms have labels, controls are keyboard-operable, status text is explicit, and responsive styles exist; no formal contrast/accessibility audit was run. |

## Acceptance criteria

| SRS | Status | Verification |
| --- | --- | --- |
| AC-01 | Verified | Existing authentication tests cover unauthenticated protected access. |
| AC-02 | Verified | Role, user, analysis, and alert owner-access tests cover allowed and denied actions. |
| AC-03 | Verified | Synthetic PCAP test confirms completed job and `SIG-NET-001` evidence. |
| AC-04 | Verified | Tests cover invalid extension, empty, malformed, and oversized uploads. |
| AC-05 | Verified | Alert persistence, detail, evidence, method, severity, and state are tested. |
| AC-06 | Verified | Dashboard ownership and severity/time filters plus alert filters are tested. |
| AC-07 | Verified | A processing failure is persisted as failed and health remains available. |
| AC-08 | Partial | Setup/demo instructions are documented; a clean-machine reproduction was not performed. |

## Design deviations and operational limits

- The SDD's replaceable in-process queue is implemented with FastAPI background tasks. It is not durable across process restarts and is intended only for the MVP.
- The analyzer is a small, explicit signature demonstration. It does not claim broad attack coverage, and no ML scores are fabricated in the absence of an approved artifact.
- Optional local intelligence requires an authorized file provided by the operator. External lookups are not implemented.
- Automated tests use an in-memory Mongo-compatible test double because MongoDB was not running in the development environment. Live database integration and the SRS timing target remain to be verified with MongoDB available.
- The existing SRS and SDD were read-only during implementation.
