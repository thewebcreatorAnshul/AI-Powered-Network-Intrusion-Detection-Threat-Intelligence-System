# AI-Powered Network Intrusion Detection and Threat Intelligence System

This repository implements the project MVP described by the SRS and SDD in [`docs/`](docs/). It accepts authorized PCAP/PCAPNG captures, creates scoped analysis jobs, derives packet/flow summaries, evaluates a transparent signature catalog, and stores findings as reviewable alerts.

## Requirements and current scope

- Python 3.11+ and MongoDB 6+ (local MongoDB is suitable for the demonstration).
- Node.js 20.19+ and npm for the React/Vite client.
- PCAP and PCAPNG are accepted. Only the submitting user and Administrators can access jobs and alerts; only Administrators can change alert workflow status or manage accounts.
- The included signatures are `SIG-NET-001` (10 or more distinct TCP destination ports receiving SYN-only probes from one source to one destination within 60 seconds) and `SIG-NET-002` (100 or more SYN-only packets to one TCP service endpoint within one second). Both report their rule/version, severity, and observed evidence. These are narrow pattern detectors, not broad attack coverage or proof of compromise.
- ML scoring is skipped because no approved trained model or documented training dataset exists in this checkout. The UI and job summary make that explicit; no model output is fabricated.
- Threat intelligence is offline by default. Optional local enrichment can be enabled with an authorized local JSON indicator file. No IOC set or external provider is bundled or queried.
- Uploaded captures are staged under the backend upload directory and deleted when processing ends. A startup cleanup removes expired staged files using `RETENTION_HOURS`.

## Environment setup

If there is no existing local environment file, copy the sample with `Copy-Item backend/.env.example backend/.env`. Then set a unique `JWT_SECRET` of at least 32 characters and a private administrator password. Keep `.env` local; it is ignored by Git. The repository's local ignored `.env` is separate from the safe sample. Rotate the signing key if replacing an existing project key because that invalidates issued tokens.

| Variable | Purpose |
| --- | --- |
| `MONGODB_URI` | MongoDB connection URI. |
| `MONGODB_DATABASE` | Application database name. |
| `JWT_SECRET` | Per-environment signing key; minimum 32 characters. |
| `JWT_EXPIRE_MINUTES` | Access token lifetime. |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | Optional first-admin bootstrap; only creates an administrator if none exists. |
| `ADMIN_PASSWORD_RESET` | Explicit opt-in to reset the configured active administrator password at startup. |
| `ALLOWED_ORIGINS` | Comma-separated browser origins; defaults to localhost Vite origins. |
| `UPLOAD_DIR` | Temporary capture staging directory. |
| `MAX_UPLOAD_MB` | Maximum streamed upload size; defaults to 25 MB. |
| `RETENTION_HOURS` | Maximum staging-file age for startup cleanup; defaults to 24 hours. |
| `THREAT_INTEL_MODE` | `offline` (default) or `local`. |
| `THREAT_INTEL_FILE` | Optional JSON file used only in `local` mode; relative paths are resolved from `backend/`; maximum size is 5 MB. |

Local indicator JSON may be a list or an object with an `indicators` list:

```json
[
  {"indicator": "198.51.100.42", "type": "ip", "source": "authorized-local-source"}
]
```

Use only indicators whose source and purpose are documented and authorized. Matching context is attached to findings; the system does not infer that an unmatched address is safe or malicious.

## Start MongoDB

Start your local MongoDB service and confirm that `MONGODB_URI` points to it. The backend checks the database through `GET /api/v1/health/database`. Tests use an in-memory Mongo-compatible fixture and do not require a running MongoDB server.

## Start the backend

PowerShell:

```powershell
cd backend
..\.venv\Scripts\python.exe -m pip install -r requirements.txt
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If using a virtual environment other than the repository's `.venv`, activate it first and use `python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000` from `backend/`.

OpenAPI documentation is available at `http://127.0.0.1:8000/docs` while the API is running. The API prefix is `/api/v1`.

## Start the frontend
## Production preview

Build the frontend:

```powershell
cd frontend
npm run build
npm run preview

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal (normally `http://127.0.0.1:5173`). To use another API address, set `VITE_API_BASE_URL` before starting Vite, for example `http://127.0.0.1:8000/api/v1`.

## Demo workflow

1. Start MongoDB, then the backend and frontend.
2. Sign in with the configured bootstrap Administrator account. If the database already has an Administrator, the startup credentials do not replace it unless `ADMIN_PASSWORD_RESET=true` is deliberately enabled.
3. In **User management**, create a Normal User account.
4. Sign out and sign in as that Normal User.
5. Generate a controlled synthetic capture locally (this writes a file only and sends no traffic):

   ```powershell
   .\.venv\Scripts\python.exe .\scripts\create_demo_capture.py
   ```

6. Upload `datasets/demo_syn_scan.pcap` from **Analysis jobs**. The expected signature is `SIG-NET-001`, a high-severity TCP SYN port-scan pattern, with the source, destination, destination ports, and probe count shown as evidence. The job endpoint returns `queued`; poll its detail page until it is `completed` or `failed`.
7. Review the corresponding alert and summary. Sign in as the Administrator to see workspace-wide jobs/alerts and update alert status.
8. Try a `.txt`, empty, malformed, and oversized file to confirm upload validation. The capture file is ignored by Git and should not be committed.

## API outline

- `GET /api/v1/health`, `GET /api/v1/health/database`
- `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me`
- `GET/POST /api/v1/users`, `GET/PATCH /api/v1/users/{user_id}` (Administrator operations are restricted)
- `POST /api/v1/analyses` (multipart `file`); `GET /api/v1/analyses`; `GET /api/v1/analyses/{job_id}`; `GET /api/v1/analyses/{job_id}/export`
- `GET /api/v1/alerts`; `GET /api/v1/alerts/{alert_id}`; `PATCH /api/v1/alerts/{alert_id}` (Administrator only)
- `GET /api/v1/dashboard`

Use `Authorization: Bearer <access_token>` for protected routes. Job and alert lists support bounded pagination; status, search, severity, method, and time filters are validated. Normal User ownership is checked server-side.

## Tests and build

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
cd frontend
npm run build
npm audit --audit-level=moderate
```

Tests cover auth/RBAC, cross-user ownership, upload limits and parsing, PCAP/PCAPNG, job states, both signature thresholds, alert persistence/status changes, dashboard scoping/filters, safe export, and local IOC enrichment. The in-memory database fixture clears users, jobs, alerts, audit events, and staged files for each test.

## Known limitations

- The in-process FastAPI background task is appropriate for the small demonstration, not durable distributed processing. A process restart can interrupt a job.
- - The analyzer currently implements two deterministic network signatures: TCP SYN port-scan detection (`SIG-NET-001`) and TCP SYN-flood detection (`SIG-NET-002`). Detection coverage is limited to these patterns and does not guarantee detection of other attack classes.
- No ML model is included because no compatible, provenance-documented model or dataset was present. Model metrics and evaluation are therefore not claimed.
- No intelligence feed is bundled; external enrichment is not implemented. Local enrichment requires a user-supplied authorized indicator file.
- Alert search/pagination and dashboards operate on the current MongoDB collections; large-scale aggregation and production load are outside this MVP.
- The API uses bearer tokens, but logout is client-side token removal; server-side token revocation is not implemented.
- Shared deployment still requires HTTPS, a least-privilege database account, protected staging permissions, secret rotation, and deployment-specific CORS/storage review.
- End-to-end verification against a live MongoDB service depends on having MongoDB running locally; the automated suite uses an in-memory compatible store.

## Authoritative project documents

Keep [`docs/M1_SRS_Intrusion_Detection.docx`](docs/M1_SRS_Intrusion_Detection.docx) and [`docs/M1_SDD_Intrusion_Detection.docx`](docs/M1_SDD_Intrusion_Detection.docx) as the project requirements/design sources. This implementation follows their PCAP-first MVP and documents the absent model and optional local intelligence inputs above.
