# AI-Powered Network Intrusion Detection and Threat Intelligence System

This repository implements the project MVP described by the Software Requirements Specification (SRS) and Software Design Description (SDD) in [`docs/`](docs/).

The system accepts authorized PCAP and PCAPNG captures, creates scoped analysis jobs, derives packet and flow summaries, evaluates a transparent signature catalog, and stores findings as reviewable alerts.

## Requirements and Current Scope

### Requirements

- Python 3.11+
- MongoDB 6+ (local MongoDB is suitable for demonstration)
- Node.js 20.19+ and npm for the React/Vite frontend

### Implemented Scope

- PCAP and PCAPNG capture upload and analysis.
- Scoped analysis jobs and reviewable alerts.
- Role-based access control for Administrators and Normal Users.
- Only the submitting user and Administrators can access jobs and alerts.
- Only Administrators can change alert workflow status or manage accounts.
- Packet and flow summaries with evidence-based detection findings.
- Optional local threat-intelligence enrichment using an authorized JSON indicator file.

### Detection Signatures

The current implementation includes two deterministic network signatures:

| Signature | Detection Pattern |
|---|---|
| `SIG-NET-001` | 10 or more distinct TCP destination ports receiving SYN-only probes from one source to one destination within 60 seconds. |
| `SIG-NET-002` | 100 or more SYN-only packets to one TCP service endpoint within one second. |

Both signatures report their rule/version, severity, and observed evidence.

These are narrow pattern detectors. They do not provide broad attack coverage or prove that a system has been compromised.

### ML and Threat Intelligence Scope

- ML scoring is skipped because no approved trained model or documented training dataset exists in this checkout.
- The UI and job summary explicitly indicate that ML scoring is unavailable. No model output is fabricated.
- Threat intelligence is offline by default.
- Optional local enrichment can be enabled with an authorized local JSON indicator file.
- No IOC set or external provider is bundled or queried.

### Capture Storage and Retention

Uploaded captures are staged under the backend upload directory and deleted when processing ends. Startup cleanup removes expired staged files using `RETENTION_HOURS`.

## Environment Setup

If a local environment file does not already exist, copy the sample:

```powershell
Copy-Item backend/.env.example backend/.env
```

Configure a unique `JWT_SECRET` of at least 32 characters and a private administrator password.

Keep `backend/.env` local. It is ignored by Git. The tracked `backend/.env.example` is a safe configuration sample and should not contain real secrets.

Rotate the signing key if replacing an existing project key, because this invalidates issued tokens.

### Environment Variables

| Variable | Purpose |
|---|---|
| `MONGODB_URI` | MongoDB connection URI. |
| `MONGODB_DATABASE` | Application database name. |
| `JWT_SECRET` | Per-environment signing key; minimum 32 characters. |
| `JWT_EXPIRE_MINUTES` | Access token lifetime. |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | Optional first-admin bootstrap; creates an administrator only if none exists. |
| `ADMIN_PASSWORD_RESET` | Explicit opt-in to reset the configured active administrator password at startup. |
| `ALLOWED_ORIGINS` | Comma-separated browser origins; defaults to localhost Vite origins. |
| `UPLOAD_DIR` | Temporary capture staging directory. |
| `MAX_UPLOAD_MB` | Maximum streamed upload size; defaults to 25 MB. |
| `RETENTION_HOURS` | Maximum staging-file age for startup cleanup; defaults to 24 hours. |
| `THREAT_INTEL_MODE` | `offline` (default) or `local`. |
| `THREAT_INTEL_FILE` | Optional JSON file used only in `local` mode. Relative paths are resolved from `backend/`; maximum size is 5 MB. |

### Local Indicator JSON Format

The local indicator JSON file may be a list or an object containing an `indicators` list.

Example:

```json
[
  {
    "indicator": "198.51.100.42",
    "type": "ip",
    "source": "authorized-local-source"
  }
]
```

Use only indicators whose source and purpose are documented and authorized.

Matching context is attached to findings. The system does not infer that an unmatched address is safe or malicious.

## Start MongoDB

Start your local MongoDB service and confirm that `MONGODB_URI` points to it.

The backend checks database connectivity through:

```text
GET /api/v1/health/database
```

The automated tests use an in-memory Mongo-compatible fixture and do not require a running MongoDB server.

## Start the Backend

From the repository root, run the following in PowerShell:

```powershell
cd backend
..\.venv\Scripts\python.exe -m pip install -r requirements.txt
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If using a virtual environment other than the repository's `.venv`, activate it first and run the following from `backend/`:

```powershell
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

OpenAPI documentation is available while the API is running:

- [API documentation](http://127.0.0.1:8000/docs)

The API prefix is `/api/v1`.

## Start the Frontend

### Install Dependencies

From the repository root:

```powershell
cd frontend
npm install
```

### Development Mode

Start the Vite development server:

```powershell
npm run dev
```

Open the URL shown in the terminal, normally:

- [http://127.0.0.1:5173](http://127.0.0.1:5173)

### Production Preview

Build the frontend:

```powershell
npm run build
```

Start the local production preview:

```powershell
npm run preview
```

Open the preview URL shown in the terminal, normally:

- [http://127.0.0.1:4173](http://127.0.0.1:4173)

### Configure the API Address

To use another API address, set `VITE_API_BASE_URL` before starting Vite.

Example in PowerShell:

```powershell
$env:VITE_API_BASE_URL = "http://127.0.0.1:8000/api/v1"
npm run dev
```

## Demo Workflow

1. Start MongoDB, then start the backend and frontend.
2. Sign in with the configured bootstrap Administrator account.
3. If the database already has an Administrator, startup credentials do not replace that account unless `ADMIN_PASSWORD_RESET=true` is deliberately enabled.
4. In **User Management**, create a Normal User account.
5. Sign out and sign in as that Normal User.
6. Generate a controlled synthetic capture locally. This creates a file only and sends no network traffic:

   ```powershell
   .\.venv\Scripts\python.exe .\scripts\create_demo_capture.py
   ```

7. Upload `datasets/demo_syn_scan.pcap` from **Analysis Jobs**.
8. The expected signature is `SIG-NET-001`, a high-severity TCP SYN port-scan pattern. Evidence includes the source, destination, destination ports, and probe count.
9. The job endpoint returns `queued`. Poll its detail page until the status becomes `completed` or `failed`.
10. Review the corresponding alert and summary.
11. Sign in as the Administrator to view workspace-wide jobs and alerts and update alert status.
12. Try a `.txt`, empty, malformed, and oversized file to confirm upload validation.

Generated capture files are ignored by Git and should not be committed.

## API Outline

### Health

- `GET /api/v1/health`
- `GET /api/v1/health/database`

### Authentication

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`

### Users

- `GET /api/v1/users`
- `POST /api/v1/users`
- `GET /api/v1/users/{user_id}`
- `PATCH /api/v1/users/{user_id}`

Administrator operations are restricted.

### Analysis Jobs

- `POST /api/v1/analyses` — multipart upload using `file`
- `GET /api/v1/analyses`
- `GET /api/v1/analyses/{job_id}`
- `GET /api/v1/analyses/{job_id}/export`

### Alerts

- `GET /api/v1/alerts`
- `GET /api/v1/alerts/{alert_id}`
- `PATCH /api/v1/alerts/{alert_id}` — Administrator only

### Dashboard

- `GET /api/v1/dashboard`

Use the following header for protected routes:

```text
Authorization: Bearer <access_token>
```

Job and alert lists support bounded pagination. Status, search, severity, method, and time filters are validated. Normal User ownership is checked server-side.

## Tests and Build

Run the automated backend tests from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Build the frontend:

```powershell
cd frontend
npm run build
```

Check frontend dependencies for known vulnerabilities:

```powershell
npm audit --audit-level=moderate
```

### Test Coverage

The automated tests cover:

- Authentication and role-based access control.
- Cross-user ownership.
- Upload limits and parsing.
- PCAP and PCAPNG handling.
- Analysis job states.
- Both signature thresholds.
- Alert persistence and status changes.
- Dashboard scoping and filters.
- Safe export.
- Local IOC enrichment.

The in-memory database fixture clears users, jobs, alerts, audit events, and staged files for each test.

## Known Limitations

- The in-process FastAPI background task is appropriate for a small demonstration, not durable distributed processing. A process restart can interrupt a job.
- The analyzer currently implements two deterministic network signatures: TCP SYN port-scan detection (`SIG-NET-001`) and TCP SYN-flood detection (`SIG-NET-002`). Detection coverage is limited to these patterns and does not guarantee detection of other attack classes.
- No ML model is included because no compatible, provenance-documented model or dataset was present. Model metrics and evaluation are therefore not claimed.
- No intelligence feed is bundled; external enrichment is not implemented. Local enrichment requires a user-supplied authorized indicator file.
- Alert search, pagination, and dashboards operate on the current MongoDB collections. Large-scale aggregation and production load are outside this MVP.
- Logout removes the bearer token from the client. Server-side token revocation is not implemented, so a token may remain usable until it expires.
- Shared deployment still requires HTTPS, a least-privilege database account, protected staging permissions, secret rotation, and deployment-specific CORS and storage review.
- End-to-end verification against a live MongoDB service depends on having MongoDB running locally. The automated suite uses an in-memory compatible store.

## Authoritative Project Documents

The following documents are the project's requirements and design sources:

- [`docs/M1_SRS_Intrusion_Detection.docx`](docs/M1_SRS_Intrusion_Detection.docx)
- [`docs/M1_SDD_Intrusion_Detection.docx`](docs/M1_SDD_Intrusion_Detection.docx)

This implementation follows their PCAP-first MVP scope and documents the absent ML model and optional local intelligence inputs above.
