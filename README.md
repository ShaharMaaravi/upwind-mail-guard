# Upwind Mail Guard

A Gmail add-on with a separate Python backend, being built for the Upwind Security Analyst assignment.

**Current status: milestone 1 analysis foundation implemented and locally tested.**
The Gmail diagnostic connection is live-verified. The backend now has an analysis contract,
offline normalization, and a tested scoring policy, but no enabled detection rules yet.
`/v1/analyze` explicitly returns an unavailable result with a null score. The Gmail card still
tests the connection. This is not the final assignment submission.

## What works now

- A contextual Gmail card with an explicit **Test connection** action.
- Bounded extraction of sender, Reply-To, subject, plain text, HTML, and an authentication header.
- An authenticated diagnostic API returning character counts, truncation, and missing-field information.
- Clear diagnostic and failure cards; missing data never becomes a safe verdict.
- Automated backend, add-on, build, and local HTTP integration tests.
- Strict analysis input/output models, address/HTML/URL normalization, and offline domain boundaries.
- Pure scoring with stable findings, deduplication, category caps, and exact contribution accounting.

The basic flow has also been verified in a personal Gmail account through a temporary HTTPS tunnel:
authorized selected-message extraction, diagnostic rendering, backend outage, and recovery.
Broader live edge cases remain listed in the [verification record](docs/live-verification.md).
Durable hosting is not configured. The container definition is included but has not been built
locally because Docker's daemon was unavailable.

## Quick start

Requires Python 3.12 and Node.js 22 or newer. Run from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements-dev.txt
pytest -q
ruff check backend
ruff format --check backend
npm test
npm run test:integration
```

The integration command starts and stops a real loopback HTTP server and runs the add-on code
against it with synthetic data. Google services remain mocked. No Google credentials are needed.
JavaScript tests use Node's built-in test runner; no npm packages are required.

Generate a local secret without putting it in source code or command-line arguments:

```bash
python - <<'PY'
import os, secrets
fd = os.open('.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as f:
    f.write('MAIL_GUARD_API_TOKEN=' + secrets.token_urlsafe(32) + '\n')
PY
set -a
source .env
set +a
python -m uvicorn app.main:create_app --factory --app-dir backend \
  --host 127.0.0.1 --port 8000 --no-access-log \
  --limit-concurrency 32 --timeout-keep-alive 5
```

The secret-generation command refuses to overwrite an existing `.env`. Reuse your existing token
if already configured. `GET /healthz` returns `{"status":"ok"}`. Startup fails if the token is absent
or has an invalid format. The token must be generated randomly; a valid length alone is not entropy.

For Google setup, an HTTPS backend, and the exact files to upload, follow
[Gmail installation](docs/gmail-setup.md). A public Git repository does not install the add-on in Gmail.

## Architecture

```mermaid
flowchart LR
    G[Selected Gmail message] --> A[Apps Script adapter]
    A -->|Authenticated HTTPS JSON| B[Request guard]
    B --> V[Strict schema validation]
    V --> D[Diagnostic field counts]
    D -->|Validated response| C[Gmail result card]
    V -->|Analysis endpoint| N[Offline normalization]
    N --> U[Coverage and unavailable result]
```

| Location | Responsibility |
| --- | --- |
| `addon/src/Extraction.js` | Selected-message access, field limits, missing/truncated data |
| `addon/src/ApiClient.js` | Authenticated request, redirects disabled, response validation |
| `addon/src/Cards.js` | Diagnostic, consent, and failure presentation |
| `addon/src/Handlers.js` | Gmail contextual and action callbacks |
| `backend/app/security.py` | Authentication, streaming byte limit, upload deadline, rate limit |
| `backend/app/schemas.py` | Versioned diagnostic request/response contract |
| `backend/app/analysis_schemas.py` | Analysis input, findings, score accounting, and coverage contract |
| `backend/app/normalization.py` | Bounded address, text, HTML, URL, and metadata normalization |
| `backend/app/domains.py` | IDNA and pinned offline Public Suffix List boundaries |
| `backend/app/scoring.py` | Pure provisional policy; receives signals from future detectors |
| `backend/app/analysis.py` | Analysis orchestration; no detectors enabled yet |
| `backend/app/main.py` | Health, diagnostic, and analysis routes |
| `scripts/` | Reproducible add-on build and local integration check |

`POST /v1/diagnose` takes a schema version, random request reference, bounded message fields,
and truncation flags. See [the synthetic request](fixtures/diagnostic-request.json).
The response contains counts only; it never echoes email content. `null` means unavailable,
while zero characters means available but empty. The diagnostic response has no score field.

`POST /v1/analyze` adds optional bounded attachment metadata and returns normalization coverage.
It currently returns `analysis_status: "unavailable"`, `score: null`, and no findings or checks run.
The pure scorer is tested with injected signals; those tests are not evidence of detection accuracy.
See the [analysis contract and scoring policy](docs/analysis-contract.md) and
[synthetic request](fixtures/analysis-request.json). Gmail will use this endpoint after the rules
and result cards are implemented. Both endpoints share authentication, request limits, and rate limits.

## Security boundaries and limitations

- Gmail event tokens and message IDs stay inside Apps Script. No mailbox-wide scope is requested.
- The backend token lives in Script Properties and the backend environment. Script editors can
  access it; this is single-demo authentication, not multi-user authorization.
- The build pins the same HTTPS origin in the fetch client and manifest allowlist. Redirects
  are disabled and TLS verification stays enabled.
- The API authenticates before reading JSON, limits the request to 256 KiB even without a
  trustworthy Content-Length, and allows five seconds to receive a body.
- The single-instance limiter allows 30 authenticated requests/minute. It resets on restart and
  does not coordinate between instances. Public health and unauthorized traffic need hosting-level
  protection at production scale.
- No database, email-content logging, URL fetching, remote image loading, or attachment inspection.
  Authentication headers are untrusted text; SPF/DKIM/DMARC are not verified.
- Domain normalization uses the dependency's pinned PSL snapshot, including private suffixes.
  It does not download data or resolve DNS during a scan. Unknown suffixes remain coverage gaps.
- HTML parsing does not reproduce browser rendering, CSS visibility, quoted-message boundaries,
  or every browser URL interpretation. Only HTTP(S) link targets are normalized; at most 100 raw
  candidates are considered, even if they repeat. These limits can omit important evidence.
- Gmail body getters retrieve content before local truncation. The backend limit does not bound
  Google's extraction cost; test large messages live. Attachments are deliberately not downloaded.
- Apps Script's synchronous URL fetch has no configurable per-call timeout. A platform execution
  deadline may terminate the callback before it can render our error card. Backend outages and
  cold starts must therefore be tested in Gmail, not inferred from mocks.
- Deployment infrastructure can introduce logging; inspect its settings before testing real mail.
  Use synthetic emails for the integration test.

## Tests and delivery

The suite exercises authentication, malformed/oversized/chunked requests, slow uploads, disconnects,
strict input types, redacted errors, Unicode, partial extraction, forged authentication claims,
backend redirects/errors, response correlation, escaped card text, and deployment URL validation.
It also covers PSL wildcard/exception/private boundaries, Unicode domains, deceptive user-info,
IPv4/IPv6 URLs, inert HTML, bounded repeated links, score reconciliation, and unavailable analysis.
Milestone 1 passed 167 Python tests, 34 Node tests, lint/format checks, and real local HTTP integration.
CI targets Python 3.12 / Node 22. Milestone 0 passed remote CI; milestone 1 CI awaits an approved push.

Read [progress](docs/progress.md) for executed checks and outstanding gates,
[decisions](docs/decisions.md) for tradeoffs, and the [implementation plan](docs/implementation-plan.md)
for upcoming detection and scoring milestones. Each milestone is committed only with the author's approval.
