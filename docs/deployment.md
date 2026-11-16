# Run the backend for the submission

## Hosted submission: Northflank

The deployed backend is **https://p01--upwind-mail-guard--vpdljyyj7txr.code.run**. Its public
[health endpoint](https://p01--upwind-mail-guard--vpdljyyj7txr.code.run/healthz) returns `{"status":"ok"}`;
`POST /v1/analyze` and `POST /v1/diagnose` require the private demo bearer token.
The token is in provider runtime variables and Google Script Properties, never the repository.
A public backend URL does not install the Gmail test add-on or grant access to its token.
Reviewers can reproduce the service with their own token using the configuration below.

Verified on **2026-11-17**:

| Setting | Deployed value |
| --- | --- |
| Provider / plan | Northflank Developer Sandbox, service labeled Free |
| Project / service | Default / upwind-mail-guard |
| Region | Europe-West (London) |
| Source | `ShaharMaaravi/upwind-mail-guard`, `main` |
| Initially tested backend commit | `fa634446ca83ddff1b7023f7c1ea89d9d4ef14ed` |
| Build | Root `Dockerfile`, context `/`, BuildKit |
| Runtime | One `nf-compute-10` instance: 0.1 shared CPU / 256 MB |
| Network | Public HTTP target port 8080, provider-managed HTTPS domain |
| Readiness | HTTP `/healthz`, port 8080, initial delay 10 s, interval 10 s, timeout 5 s, three failures, one success |
| Runtime secret | `MAIL_GUARD_API_TOKEN`; same value as Google Script Properties |
| Storage | No volume or database |
| Deployment workflow | Northflank CI/CD enabled: builds and deploys pushes to `main` |

The author completed card verification themselves; no paid upgrade was selected. Northflank's
service billing page showed **no accrued costs** after deployment. Keep the Sandbox plan and the
listed resources; review billing before changing plan/resources. Free-tier terms and availability
can change. This observation is not a permanent billing or uptime guarantee.

A team billing alert with threshold **$0** was created and verified after reload on 2026-11-17, so
any recorded billable usage above zero is configured to trigger an email. This is an alert, not a
spending cap or a guarantee of notification before charging. The account's $50 billing threshold
triggers invoicing/payment; it does not stop spending. No hard spending cap or per-charge approval
control was found. Northflank documents that the card is not charged until paid services are
created/used; keep the current free configuration. See
[alerts](https://northflank.com/docs/v1/application/billing/monitor-spending), [billing
thresholds](https://northflank.com/docs/v1/application/billing/billing-thresholds), and [card
billing](https://northflank.com/docs/v1/application/billing/add-a-card).

To reproduce: connect only the intended repository, create a Combined service with these settings,
add the runtime secret (not a build argument), and wait for **Running / 1 of 1 checks passing**.
The provider's default build resources were `nf-compute-400-16`; runtime resources remain the small
free instance. Build/runtime secrets must not be printed. Do not enable request-body or
Authorization-header logging. Northflank's automatic deployment is separate from GitHub Actions:
a push can deploy before the repository's CI finishes, so push only reviewed/tested changes and
check both systems after release.

Then build/upload the add-on for the exact hosted origin using [Gmail setup](gmail-setup.md).
Both the generated source and manifest allowlist must agree. OAuth scopes stay limited to the
selected message; Google tokens never go to Northflank.

Hosted HTTPS verification covered health, unauthorized rejection, security headers, the 95-point
fixture, all 20 corpus scores, malformed JSON, and oversized requests. The slowest corpus response
was 0.44 s in the recorded run; this is a small smoke check, not a load test or latency guarantee.
For an oversized Content-Length, the server rejects before reading the body. A Python test client
reported a TLS EOF while still uploading; curl with `Expect: 100-continue` observed the intended
HTTP **413 / request_too_large**. TLS verification stayed enabled.

Gmail then returned **0 / 25 / 75** for the existing synthetic messages with the local backend
stopped. The obsolete tunnel was stopped afterward. Hosted logs showed only platform/Uvicorn
startup entries after testing, with no request/content/token entries visible. Provider retention
outside those visible logs was not audited. Earlier failure/timeout experiments used the local
backend; no hosted outage or long-term availability test is claimed.

The service stays separate from the laptop. Before a demo, check health and one synthetic Gmail
analysis. A restart or provider outage can still exceed Google's callback deadline. One instance
also means the in-memory rate limiter is not distributed; do not scale this demo without revisiting
rate limits and multi-user authorization.

## Local development and fallback

1. Follow the root [README](../README.md#quick-start) to install dependencies, generate the
   ignored `.env`, and run the backend on `127.0.0.1:8000`.
2. In a second terminal, run `cloudflared tunnel --url http://127.0.0.1:8000`.
3. Check the public `/healthz`, then build and install the add-on for the exact printed HTTPS
   origin using [Gmail setup](gmail-setup.md). Its Script Property must match the backend token.
4. Keep both terminals open and the laptop awake with internet access. Rehearse the existing
   synthetic messages using [the demo script](demo.md).

The tunnel was exercised in Gmail with benign, suspicious, truncated, and failure cases. It is
temporary, not an always-on deployment. Restarting it can change the origin: rebuild and upload
both the add-on source and manifest, then recheck a synthetic message. Never put the live token
in a URL, Git, a screenshot, or command-line arguments. Cloudflare transports the HTTPS traffic.

## Docker alternative

Requires a running Docker engine. From the repository root:

```bash
docker build -t upwind-mail-guard:local .
python3 scripts/container-smoke.py upwind-mail-guard:local
docker run --rm --name upwind-mail-guard-demo \
  --env-file .env --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --memory=256m --cpus=0.5 \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -p 127.0.0.1:8000:8080 upwind-mail-guard:local
```

Stop the Python backend first if it already occupies port 8000. The container maps its internal
8080 port to the same local 8000 port, so the tunnel command stays the same. Stop the foreground
container with Ctrl+C. The smoke script uses a generated temporary secret, random loopback port,
and uniquely named disposable containers; it removes only containers it created.

The image contains runtime code/dependencies only, runs as UID 10001, disables access logs, and
refuses startup without a valid secret. The container smoke check verifies health, authentication,
the 95-point fixture, all 20 corpus scores, log markers, and missing-secret startup failure.
Linux ARM64 and AMD64 images were built and run locally on 2026-11-17; AMD64 used Docker Desktop
emulation. This is a demo resource limit, not a load test or hosting cost guarantee.

## Token rotation and hosting alternatives

For rotation, generate a new random secret locally, update the backend environment and Google
Script Property, restart the backend, and verify a synthetic message. Keep only one demo token
active. Local setup and the smoke check do not require sharing your Google credentials.

Railway's connected Free plan rejected a separate project because of its resource limit. Render's
free idle wake-up could exceed Gmail's deadline. Northflank was selected for an always-on free
container with the existing Dockerfile; a VPS offers more control but adds cost and operations.
The local tunnel remains a reproducible development fallback, not the submitted hosting dependency.

Provider references: [pricing](https://northflank.com/pricing),
[build and deploy](https://northflank.com/docs/v1/application/getting-started/build-and-deploy-your-code),
[resource plans](https://northflank.com/docs/v1/application/billing/resource-plans-and-quotas).
