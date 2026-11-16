# Progress

## Milestone 0 — integration scaffold

**Implemented:** diagnostic FastAPI backend, request guard, strict schemas, Gmail extraction/client/
cards/handlers, add-on build, synthetic request, pinned Python dependencies, Dockerfile, CI, setup
instructions, and live verification checklist. No detection engine or score yet.

**Automated verification (2026-11-16):** 41 Python tests and 34 Node tests passed; Ruff lint and format checks passed. The real local HTTP integration passed. Python 3.12.0 / Node 25.2.1 were used locally; CI targets Python 3.12 / Node 22. Tests use synthetic data only.
Local integration runs the actual add-on JavaScript against a real loopback Python HTTP service;
Google APIs/CardService are mocked. It is not proof of Gmail installation or authorization.

**External HTTPS verified (2026-11-16):** the local backend is reachable through a temporary
Cloudflare tunnel. Public health, rejection of unauthorized requests, and an authenticated synthetic
diagnostic with exact field counts passed. The author explicitly approved sending the demo-only
token and synthetic fixture through Cloudflare. TLS verification remained enabled; the local Python
client used the macOS trust store. Backend and tunnel were restarted after an editor crash; the
ignored add-on build and combined manual-upload script were regenerated for the new address.

**Gmail live verification (2026-11-16): core integration passed.** Native Safari control was used
to upload/save the script and manifest, store the demo token with explicit approval, and install
the Workspace test deployment. The author approved the unverified-app authorization and one
synthetic self-addressed test email. The narrow `gmail.addons.current.message.action` scope worked.

The selected synthetic message produced a real authenticated HTTPS response inside Gmail:
subject 27 characters, plain text 39, HTML 64, sender 43, Reply-To 0, authentication header 0.
The empty header was available-but-empty, not an unavailable getter or a verified authentication
result. The backend returned counts only. No maliciousness score or safety verdict was displayed.

Stopping the identified backend produced **Analysis unavailable**. Restarting it and reopening
the synthetic message produced **Backend connected** again with a new request reference. Returning
to search results displayed **Open an email**; reopening the message produced a fresh action card.
The successful result was left visible in Gmail. Backend and tunnel remain running for development.

**Remaining validation:** see [live verification](live-verification.md) for untested thread
selection, large-message, HTML-like subject, Google timeout, and Google logging cases. Attachment
metadata-only retrieval remains deferred; no attachment bytes were accessed. The Docker daemon
was unavailable, so no image build was run.

**Delivery:** the author approved committing and pushing milestone 0 on 2026-11-16.
Commit `42c662a` is on `main`; [remote CI passed](https://github.com/ShaharMaaravi/upwind-mail-guard/actions/runs/43956286807).

## Milestone 1 — analysis foundation

**Implemented:** strict versioned analysis request/response, optional bounded attachment metadata,
pure normalization of addresses/text/HTML/URLs, pinned offline Public Suffix List with private
suffixes, coverage issues, stable finding IDs, per-rule/evidence deduplication, provisional weights,
category/global caps, and exact accounting of awarded/suppressed points.

`POST /v1/analyze` shares the diagnostic route's request guard. It returns coverage but explicitly
reports `analysis_status: unavailable`, `score: null`, and `detection_rules_not_implemented`.
Policy definitions are not enabled detectors. The Gmail script still uses `/v1/diagnose`.

**Automated verification (2026-11-16):** 167 Python tests and 34 Node tests passed; Ruff lint/format
and dependency consistency checks passed. The real local HTTP integration passed for the add-on
diagnostic flow and the new analysis endpoint. Local environment: Python 3.12.0 / Node 25.2.1.

New cases cover strict attachment limits/types, malformed/nested addresses, untrusted HTML,
Unicode/IDNA, PSL wildcard/exception/private suffixes, unknown domains, IPv4/IPv6 and user-info,
repeated-link budgets, missing versus empty input, text expansion, redacted errors, score caps,
deduplication, deterministic ordering, coverage-aware verdict constraints, and protection of both
routes from streamed oversize/slow/unauthorized requests. A cold domain lookup is tested with
network access forbidden and no disk cache; a changed PSL snapshot fails its integrity check.

**Example trace:** `fixtures/analysis-request.json` contains a displayed URL on `example.com`
targeting `example.net`, and a synthetic `invoice.pdf.exe` metadata record. Normalization preserves
the target and display evidence separately and reports one attachment. The API still returns no
score because detectors have not run. Separately, injected URL signals worth 40 + 25 + 15 points
produce 60 awarded points and 20 category-suppressed points. This validates arithmetic, not detection.

**Remaining:** detectors/accuracy fixtures (milestone 2), Gmail score/evidence rendering (milestone 3),
metadata-only Gmail attachment feasibility, live edge cases, durable hosting, and container build.
No new Google upload or live analysis test is claimed by this milestone. The existing diagnostic
process was left running; restart the backend to serve the new route outside the integration test.

**Delivery:** the author approved committing and pushing milestone 1 on 2026-11-16.
Commit `c5a7233` is on `main`; [remote CI passed](https://github.com/ShaharMaaravi/upwind-mail-guard/actions/runs/43959963127).

## Milestone 2 — deterministic detection engine

**Implemented:** eight pure detectors for displayed/target URL site mismatch, URL user-info, literal
IP hosts, Reply-To domain mismatch, English credential/payment requests with nearby pressure,
executable filenames, and misleading double extensions. `/v1/analyze` now runs the detectors,
deduplicates signals, computes the score, and returns findings with exact point accounting.
Policy version is `heuristic-v2`; normalization version is `normalize-v2`.

Each rule is explicitly run or skipped with a reason. Positive findings survive partial input; low
partial scores are inconclusive. Inputs that support no check return unavailable/null score. Content
matching retains its actual source field and does not combine unrelated fields. Authentication text
never adds/subtracts risk. URL findings omit credential/query text, and filename evidence preserves
extensions while making control/bidi characters visible.

**Automated verification (2026-11-16):** 243 Python tests and 34 Node tests passed, plus Ruff lint /
format checks and real localhost HTTP integration. No dependencies were added. The 20-case synthetic
corpus exercises expected findings, exact scores, coverage, and three documented false-positive
examples. Adversarial tests cover duplicated/malformed links, IPs/IDNs/private suffixes, missing
inputs, unsupported display URLs, Unicode/obfuscated filenames, truncation, response accounting,
forged authentication, and no network access. The maximum current 100-link/20-attachment case
produces 343 findings and reconciles the 100-point cap.

**Example trace:** the existing synthetic request now returns four findings totaling **95**:
URL mismatch 40, executable filename 35, double extension 5 after the attachment category cap,
and Reply-To mismatch 15. All eight rules run; missing authentication data makes coverage partial.
The real localhost HTTP integration verifies this score and the existing add-on diagnostic flow.

**Limits and remaining work:** these authored fixtures are regression tests, not independent
accuracy evidence. Known tracking/quoted-content/ordinary-invoice false positives and English-only
content matching are documented in [detection rules](detection-rules.md). Gmail still uses the
diagnostic endpoint; no new Google upload, email send, or live analysis verification occurred.
The existing backend process was left running on the earlier code; a new process is used by local
HTTP tests. Gmail analysis cards, metadata-only attachment feasibility, live edge cases, container
build, durable hosting, and final demo remain pending.

**Delivery:** the author approved committing and pushing milestone 2 on 2026-11-16.
Commit `d4d62ce` is on `main`; [remote CI passed](https://github.com/ShaharMaaravi/upwind-mail-guard/actions/runs/43962962748).

## Milestone 3 — Gmail analysis product

**Implemented:** selected-message analysis action; metadata-only Gmail API retrieval; strict response
validation; score/verdict/action cards; escaped evidence and contribution accounting; executed/skipped
checks and coverage; complete, partial, inconclusive, unavailable, and transport-error states.
The card shows the strongest eight findings and accounts for omitted findings and points. The
analysis response limit is 512 KiB; the metadata response limit is 128 KiB. No package dependencies or
broader OAuth scopes were added. Gmail API v1 enablement is declared in the manifest.

**Automated verification (2026-11-16–17):** 243 Python tests and 84 Node tests passed, plus Ruff
lint/format and real localhost HTTP integration. New tests cover metadata masks and Google-only
tokens, malformed/deep/oversized MIME trees, UTF-8 byte limits, 29 response-tampering cases,
partial/unavailable coverage, escaped markup, hidden-finding accounting, errors, and expired access.
The real HTTP check runs the actual add-on action and validates/renders all 20 detection-corpus
responses. Google APIs/CardService are mocked in that check. Local Python 3.12.0 / Node 25.2.1;
CI remains Python 3.12 / Node 22. No new remote CI result is claimed before commit/push approval.

**Live Gmail verification (2026-11-16–17):** uploaded/saved the analysis code and manifest and
restarted the local backend on milestone 2. The author approved one additional synthetic self-email
with a harmless text attachment and later approved enabling Gmail API under Google's terms.
Initially unavailable metadata produced an honest partial result with six checks. API enablement
resolved it without broader scopes: benign **0 / low observed risk**, suspicious **75 / high risk**,
both with all eight implemented checks and complete supplied-field coverage. The suspicious email
reported one metadata record; its literal HTML-like subject and evidence rendered as text.

Switching between the two messages reset to a fresh action card. Returning to the message list
showed the homepage. Stopping the backend replaced the prior result with **Analysis unavailable**
and no score; restoring it and analyzing again returned **75**. The successful result was left
visible. An expanded Google execution showed no logs available (Google notes logs may be delayed).
Backend/tunnel logs were checked for the demo token and synthetic message snippets without exposing
them. No real email content, Gmail token, message ID, private screenshot, or secret is committed.

**Example trace:** the live suspicious email requested credentials and payment under pressure and
contained a URL with user-info and an IP host. Awards were 25 + 10 content points (15 suppressed
by the content cap), plus 25 + 15 URL points = **75**. Repeated plain/HTML signals were deduplicated.
The harmless `.txt` attachment caused no finding; successful metadata retrieval allowed both
attachment checks to run.

**Remaining:** within-thread message selection, long-message timing/truncation, Google's hard
execution deadline, live wrong-token behavior, container build, durable hosting decision, fresh
checkout rehearsal, and final submission packaging. See [live verification](live-verification.md).
The active development tunnel and backend must stay running for Gmail to work.

**Delivery:** the author approved committing and pushing milestone 3 on 2026-11-17.
Commit `c51da73` is on `main`; [remote CI passed](https://github.com/ShaharMaaravi/upwind-mail-guard/actions/runs/43967672359).

## Milestone 4 — security validation and live edge cases

**Implemented:** an application exception boundary prevents unexpected exception/validation text
from reaching clients or Uvicorn logs. It returns a generic 500 and fixed `request_failed` log;
late response failures are sanitized, and cancellation propagates. Added a bounded, escaped
analyzed-text preview and thread-selection guidance after observing Gmail's message-focus behavior.
No scoring policy, dependencies, OAuth scopes, or backend payload fields changed.

**Automated verification (2026-11-17):** 248 Python tests and 87 Node tests passed, Ruff lint/format
passed, and real localhost HTTP integration passed. The new subprocess regression injects analyzer
exceptions and invalid responses and checks the actual Uvicorn output for content/credential markers.
A separate 300-case deterministic mutation exercise completed with network access forbidden and no
crashes or score inconsistencies. `pip-audit==2.10.1` reported no known vulnerabilities for all 21
pinned runtime packages and nine additional development packages; none were skipped. The check uses
current PyPI advisory data and is not an exhaustive security guarantee. See [security review](security-review.md).

**Live Gmail verification (2026-11-17):** the author approved one synthetic reply to the existing
benign thread, starting with urgent credential wording followed by 20,000 neutral test characters.
The reply scored **25 / suspicious / partial**, with both plain text and HTML marked truncated and
all eight checks run. Selecting the original message returned **0 / low observed risk / complete**.
After sending the reply, Gmail initially retained the original action context; explicitly selecting
its header refreshed the context. The deployed preview and guidance make this distinction visible.

A temporary backend configured with a different generated secret returned **Backend authentication
failed**, without a score. A separate authenticated 45-second delay produced Google's **maximum
execution time exceeded** platform error, without a new score; the callback could not render its own
failure card. Restoring the normal backend, returning to the message list, reopening the thread, and
analyzing again returned **25** with the correct text preview and truncation notes. The successful
result was left visible. Temporary fault servers were stopped; the normal backend/tunnel are running.
Local application/tunnel/fault logs were checked for the real demo token and tested message snippets.

**Review limits:** API/add-on/parse/scoring controls and known gaps are documented in security-review.md.
The Docker command is installed but its daemon socket was unavailable; no local container build is
claimed. Hosting, fresh checkout, and final demo packaging remain milestone 5. No private mail or
screenshots were added to the repository, and no new external service was deployed.

**Delivery:** the author approved committing and pushing milestone 4 on 2026-11-17.
Commit `fa63444` is on `main`; [remote CI passed](https://github.com/ShaharMaaravi/upwind-mail-guard/actions/runs/43971607094).

## Milestone 5 — readable cards and reproducible submission

**Implemented:** a compact native Gmail result with colored verdict, short action, coverage,
subject/preview, and the three strongest reasons. Expandable sections retain full evidence,
requested/awarded/capped point arithmetic, omitted findings, and check details. A fixed footer
keeps Analyze available. Incomplete coverage, unavailable fields, truncation, and the low-score
safety caveat remain visible. Rule labels are shorter; scoring and permissions are unchanged.

Added a disposable-container verification script and CI container job. Updated README, Gmail
installation, demo instructions, and a deployment guide for the local server/tunnel and Docker.

**Automated verification (2026-11-17):** copied the complete proposed source into a clean directory
without secrets/build output/caches and installed pinned dependencies into a new virtual environment.
All **248 Python / 90 Node tests**, Ruff lint/format, and real local HTTP integration passed
(Python 3.12.0, Node 25.2.1). The 20 corpus responses passed add-on validation/rendering over HTTP;
Google services remain mocked in that check. Three new structural card tests check collapsed
layout, retained evidence/accounting, always-visible coverage gaps, and no unavailable numeric score.

Docker Desktop started via its CLI. Built and ran the existing Dockerfile as Linux ARM64 and AMD64
(AMD64 emulated locally). The script verified UID 10001, read-only execution with dropped capabilities,
256 MiB/0.5 CPU limits, excluded source/secrets, public health, unauthorized rejection, the 95-point
fixture, all 20 corpus scores, absence of selected content/token log markers, and refusal to start
without the secret. Temporary containers were removed. Observed memory after the fixture run was
about 49 MiB ARM64 / 65 MiB AMD64; this is not a load test or cost estimate.

**Live Gmail verification:** saved the redesigned source in the existing project, keeping the same
origin, token, manifest, and OAuth permissions. The truncated reply showed **25 / suspicious / partial**
with truncation visible; expanded sections retained evidence and check details. The suspicious
message showed **75 / high risk**, top three of four reasons, and escaped literal markup. The original
benign message showed **0 / low observed risk**, all eight checks, the correct Unicode preview, and
no findings. The fixed Analyze footer worked; the benign result was left visible. Existing synthetic
emails were reused, and no additional messages were sent. M4 failure/recovery checks remain valid:
the backend and transport code are unchanged.

**Hosting (2026-11-17):** deployed the unchanged backend/Dockerfile from `fa63444` to Northflank
Developer Sandbox after approved signup, user-completed card verification, repository-only GitHub
access, and approval for the demo secret/public endpoint/synthetic tests. One 0.1 CPU / 256 MB London
instance, public HTTPS port 8080, `/healthz` readiness, no database/volume. The UI showed Free,
Running, 1/1 checks passing, and no accrued costs. Northflank CI/CD builds/deploys main automatically.

Verified hosted health, unauthorized 401, security headers, the 95-point fixture, all 20 corpus
scores (slowest 0.44 s in the recorded run), malformed JSON 422, and oversized payload 413. An early
server rejection closed the Python client's upload; curl with Expect: 100-continue observed 413.
No TLS bypass or backend change was needed. An additional local AMD64 run at 0.1 CPU / 256 MB
passed after increasing the smoke client's startup allowance from 10 to 60 seconds; memory was
about 77 MiB. That experiment changed no committed script and is not a hosting latency guarantee.

Updated the generated Apps Script source and manifest to the hosted origin, preserving scopes and
Google Script Properties. With the local backend stopped, Gmail returned benign **0**, long reply
**25 / partial** with truncation, and suspicious **75**, all with correct message previews/coverage.
No new emails were sent. The obsolete tunnel was then stopped. Provider-visible application logs
contained only seven platform/Uvicorn startup entries after tests. Earlier outage/wrong-token/timeout
checks were local; no hosted outage or long-term uptime claim is made. See [deployment](deployment.md).

**Billing notification follow-up (2026-11-17):** created a $0 team billing alert and verified it
persisted after page reload. Account usage remained $0.00 on Developer Sandbox. This configures
email notification for positive billable usage; it is not a hard cap or a guarantee that
notification precedes charging. No paid upgrade/resource was added. The provider's $50 billing
threshold triggers automatic invoicing/payment and is not a spending limit. See the deployment guide
for source references and limitations.

**Delivery:** the author approved committing and pushing milestone 5 on 2026-11-17.
[Release checks](https://github.com/ShaharMaaravi/upwind-mail-guard/actions/workflows/ci.yml)
include the Python/Node/integration suite and the new container job. Verify the run for the released
revision, and confirm Northflank deploys that revision successfully. No private screenshots or mail,
credentials, temporary tunnel origin, or original assignment PDF are included in source.

## Release and demonstration checklist

1. For the approved release, verify both GitHub CI jobs and Northflank deployment at the pushed revision.
2. Before the interview, check hosted health and rehearse the existing synthetic messages; no laptop server/tunnel is required.
3. Submit the repository link through the author's chosen channel; sending it is a separate action.

Detailed explanations and interview practice are deferred until after implementation at the
author's request. Decisions are recorded as we build so they can be reviewed later.
