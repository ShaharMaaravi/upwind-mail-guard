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
This record accompanies the approved commit; remote CI is checked after the push.

## Upcoming

1. Complete Gmail score/verdict/evidence experience.
2. Security checks, submission README, live demo rehearsal.

Detailed explanations and interview practice are deferred until after implementation at the
author's request. Decisions are recorded as we build so they can be reviewed later.
