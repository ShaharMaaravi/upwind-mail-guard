# Implementation decisions

## 001 — Separate diagnostic endpoint for milestone 0

**Chosen:** `/v1/diagnose` proves transport and extraction with field counts and coverage.
It has no risk score or verdict. Gmail tokens and message IDs never leave Apps Script.

**Alternative:** return a fake analysis result from `/v1/analyze`.
**Cost:** a temporary endpoint to retire or restrict after integration; benefit is that an unfinished
detector cannot accidentally present a reassuring result. Request/response validation is reusable.

## 002 — Explicit action and minimal Gmail scope

**Chosen:** render a contextual card without reading content; read the selected event message only
after Test connection. Prefer `gmail.addons.current.message.action`.

**Alternative:** `current.message.readonly` permits broader open-thread access and may be needed
if a required getter is unavailable. Live evidence, not mocked tests, decides whether to change it.
The original assignment does not require automatic analysis or mailbox-wide access.

## 003 — One stateless Python application, plain Apps Script JavaScript

**Chosen:** FastAPI, strict Pydantic models, small modules and Node's built-in test runner.
**Alternative:** all TypeScript reduces language switching; a database/queue would support history
or expensive asynchronous analysis. Neither is needed for this first connection test.

## 004 — Shared demo secret and pinned HTTPS destination

**Chosen:** a randomly generated bearer token, Script Properties/backend environment, and one
build-time host matching the manifest allowlist. Redirects disabled, TLS verification enabled.
**Alternative:** verified user identity tokens and per-user authorization for broader distribution.
**Cost:** script editors share trust; token rotation is manual. Per-process rate limiting is not
a distributed abuse control. Do not use this authentication design unchanged for multiple tenants.

## 005 — Limits before JSON parsing and safe diagnostics

**Chosen:** 256 KiB streamed-body ceiling, five-second upload deadline, strict field lengths,
redacted validation errors, and no content logs. Character counts distinguish unavailable from empty.
**Alternative:** relying on Content-Length misses streaming/lying clients; default validation
responses can echo input. Hosting-level limits can complement these application controls.

## 006 — Defer attachment retrieval and authentication trust

**Chosen:** do not call Gmail attachment-blob getters in the integration scaffold. Report
`not_inspected`. Probe authentication-header availability but treat its contents as unverified.
**Alternative:** immediately download attachment blobs just to inspect names, or trust an
Authentication-Results string. Both would hide important scope/resource/trust questions.
**Consequence:** the live spike must identify whether metadata-only attachment retrieval is viable.
Header availability alone does not establish trusted SPF/DKIM/DMARC evidence.

## 007 — Test boundaries honestly

**Chosen:** unit/transport tests plus actual local HTTP integration, with a separate live Gmail gate.
**Alternative:** call a mocked Google test end-to-end. That would miss scope restrictions,
CardService rendering behavior, Google timeouts, and real message-selection semantics.

## 008 — Separate normalization, policy, and orchestration

**Chosen:** plain immutable data records for normalized evidence and signals, strict Pydantic
contracts at the API boundary, and a pure scoring function. `/v1/analyze` reports unavailable until
detectors actually execute. Existing diagnostic behavior remains usable during implementation.
**Alternative:** build rules directly inside HTTP handlers and use zero as a scaffold result.
**Cost:** a few small modules and an explicit unavailable branch; benefit is independently testable
policy and no misleading score from unfinished analysis.

## 009 — Offline domain boundaries, including private suffixes

**Chosen:** `idna` UTS #46 normalization followed by `tldextract==5.4.0` using only its packaged PSL,
verified against a recorded SHA-256. Network suffix sources and disk caching are disabled. Private
suffixes distinguish unrelated tenants such as `alice.github.io` and `bob.github.io`.
**Alternative:** last-two-label splitting fails on `co.uk`; a handwritten suffix table becomes stale;
live updates make scans network-dependent and change results without a policy review.
**Cost:** a dependency and transitive packages, a frozen snapshot that ages, and an intentional
maintenance step. Unknown suffixes are coverage gaps, not guessed identities. Update instructions
are in [the contract](analysis-contract.md).

## 010 — Inert, bounded normalization

**Chosen:** standard-library address and HTML parsers, validated HTTP(S) URLs, 100 raw link
candidates across HTML then plain text, and at most 20 metadata records. Deduplication preserves
different anchor labels for the same target. Limits and ambiguous/unsupported input remain visible
as coverage issues. No DNS, remote images, URL fetches, or attachment bytes are used.
**Alternative:** browser rendering would match visual/URL behavior more closely but adds attack
surface, deployment weight, and side-effect control. Parsing raw markup with regex alone loses
attribute/entity structure. Plain-text URL recognition still uses a bounded regex.
**Cost:** HTML visibility and quoted content are not reconstructed; a finite budget can miss a
later malicious link. Internationalized domains are normalized, not automatically called malicious.

## 011 — Auditable provisional score

**Chosen:** fixed versioned weights, one award per rule/evidence pair, category caps, then a global
100 cap. Stronger findings consume the budget first with deterministic tie-breaking. Every finding
records requested, awarded, category-suppressed, and globally-suppressed points; zero-point findings
are retained. Positive risk remains visible with partial coverage; a low partial score is inconclusive.
**Alternative:** a calibrated classifier needs representative labeled data and evaluation; a simple
unbounded sum lets repeated/correlated evidence dominate. Neither fits the current evidence or scope.
**Cost:** heuristic thresholds and weights need refinement with benign/adversarial fixtures in
milestone 2. At milestone 1, tests injected signals and did not exercise detectors. Milestone 2 adds
actual detector fixtures; neither suite establishes production accuracy.

## 012 — Eight narrow detectors before broader semantic analysis

**Chosen:** pure checks over normalized evidence with fixed prerequisites. Compare whole URL/domain
labels by site identity (registrable domain or literal IP); ignore arbitrary anchor prose. Compare
sender/Reply-To registrable domains. Use bounded English request-plus-pressure patterns and simple
negation suppression. Screen a limited executable/script/installer/shortcut suffix set; only a
document/archive extension immediately before that suffix triggers double-extension scoring.
**Alternative:** brand allowlists, reputation lookups, a trained classifier, or an LLM could broaden
coverage but require new trust boundaries, data, costs, and evaluation. MIME declarations alone do
not establish attachment type. **Cost:** known false positives and evasion gaps, now made explicit
in [the rule specification](detection-rules.md) and synthetic fixtures.

## 013 — Record executed and skipped checks separately

**Chosen:** a successful parse can still have missing data. Evaluate usable evidence, return positive
findings, and report every skipped check with a reason. A low partial score is inconclusive; when no
check is evaluable, return unavailable with a null score. Keep authentication unverified regardless
of header strings. **Alternative:** treating missing inputs as empty hides unperformed checks, while
rejecting every partial message discards useful warnings. **Cost:** response/UI coverage logic is
more explicit. The next milestone must show it faithfully.

## 014 — Preserve useful evidence while bounding disclosure

**Chosen:** URL findings describe site identities without echoing user-info credentials or query
strings; content findings return one bounded excerpt with its actual source field. Render controls
and bidi characters visibly in evidence; shorten long filenames in the middle to retain the suffix.
Content signals are awarded once per rule/message, attachment signals once per rule/normalized name,
and URL signals once per rule/canonical URL (plus displayed identity for mismatches).
**Alternative:** echo entire messages/URLs or count every match. **Cost:** some context and distinct
same-name attachments are collapsed. The Gmail UI must still escape all evidence as untrusted text.


## 015 — Read attachment metadata without downloading content

**Chosen:** request only MIME names/types/sizes from the selected-message Gmail API, using an
explicit partial-response mask. Google tokens remain on Google requests. Enable Gmail API v1
through the manifest dependency; retain the existing current-message action scope. Bound the
response to 128 KiB, MIME depth to four below root, nodes to 200, and named parts to 20. A failed
request gives unavailable metadata; reaching a limit gives explicit truncation.
**Alternative:** GmailApp attachment getters can retrieve blobs, while granting mailbox-wide
access expands permissions beyond this product. Omitting attachments entirely loses two checks.
**Cost:** one additional Google request and API enablement, possible partial coverage for complex
MIME trees, and named inline parts treated as attachment records. In the live test, enabling Gmail
API resolved unavailable metadata without requesting broader scopes.
References: [message API](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get),
[partial responses](https://developers.google.com/workspace/gmail/api/guides/performance), and
[current-message API tokens](https://developers.google.com/workspace/add-ons/guides/alternate-runtimes).

## 016 — Validate the analysis response before presenting a verdict

**Chosen:** validate exact fields, policy/normalizer versions, request correlation, rule identities,
input-derived coverage, verdict thresholds, point reconciliation, and category limits in the add-on.
Cap the UTF-8 response at 512 KiB and fail with an unavailable card for malformed/inconsistent data.
The backend remains the scoring authority; the client checks consistency rather than running rules.
**Alternative:** trust a successful HTTP status or render arbitrary response objects. A generated
schema client could reduce duplication but needs a build dependency and still needs semantic checks.
**Cost:** a small explicit JavaScript validator that must change alongside the versioned contract.
The HTTP integration exercises all 20 corpus responses through that validator to detect drift.

## 017 — Bound visible evidence while preserving score accounting

**Chosen:** display the eight strongest findings with evidence, requested/awarded points, and cap
suppression. Report omitted finding count and awarded points, plus complete aggregate arithmetic.
Escape every untrusted subject/evidence/explanation string; do not create link actions from evidence.
Each analysis reads the current action event, and message-context changes create a fresh start card.
**Alternative:** render every finding, paginate through persistent state, or hide capped findings.
**Cost:** some evidence requires backend inspection; the compact Gmail card avoids hundreds of
widgets and still explains the full score. Subsequent live tests cover literal HTML-like text,
switching between distinct messages, and selection within one multi-message thread (milestone 4).


## 018 — Keep unexpected failures out of content-bearing logs

**Chosen:** catch ordinary unexpected HTTP failures inside the request guard, before they escape to
Uvicorn. Return a fixed 500 payload and log only `request_failed`; do not attach the exception or
traceback. If a response has started, abort with a sanitized error; do not send a second response.
Cancellation propagates. Real-process tests inject both analyzer and response-validation failures.
**Alternative:** a framework-level 500 handler can still re-raise errors to the server, and logging
full exceptions can expose validation inputs or message text. **Cost:** reduced production debugging
detail; reproduce with synthetic fixtures locally. Hosting/provider logging remains a separate boundary.

## 019 — Make selected-message context visible

**Chosen:** explain header selection in a Gmail conversation and display the first 120 code points
of already-extracted plain text, escaped and whitespace-collapsed, in the result card. No new backend
field or Google permission is needed. Empty and unavailable previews are distinct.
**Alternative:** read every message in a thread or assume sending a reply selects it. The live test
showed that Gmail can preserve the original context after a reply is sent. **Cost:** one extra card
paragraph and explicit selection by the user; the preview makes same-subject results distinguishable.

## 020 — Put the result first and expand the evidence on demand

**Chosen:** native CardService collapsible sections and a fixed Analyze footer. Show verdict,
recommended action, coverage gaps, message preview, and the three strongest reasons initially.
Retain all previously shown evidence, cap arithmetic, and omitted-point accounting under **Why
this score**; detailed checks and caveats live under **Checks and limitations**. Partial status,
missing/truncated fields, and a low-score safety caveat remain visible.
**Alternative:** a long flat card exposes everything but makes the main result difficult to scan;
custom pagination adds callbacks and retained message state. **Cost:** one expansion to inspect
the full explanation. Native layout and expansion labels follow Gmail's locale. Structural tests
verify that collapse cannot hide coverage gaps, and live Gmail checks exercised expansion and the footer.
References: [CardSection](https://developers.google.com/apps-script/reference/card-service/card-section),
[FixedFooter](https://developers.google.com/apps-script/reference/card-service/fixed-footer).

## 021 — Host the portable container on a free always-on service

**Chosen:** Northflank Developer Sandbox, one 0.1 CPU / 256 MB instance, public HTTPS port 8080,
`/healthz` readiness, and a runtime secret. The existing non-root Dockerfile runs unchanged.
Gmail passed 0/25/75 with the local backend stopped. Preserve local/tunnel instructions for development
and the ARM64/AMD64 container smoke check for reproducibility. **Alternative:** a local tunnel meets
backend separation but depends on the laptop; the author requires hosted delivery. Railway's Free
plan rejected another project, and an idle-sleeping free instance can exceed Gmail's deadline.
A paid host/VPS could provide larger resources and stronger availability at added cost/operations.
**Cost:** provider account, user-completed card verification, separate secret storage, small resource
limits, and dependence on free-tier availability. No paid upgrade was selected. Readiness handles
startup; it does not guarantee response deadlines. Keep one instance for the in-memory limiter.
Northflank builds/deploys `main` automatically, independently of GitHub CI, so releases still need
local checks, explicit commit approval, and verification of both remote systems.
See [deployment configuration and evidence](deployment.md).
