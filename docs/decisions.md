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
milestone 2. Score tests currently inject signals and do not measure detector accuracy.
