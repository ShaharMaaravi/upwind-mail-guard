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
