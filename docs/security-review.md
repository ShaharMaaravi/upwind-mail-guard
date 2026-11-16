# Milestone 4 security review

Reviewed on 2026-11-17 for a single-user demonstration. The backend processes untrusted email data
in memory; it is not a malware sandbox, an identity service, or an independently evaluated phishing
classifier. The public repository is separate from installation in the demonstration Gmail account.

## Boundaries and evidence

| Boundary | Control | Verification |
| --- | --- | --- |
| Gmail → add-on | Explicit action and current-message scope; no mailbox-wide scope | Live benign, suspicious, and same-thread selection tests |
| Google credentials | OAuth/event tokens only on the selected-message Google request | Add-on request assertions; backend schemas reject extra token fields |
| Attachment retrieval | MIME names/types/sizes only; no body data or download IDs; depth/node/byte/count limits | Mocked request-mask and malformed-tree tests; one harmless named part retrieved live |
| Add-on → backend | Pinned HTTPS origin, high-entropy shared secret, no redirects | Client/build tests, live HTTPS requests, authentication-failure check |
| HTTP input | Authentication before parsing; streaming 256 KiB limit; five-second upload deadline; 30 authenticated requests/minute | Raw ASGI oversize/chunk/length/disconnect/slow-upload tests on both message routes |
| Parsing and detection | Bounded fields/links/attachments, inert parsers, offline pinned PSL; no URL fetches or attachment execution | Adversarial fixtures, network-disabled domain/rule tests, deterministic mutation exercise |
| Output and UI | Strict response model/client consistency checks; escaped inert evidence; honest coverage; bounded visible findings | Response-tampering/Unicode/point-accounting tests and live CardService results |
| Unexpected failures | Generic 500 response and fixed `request_failed` log only | Injected analyzer and response-validation failures through a real Uvicorn process |
| Retention | No database, access logs disabled, exception logging disabled in Apps Script | Source/configuration review; synthetic-marker checks of local logs; Google execution inspection |

## Changes resulting from review

Unhandled Python exceptions previously escaped the application. Exception messages and response
validation errors can contain email content, so generic HTTP 500 responses alone do not protect
server logs. The request guard now catches ordinary unexpected failures before Uvicorn logs them,
returns `{"error":"internal_error"}`, and emits only the fixed operational code `request_failed`.
It includes no exception object, traceback, request body, headers, token, or message reference.
Cancellation still propagates. If headers have already been sent, it aborts using a sanitized
exception rather than trying to send a second response. Current product routes are non-streaming.

This intentionally sacrifices automatic stack traces. Reproduce failures locally with synthetic
fixtures when debugging; do not enable email-bearing exception logs in a public deployment.
Hosting infrastructure and Google/Cloudflare remain separate retention boundaries: these checks do
not establish their internal retention policies.

The thread test exposed a Gmail interaction detail: after sending a reply, the add-on can still
target the earlier message until the user selects/expands the intended message header. The start
card now explains that action, and every result includes a bounded, escaped analyzed-text preview.
It uses already-extracted text locally and adds no fields to the backend payload. This makes
same-subject results distinguishable without granting thread-wide access.

## Verification

- Full suite: 248 Python and 87 Node tests, Ruff lint/format, and real localhost HTTP integration.
  The integration exercises the actual add-on action plus validation/rendering of all 20 corpus cases.
- A separate deterministic exercise applied 300 seed-4 text/HTML/Unicode/control-character mutations
  with socket creation forbidden. No unexpected network access, crash, or score-accounting mismatch
  was observed. This bounded exercise is not exhaustive fuzzing or detection-accuracy evidence.
- `pip-audit==2.10.1` checked the pinned runtime and development requirements against its default
  PyPI advisory service. No known vulnerabilities were reported; see the progress record for counts.
  This is a dated advisory check, not a guarantee that dependencies are vulnerability-free.
- Live Gmail results and remaining deployment gates are in [live verification](live-verification.md).

To repeat the advisory check, install the audit tool in a separate temporary virtual environment
and run from the repository root:

```bash
python -m pip_audit --requirement backend/requirements.txt --no-deps --disable-pip
python -m pip_audit --requirement backend/requirements-dev.txt --no-deps --disable-pip
```

The requirements enumerate pinned transitive dependencies. `--no-deps` audits those exact versions
without executing dependency resolution/builds. Dependency consistency is checked separately with
`python -m pip check`. Package hashes and container base-image digest pinning remain future supply
chain improvements; this milestone does not silently claim those controls.

## Residual limits

The shared secret authorizes the demo, not individual users. The limiter is process-local and resets
on restart; public health/unauthorized traffic still need hosting-level protection at scale. Gmail
body getters and HTTP responses are materialized before application-level size checks. Google can
terminate an add-on callback before it renders a custom failure card. HTML visibility, quoted content,
non-English meaning, trustworthy SPF/DKIM/DMARC, attachment contents, and independent accuracy
evaluation remain outside the implemented detector. The README explains known false positives.

Docker build, durable hosting choice, and final fresh-checkout/live-demo rehearsal belong to the
submission-packaging milestone. Docker's local daemon was unavailable during this review.
