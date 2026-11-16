# Working on Upwind Mail Guard

## Goal and context

This repository supports an Upwind Security Analyst take-home assignment. The candidate must understand the implementation, architecture, tradeoffs, and alternatives well enough to explain and modify the solution during an interview. Optimize for a small, complete, explainable product.

Read README.md first. It contains the assignment requirements and proposed architecture, milestones, security boundaries, alternatives, and references. Those proposals are not evidence that features are implemented. Inspect the actual files and git status before continuing.

## Current handoff

Milestone 5 implements compact Gmail cards with expandable details, a fixed Analyze footer, and reproducible submission/container instructions. A clean source copy and new environment passed 248 Python / 90 Node tests, lint/format, and HTTP integration. Milestone 4 is committed/pushed as fa63444 with passing remote CI. The author explicitly approved committing and pushing milestone 5 on 2026-11-17. Read docs/deployment.md, docs/security-review.md, docs/progress.md, and docs/live-verification.md for evidence and limitations.

The live suite now covers benign 0, suspicious 75, a 20,068-character reply scoring 25 with truncation, selection within one thread, metadata, escaped text, wrong backend token, Google's execution timeout, and recovery. Gmail can retain an earlier message context after sending a reply; users must select/expand the intended header and check its analyzed-text preview. The 45-second delay returned Google's platform error, not our custom card. Temporary fault servers were stopped and the normal backend/tunnel restored.

The compact cards were verified live with scores 0/25/75; collapse preserves prominent coverage warnings and full expandable accounting. Linux ARM64/AMD64 containers were built and verified locally. The author requires free hosting. Northflank Developer Sandbox now runs one nf-compute-10 instance (0.1 CPU/256 MB) in Europe-West/London, public HTTPS port 8080, HTTP /healthz readiness, no storage. Service URL: https://p01--upwind-mail-guard--vpdljyyj7txr.code.run. The author completed card verification and approved repository-only GitHub access, saving the demo token, public deployment, and synthetic tests. No paid upgrade was selected; the service is labeled Free and billing showed no accrued costs. It builds/deploys main automatically (Northflank CI/CD defaults); the initial tested hosted backend commit was fa634446ca83ddff1b7023f7c1ea89d9d4ef14ed. No backend/Dockerfile changes exist in M5.

Hosted HTTPS checks passed: health, unauthorized 401, 95-point fixture, all 20 corpus scores (slowest 0.44 s in the recorded run), security headers, malformed 422, and oversized 413. The oversize client uses Expect: 100-continue to observe the server's early rejection without a TLS upload-close error. This is client test handling, not a backend change. Apps Script source and manifest now pin the hosted origin; Google Script Properties and scopes are unchanged. Live Gmail 0/25/75 passed with the local backend stopped. The obsolete local tunnel was then stopped. Hosted logs showed only seven platform/Uvicorn startup lines after tests; this is not a guarantee about provider retention. Local runtime metadata is in /private/tmp/upwind-live-tools/processes.json, with both processes marked inactive. Local fallback instructions remain documented.

The author explicitly requires notification before any charge. A $0 team billing alert was saved and verified after reload; current usage is $0.00 and plan remains Developer Sandbox. Alerts do not guarantee advance notice or block charges. The displayed $50 billing threshold is an automatic invoice/payment trigger, not a hard cap. No hard cap or per-charge approval control was found. Do not claim charges are impossible, and never upgrade/add paid resources without explicit authorization. This limitation was explained to the author.

Milestone 5 commit/push is approved. Verify GitHub Actions and Northflank for the released main revision after pushing. The workflow contains both the test and container jobs; a passing earlier revision is not evidence for a later release. Do not claim production accuracy or guaranteed uptime. Preserve current-message scopes, Google-only token handling, offline PSL behavior, exact score accounting, and honest unavailable/partial results. Never turn mocked Google tests into live verification claims.

The author is working toward a next-day submission and asked to implement and test each milestone first, with detailed learning afterward. Record decisions without lengthy teaching interruptions. Obtain the author's explicit approval before each milestone commit; do not commit or push automatically.

The assignment PDF was read in full during planning. Its essential requirements are in the README. Do not publish the original private PDF or personal email content.

## Collaboration style

- Implement in small, coherent milestones; avoid a single large unexplained code dump.
- Before a meaningful design choice, explain the problem, chosen approach, a realistic alternative, and the cost of the choice. Proceed with routine work within the user's requested scope.
- After each milestone, trace one concrete example through the code and summarize relevant tests, remaining limitations, and likely interview questions.
- Maintain docs/decisions.md and docs/progress.md as implementation proceeds. Distinguish planned, implemented, automated-tested, and live-verified behavior.
- Keep the README accurate and reviewer-facing. Replace planning-only material with tested setup/run/demo instructions before submission.
- Use clear English for code and project documentation. Follow the user's chosen language for explanations.

## Engineering constraints

- The Gmail add-on is the product, with a separate backend. A CLI or separate web dashboard does not replace it.
- Prefer Apps Script/CardService and a modular Python/FastAPI backend unless evidence supports a change.
- Keep the analysis core deterministic and independent of Gmail/UI/network code.
- Treat all message data and external responses as untrusted. Bound inputs, escape rendered evidence, and avoid fetching message URLs or opening attachment contents.
- Keep Gmail tokens in the add-on and secrets outside source control. Use only synthetic fixtures. Inspect logs and error responses for accidental content exposure.
- Missing data, partial analysis, and backend failures must not be presented as a safe verdict.
- A heuristic score is not a calibrated probability. Document provisional weights and thresholds.
- Authentication-Results requires a justified trust boundary; a matching header string alone is insufficient.
- Prefer focused tests of observable behavior and important security boundaries. Record what was actually run.
- Do not add databases, queues, LLMs, reputation providers, or microservices without a concrete benefit that justifies their complexity.
- A public repository is authorized. Publishing private data, incurring hosting charges, and sending a submission to the recruiter are separate actions; do not infer those from repository creation.
