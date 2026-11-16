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
was unavailable, so no image build was run. Remote CI is triggered by the approved push; its result must be checked separately.

**Delivery:** the author approved committing and pushing milestone 0 on 2026-11-16. This record accompanies the first implementation commit; see Git history for its identifier.

## Upcoming

1. Strict analysis contract and pure normalization/scoring foundation.
2. Focused deterministic detection rules with benign/adversarial fixtures.
3. Complete Gmail score/verdict/evidence experience.
4. Security checks, submission README, live demo rehearsal.

Detailed explanations and interview practice are deferred until after implementation at the
author's request. Decisions are recorded as we build so they can be reviewed later.
