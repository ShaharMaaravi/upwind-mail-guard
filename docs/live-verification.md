# Live Gmail verification

**Core integration passed on 2026-11-16; analysis product passed on 2026-11-16–17; security/edge checks passed on 2026-11-17.** This record distinguishes observed Gmail behavior
from automated coverage and broader cases still pending before final submission.

Earlier environment (milestones 0–4): personal Gmail account, unpublished Apps Script test deployment,
local FastAPI backend behind a temporary Cloudflare HTTPS tunnel. Milestone 5 moved the backend
to Northflank and repeated the successful Gmail checks with the local backend stopped. Scope:
`https://www.googleapis.com/auth/gmail.addons.current.message.action`.
No broad mailbox scope was added. The author explicitly approved authorization, storing the demo
token in Script Properties, and sending one synthetic email to the same account.

## Milestone 0: diagnostic integration

- [x] Install the test deployment and authorize the intended current-message action scope.
- [x] Outside an opened message, the add-on asks the user to open an email.
- [x] A synthetic message displays the explicit Test connection action and transmission notice.
- [x] Clicking the action displays a real backend-connected diagnostic card in Gmail.
- [x] All implemented getters worked: sender 43 characters; Reply-To 0; subject 27; plain text 39;
      HTML 64; authentication header 0. Counts reflect Gmail's representation, including its
      formatting. Zero-length fields remained distinct from unavailable fields.
- [x] The synthetic body included emoji and Hebrew and completed the full round trip.
- [x] Attachments are explicitly not inspected; authentication claims remain unverified.
- [x] Stopping the backend produced Analysis unavailable, with no score or safe verdict.
- [x] Restarting the backend and reopening the message produced a successful result with a new
      request reference. Returning to search results reset to the homepage, and reopening the
      message produced a fresh action card.
- [x] Local backend/tunnel logs were checked for the demo token and synthetic body text; neither
      was present. No real email content was submitted to the backend.

The outage test used an unavailable origin, which returned promptly through the tunnel. It does
not prove behavior at Google's hard execution deadline. For reliable retries in this test, return
to the message list and reopen the message; simply closing/reopening the sidebar may retain a card.

## Milestone 3: analysis product

The author approved one additional synthetic self-email with a harmless `.txt` attachment and
the Gmail API terms. The current-message action scope stayed unchanged. Only synthetic messages
were analyzed. The selected-message metadata request excludes attachment content and download IDs;
the code and mocked request assertions establish that boundary, while the live result establishes
successful retrieval of the named metadata record.

- [x] Updated Analyze action and transmission notice displayed in Gmail.
- [x] Before API enablement, metadata failure produced partial coverage, two skipped attachment
      checks, and an inconclusive zero for the benign message. It did not pretend metadata was empty.
- [x] Enabling Gmail API v1 resolved metadata retrieval without broader OAuth scopes.
- [x] Benign synthetic message: **0 / low observed risk**, complete supplied-field coverage,
      all eight checks run, no findings, zero attachment metadata records.
- [x] Suspicious synthetic message: **75 / high risk**, complete supplied-field coverage,
      all eight checks run, one harmless attachment metadata record. Contributions: credential
      pressure 25, URL user-info 25, IP host 15, payment pressure 10 (15 category-suppressed).
      Requested 90 minus category suppression 15 equals 75; duplicate signals were removed.
- [x] Literal HTML-like subject remained text. Evidence/explanations were visible in CardService
      and the add-on created no URL-opening controls. Message links were not visited during testing.
- [x] Switching between two distinct messages reset the add-on to a fresh action card. The benign
      message did not inherit the suspicious message's score. The message-list context showed the homepage.
- [x] Stopping the identified backend replaced a prior score with **Analysis unavailable** and no
      score. After restarting, a new analysis of the suspicious message returned **75** again.
- [x] A recent Apps Script execution showed **No logs are available for this execution**. Google
      notes that logs may be delayed; this observation is not a guarantee about provider retention.
- [x] Backend/tunnel logs contained neither the demo API token nor tested synthetic subject/body
      snippets. No email content logging was enabled, and no real email content was sent to the backend.

At that milestone, the local backend and temporary HTTPS tunnel remained running. Local tests passed
243 Python / 84 Node cases plus HTTP integration; milestones 0–2 passed remote CI. These checks do
not establish production detection accuracy or final deployment readiness.

## Milestone 4: thread selection and failure boundaries

The author approved one further synthetic self-reply in the benign test thread. Its 20,068-character
body starts with credential-pressure wording and continues with neutral filler; no links or attachments.

- [x] Selected the long reply: **25 / suspicious / partial**, with HTML and plain-text truncation
      visible, all eight checks run, and one credential-pressure finding.
- [x] Selected the original message in the same thread: **0 / low observed risk / complete**.
      Sending a reply alone initially left the original message context active; selecting/expanding
      the intended message header refreshed it. Results now show a bounded analyzed-text preview,
      and the start card explains that one message is analyzed at a time.
- [x] Deployed the preview and verified it matches the original message and long reply respectively.
- [x] Temporarily configured the backend with a different generated secret: Gmail displayed
      **Analysis unavailable — Backend authentication failed**, with no score. Google Script
      Properties and the user's stored demo secret were unchanged.
- [x] Delayed an authenticated backend response by 45 seconds: Gmail displayed its platform error,
      **maximum execution time exceeded**, with no new score. This is distinct from the application's
      custom failure card; the callback did not have an opportunity to finish normally.
- [x] Restored the normal backend, returned to the message list, reopened the thread, and analyzed
      again: **25 / suspicious / partial**, the right preview, and both body truncation notes.
- [x] Checked the local backend, tunnel, and temporary fault-server logs for the demo token and
      synthetic message snippets. The fault servers were stopped and the normal backend restored.

Google's [documented Workspace add-on runtime limit](https://developers.google.com/apps-script/guides/services/quotas#current_limitations)
is 30 seconds. This experiment verifies the platform error for this deployment, not a configurable
client timeout or successful handling of every cold start. Return to the message list and reopen the
message after the backend recovers. A 20 KiB fixture does not establish arbitrary message-size safety.

## Milestone 5: compact cards and submission rehearsal

- [x] Uploaded/saved the revised card code in the same Apps Script project, without changing
      permissions, manifest, backend token, or HTTPS origin. Existing synthetic messages were reused.
- [x] Long reply: **25 / suspicious / partial** with truncation visible while details are collapsed.
      Expanded **Why this score** and **Checks and limitations** retained evidence, accounting, and limits.
- [x] Suspicious message: **75 / high risk**, three leading reasons and an explicit four-finding
      count, literal HTML-like subject escaped, and fixed **Analyze again** footer. The final shorter
      credential label was saved and verified by a fresh analysis.
- [x] Original benign message: **0 / low observed risk**, all eight checks, Unicode preview,
      no findings, compact limitations section, and footer. Visually inspected and left visible.
- [x] Built and exercised Linux ARM64/AMD64 containers, including authenticated fixtures, missing
      secret, non-root/read-only execution, bounded resources, and selected log-marker checks.
      AMD64 ran through local Docker emulation; remote container CI remains a separate delivery gate.
- [x] Rehearsed reviewer setup from a clean source copy and new virtual environment: pinned install,
      248 Python / 90 Node tests, lint/format, and real HTTP integration passed.
- [x] Deployed Northflank Developer Sandbox after the author's explicit approvals. The service is
      labeled Free; billing showed no accrued costs. One 0.1 CPU / 256 MB instance in London,
      port 8080, passing `/healthz` readiness, no storage or database.
- [x] Hosted HTTPS: health, unauthorized 401, security headers, fixture 95, all 20 corpus scores,
      malformed JSON 422, oversized payload 413. Slowest corpus response: 0.44 s in the recorded run.
      Expect: 100-continue exposed the early 413 after the original upload client reported TLS EOF.
- [x] Updated and saved both Apps Script source and manifest for the hosted origin; scopes and
      Google Script Properties unchanged. Reused existing synthetic messages with approval.
- [x] Stopped the local backend, then verified Gmail **0 / complete**, **25 / partial** with body
      truncation, and **75 / complete**. Correct previews, escaped text, and top-three reasons.
      The suspicious 75 result was left visible. No new email was sent.
- [x] Stopped the obsolete tunnel after hosted verification. Neither local process is required.
- [x] Inspected hosted application logs after tests: only seven platform/Uvicorn startup lines
      were visible, without request content or credential entries. Provider retention beyond this
      view was not audited. Earlier local failure tests were not repeated as hosted outages.
- [x] Milestone 4 remote CI passed after approved commit/push (`fa63444`).

## Release and demonstration checks

- [x] Author approved milestone 5 commit/push on 2026-11-17.
- For every release, check [GitHub Actions](https://github.com/ShaharMaaravi/upwind-mail-guard/actions/workflows/ci.yml)
  at the released revision, including the container job, and verify the matching Northflank deployment.
- [ ] Immediately before the interview, confirm hosted health and analyze a synthetic Gmail message.
      No local server/tunnel is required; earlier rehearsal does not guarantee future availability.

Do not commit personal email bodies, addresses, credentials, or private screenshots as evidence.
