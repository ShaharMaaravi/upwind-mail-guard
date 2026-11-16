# Live Gmail verification

**Core integration passed on 2026-11-16; analysis product passed on 2026-11-16–17; security/edge checks passed on 2026-11-17.** This record distinguishes observed Gmail behavior
from automated coverage and broader cases still pending before final submission.

Environment: personal Gmail account, unpublished Apps Script test deployment, local FastAPI
backend behind a temporary Cloudflare HTTPS tunnel. Scope:
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

The local backend and temporary HTTPS tunnel remain running for development. Local tests passed
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

## Submission gates still pending

- [ ] Build/run the container; the local Docker daemon socket is unavailable.
- [ ] Decide the final hosting arrangement and document its startup/cold-start behavior.
- [ ] Milestone 4 remote CI after approved commit/push.
- [ ] Fresh-checkout reviewer setup and final demonstration rehearsal.

Do not commit personal email bodies, addresses, credentials, or private screenshots as evidence.
