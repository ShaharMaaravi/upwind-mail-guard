# Install and test the Gmail add-on

These are installation instructions, not a record of completed Gmail verification.
Complete the local README checks first. Use your own demonstration account and synthetic messages.

## 1. Make the backend reachable over HTTPS

The submitted demo uses the hosted Northflank backend at **https://p01--upwind-mail-guard--vpdljyyj7txr.code.run**.
See [backend deployment](deployment.md) for the exact configuration and verification. It works
without the development laptop. Analysis remains authenticated; the repository does not expose
the demo token. To install your own copy, deploy the included Dockerfile with your own random
`MAIL_GUARD_API_TOKEN`, port 8080, one instance, and `/healthz` readiness check.

For local development, run the README service and a temporary HTTPS tunnel:

```bash
cloudflared tunnel --url http://127.0.0.1:8000
```

Apps Script cannot reach your laptop's `localhost` directly. Install cloudflared from
[Cloudflare's official instructions](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/).
Use the exact printed HTTPS origin, keep both processes running, and rebuild/upload when the
origin changes. This is a fallback; the submitted hosted deployment does not use the tunnel.
Do not enable email-body or Authorization-header logging on either deployment.

## 2. Build the add-on

Substitute the actual HTTPS origin (no path, query, port, or credentials):

```bash
npm run build:addon -- https://YOUR-PUBLIC-BACKEND-HOST
```

This generates `addon/build/appsscript.json`, `Deployment.js`, and the five source files.
The host is pinned in both the generated source and Google's fetch allowlist. A separate narrow
prefix permits Gmail's message metadata API. No secrets enter
the build. Generated files are ignored by Git. Rebuild and upload again after changing the host.

## 3. Create the Apps Script project

1. Open [Apps Script](https://script.google.com/) in the same Google account you will demonstrate.
2. Create a standalone project named **Upwind Mail Guard**.
3. In **Project Settings**, enable **Show appsscript.json manifest file in editor**.
4. Replace the manifest with `addon/build/appsscript.json`.
5. Create script files named `Deployment`, `Extraction`, `Validation`, `ApiClient`, `Cards`, and `Handlers`.
   Paste the matching generated `.js` file into each. Google displays them as `.gs` files.
   Remove the unused default `Code.gs` if it only contains the initial empty function.
6. Under **Project Settings → Script Properties**, add `MAIL_GUARD_API_TOKEN` with the same
   token as your local `.env` or hosted backend secret. Copy the value only, without the name
   or equals sign. Do not paste it into code, screenshots, Git, or this chat.
7. Save the project. Confirm **Services** lists **Gmail API v1**. The generated manifest declares
   this dependency. If absent, use **Services → Add a service → Gmail API → v1 → Add** and review
   Google's API terms. For a standard Google Cloud project, also enable Gmail API in that project;
   see [advanced service setup](https://developers.google.com/apps-script/guides/services/advanced#enable_advanced_services).

The manifest requests current-message content only after an explicit user interaction, plus
add-on execution and external requests. The implemented getters and metadata request worked in
the demonstration account with this narrow scope. Missing getters/metadata remain unavailable.
The Gmail API request uses the Apps Script OAuth token plus the current-message event token;
neither token goes to the backend. Its partial-response mask excludes attachment content and
download IDs. Enabling the Gmail service does not require adding mailbox-wide OAuth scopes.

Optional local synchronization: install Google's `@google/clasp`, enable the Apps Script API
for your account, run `clasp login`, copy `addon/.clasp.example.json` to `addon/.clasp.json`,
and replace the script ID with the ID shown in Project Settings. From `addon/`, run `clasp push`
after building. Keep OAuth files and `.clasp.json` out of Git. Do not push into an unrelated project.
Manual upload above avoids this additional tooling for the first test.

## 4. Install and authorize the test deployment

1. In the Apps Script editor choose **Deploy → Test deployments**.
2. Select **Google Workspace Add-on** as the deployment type if prompted, then **Install**.
3. Open or refresh Gmail in the same account and select the add-on from the right sidebar.
4. Complete Google's authorization flow yourself. Check that the project and scopes match the
   intended add-on. Workspace administrators may restrict testing or authorization.
5. Open a synthetic email and click **Analyze this email**.

Expected result: a compact score/verdict, recommended action, coverage, selected subject, preview,
and strongest reasons. Expand **Why this score** for evidence and contribution arithmetic;
expand **Checks and limitations** for all check details and the random analysis reference.
The **Analyze again** button stays in the footer. In a conversation,
expand the intended message header and check that preview, especially after sending a reply.
A benign message can score zero but must not be labeled safe. Missing metadata should show partial coverage and skipped attachment checks.
If metadata stays unavailable, check that Gmail API v1 is enabled and the manifest has the exact
generated Gmail fetch prefix. Do not broaden OAuth scopes to conceal a configuration problem.

Google's current guides:
[test deployment](https://developers.google.com/workspace/add-ons/how-tos/testing-workspace-addons),
[scopes](https://developers.google.com/workspace/add-ons/concepts/workspace-scopes),
[clasp](https://developers.google.com/apps-script/guides/clasp),
[per-message Gmail API headers](https://developers.google.com/workspace/add-ons/guides/alternate-runtimes#accessing_gmail_data),
[partial responses](https://developers.google.com/workspace/gmail/api/guides/performance#partial_response).

## 5. Finish the live gate

Follow [the demo script](demo.md) and [live verification](live-verification.md). Record actual results in progress.md.
Do not call the integration complete just because local tests pass.

If configuration fails, check the token match, backend health, current backend URL, rebuilt source,
manifest allowlist, and Google authorization. A Google execution timeout can prevent our own
failure card from rendering; observe and record the platform's actual behavior.

Token rotation: stop test traffic, generate a replacement secret locally, update the backend and
Script Properties, restart the backend, and rerun the live check. Never post the old/new value.
