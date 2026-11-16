# Install and test milestone 0

These are installation instructions, not a record of completed Gmail verification.
Complete the local README checks first. Use your own demonstration account and synthetic messages.

## 1. Make the backend reachable over HTTPS

Run the local service using the README. Apps Script runs on Google's servers and cannot reach
your laptop's `localhost` directly.

For this first integration experiment, a temporary HTTPS tunnel avoids choosing a hosting provider.
If you already have Cloudflare's `cloudflared` installed, run in a second terminal:

```bash
cloudflared tunnel --url http://127.0.0.1:8000
```

Use the exact HTTPS origin printed by the tunnel. Obtain cloudflared only from
[Cloudflare's installation instructions](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/).
The tunnel exposes this development server through Cloudflare; authentication remains required
for message requests. Keep both processes running. The URL can change when restarted.
The tunnel is a development option, not a verified final-demo hosting arrangement.

Alternatively, deploy the included Dockerfile to an HTTPS container host, listen on port 8080,
set `MAIL_GUARD_API_TOKEN` in its secret environment, and use one instance for the initial demo.
Do not add email bodies or authorization headers to hosting logs. Choose hosting and any cost
explicitly; nothing has been deployed or billed by this scaffold.

## 2. Build the add-on

Substitute the actual HTTPS origin (no path, query, port, or credentials):

```bash
npm run build:addon -- https://YOUR-PUBLIC-BACKEND-HOST
```

This generates `addon/build/appsscript.json`, `Deployment.js`, and the four source files.
The host is pinned in both the generated source and Google's fetch allowlist. No secrets enter
the build. Generated files are ignored by Git. Rebuild and upload again after changing the host.

## 3. Create the Apps Script project

1. Open [Apps Script](https://script.google.com/) in the same Google account you will demonstrate.
2. Create a standalone project named **Upwind Mail Guard**.
3. In **Project Settings**, enable **Show appsscript.json manifest file in editor**.
4. Replace the manifest with `addon/build/appsscript.json`.
5. Create script files named `Deployment`, `Extraction`, `ApiClient`, `Cards`, and `Handlers`.
   Paste the matching generated `.js` file into each. Google displays them as `.gs` files.
   Remove the unused default `Code.gs` if it only contains the initial empty function.
6. Under **Project Settings → Script Properties**, add `MAIL_GUARD_API_TOKEN` with the same
   token as your local `.env` or hosted backend secret. Copy the value only, without the name
   or equals sign. Do not paste it into code, screenshots, Git, or this chat.
7. Save the project.

The manifest requests current-message content only after an explicit user interaction, plus
add-on execution and external requests. We have not yet proven this scope permits all desired
getters in the demonstration account. Missing getters are shown as unavailable, never fabricated.

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
5. Open a synthetic email and click **Test connection**.

Expected result: **Backend connected — diagnostic only**, selected subject, field counts,
availability/truncation, and a random test reference. There must be no maliciousness score.

Google's current guides:
[test deployment](https://developers.google.com/workspace/add-ons/how-tos/testing-workspace-addons),
[scopes](https://developers.google.com/workspace/add-ons/concepts/workspace-scopes),
[clasp](https://developers.google.com/apps-script/guides/clasp).

## 5. Finish the live gate

Run every item in [live verification](live-verification.md). Record actual results in progress.md.
Do not call the integration complete just because local tests pass.

If configuration fails, check the token match, backend health, current tunnel URL, rebuilt source,
manifest allowlist, and Google authorization. A Google execution timeout can prevent our own
failure card from rendering; observe and record the platform's actual behavior.

Token rotation: stop test traffic, generate a replacement secret locally, update the backend and
Script Properties, restart the backend, and rerun the live check. Never post the old/new value.
