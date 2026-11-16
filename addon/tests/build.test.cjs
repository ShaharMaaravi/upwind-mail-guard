const assert = require('node:assert/strict');
const { test } = require('node:test');
const { spawnSync } = require('node:child_process');
const { mkdtempSync, mkdirSync, cpSync, readFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');

test('build pins a matching HTTPS origin in source and manifest; excludes tests and secrets', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'mail-guard-build-'));
  try {
    mkdirSync(path.join(root, 'scripts'));
    cpSync(path.join(__dirname, '../../scripts/build-addon.mjs'), path.join(root, 'scripts/build-addon.mjs'));
    cpSync(path.join(__dirname, '..'), path.join(root, 'addon'), { recursive: true });
    const run = spawnSync(process.execPath, ['scripts/build-addon.mjs', 'https://mail-guard.demo-host.dev'], {
      cwd: root, encoding: 'utf8'
    });
    assert.equal(run.status, 0, run.stderr);
    const manifest = JSON.parse(readFileSync(path.join(root, 'addon/build/appsscript.json')));
    assert.deepEqual(manifest.urlFetchWhitelist, ['https://mail-guard.demo-host.dev/']);
    assert.ok(manifest.oauthScopes.includes('https://www.googleapis.com/auth/gmail.addons.current.message.action'));
    assert.ok(!manifest.oauthScopes.includes('https://mail.google.com'));
    assert.equal(manifest.exceptionLogging, 'NONE');
    assert.equal(readFileSync(path.join(root, 'addon/build/Deployment.js'), 'utf8'),
      'var BACKEND_ORIGIN = "https://mail-guard.demo-host.dev";\n');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('build rejects non-HTTPS, credential-bearing, local, placeholder and ambiguous URLs', () => {
  for (const url of [undefined, 'http://backend.dev', 'https://user:secret@backend.dev',
    'https://backend.dev/path', 'https://backend.dev?key=secret', 'https://backend.dev/#fragment',
    'https://backend.dev:8443', 'https://127.0.0.1', 'https://localhost', 'https://host.local',
    'https://example.com', 'https://backend.example.com', 'not a URL']) {
    const run = spawnSync(process.execPath, ['scripts/build-addon.mjs', ...(url ? [url] : [])], {
      cwd: path.join(__dirname, '../..'), encoding: 'utf8'
    });
    assert.notEqual(run.status, 0, url);
    assert.ok(!run.stderr.includes('user:secret'));
  }
});
