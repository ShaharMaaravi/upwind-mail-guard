/** Real local HTTP integration using the actual add-on code and mocked Google services.
 * This is NOT a Gmail installation test. Secrets travel through stdin/environment, not argv.
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { once } = require('node:events');
const { harness } = require('../addon/tests/helpers.cjs');

const root = path.join(__dirname, '..');
const python = process.env.PYTHON || path.join(root, '.venv/bin/python');
const token = crypto.randomBytes(32).toString('base64url');
const bridge = `
import json, sys, urllib.request
data=json.load(sys.stdin)
request=urllib.request.Request(data['url'], data=data['payload'].encode(), headers=data['headers'])
with urllib.request.urlopen(request, timeout=5) as response:
 print(json.dumps({'status':response.status,'body':response.read().decode()}))
`;

async function main() {
  const reservation = net.createServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  const backend = spawn(python, ['-m', 'uvicorn', 'app.main:create_app', '--factory',
    '--app-dir', 'backend', '--host', '127.0.0.1', '--port', String(port), '--no-access-log'], {
    cwd: root, env: { ...process.env, MAIL_GUARD_API_TOKEN: token }, stdio: ['ignore', 'pipe', 'pipe']
  });
  let startupError;
  backend.on('error', error => { startupError = error; });
  try {
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      if (startupError) throw startupError;
      if (backend.exitCode !== null) throw new Error('Backend failed to start');
      try { ready = (await fetch(origin + '/healthz')).ok; } catch { /* starting */ }
      if (ready) break;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.ok(ready, 'Backend did not become ready');
    const unauthorized = await fetch(origin + '/v1/diagnose', { method: 'POST', body: '{}' });
    assert.equal(unauthorized.status, 401);
    const { context, calls } = harness({
      BACKEND_ORIGIN: origin,
      PropertiesService: { getScriptProperties: () => ({ getProperty: () => token }) },
      UrlFetchApp: { fetch(url, options) {
        const result = spawnSync(python, ['-c', bridge], {
          input: JSON.stringify({ url, payload: options.payload,
            headers: { ...options.headers, 'Content-Type': options.contentType } }), encoding: 'utf8'
        });
        assert.equal(result.status, 0, 'HTTP bridge failed');
        const response = JSON.parse(result.stdout);
        return { getResponseCode: () => response.status, getContentText: () => response.body };
      } }
    });
    context.onTestConnection({ gmail: { messageId: 'synthetic-selected-message', accessToken: 'fake' } });
    assert.ok(JSON.stringify(calls).includes('Backend connected'));
    assert.ok(!JSON.stringify(calls).includes('Analysis unavailable'));
    const analysisPayload = fs.readFileSync(path.join(root, 'fixtures/analysis-request.json'), 'utf8');
    const missingAuth = await fetch(origin + '/v1/analyze', { method: 'POST', body: analysisPayload });
    assert.equal(missingAuth.status, 401);
    const analysis = await fetch(origin + '/v1/analyze', {
      method: 'POST', body: analysisPayload,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    });
    assert.equal(analysis.status, 200);
    const result = await analysis.json();
    assert.equal(result.request_id, JSON.parse(analysisPayload).request_id);
    assert.equal(result.analysis_status, 'unavailable');
    assert.equal(result.score, null);
    assert.deepEqual(result.findings, []);
    assert.ok(result.coverage.limitations.includes('detection_rules_not_implemented'));
    console.log('PASS: add-on extraction → real local HTTP → backend → validated result card');
    console.log('PASS: real HTTP rejects missing credentials');
    console.log('PASS: real analysis HTTP contract preserves coverage without inventing a score');
    console.log('Google services are mocked. Live Gmail/HTTPS verification is still required.');
  } finally {
    if (backend.pid && backend.exitCode === null) {
      const exited = once(backend, 'exit');
      backend.kill('SIGTERM');
      await exited;
    }
  }
}
main().catch(() => { console.error('Local integration failed. Check Python dependencies and port access.'); process.exitCode = 1; });
