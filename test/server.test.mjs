import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const projectDirectory = fileURLToPath(new URL('..', import.meta.url));

test('serves public config and protects admin writes', async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), 'ub-launcher-admin-'));
  const port = 18602;
  const password = 'local-test-password';
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: projectDirectory,
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: String(port),
      UB_ADMIN_PASSWORD: password,
      UB_PUBLIC_BASE_URL: 'https://launcher.unitedbangla.top',
      UB_ADMIN_DATA_DIR: dataDirectory
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  try {
    await waitUntilReady(child);

    const publicResponse = await fetch(`${origin}/config.json`);
    assert.equal(publicResponse.status, 200);
    assert.equal((await publicResponse.json()).schemaVersion, 1);

    assert.equal((await fetch(`${origin}/admin/config`)).status, 401);

    const authorization = `Basic ${Buffer.from(`admin:${password}`).toString('base64')}`;
    const savedResponse = await fetch(`${origin}/admin/config`, {
      method: 'PUT',
      headers: { Authorization: authorization, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        currentVersion: '1.1.0',
        latestVersion: '1.2.0',
        forceUpdate: true,
        updateTitle: 'Bug fix ready',
        updateMessage: 'Please update.',
        updateUrl: 'https://launcher.unitedbangla.top/download',
        releaseNotesUrl: 'https://launcher.unitedbangla.top/releases/1.2.0',
        assets: { heroBanner: 'https://launcher.unitedbangla.top/assets/banner.png' },
        partnerServers: [{
          id: 'united-bangla',
          name: 'United Bangla SMP',
          address: 'play.unitedbangla.top:25565',
          description: 'Official community server',
          version: '1.8–1.21',
          badge: 'OFFICIAL',
          enabled: true
        }]
      })
    });
    assert.equal(savedResponse.status, 200);
    const saved = await savedResponse.json();
    assert.equal(saved.forceUpdate, true);
    assert.equal(saved.currentVersion, '1.1.0');
    assert.equal(saved.latestVersion, '1.2.0');
    assert.equal(saved.minimumVersion, '1.2.0');
    assert.equal(saved.releaseNotesUrl, 'https://launcher.unitedbangla.top/releases/1.2.0');
    assert.equal(saved.partnerServers[0].address, 'play.unitedbangla.top:25565');

    const heartbeatResponse = await fetch(`${origin}/analytics/heartbeat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        installId: 'd3932ca5-2aef-4ec0-a6f7-1a753645b023',
        event: 'launcher_open',
        launcherVersion: '1.2.0',
        os: 'Windows 11',
        architecture: 'X64',
        locale: 'en-US',
        accountType: 'Anonymous'
      })
    });
    assert.equal(heartbeatResponse.status, 204);

    const analyticsResponse = await fetch(`${origin}/admin/analytics`, {
      headers: { Authorization: authorization }
    });
    assert.equal(analyticsResponse.status, 200);
    const analytics = await analyticsResponse.json();
    assert.equal(analytics.summary.totalUsers, 1);
    assert.equal(analytics.summary.onlineNow, 1);
    assert.equal(analytics.summary.totalSessions, 1);
    assert.equal(analytics.users[0].email, '');

    const unsafeResponse = await fetch(`${origin}/admin/config`, {
      method: 'PUT',
      headers: { Authorization: authorization, 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentVersion: '1.2.0', latestVersion: '1.3.0', forceUpdate: true })
    });
    const sanitized = await unsafeResponse.json();
    assert.equal(sanitized.forceUpdate, false);
  } finally {
    child.kill();
    await once(child, 'exit').catch(() => {});
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

async function waitUntilReady(child) {
  let errors = '';
  child.stderr.on('data', chunk => { errors += chunk.toString(); });
  const deadline = Date.now() + 5000;

  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(errors || 'Admin server exited before startup.');
    try {
      const response = await fetch('http://127.0.0.1:18602/health');
      if (response.ok) return;
    } catch {
      // Server is still starting.
    }
    await new Promise(resolve => setTimeout(resolve, 80));
  }

  throw new Error(`Admin server did not start. ${errors}`);
}
