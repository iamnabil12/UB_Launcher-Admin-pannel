import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import net from 'node:net';
import { resolveMinecraftSrv } from '../minecraft-dns.mjs';

const projectDirectory = fileURLToPath(new URL('..', import.meta.url));

test('serves public config and protects admin writes', async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), 'ub-launcher-admin-'));
  const port = 18602;
  const password = 'test-6';
  const origin = `http://127.0.0.1:${port}`;
  const minecraftServer = createMinecraftStatusServer();
  await new Promise((resolve, reject) => {
    minecraftServer.once('error', reject);
    minecraftServer.listen(0, '127.0.0.1', resolve);
  });
  const minecraftPort = minecraftServer.address().port;
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: projectDirectory,
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: String(port),
      UB_ADMIN_PASSWORD: password,
      UB_PRIMARY_ADMIN_USERNAME: 'admin',
      UB_PUBLIC_BASE_URL: origin,
      UB_ADMIN_DATA_DIR: dataDirectory
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stderr.on('data', chunk => { process.stderr.write(chunk); });

  try {
    await waitUntilReady(child);

    const publicResponse = await fetch(`${origin}/config.json`);
    assert.equal(publicResponse.status, 200);
    assert.equal((await publicResponse.json()).schemaVersion, 1);

    const authorization = `Basic ${Buffer.from(`admin:${password}`).toString('base64')}`;

    const adminShellResponse = await fetch(`${origin}/admin`);
    assert.equal(adminShellResponse.status, 200);
    assert.match(adminShellResponse.headers.get('content-type'), /^text\/html/);
    assert.equal(adminShellResponse.headers.get('www-authenticate'), null);

    const unauthenticatedConfigResponse = await fetch(`${origin}/admin/config`);
    assert.equal(unauthenticatedConfigResponse.status, 401);
    assert.equal(unauthenticatedConfigResponse.headers.get('www-authenticate'), null);

    // /admin/session is deliberately cookie-only so a browser's cached Basic
    // credentials cannot skip the visible login page.
    assert.equal((await fetch(`${origin}/admin/session`, {
      headers: { Authorization: authorization }
    })).status, 401);

    const unknownLoginResponse = await fetch(`${origin}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'not-an-admin', password: 'incorrect' })
    });
    assert.equal(unknownLoginResponse.status, 401);
    assert.deepEqual(await unknownLoginResponse.json(), { error: 'Invalid username or password.' });

    const wrongPasswordResponse = await fetch(`${origin}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'incorrect' })
    });
    assert.equal(wrongPasswordResponse.status, 401);
    assert.deepEqual(await wrongPasswordResponse.json(), { error: 'Invalid username or password.' });

    const loginResponse = await fetch(`${origin}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password })
    });
    assert.equal(loginResponse.status, 200);
    assert.equal((await loginResponse.json()).administrator.username, 'admin');
    const setCookie = loginResponse.headers.get('set-cookie');
    assert.match(setCookie, /^ub_admin_session=[a-zA-Z0-9_-]{43};/);
    assert.match(setCookie, /Path=\/admin/);
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    assert.doesNotMatch(setCookie, /; Secure/);
    const sessionCookie = setCookie.split(';', 1)[0];

    const sessionResponse = await fetch(`${origin}/admin/session`, {
      headers: { Cookie: sessionCookie }
    });
    assert.equal(sessionResponse.status, 200);
    const currentSession = await sessionResponse.json();
    assert.equal(currentSession.authenticated, true);
    assert.equal(currentSession.administrator.username, 'admin');

    assert.equal((await fetch(`${origin}/admin/config`, {
      headers: { Cookie: sessionCookie }
    })).status, 200);

    const oversizedLoginResponse = await fetch(`${origin}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'x'.repeat(5000) })
    });
    assert.equal(oversizedLoginResponse.status, 413);

    const logoutResponse = await fetch(`${origin}/admin/logout`, {
      method: 'POST',
      headers: { Cookie: sessionCookie }
    });
    assert.equal(logoutResponse.status, 204);
    assert.match(logoutResponse.headers.get('set-cookie'), /^ub_admin_session=;/);
    assert.match(logoutResponse.headers.get('set-cookie'), /Max-Age=0/);
    assert.equal((await fetch(`${origin}/admin/session`, {
      headers: { Cookie: sessionCookie }
    })).status, 401);
    assert.equal((await fetch(`${origin}/admin/config`, {
      headers: { Cookie: sessionCookie }
    })).status, 401);

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
          autoProfile: false,
          enabled: true
        }, {
          id: 'local-profile-test',
          name: '',
          address: `127.0.0.1:${minecraftPort}`,
          description: '',
          version: 'Any version',
          badge: 'PARTNER',
          autoProfile: true,
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
    assert.equal(saved.partnerServers[1].name, 'Mock Partner Server');
    assert.equal(saved.partnerServers[1].version, '1.21.11');
    assert.match(saved.partnerServers[1].iconUrl, /^http:\/\/127\.0\.0\.1:18602\/assets\/partner-/);
    assert.equal(saved.partnerServers[1].iconForAddress, `127.0.0.1:${minecraftPort}`);
    const faviconResponse = await fetch(saved.partnerServers[1].iconUrl);
    assert.equal(faviconResponse.status, 200);
    assert.equal(faviconResponse.headers.get('content-type'), 'image/png');

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

    const administratorsResponse = await fetch(`${origin}/admin/administrators`, {
      headers: { Authorization: authorization }
    });
    assert.equal(administratorsResponse.status, 200);
    const initialAdministrators = (await administratorsResponse.json()).administrators;
    assert.equal(initialAdministrators.length, 1);
    assert.equal(initialAdministrators[0].isPrimary, true);

    const shortPasswordResponse = await fetch(`${origin}/admin/administrators`, {
      method: 'POST',
      headers: { Authorization: authorization, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'too-short', password: '12345' })
    });
    assert.equal(shortPasswordResponse.status, 400);
    assert.match((await shortPasswordResponse.json()).error, /at least 6 characters/);

    const createAdministratorResponse = await fetch(`${origin}/admin/administrators`, {
      method: 'POST',
      headers: { Authorization: authorization, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'moderator.one', password: 'sixsix' })
    });
    assert.equal(createAdministratorResponse.status, 201);
    const createdAdministrators = await createAdministratorResponse.json();
    assert.equal(createdAdministrators.administrators.length, 2);
    const addedAdministrator = createdAdministrators.created;

    const secondAuthorization = `Basic ${Buffer.from('moderator.one:sixsix').toString('base64')}`;
    assert.equal((await fetch(`${origin}/admin/config`, {
      headers: { Authorization: secondAuthorization }
    })).status, 200);

    const removePrimaryAdministratorResponse = await fetch(
      `${origin}/admin/administrators/${initialAdministrators[0].id}`,
      { method: 'DELETE', headers: { Authorization: secondAuthorization } }
    );
    assert.equal(removePrimaryAdministratorResponse.status, 403);
    assert.deepEqual(await removePrimaryAdministratorResponse.json(), {
      error: 'The main administrator account cannot be removed.'
    });

    const removeAdministratorResponse = await fetch(`${origin}/admin/administrators/${addedAdministrator.id}`, {
      method: 'DELETE',
      headers: { Authorization: authorization }
    });
    assert.equal(removeAdministratorResponse.status, 200);
    assert.equal((await removeAdministratorResponse.json()).administrators.length, 1);

    const wrongCurrentPasswordResponse = await fetch(`${origin}/admin/change-password`, {
      method: 'POST',
      headers: { Authorization: authorization, 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword: 'wrong-password', newPassword: 'new-valid-password' })
    });
    assert.equal(wrongCurrentPasswordResponse.status, 400);
    assert.match((await wrongCurrentPasswordResponse.json()).error, /Current password is incorrect/);

    const changePasswordResponse = await fetch(`${origin}/admin/change-password`, {
      method: 'POST',
      headers: { Authorization: authorization, 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword: password, newPassword: 'new-updated-password' })
    });
    assert.equal(changePasswordResponse.status, 200);
    assert.equal((await changePasswordResponse.json()).message, 'Password changed successfully.');

    const oldLoginResponse = await fetch(`${origin}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password })
    });
    assert.equal(oldLoginResponse.status, 401);

    const newLoginResponse = await fetch(`${origin}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'new-updated-password' })
    });
    assert.equal(newLoginResponse.status, 200);

    const updatedAuthorization = `Basic ${Buffer.from('admin:new-updated-password').toString('base64')}`;

    const unsafeResponse = await fetch(`${origin}/admin/config`, {
      method: 'PUT',
      headers: { Authorization: updatedAuthorization, 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentVersion: '1.2.0', latestVersion: '1.3.0', forceUpdate: true })
    });
    const sanitized = await unsafeResponse.json();
    assert.equal(sanitized.forceUpdate, false);

    // Eight failed attempts are allowed in the window; subsequent attempts
    // receive a Retry-After response. The successful login above cleared the
    // earlier failures, so this also checks successful-login reset behavior.
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const failedResponse = await fetch(`${origin}/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'still-wrong' })
      });
      assert.equal(failedResponse.status, 401);
      assert.deepEqual(await failedResponse.json(), { error: 'Invalid username or password.' });
    }
    const rateLimitedResponse = await fetch(`${origin}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'new-updated-password' })
    });
    assert.equal(rateLimitedResponse.status, 429);

    assert.ok(Number(rateLimitedResponse.headers.get('retry-after')) > 0);
    assert.deepEqual(await rateLimitedResponse.json(), {
      error: 'Too many login attempts. Try again later.'
    });
  } finally {
    child.kill();
    await once(child, 'exit').catch(() => {});
    await new Promise(resolve => minecraftServer.close(resolve));
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test('rejects an initial administrator password shorter than 6 characters', async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), 'ub-launcher-admin-password-'));
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: projectDirectory,
    env: {
      ...process.env,
      UB_ADMIN_PASSWORD: '12345',
      UB_PUBLIC_BASE_URL: 'http://localhost:8602',
      UB_ADMIN_DATA_DIR: dataDirectory
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let errors = '';
  child.stderr.on('data', chunk => { errors += chunk.toString(); });
  const [exitCode] = await once(child, 'exit');
  assert.notEqual(exitCode, 0);
  assert.match(errors, /at least 6 characters/);
  await rm(dataDirectory, { recursive: true, force: true });
});

test('falls back to DNS over HTTPS for Minecraft SRV records', async () => {
  const requestedUrls = [];
  const records = await resolveMinecraftSrv('play.example.com', {
    resolveSrv: async () => { throw new Error('Native resolver refused SRV query.'); },
    fetchImpl: async url => {
      requestedUrls.push(String(url));
      if (requestedUrls.length === 1) return { ok: false };
      return {
        ok: true,
        json: async () => ({
          Status: 0,
          Answer: [{
            name: '_minecraft._tcp.play.example.com.',
            type: 33,
            TTL: 300,
            data: '0 5 19132 edge.example.com.'
          }]
        })
      };
    },
    timeoutMs: 100
  });

  assert.equal(requestedUrls.length, 2);
  assert.match(requestedUrls[0], /^https:\/\/cloudflare-dns\.com\/dns-query\?/);
  assert.match(requestedUrls[1], /^https:\/\/dns\.google\/resolve\?/);
  assert.deepEqual(records, [{ name: 'edge.example.com', port: 19132, priority: 0, weight: 5 }]);
});

test('does not query DNS over HTTPS for an invalid hostname', async () => {
  let fetchCalled = false;
  await assert.rejects(
    resolveMinecraftSrv('example.com/../../admin', {
      resolveSrv: async () => [],
      fetchImpl: async () => { fetchCalled = true; return { ok: false }; }
    }),
    /valid hostname/
  );
  assert.equal(fetchCalled, false);
});

function createMinecraftStatusServer() {
  const favicon = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M\/wHwAF\/gL+3dL8AAAAAElFTkSuQmCC';
  return net.createServer(socket => {
    socket.once('data', () => {
      const status = JSON.stringify({
        version: { name: '1.21.11', protocol: 774 },
        players: { max: 100, online: 1 },
        description: { text: 'Mock Partner Server' },
        favicon: `data:image/png;base64,${favicon}`
      });
      const body = Buffer.concat([encodeVarInt(0), encodeMinecraftString(status)]);
      socket.end(Buffer.concat([encodeVarInt(body.length), body]));
    });
  });
}

function encodeMinecraftString(value) {
  const bytes = Buffer.from(value, 'utf8');
  return Buffer.concat([encodeVarInt(bytes.length), bytes]);
}

function encodeVarInt(value) {
  let remaining = value >>> 0;
  const bytes = [];
  do {
    let next = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining) next |= 0x80;
    bytes.push(next);
  } while (remaining);
  return Buffer.from(bytes);
}

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
