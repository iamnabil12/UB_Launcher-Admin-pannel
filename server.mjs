import { createServer } from 'node:http';
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveMinecraftSrv } from './minecraft-dns.mjs';

const projectDirectory = dirname(fileURLToPath(import.meta.url));
const port = parsePort(process.env.PORT, 8602);
const host = process.env.HOST || '127.0.0.1';
const password = process.env.UB_ADMIN_PASSWORD || '';
const primaryAdministratorUsername = normalizeAdministratorUsername(
  process.env.UB_PRIMARY_ADMIN_USERNAME || 'iamnabilgamer'
);
const publicBaseUrl = normalizeBaseUrl(
  process.env.UB_PUBLIC_BASE_URL || 'https://launcher.unitedbangla.top'
);
const dataDirectory = resolveDataDirectory(process.env.UB_ADMIN_DATA_DIR);
const assetDirectory = join(dataDirectory, 'assets');
const configPath = join(dataDirectory, 'config.json');
const analyticsPath = join(dataDirectory, 'users.json');
const administratorsPath = join(dataDirectory, 'administrators.json');
const adminHtmlPath = join(projectDirectory, 'public', 'admin.html');
const maximumRequestBytes = 8 * 1024 * 1024;
const maximumLoginRequestBytes = 4 * 1024;
const maximumAnalyticsRequestBytes = 32 * 1024;
const maximumAdministratorRequestBytes = 16 * 1024;
const maximumConfigRequestBytes = 512 * 1024;
const maximumAssetBytes = 6 * 1024 * 1024;
const sessionLifetimeMs = 12 * 60 * 60 * 1000;
const sessionCookieName = 'ub_admin_session';
const maximumFailedLogins = 8;
const failedLoginWindowMs = 15 * 60 * 1000;
const secureSessionCookies = new URL(publicBaseUrl).protocol === 'https:';
const analyticsRateLimits = new Map();
const failedLoginAttempts = new Map();
const administratorSessions = [];
let analyticsWriteQueue = Promise.resolve();
let administratorStore = { administrators: [] };

if (password.length < 6) {
  throw new Error('UB_ADMIN_PASSWORD must contain at least 6 characters.');
}
if (!isValidAdministratorUsername(primaryAdministratorUsername)) {
  throw new Error('UB_PRIMARY_ADMIN_USERNAME must be a valid administrator username.');
}

const defaultConfig = {
  schemaVersion: 1,
  currentVersion: '1.0.0',
  latestVersion: '1.0.0',
  // Kept in the public JSON only so already-released launcher builds continue to work.
  minimumVersion: '1.0.0',
  forceUpdate: false,
  updateTitle: 'Update Available',
  updateMessage: 'A new version of UB Launcher is available. Update now to get the latest features, improvements, and bug fixes.',
  updateUrl: '',
  releaseNotesUrl: '',
  assets: {},
  partnerServers: []
};

await mkdir(assetDirectory, { recursive: true });
if (!existsSync(configPath)) await saveConfig(defaultConfig);
await initializeAdministrators();
const adminHtml = await readFile(adminHtmlPath, 'utf8');

const server = createServer(async (request, response) => {
  applySecurityHeaders(response);

  try {
    const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);

    if (request.method === 'GET' && url.pathname === '/health') {
      return sendJson(response, 200, { status: 'ok' }, { 'Cache-Control': 'no-store' });
    }

    if (request.method === 'GET' && url.pathname === '/config.json') {
      return sendJson(response, 200, await loadConfig(), { 'Cache-Control': 'no-cache' });
    }

    if (request.method === 'GET' && url.pathname.startsWith('/assets/')) {
      return serveAsset(response, url.pathname.slice('/assets/'.length));
    }

    if (request.method === 'POST' && url.pathname === '/analytics/heartbeat') {
      enforceAnalyticsRateLimit(request);
      await recordAnalyticsEvent(await readJson(request, maximumAnalyticsRequestBytes));
      response.writeHead(204, { 'Cache-Control': 'no-store' });
      return response.end();
    }

    if (request.method === 'GET' && url.pathname === '/') {
      response.writeHead(302, { Location: '/admin' });
      return response.end();
    }

    // Always serve the application shell. The page uses /admin/session to
    // decide whether to show the login screen or the control panel.
    if (request.method === 'GET' && (url.pathname === '/admin' || url.pathname === '/admin/')) {
      response.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
      });
      return response.end(adminHtml);
    }

    if (request.method === 'POST' && url.pathname === '/admin/login') {
      return await loginAdministrator(request, response);
    }

    if (request.method === 'GET' && url.pathname === '/admin/session') {
      const sessionAdministrator = authenticateSession(request);
      if (!sessionAdministrator) return sendAuthenticationRequired(response);
      return sendJson(response, 200, {
        authenticated: true,
        administrator: toPublicAdministrator(sessionAdministrator)
      }, { 'Cache-Control': 'no-store' });
    }

    if (request.method === 'POST' && url.pathname === '/admin/logout') {
      revokeSession(request);
      response.writeHead(204, {
        'Cache-Control': 'no-store',
        'Set-Cookie': serializeSessionCookie('', 0)
      });
      return response.end();
    }

    const administrator = authenticateAdministrator(request);
    if (!administrator) {
      return sendAuthenticationRequired(response);
    }

    if (request.method === 'GET' && url.pathname === '/admin/config') {
      return sendJson(response, 200, await loadConfig(), { 'Cache-Control': 'no-store' });
    }

    if (request.method === 'GET' && url.pathname === '/admin/analytics') {
      return sendJson(response, 200, await getAnalyticsDashboard(), { 'Cache-Control': 'no-store' });
    }

    if (request.method === 'GET' && url.pathname === '/admin/administrators') {
      return sendJson(response, 200, {
        administrators: administratorStore.administrators.map(toPublicAdministrator)
      }, { 'Cache-Control': 'no-store' });
    }

    if (request.method === 'POST' && url.pathname === '/admin/administrators') {
      const created = await addAdministrator(await readJson(request, maximumAdministratorRequestBytes));
      return sendJson(response, 201, {
        created: toPublicAdministrator(created),
        administrators: administratorStore.administrators.map(toPublicAdministrator)
      }, { 'Cache-Control': 'no-store' });
    }

    const deleteAdministratorMatch = /^\/admin\/administrators\/([a-zA-Z0-9_-]{8,80})$/.exec(url.pathname);
    if (request.method === 'DELETE' && deleteAdministratorMatch) {
      await removeAdministrator(deleteAdministratorMatch[1], administrator.id);
      return sendJson(response, 200, {
        administrators: administratorStore.administrators.map(toPublicAdministrator)
      }, { 'Cache-Control': 'no-store' });
    }

    if (request.method === 'POST' && url.pathname === '/admin/change-password') {
      const payload = await readJson(request, maximumAdministratorRequestBytes);
      const currentPassword = String(payload?.currentPassword || '');
      const newPassword = String(payload?.newPassword || '');

      if (!verifyPassword(currentPassword, administrator.passwordHash)) {
        const error = new Error('Current password is incorrect.');
        error.statusCode = 400;
        throw error;
      }

      if (newPassword.length < 6) {
        const error = new Error('New password must contain at least 6 characters.');
        error.statusCode = 400;
        throw error;
      }

      administrator.passwordHash = hashPassword(newPassword);
      await saveAdministrators();
      return sendJson(response, 200, { message: 'Password changed successfully.' }, { 'Cache-Control': 'no-store' });
    }


    if (request.method === 'PUT' && url.pathname === '/admin/config') {
      const configuration = sanitizeConfig(await readJson(request, maximumConfigRequestBytes));
      await enrichPartnerProfiles(configuration.partnerServers);
      await saveConfig(configuration);
      return sendJson(response, 200, configuration, { 'Cache-Control': 'no-store' });
    }

    if (request.method === 'POST' && url.pathname === '/admin/upload') {
      const uploaded = await readJson(request);
      const savedUrl = await saveUploadedAsset(uploaded);
      return sendJson(response, 200, { url: savedUrl }, { 'Cache-Control': 'no-store' });
    }

    return sendJson(response, 404, { error: 'Not found.' });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Request failed.';
    const status = Number.isInteger(error?.statusCode) ? error.statusCode : 400;
    return sendJson(response, status, { error: message }, { 'Cache-Control': 'no-store' });
  }
});

server.listen(port, host, () => {
  console.log(`UB Launcher Admin listening on http://${host}:${port}`);
});

function authenticateAdministrator(request) {
  const sessionAdministrator = authenticateSession(request);
  if (sessionAdministrator) return sessionAdministrator;

  const header = String(request.headers.authorization || '');
  if (!header.startsWith('Basic ') || header.length > 4096) return null;

  let supplied;
  try {
    supplied = Buffer.from(header.slice(6), 'base64').toString('utf8');
  } catch {
    return null;
  }

  const separator = supplied.indexOf(':');
  if (separator < 1) return null;
  const username = supplied.slice(0, separator).trim();
  const suppliedPassword = supplied.slice(separator + 1);
  return authenticateCredentials(username, suppliedPassword);
}

async function loginAdministrator(request, response) {
  const clientAddress = getClientAddress(request);
  const blockedForMs = getLoginBlockRemaining(clientAddress);
  if (blockedForMs > 0) {
    return sendJson(response, 429, { error: 'Too many login attempts. Try again later.' }, {
      'Cache-Control': 'no-store',
      'Retry-After': String(Math.max(1, Math.ceil(blockedForMs / 1000)))
    });
  }

  const credentials = await readJson(request, maximumLoginRequestBytes);
  const username = String(credentials?.username || '').trim();
  const suppliedPassword = String(credentials?.password || '');
  const administrator = authenticateCredentials(username, suppliedPassword);

  if (!administrator) {
    recordFailedLogin(clientAddress);
    return sendJson(response, 401, { error: 'Invalid username or password.' }, {
      'Cache-Control': 'no-store'
    });
  }

  failedLoginAttempts.delete(clientAddress);
  const token = createAdministratorSession(administrator.id);
  return sendJson(response, 200, {
    authenticated: true,
    administrator: toPublicAdministrator(administrator)
  }, {
    'Cache-Control': 'no-store',
    'Set-Cookie': serializeSessionCookie(token, Math.floor(sessionLifetimeMs / 1000))
  });
}

function authenticateCredentials(username, suppliedPassword) {
  const normalizedUsername = String(username || '').trim().toLowerCase();
  const passwordValue = String(suppliedPassword || '');
  const administrator = administratorStore.administrators.find(
    item => item.username.toLowerCase() === normalizedUsername
  );

  // Verify against a real scrypt hash even for an unknown username so the
  // response does not reveal which account names exist through timing.
  const comparisonAccount = administrator || administratorStore.administrators[0];
  if (!comparisonAccount) return null;
  const passwordWithinLimit = passwordValue.length <= 1024;
  const passwordMatches = verifyPassword(passwordValue.slice(0, 1024), comparisonAccount.passwordHash);
  return administrator && passwordWithinLimit && passwordMatches ? administrator : null;
}

function createAdministratorSession(administratorId) {
  pruneExpiredSessions();
  const token = randomBytes(32).toString('base64url');
  administratorSessions.push({
    administratorId,
    tokenHash: hashSessionToken(token),
    expiresAt: Date.now() + sessionLifetimeMs
  });
  return token;
}

function authenticateSession(request) {
  const token = readSessionToken(request);
  if (!token) return null;
  pruneExpiredSessions();
  const suppliedHash = hashSessionToken(token);
  const session = administratorSessions.find(item =>
    item.tokenHash.length === suppliedHash.length && timingSafeEqual(item.tokenHash, suppliedHash)
  );
  if (!session) return null;
  return administratorStore.administrators.find(item => item.id === session.administratorId) || null;
}

function revokeSession(request) {
  const token = readSessionToken(request);
  if (!token) return;
  const suppliedHash = hashSessionToken(token);
  const index = administratorSessions.findIndex(item =>
    item.tokenHash.length === suppliedHash.length && timingSafeEqual(item.tokenHash, suppliedHash)
  );
  if (index >= 0) administratorSessions.splice(index, 1);
}

function revokeAdministratorSessions(administratorId) {
  for (let index = administratorSessions.length - 1; index >= 0; index -= 1) {
    if (administratorSessions[index].administratorId === administratorId) {
      administratorSessions.splice(index, 1);
    }
  }
}

function pruneExpiredSessions() {
  const now = Date.now();
  for (let index = administratorSessions.length - 1; index >= 0; index -= 1) {
    if (administratorSessions[index].expiresAt <= now) administratorSessions.splice(index, 1);
  }
}

function hashSessionToken(token) {
  return createHash('sha256').update(token, 'utf8').digest();
}

function readSessionToken(request) {
  const cookies = String(request.headers.cookie || '').split(';');
  for (const cookie of cookies) {
    const separator = cookie.indexOf('=');
    if (separator < 1) continue;
    if (cookie.slice(0, separator).trim() !== sessionCookieName) continue;
    const token = cookie.slice(separator + 1).trim();
    return /^[a-zA-Z0-9_-]{43}$/.test(token) ? token : '';
  }
  return '';
}

function serializeSessionCookie(token, maximumAgeSeconds) {
  const parts = [
    `${sessionCookieName}=${token}`,
    'Path=/admin',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maximumAgeSeconds}`
  ];
  if (secureSessionCookies) parts.push('Secure');
  return parts.join('; ');
}

function getLoginBlockRemaining(clientAddress) {
  const attempt = failedLoginAttempts.get(clientAddress);
  if (!attempt) return 0;
  const elapsed = Date.now() - attempt.startedAt;
  if (elapsed >= failedLoginWindowMs) {
    failedLoginAttempts.delete(clientAddress);
    return 0;
  }
  return attempt.count >= maximumFailedLogins ? failedLoginWindowMs - elapsed : 0;
}

function recordFailedLogin(clientAddress) {
  const now = Date.now();
  const current = failedLoginAttempts.get(clientAddress);
  if (!current || now - current.startedAt >= failedLoginWindowMs) {
    failedLoginAttempts.set(clientAddress, { startedAt: now, count: 1 });
    return;
  }
  current.count += 1;
}

function getClientAddress(request) {
  const directAddress = String(request.socket.remoteAddress || 'unknown');
  if (!isLoopbackAddress(directAddress)) return directAddress;

  const forwarded = String(request.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return net.isIP(forwarded) ? forwarded : directAddress;
}

function isLoopbackAddress(value) {
  return value === '127.0.0.1' || value === '::1' || value === '::ffff:127.0.0.1';
}

function sendAuthenticationRequired(response) {
  return sendJson(response, 401, { error: 'Authentication required.' }, {
    'Cache-Control': 'no-store'
  });
}

async function initializeAdministrators() {
  try {
    const parsed = JSON.parse(await readFile(administratorsPath, 'utf8'));
    const administrators = Array.isArray(parsed?.administrators)
      ? parsed.administrators.filter(isStoredAdministrator)
      : [];
    if (administrators.length > 0) {
      administratorStore = { administrators };
      return;
    }
  } catch {
    // First start: create the administrator configured in .env below.
  }

  administratorStore = {
    administrators: [{
      id: `admin-${randomBytes(10).toString('hex')}`,
      username: primaryAdministratorUsername,
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString()
    }]
  };
  await saveAdministrators();
}

function isStoredAdministrator(value) {
  return value && typeof value === 'object' &&
    /^[a-zA-Z0-9_-]{8,80}$/.test(String(value.id || '')) &&
    isValidAdministratorUsername(value.username) &&
    /^scrypt\$[^$]+\$[^$]+$/.test(String(value.passwordHash || '')) &&
    !Number.isNaN(Date.parse(value.createdAt));
}

async function addAdministrator(value) {
  const username = normalizeAdministratorUsername(value?.username);
  const newPassword = String(value?.password || '');
  if (!isValidAdministratorUsername(username)) {
    throw new Error('Username must be 3-32 characters: letters, numbers, dot, dash, or underscore.');
  }
  if (newPassword.length < 6) {
    throw new Error('Administrator password must contain at least 6 characters.');
  }
  if (administratorStore.administrators.some(item => item.username.toLowerCase() === username.toLowerCase())) {
    throw new Error('That administrator username already exists.');
  }

  const administrator = {
    id: `admin-${randomBytes(10).toString('hex')}`,
    username,
    passwordHash: hashPassword(newPassword),
    createdAt: new Date().toISOString()
  };
  administratorStore.administrators.push(administrator);
  await saveAdministrators();
  return administrator;
}

async function removeAdministrator(id, currentAdministratorId) {
  const target = administratorStore.administrators.find(item => item.id === id);
  if (!target) throw new Error('Administrator was not found.');
  if (isPrimaryAdministrator(target)) {
    const error = new Error('The main administrator account cannot be removed.');
    error.statusCode = 403;
    throw error;
  }
  if (administratorStore.administrators.length <= 1) {
    throw new Error('At least one administrator account must remain.');
  }
  if (target.id === currentAdministratorId) {
    throw new Error('You cannot remove the administrator account currently signed in.');
  }
  administratorStore.administrators = administratorStore.administrators.filter(item => item.id !== id);
  revokeAdministratorSessions(target.id);
  await saveAdministrators();
}

async function saveAdministrators() {
  const temporaryPath = `${administratorsPath}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(administratorStore, null, 2)}\n`, 'utf8');
  await rename(temporaryPath, administratorsPath);
}

function toPublicAdministrator(value) {
  return {
    id: value.id,
    username: value.username,
    createdAt: value.createdAt,
    isPrimary: isPrimaryAdministrator(value)
  };
}

function isPrimaryAdministrator(value) {
  return String(value?.username || '').toLowerCase() === primaryAdministratorUsername.toLowerCase();
}

function normalizeAdministratorUsername(value) {
  return String(value || '').trim();
}

function isValidAdministratorUsername(value) {
  return /^[a-zA-Z0-9._-]{3,32}$/.test(String(value || ''));
}

function hashPassword(value) {
  const salt = randomBytes(16);
  const derived = scryptSync(value, salt, 64);
  return `scrypt$${salt.toString('base64')}$${derived.toString('base64')}`;
}

function verifyPassword(value, encoded) {
  const parts = String(encoded || '').split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  try {
    const expected = Buffer.from(parts[2], 'base64');
    const actual = scryptSync(value, Buffer.from(parts[1], 'base64'), expected.length);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

async function readJson(request, maximumBytes = maximumRequestBytes) {
  const contentLength = Number(request.headers['content-length'] || 0);
  if (Number.isFinite(contentLength) && contentLength > maximumBytes) {
    request.resume();
    const error = new Error('Request is too large.');
    error.statusCode = 413;
    throw error;
  }

  const chunks = [];
  let total = 0;

  for await (const chunk of request) {
    total += chunk.length;
    if (total > maximumBytes) {
      const error = new Error('Request is too large.');
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new Error('Invalid JSON request.');
  }
}

async function loadConfig() {
  try {
    return sanitizeConfig(JSON.parse(await readFile(configPath, 'utf8')));
  } catch {
    return structuredClone(defaultConfig);
  }
}

async function saveConfig(value) {
  const temporaryPath = `${configPath}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await rename(temporaryPath, configPath);
}

function sanitizeConfig(value) {
  const input = value && typeof value === 'object' ? value : {};
  const sourceAssets = input.assets && typeof input.assets === 'object' ? input.assets : {};
  const updateUrl = isHttpsUrl(input.updateUrl) ? String(input.updateUrl).trim() : '';
  const releaseNotesUrl = isHttpsUrl(input.releaseNotesUrl) ? String(input.releaseNotesUrl).trim() : '';
  const partnerServers = Array.isArray(input.partnerServers)
    ? input.partnerServers.map(sanitizePartnerServer).filter(Boolean).slice(0, 30)
    : [];
  const assets = Object.fromEntries(
    Object.entries(sourceAssets)
      .filter(([name, url]) => /^[a-zA-Z][a-zA-Z0-9]{0,63}$/.test(name) && isHttpsOrLoopbackUrl(url))
      .slice(0, 40)
      .map(([name, url]) => [name, String(url).trim()])
  );
  const currentVersion = text(
    input.currentVersion || input.minimumVersion,
    32,
    defaultConfig.currentVersion
  );
  const latestVersion = text(input.latestVersion, 32, defaultConfig.latestVersion);
  const forceUpdate = Boolean(input.forceUpdate) && Boolean(updateUrl);

  return {
    schemaVersion: 1,
    currentVersion,
    latestVersion,
    // Older launchers use this field. New launchers use latestVersion directly.
    minimumVersion: forceUpdate ? latestVersion : currentVersion,
    forceUpdate,
    updateTitle: text(input.updateTitle, 120, defaultConfig.updateTitle),
    updateMessage: text(input.updateMessage, 500, defaultConfig.updateMessage),
    updateUrl,
    releaseNotesUrl,
    assets,
    partnerServers
  };
}

function sanitizePartnerServer(value) {
  if (!value || typeof value !== 'object') return null;
  const address = String(value.address || '').trim().slice(0, 255);
  if (!/^[a-zA-Z0-9.-]+(?::[0-9]{1,5})?$/.test(address)) return null;

  return {
    id: /^[a-zA-Z0-9_-]{3,50}$/.test(String(value.id || ''))
      ? String(value.id)
      : `server-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    // A display name is optional. When it is blank, the server address is shown
    // until a Minecraft status ping provides its MOTD.
    name: text(value.name, 80, address),
    address,
    description: text(value.description, 180, ''),
    version: text(value.version, 32, 'Any version'),
    badge: text(value.badge, 24, 'PARTNER'),
    // The launcher never needs an administrator to paste an icon URL. The icon
    // is obtained from the Minecraft server's standard status response.
    iconUrl: isHttpsOrLoopbackUrl(value.iconUrl) ? String(value.iconUrl).trim() : '',
    iconForAddress: String(value.iconForAddress || '').trim().slice(0, 255),
    autoProfile: value.autoProfile !== false,
    websiteUrl: isHttpsUrl(value.websiteUrl) ? String(value.websiteUrl).trim() : '',
    enabled: value.enabled !== false
  };
}

async function enrichPartnerProfiles(servers) {
  // A status request is only needed for a newly added server or when its address
  // changed. Existing working icons are kept if a server happens to be offline.
  const work = servers.filter(server =>
    server.autoProfile && (!server.iconUrl || server.iconForAddress !== server.address)
  );
  await runWithConcurrency(work, 4, async server => {
    try {
      const profile = await queryMinecraftStatus(server.address);
      const motd = flattenMinecraftText(profile.description);
      const fetchedIcon = await saveMinecraftFavicon(profile.favicon, server.id);

      if (server.name === server.address && motd) {
        server.name = truncate(motd, 80);
      }
      if (!server.description && motd) {
        server.description = truncate(motd, 180);
      }
      if (server.version === 'Any version' && profile.version?.name) {
        server.version = truncate(profile.version.name, 32);
      }
      if (fetchedIcon) {
        server.iconUrl = fetchedIcon;
        server.iconForAddress = server.address;
      }
    } catch (error) {
      // A partner server can be temporarily offline. Keep publishing the rest of
      // the configuration and use the launcher fallback icon for this one.
      console.warn(`Could not refresh Minecraft profile for ${server.address}: ${error instanceof Error ? error.message : 'unknown error'}`);
    }
  });
}

async function runWithConcurrency(items, limit, work) {
  const queue = [...items];
  const workers = Array.from({ length: Math.min(limit, queue.length) }, async () => {
    while (queue.length) {
      const item = queue.shift();
      if (item) await work(item);
    }
  });
  await Promise.all(workers);
}

async function queryMinecraftStatus(address) {
  const endpoints = await resolveMinecraftEndpoints(address);
  const errors = [];

  for (const endpoint of endpoints) {
    try {
      return await queryMinecraftEndpoint(endpoint);
    } catch (error) {
      errors.push(`${endpoint.connectHost}:${endpoint.port} - ${error instanceof Error ? error.message : 'unknown error'}`);
    }
  }

  throw new Error(errors.length ? errors.join('; ') : 'Minecraft server did not respond.');
}

async function resolveMinecraftEndpoints(address) {
  const direct = splitMinecraftAddress(address);
  const handshakeHost = direct.host;
  const directEndpoint = {
    connectHost: direct.host,
    port: direct.port,
    handshakeHost,
    handshakePort: direct.port
  };

  // An explicitly supplied port always wins. Minecraft's SRV lookup is only
  // used when players enter a hostname without one.
  if (direct.hasExplicitPort || net.isIP(direct.host)) return [directEndpoint];

  try {
    const records = (await resolveMinecraftSrv(direct.host))
      .sort((left, right) => left.priority - right.priority || right.weight - left.weight);
    const srvEndpoints = records.map(record => ({
      connectHost: String(record.name).replace(/\.$/, ''),
      port: record.port,
      handshakeHost,
      handshakePort: record.port
    }));
    // Keep the normal port as a final fallback in case DNS contains a stale SRV
    // record while the server is still reachable directly.
    return [...srvEndpoints, directEndpoint];
  } catch {
    return [directEndpoint];
  }
}

function queryMinecraftEndpoint({ connectHost, port, handshakeHost, handshakePort }) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: connectHost, port });
    let buffer = Buffer.alloc(0);
    let finished = false;

    const finish = (error, value) => {
      if (finished) return;
      finished = true;
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };

    socket.setTimeout(5000, () => finish(new Error('Minecraft server did not respond in time.')));
    socket.once('error', error => finish(error));
    socket.once('connect', () => {
      const handshake = Buffer.concat([
        encodeVarInt(0),
        encodeVarInt(-1),
        encodeMinecraftString(handshakeHost),
        encodeUnsignedShort(handshakePort),
        encodeVarInt(1)
      ]);
      writeMinecraftPacket(socket, handshake);
      writeMinecraftPacket(socket, encodeVarInt(0));
    });
    socket.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        const packetLength = decodeVarInt(buffer, 0);
        if (!packetLength || buffer.length < packetLength.size + packetLength.value) return;
        const packet = buffer.subarray(packetLength.size, packetLength.size + packetLength.value);
        const packetId = decodeVarInt(packet, 0);
        if (!packetId || packetId.value !== 0) return finish(new Error('Unexpected Minecraft status response.'));
        const jsonLength = decodeVarInt(packet, packetId.size);
        if (!jsonLength || packet.length < packetId.size + jsonLength.size + jsonLength.value) {
          return finish(new Error('Malformed Minecraft status response.'));
        }
        const start = packetId.size + jsonLength.size;
        const json = packet.subarray(start, start + jsonLength.value).toString('utf8');
        finish(null, JSON.parse(json));
      } catch (error) {
        finish(error instanceof Error ? error : new Error('Could not read Minecraft server profile.'));
      }
    });
  });
}

function splitMinecraftAddress(address) {
  const separator = address.lastIndexOf(':');
  if (separator > 0 && address.indexOf(':') === separator) {
    return {
      host: address.slice(0, separator),
      port: Number(address.slice(separator + 1)),
      hasExplicitPort: true
    };
  }
  return { host: address, port: 25565, hasExplicitPort: false };
}

function writeMinecraftPacket(socket, body) {
  socket.write(Buffer.concat([encodeVarInt(body.length), body]));
}

function encodeMinecraftString(value) {
  const bytes = Buffer.from(value, 'utf8');
  return Buffer.concat([encodeVarInt(bytes.length), bytes]);
}

function encodeUnsignedShort(value) {
  const bytes = Buffer.allocUnsafe(2);
  bytes.writeUInt16BE(value, 0);
  return bytes;
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

function decodeVarInt(buffer, offset) {
  let value = 0;
  let position = offset;
  for (let index = 0; index < 5; index += 1) {
    if (position >= buffer.length) return null;
    const byte = buffer[position++];
    value |= (byte & 0x7f) << (7 * index);
    if (!(byte & 0x80)) return { value, size: position - offset };
  }
  throw new Error('Invalid Minecraft VarInt.');
}

function flattenMinecraftText(value) {
  if (typeof value === 'string') return cleanMinecraftText(value);
  if (!value || typeof value !== 'object') return '';
  const pieces = [];
  if (typeof value.text === 'string') pieces.push(value.text);
  if (Array.isArray(value.extra)) pieces.push(...value.extra.map(flattenMinecraftText));
  return cleanMinecraftText(pieces.join(''));
}

function cleanMinecraftText(value) {
  return String(value || '').replace(/\u00a7[0-9A-FK-OR]/gi, '').replace(/\s+/g, ' ').trim();
}

async function saveMinecraftFavicon(value, serverId) {
  const matched = /^data:image\/png;base64,([a-zA-Z0-9+/]+={0,2})$/.exec(String(value || ''));
  if (!matched) return '';
  const image = Buffer.from(matched[1], 'base64');
  const pngSignature = '89504e470d0a1a0a';
  if (image.length < 16 || image.length > 1024 * 1024 || image.subarray(0, 8).toString('hex') !== pngSignature) {
    return '';
  }
  const safeId = String(serverId || 'server').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 50) || 'server';
  const filename = `partner-${safeId}-${createHash('sha256').update(image).digest('hex').slice(0, 16)}.png`;
  const destination = join(assetDirectory, filename);
  if (!existsSync(destination)) await writeFile(destination, image);
  return `${publicBaseUrl}/assets/${encodeURIComponent(filename)}`;
}

async function recordAnalyticsEvent(value) {
  const event = sanitizeAnalyticsEvent(value);
  analyticsWriteQueue = analyticsWriteQueue.then(async () => {
    const store = await loadAnalyticsStore();
    const now = new Date().toISOString();
    const existing = store.users[event.installId];
    const user = existing || {
      installId: event.installId,
      firstSeen: now,
      sessions: 0,
      gameLaunches: 0
    };

    user.lastSeen = now;
    user.launcherVersion = event.launcherVersion;
    user.os = event.os;
    user.architecture = event.architecture;
    user.locale = event.locale;
    user.accountType = event.accountType;
    user.displayName = event.displayName;
    user.email = event.email;
    user.lastEvent = event.event;
    if (event.event === 'launcher_open') user.sessions = Number(user.sessions || 0) + 1;
    if (event.event === 'game_launch') user.gameLaunches = Number(user.gameLaunches || 0) + 1;
    store.users[event.installId] = user;

    const ordered = Object.values(store.users)
      .sort((left, right) => String(right.lastSeen).localeCompare(String(left.lastSeen)))
      .slice(0, 50000);
    store.users = Object.fromEntries(ordered.map(item => [item.installId, item]));
    await saveAnalyticsStore(store);
  });
  await analyticsWriteQueue;
}

function sanitizeAnalyticsEvent(value) {
  const input = value && typeof value === 'object' ? value : {};
  const installId = String(input.installId || '').trim();
  if (!/^[a-fA-F0-9-]{32,36}$/.test(installId)) throw new Error('Invalid anonymous install ID.');
  const allowedEvents = new Set(['launcher_open', 'game_launch', 'heartbeat']);
  const event = allowedEvents.has(input.event) ? input.event : 'heartbeat';

  return {
    installId,
    event,
    launcherVersion: text(input.launcherVersion, 32, 'Unknown'),
    os: text(input.os, 100, 'Unknown'),
    architecture: text(input.architecture, 30, 'Unknown'),
    locale: text(input.locale, 30, 'Unknown'),
    accountType: text(input.accountType, 30, 'Anonymous'),
    displayName: text(input.displayName, 80, ''),
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(input.email || ''))
      ? String(input.email).trim().slice(0, 160)
      : ''
  };
}

async function loadAnalyticsStore() {
  try {
    const value = JSON.parse(await readFile(analyticsPath, 'utf8'));
    return value && typeof value.users === 'object' ? value : { users: {} };
  } catch {
    return { users: {} };
  }
}

async function saveAnalyticsStore(value) {
  const temporaryPath = `${analyticsPath}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await rename(temporaryPath, analyticsPath);
}

async function getAnalyticsDashboard() {
  await analyticsWriteQueue;
  const users = Object.values((await loadAnalyticsStore()).users)
    .sort((left, right) => String(right.lastSeen).localeCompare(String(left.lastSeen)));
  const now = Date.now();
  const onlineNow = users.filter(user => now - Date.parse(user.lastSeen) <= 10 * 60 * 1000).length;
  const active24h = users.filter(user => now - Date.parse(user.lastSeen) <= 24 * 60 * 60 * 1000).length;
  const active7d = users.filter(user => now - Date.parse(user.lastSeen) <= 7 * 24 * 60 * 60 * 1000).length;
  const totalSessions = users.reduce((sum, user) => sum + Number(user.sessions || 0), 0);
  const totalGameLaunches = users.reduce((sum, user) => sum + Number(user.gameLaunches || 0), 0);
  const versions = Object.entries(users.reduce((counts, user) => {
    const version = user.launcherVersion || 'Unknown';
    counts[version] = (counts[version] || 0) + 1;
    return counts;
  }, {})).map(([version, count]) => ({ version, count })).sort((a, b) => b.count - a.count);

  return {
    summary: { totalUsers: users.length, onlineNow, active24h, active7d, totalSessions, totalGameLaunches },
    versions,
    users: users.slice(0, 1000)
  };
}

function enforceAnalyticsRateLimit(request) {
  const key = request.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const current = analyticsRateLimits.get(key);
  if (!current || now - current.startedAt > 60_000) {
    analyticsRateLimits.set(key, { startedAt: now, count: 1 });
    return;
  }
  current.count += 1;
  if (current.count > 120) throw new Error('Too many analytics requests.');
}

async function saveUploadedAsset(uploaded) {
  const originalName = safeFilename(uploaded?.name);
  const encoded = String(uploaded?.base64 || '').replace(/^data:[^;]+;base64,/, '');
  const bytes = Buffer.from(encoded, 'base64');
  const extension = extname(originalName).toLowerCase();

  if (!originalName || bytes.length === 0 || bytes.length > maximumAssetBytes) {
    throw new Error('Choose a valid image smaller than 6 MB.');
  }

  if (!['.png', '.jpg', '.jpeg', '.webp', '.svg'].includes(extension)) {
    throw new Error('Only PNG, JPG, WEBP, and SVG files are allowed.');
  }

  if (extension === '.svg' && !bytes.toString('utf8', 0, 1024).toLowerCase().includes('<svg')) {
    throw new Error('The SVG file is invalid.');
  }

  const storedName = `${Date.now()}-${originalName}`;
  await writeFile(join(assetDirectory, storedName), bytes);
  return `${publicBaseUrl}/assets/${encodeURIComponent(storedName)}`;
}

async function serveAsset(response, requestedName) {
  const filename = safeFilename(decodeURIComponent(requestedName));
  const filePath = filename ? join(assetDirectory, filename) : '';

  if (!filePath || !existsSync(filePath) || !(await stat(filePath)).isFile()) {
    return sendJson(response, 404, { error: 'Asset not found.' });
  }

  const contentTypes = {
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml; charset=utf-8'
  };

  response.writeHead(200, {
    'Content-Type': contentTypes[extname(filePath).toLowerCase()] || 'application/octet-stream',
    'Cache-Control': 'public, max-age=31536000, immutable'
  });
  response.end(await readFile(filePath));
}

function applySecurityHeaders(response) {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data: https:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
  );
}

function sendJson(response, status, value, extraHeaders = {}) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    ...extraHeaders
  });
  response.end(JSON.stringify(value));
}

function text(value, maximum, fallback) {
  const result = String(value || '').trim().slice(0, maximum);
  return result || fallback;
}

function truncate(value, maximum) {
  return String(value || '').trim().slice(0, maximum);
}

function isHttpsUrl(value) {
  try {
    return new URL(String(value)).protocol === 'https:';
  } catch {
    return false;
  }
}

function isHttpsOrLoopbackUrl(value) {
  try {
    const parsed = new URL(String(value));
    return parsed.protocol === 'https:' || (
      parsed.protocol === 'http:' &&
      (parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost' || parsed.hostname === '::1')
    );
  } catch {
    return false;
  }
}

function safeFilename(value) {
  const basename = normalize(String(value || '')).replace(/^.*[\\/]/, '');
  return /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$/.test(basename) ? basename : '';
}

function normalizeBaseUrl(value) {
  if (!isHttpsOrLoopbackUrl(value)) {
    throw new Error('UB_PUBLIC_BASE_URL must use HTTPS (HTTP is allowed only for localhost development).');
  }
  return String(value).replace(/\/$/, '');
}

function resolveDataDirectory(value) {
  if (!value) return join(projectDirectory, 'data');
  return value.startsWith('.') ? join(projectDirectory, value) : value;
}

function parsePort(value, fallback) {
  const parsed = Number(value || fallback);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error('PORT must be a valid TCP port.');
  }
  return parsed;
}
