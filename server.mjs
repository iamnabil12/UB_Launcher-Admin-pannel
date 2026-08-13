import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectDirectory = dirname(fileURLToPath(import.meta.url));
const port = parsePort(process.env.PORT, 8602);
const host = process.env.HOST || '127.0.0.1';
const password = process.env.UB_ADMIN_PASSWORD || '';
const publicBaseUrl = normalizeBaseUrl(
  process.env.UB_PUBLIC_BASE_URL || 'https://launcher.unitedbangla.top'
);
const dataDirectory = resolveDataDirectory(process.env.UB_ADMIN_DATA_DIR);
const assetDirectory = join(dataDirectory, 'assets');
const configPath = join(dataDirectory, 'config.json');
const analyticsPath = join(dataDirectory, 'users.json');
const adminHtmlPath = join(projectDirectory, 'public', 'admin.html');
const maximumRequestBytes = 8 * 1024 * 1024;
const maximumAssetBytes = 6 * 1024 * 1024;
const analyticsRateLimits = new Map();
let analyticsWriteQueue = Promise.resolve();

if (password.length < 12) {
  throw new Error('UB_ADMIN_PASSWORD must contain at least 12 characters.');
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
      await recordAnalyticsEvent(await readJson(request));
      response.writeHead(204, { 'Cache-Control': 'no-store' });
      return response.end();
    }

    if (request.method === 'GET' && url.pathname === '/') {
      response.writeHead(302, { Location: '/admin' });
      return response.end();
    }

    if (!isAuthorized(request)) {
      response.writeHead(401, {
        'Content-Type': 'text/plain; charset=utf-8',
        'WWW-Authenticate': 'Basic realm="UB Launcher Admin", charset="UTF-8"'
      });
      return response.end('Admin login required.');
    }

    if (request.method === 'GET' && (url.pathname === '/admin' || url.pathname === '/admin/')) {
      response.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
      });
      return response.end(adminHtml);
    }

    if (request.method === 'GET' && url.pathname === '/admin/config') {
      return sendJson(response, 200, await loadConfig(), { 'Cache-Control': 'no-store' });
    }

    if (request.method === 'GET' && url.pathname === '/admin/analytics') {
      return sendJson(response, 200, await getAnalyticsDashboard(), { 'Cache-Control': 'no-store' });
    }

    if (request.method === 'PUT' && url.pathname === '/admin/config') {
      const configuration = sanitizeConfig(await readJson(request));
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
    return sendJson(response, 400, { error: message }, { 'Cache-Control': 'no-store' });
  }
});

server.listen(port, host, () => {
  console.log(`UB Launcher Admin listening on http://${host}:${port}`);
});

function isAuthorized(request) {
  const supplied = Buffer.from(request.headers.authorization || '', 'utf8');
  const expected = Buffer.from(
    `Basic ${Buffer.from(`admin:${password}`).toString('base64')}`,
    'utf8'
  );
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function readJson(request) {
  const chunks = [];
  let total = 0;

  for await (const chunk of request) {
    total += chunk.length;
    if (total > maximumRequestBytes) throw new Error('Request is too large.');
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
      .filter(([name, url]) => /^[a-zA-Z][a-zA-Z0-9]{0,63}$/.test(name) && isHttpsUrl(url))
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
  const name = text(value.name, 80, '');
  const address = String(value.address || '').trim().slice(0, 255);
  if (!name || !/^[a-zA-Z0-9.-]+(?::[0-9]{1,5})?$/.test(address)) return null;

  return {
    id: /^[a-zA-Z0-9_-]{3,50}$/.test(String(value.id || ''))
      ? String(value.id)
      : `server-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name,
    address,
    description: text(value.description, 180, 'Join this partner Minecraft server.'),
    version: text(value.version, 32, 'Any version'),
    badge: text(value.badge, 24, 'PARTNER'),
    iconUrl: isHttpsUrl(value.iconUrl) ? String(value.iconUrl).trim() : '',
    websiteUrl: isHttpsUrl(value.websiteUrl) ? String(value.websiteUrl).trim() : '',
    enabled: value.enabled !== false
  };
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

function isHttpsUrl(value) {
  try {
    return new URL(String(value)).protocol === 'https:';
  } catch {
    return false;
  }
}

function safeFilename(value) {
  const basename = normalize(String(value || '')).replace(/^.*[\\/]/, '');
  return /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$/.test(basename) ? basename : '';
}

function normalizeBaseUrl(value) {
  if (!isHttpsUrl(value)) throw new Error('UB_PUBLIC_BASE_URL must be an HTTPS URL.');
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
