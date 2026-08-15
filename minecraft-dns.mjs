import { resolveSrv as nativeResolveSrv } from 'node:dns/promises';

const dnsOverHttpsProviders = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/resolve'
];

export async function resolveMinecraftSrv(host, options = {}) {
  const hostname = normalizeHostname(host);
  const queryName = `_minecraft._tcp.${hostname}`;
  const resolveSrv = options.resolveSrv || nativeResolveSrv;
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 3500;

  try {
    const nativeRecords = sanitizeSrvRecords(await resolveSrv(queryName));
    if (nativeRecords.length) return nativeRecords;
  } catch {
    // Some Windows/network DNS resolvers refuse SRV queries. HTTPS DNS below
    // gives local development the same result without changing system DNS.
  }

  if (typeof fetchImpl !== 'function') return [];

  for (const provider of dnsOverHttpsProviders) {
    try {
      const url = new URL(provider);
      url.searchParams.set('name', queryName);
      url.searchParams.set('type', 'SRV');
      const response = await fetchImpl(url, {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(timeoutMs)
      });
      if (!response?.ok) continue;
      const payload = await response.json();
      if (Number(payload?.Status || 0) !== 0) continue;
      const records = parseDnsJsonSrvAnswers(payload?.Answer);
      if (records.length) return records;
    } catch {
      // Try the next fixed provider, then let the caller use port 25565.
    }
  }

  return [];
}

export function parseDnsJsonSrvAnswers(answers) {
  if (!Array.isArray(answers)) return [];
  return sanitizeSrvRecords(answers
    .filter(answer => Number(answer?.type) === 33)
    .map(answer => {
      const matched = /^(\d+)\s+(\d+)\s+(\d+)\s+([^\s]+)$/.exec(String(answer?.data || '').trim());
      if (!matched) return null;
      return {
        priority: Number(matched[1]),
        weight: Number(matched[2]),
        port: Number(matched[3]),
        name: matched[4].replace(/\.$/, '')
      };
    })
    .filter(Boolean));
}

function sanitizeSrvRecords(records) {
  if (!Array.isArray(records)) return [];
  return records
    .map(record => ({
      name: normalizeHostnameOrEmpty(record?.name),
      port: Number(record?.port),
      priority: Number(record?.priority || 0),
      weight: Number(record?.weight || 0)
    }))
    .filter(record =>
      record.name &&
      Number.isInteger(record.port) && record.port >= 1 && record.port <= 65535 &&
      Number.isInteger(record.priority) && record.priority >= 0 && record.priority <= 65535 &&
      Number.isInteger(record.weight) && record.weight >= 0 && record.weight <= 65535
    );
}

function normalizeHostname(value) {
  const hostname = normalizeHostnameOrEmpty(value);
  if (!hostname) throw new Error('Minecraft SRV lookup requires a valid hostname.');
  return hostname;
}

function normalizeHostnameOrEmpty(value) {
  const hostname = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (!hostname || hostname.length > 253) return '';
  const labels = hostname.split('.');
  if (labels.some(label =>
    !label || label.length > 63 ||
    !/^[a-z0-9-]+$/.test(label) ||
    label.startsWith('-') || label.endsWith('-')
  )) return '';
  return hostname;
}
