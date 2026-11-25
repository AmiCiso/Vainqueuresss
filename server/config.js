// Environment parsing. No secrets are logged. No dotenv dependency: Node >= 20.12 provides process.loadEnvFile().
import fs from 'node:fs';

const int = (v, d, min = 0, max = Number.MAX_SAFE_INTEGER) => {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isFinite(n) && n >= min && n <= max ? n : d;
};

export function loadEnvFileIfPresent(path = '.env') {
  try {
    if (fs.existsSync(path) && typeof process.loadEnvFile === 'function') process.loadEnvFile(path);
  } catch (err) {
    console.warn('[config] Could not load .env file:', err && err.code ? err.code : 'error');
  }
}

/** TRUST_PROXY: unset/false -> false; integer hop count; or a comma list of IP/CIDR/keywords. `true` is refused. */
export function parseTrustProxy(raw) {
  const v = (raw ?? '').trim();
  if (!v || v.toLowerCase() === 'false' || v === '0') return false;
  if (v.toLowerCase() === 'true') {
    throw new Error('TRUST_PROXY=true would trust any X-Forwarded-For header. Use a hop count (e.g. 1) or a list of proxy IPs/CIDRs.');
  }
  if (/^\d+$/.test(v)) return Number(v);
  const list = v.split(',').map((s) => s.trim()).filter(Boolean);
  return list.length === 1 ? list[0] : list;
}

export function buildConfig(env = process.env) {
  const production = env.NODE_ENV === 'production';
  const devOrigins = [3000, 5500, 5501].flatMap((p) => [`http://localhost:${p}`, `http://127.0.0.1:${p}`]);
  const allowed = (env.ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (env.PUBLIC_ORIGIN) allowed.push(env.PUBLIC_ORIGIN.trim());
  const origins = [...new Set(allowed.length || production ? allowed : devOrigins.concat(allowed))];

  return {
    production,
    port: int(env.PORT, 3000, 0, 65535),
    host: env.HOST || (production ? '0.0.0.0' : '127.0.0.1'),
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
    hsts: env.HSTS === 'on',
    allowedOrigins: origins,
    cspConnectExtra: (env.CSP_CONNECT_EXTRA ?? '').split(/\s+/).filter(Boolean),
    maxUrlLength: 2048,
    bodyLimit: '10kb',
    providers: {
      gsbKey: (env.GOOGLE_SAFE_BROWSING_KEY || '').trim(),
      urlhausKey: (env.URLHAUS_AUTH_KEY || '').trim(),
      timeoutMs: int(env.PROVIDER_TIMEOUT_MS, 5000, 500, 15000),
      maxResponseBytes: 64 * 1024,
      maxConcurrent: int(env.PROVIDER_MAX_CONCURRENT, 8, 1, 64),
      maxQueue: int(env.PROVIDER_MAX_QUEUE, 32, 0, 512),
      // Per-instance budgets (see README: divide the provider quota across instances).
      gsbBudgetPerMinute: int(env.GSB_BUDGET_PER_MINUTE, 120, 1, 100000),
      urlhausBudgetPerMinute: int(env.URLHAUS_BUDGET_PER_MINUTE, 60, 1, 100000)
    },
    cache: {
      maxEntries: int(env.CACHE_MAX_ENTRIES, 1000, 10, 100000),
      noMatchTtlSec: int(env.CACHE_NO_MATCH_TTL_SEC, 60, 0, 3600),
      matchTtlSec: int(env.CACHE_MATCH_TTL_SEC, 300, 0, 3600)
    },
    rateLimit: {
      windowMs: 60 * 1000,
      limit: int(env.RATE_LIMIT_PER_MINUTE, 30, 1, 100000),
      store: (env.RATE_LIMIT_STORE || 'memory').toLowerCase(),
      redisUrl: env.REDIS_URL || ''
    }
  };
}
