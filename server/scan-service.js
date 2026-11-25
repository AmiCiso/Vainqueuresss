// Framework-free request logic: handleScan() and providersStatus(). Express only adapts req/res.
import { parseTarget, detectSensitive, MAX_URL_LENGTH } from '../src/shared/url-policy.js';
import { queryGsb, queryUrlhaus, ANSWERED, PROVIDER_META } from './providers.js';
import { ResultCache } from './cache.js';
import { Gate, Budget } from './guards.js';

const err = (status, code, message, extra = {}) => ({ status, headers: extra.headers || {}, json: { ok: false, error: { code, message } } });

export function createScanService(config, { fetchImpl = globalThis.fetch, now = () => Date.now() } = {}) {
  const p = config.providers;
  const cache = new ResultCache({ maxEntries: config.cache.maxEntries, now });
  const gate = new Gate({ maxConcurrent: p.maxConcurrent, maxQueue: p.maxQueue });
  const budgets = {
    gsb: new Budget({ limit: p.gsbBudgetPerMinute, now }),
    urlhaus: new Budget({ limit: p.urlhausBudgetPerMinute, now })
  };
  const observed = { gsb: null, urlhaus: null }; // last real outcome per provider (no active probing)
  const adapters = { gsb: queryGsb, urlhaus: queryUrlhaus };
  const keys = { gsb: p.gsbKey, urlhaus: p.urlhausKey };

  const ttlFor = (v) => {
    if (!ANSWERED.has(v.status)) return 0;
    if (v.status === 'match') {
      const provider = v.evidence && v.evidence.cacheDurationSec;
      return (provider ?? config.cache.matchTtlSec) * 1000;
    }
    return config.cache.noMatchTtlSec * 1000;
  };

  async function lookup(id, url) {
    if (!keys[id]) return adapters[id]({ key: '', url });
    const k = cache.key(id, url);
    const { value, cached, coalesced } = await cache.getOrCompute(k, async () => {
      const b = budgets[id].take();
      if (!b.ok) return { ...PROVIDER_FALLBACK(id), status: 'quota', reason: 'Local provider usage budget exhausted; try again shortly', retryAfterSec: b.retryAfterSec };
      let release;
      try { release = await gate.acquire(); } catch { return { ...PROVIDER_FALLBACK(id), status: 'unavailable', reason: 'Gateway is busy', retryAfterSec: 5 }; }
      try {
        return await adapters[id]({ fetchImpl, key: keys[id], url, timeoutMs: p.timeoutMs, maxBytes: p.maxResponseBytes });
      } finally { release(); }
    }, ttlFor);
    const out = { ...value, cache: cached ? 'hit' : coalesced ? 'coalesced' : 'miss' };
    if (!cached && !coalesced) observed[id] = { status: out.status, at: new Date(now()).toISOString() };
    return out;
  }

  function PROVIDER_FALLBACK(id) {
    return { id, name: PROVIDER_META[id].name, queried: false, threats: [], evidence: null, httpStatus: null, checkedAt: new Date(now()).toISOString() };
  }

  async function handleScan(body) {
    if (body === null || typeof body !== 'object' || Array.isArray(body)) return err(400, 'invalid_body', "Request body must be a JSON object with a 'url' string.");
    if (typeof body.url !== 'string' || !body.url.trim()) return err(400, 'missing_url', "Missing or empty 'url' field.");
    if (body.url.length > MAX_URL_LENGTH) return err(400, 'too_long', `URL exceeds ${MAX_URL_LENGTH} characters.`);
    const t = parseTarget(body.url);
    if (!t.ok) return err(400, t.code, t.message);
    if (t.reserved) return err(403, 'reserved_host', `Reserved, local or private targets are not sent to external providers (${t.reservedReason}).`);
    const sens = detectSensitive(t.url);
    if (sens.likely && body.acknowledgeSensitive !== true) {
      return err(409, 'sensitive_url_unacknowledged', 'This URL looks like it contains a credential or token. Confirm explicitly before it is sent to external providers.');
    }
    const url = t.externalUrl; // fragment removed, host normalized; never logged
    const [gsb, urlhaus] = await Promise.all([lookup('gsb', url), lookup('urlhaus', url)]);
    const list = [gsb, urlhaus];
    const configured = list.filter((r) => r.status !== 'not_configured');
    const answered = list.filter((r) => ANSWERED.has(r.status));
    const matched = list.filter((r) => r.status === 'match');
    const retry = Math.max(0, ...list.map((r) => r.retryAfterSec || 0));
    return {
      status: 200,
      headers: {},
      json: {
        ok: true,
        checkedAt: new Date(now()).toISOString(),
        providers: { gsb, urlhaus },
        coverage: {
          providersTotal: list.length, configured: configured.length, answered: answered.length, matched: matched.length,
          complete: configured.length > 0 && answered.length === configured.length && configured.length === list.length,
          note: 'Coverage is partial whenever a provider is unconfigured, unavailable or rate limited. A missing answer is never a clean result.'
        },
        retryAfterSec: retry || null,
        attribution: gsb.status === 'match' ? { text: 'Advisory provided by Google', href: 'https://developers.google.com/safe-browsing/v4/advisory' } : null
      }
    };
  }

  function providersStatus() {
    const entry = (id) => {
      const configured = Boolean(keys[id]);
      const last = observed[id];
      let state = 'not_configured';
      if (configured) {
        state = 'configured_unverified'; // a key being present proves nothing about validity or health
        if (last) state = ANSWERED.has(last.status) ? 'last_lookup_answered' : last.status === 'auth_error' ? 'last_lookup_auth_failed' : 'last_lookup_failed';
      }
      return { name: PROVIDER_META[id].name, configured, state, lastObserved: last, coverage: PROVIDER_META[id].coverage };
    };
    return {
      status: 200, headers: {},
      json: { ok: true, providers: { gsb: entry('gsb'), urlhaus: entry('urlhaus') }, note: 'No active probe is made. "configured_unverified" means a key exists but has not been shown to work.' }
    };
  }

  return { handleScan, providersStatus, cache, gate, budgets };
}
