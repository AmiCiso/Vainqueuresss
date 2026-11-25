// Deterministic fakes. No test ever contacts a real provider or submits real URLs/tokens.
export function jsonResponse(status, body, headers = {}) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return new Response(text, { status, headers: { 'content-type': 'application/json', ...headers } });
}

/** Build a fetch fake from a handler(url, init) -> Response | Promise<Response>; records calls. */
export function fakeFetch(handler) {
  const calls = [];
  const fn = async (url, init) => { calls.push({ url: String(url), init }); return handler(String(url), init); };
  fn.calls = calls;
  return fn;
}

export const gsbMatch = () => jsonResponse(200, { matches: [{ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threatEntryType: 'URL', threat: { url: 'x' }, cacheDuration: '300.000s' }] });
export const urlhausOk = () => jsonResponse(200, { query_status: 'ok', url_status: 'online', threat: 'malware_download', tags: ['elf'], date_added: '2026-01-01 00:00:00 UTC', urlhaus_reference: 'https://urlhaus.abuse.ch/url/1/' });

export function testConfig(over = {}) {
  return {
    production: false, port: 0, host: '127.0.0.1', trustProxy: false, hsts: false,
    allowedOrigins: ['http://localhost:3000'], cspConnectExtra: [], maxUrlLength: 2048, bodyLimit: '10kb',
    providers: { gsbKey: 'TESTKEY-GSB', urlhausKey: 'TESTKEY-UH', timeoutMs: 200, maxResponseBytes: 64 * 1024, maxConcurrent: 4, maxQueue: 4, gsbBudgetPerMinute: 100, urlhausBudgetPerMinute: 100, ...(over.providers || {}) },
    cache: { maxEntries: 50, noMatchTtlSec: 60, matchTtlSec: 300, ...(over.cache || {}) },
    rateLimit: { windowMs: 60000, limit: 30, store: 'memory', redisUrl: '', ...(over.rateLimit || {}) }
  };
}

export function memoryStorage(initial = {}, { failWrites = false, failReads = false } = {}) {
  const m = new Map(Object.entries(initial));
  return {
    getItem(k) { if (failReads) throw new Error('blocked'); return m.has(k) ? m.get(k) : null; },
    setItem(k, v) { if (failWrites) throw new Error('quota'); m.set(k, String(v)); },
    removeItem(k) { m.delete(k); },
    dump() { return JSON.stringify([...m.entries()]); },
    map: m
  };
}

/** Controllable gateway fake: each call returns a deferred the test resolves/rejects explicitly. */
export function deferredFetch() {
  const calls = [];
  const fn = (url, init) => new Promise((resolve, reject) => {
    const call = { url, init, body: JSON.parse(init.body), resolve, reject, aborted: false };
    init.signal.addEventListener('abort', () => { call.aborted = true; reject(Object.assign(new Error('aborted'), { name: 'AbortError' })); });
    calls.push(call);
  });
  fn.calls = calls;
  return fn;
}

export const gatewayBody = (gsb, urlhaus, extra = {}) => ({ ok: true, checkedAt: '2026-01-01T00:00:00Z', providers: { gsb, urlhaus }, coverage: {}, retryAfterSec: null, attribution: null, ...extra });
export const pNoMatch = () => ({ status: 'no_match', reason: null, threats: [], evidence: null, httpStatus: 200, retryAfterSec: null, checkedAt: '2026-01-01T00:00:00Z', cache: 'miss' });
export const pMatch = (t = 'GSB:SOCIAL_ENGINEERING') => ({ status: 'match', reason: null, threats: [t], evidence: { threatTypes: ['SOCIAL_ENGINEERING'], platformTypes: [], cacheDurationSec: 300, urlStatus: null, threat: null, tags: [], dateAdded: null, reference: null }, httpStatus: 200, retryAfterSec: null, checkedAt: '2026-01-01T00:00:00Z', cache: 'miss' });
export const pFail = (status, reason = 'x') => ({ status, reason, threats: [], evidence: null, httpStatus: null, retryAfterSec: null, checkedAt: null, cache: null });
export const okResp = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
export const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
