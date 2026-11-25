// Browser-side client for the gateway. One request per scan, no automatic retry, cancellable end to end
// (the abort signal stays active while the response body is read and parsed).

export class LookupError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.code = code;
    Object.assign(this, extra);
  }
}

/** Map a failure code onto the per-provider status vocabulary used by the report. */
export const FAILURE_STATUS = {
  rate_limited: 'quota',
  busy: 'unavailable',
  timeout: 'timeout',
  unreachable: 'network_error',
  server_error: 'unavailable',
  malformed: 'unexpected_response',
  rejected: 'rejected',
  consent_required: 'rejected',
  origin_not_allowed: 'rejected',
  too_large: 'rejected'
};

const ALLOWED_STATUS = new Set(['match', 'no_match', 'not_configured', 'auth_error', 'quota', 'timeout', 'network_error', 'unavailable', 'unexpected_response', 'rejected']);
const str = (v, max = 300) => (typeof v === 'string' ? v.slice(0, max) : null);
const arr = (v, n, max = 80) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string').slice(0, n).map((x) => x.slice(0, max)) : []);
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function cleanProvider(p) {
  if (!isObj(p) || !ALLOWED_STATUS.has(p.status)) return null;
  const ev = isObj(p.evidence) ? p.evidence : null;
  return {
    status: p.status,
    reason: str(p.reason),
    threats: arr(p.threats, 10),
    evidence: ev ? {
      threatTypes: arr(ev.threatTypes, 10), platformTypes: arr(ev.platformTypes, 10),
      cacheDurationSec: Number.isFinite(ev.cacheDurationSec) ? ev.cacheDurationSec : null,
      urlStatus: str(ev.urlStatus, 20), threat: str(ev.threat, 60), tags: arr(ev.tags, 10, 40),
      dateAdded: str(ev.dateAdded, 40),
      reference: typeof ev.reference === 'string' && ev.reference.startsWith('https://urlhaus.abuse.ch/') ? ev.reference.slice(0, 200) : null
    } : null,
    httpStatus: Number.isFinite(p.httpStatus) ? p.httpStatus : null,
    retryAfterSec: Number.isFinite(p.retryAfterSec) ? p.retryAfterSec : null,
    checkedAt: str(p.checkedAt, 40),
    cache: ['hit', 'miss', 'coalesced'].includes(p.cache) ? p.cache : null
  };
}

/** Validate and whitelist the gateway response. Throws LookupError('malformed') on any structural problem. */
export function validateLookupResponse(json) {
  if (!isObj(json) || json.ok !== true || !isObj(json.providers)) throw new LookupError('malformed', 'The gateway returned an unexpected response.');
  const gsb = cleanProvider(json.providers.gsb);
  const urlhaus = cleanProvider(json.providers.urlhaus);
  if (!gsb || !urlhaus) throw new LookupError('malformed', 'The gateway response was missing provider results.');
  const attr = isObj(json.attribution) && json.attribution.text === 'Advisory provided by Google' ? { text: 'Advisory provided by Google', href: 'https://developers.google.com/safe-browsing/v4/advisory' } : null;
  return { providers: { gsb, urlhaus }, retryAfterSec: Number.isFinite(json.retryAfterSec) ? json.retryAfterSec : null, attribution: attr, checkedAt: str(json.checkedAt, 40) };
}

function retryAfterSeconds(res) {
  const n = Number(res.headers.get('retry-after'));
  return Number.isFinite(n) && n > 0 && n < 86400 ? Math.ceil(n) : null;
}

export async function requestLookup({ url, acknowledgeSensitive = false, signal, apiBase = '', fetchImpl = globalThis.fetch.bind(globalThis), timeoutMs = 12000 }) {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
  const onAbort = () => controller.abort();
  if (signal) { if (signal.aborted) controller.abort(); else signal.addEventListener('abort', onAbort, { once: true }); }
  try {
    let res;
    try {
      res = await fetchImpl(`${apiBase}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, acknowledgeSensitive }),
        signal: controller.signal,
        credentials: 'omit',
        redirect: 'error'
      });
    } catch (err) {
      if (signal && signal.aborted) throw new LookupError('aborted', 'Lookup cancelled.');
      if (timedOut) throw new LookupError('timeout', 'The lookup timed out.');
      throw new LookupError('unreachable', 'Could not reach the VanQ gateway. Is the server running?');
    }
    let body = null;
    let parseFailed = false;
    try {
      const text = await res.text(); // abort/timeout still apply while the body is read
      if (text) body = JSON.parse(text);
    } catch (err) {
      if (signal && signal.aborted) throw new LookupError('aborted', 'Lookup cancelled.');
      if (timedOut) throw new LookupError('timeout', 'The lookup timed out while reading the response.');
      parseFailed = true;
    }
    const code = isObj(body) && isObj(body.error) && typeof body.error.code === 'string' ? body.error.code : null;
    if (res.status === 429) throw new LookupError('rate_limited', 'Rate limit reached. Please wait before scanning again.', { retryAfterSec: retryAfterSeconds(res) });
    if (res.status === 413) throw new LookupError('too_large', 'The request was too large.');
    if (res.status === 409 && code === 'sensitive_url_unacknowledged') throw new LookupError('consent_required', 'The server requires explicit confirmation for this URL.');
    if (res.status === 403 && code === 'origin_not_allowed') throw new LookupError('origin_not_allowed', 'This page’s origin is not allowed by the gateway (CORS).');
    if (res.status === 403 && code === 'reserved_host') throw new LookupError('rejected', 'Reserved, local or private targets are never sent to providers.');
    if (res.status >= 400 && res.status < 500) throw new LookupError('rejected', `The gateway rejected the request (${res.status}).`);
    if (res.status === 503) throw new LookupError('busy', 'The gateway is busy.', { retryAfterSec: retryAfterSeconds(res) });
    if (res.status >= 500) throw new LookupError('server_error', `The gateway reported an error (${res.status}).`);
    if (res.status !== 200 || parseFailed) throw new LookupError('malformed', 'The gateway returned an unreadable response.');
    return validateLookupResponse(body);
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

/**
 * Resolve the API base: <meta name="vq-api-base"> if set; otherwise same origin.
 * Convenience for the two documented static-dev ports only (VS Code Live Server 5500/5501): talk to the
 * gateway on localhost:3000. Any other origin, including the gateway on a custom PORT, uses same-origin.
 */
export function resolveApiBase(doc = globalThis.document, loc = globalThis.location) {
  const meta = doc && doc.querySelector ? doc.querySelector('meta[name="vq-api-base"]') : null;
  const configured = meta && meta.content ? meta.content.trim().replace(/\/+$/, '') : '';
  if (configured) return configured;
  if (loc && /^(localhost|127\.0\.0\.1)$/.test(loc.hostname) && ['5500', '5501'].includes(loc.port)) return 'http://localhost:3000';
  return '';
}
