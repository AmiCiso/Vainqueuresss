// Provider adapters. Endpoints are FIXED and allowlisted; user input is only ever sent as data.
//  - Google Safe Browsing Lookup API v4:  POST https://safebrowsing.googleapis.com/v4/threatMatches:find
//    (non-commercial use only; commercial deployments should evaluate Web Risk -- see README)
//  - URLhaus (abuse.ch):                  POST https://urlhaus-api.abuse.ch/v1/url/  (Auth-Key header)
//    URLhaus lists URLs observed distributing malware. It is NOT a complete phishing detector.
// Response shapes are validated; a malformed shape is never converted into "no match".
import { fetchJson, ProviderError } from './net.js';

export const GSB_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
export const URLHAUS_ENDPOINT = 'https://urlhaus-api.abuse.ch/v1/url/';

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const THREAT_TYPES = new Set(['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION', 'THREAT_TYPE_UNSPECIFIED']);

export const PROVIDER_META = {
  gsb: { id: 'gsb', name: 'Google Safe Browsing (Lookup API v4)', coverage: 'Google-maintained lists of social-engineering, malware and unwanted-software URLs. Not exhaustive.' },
  urlhaus: { id: 'urlhaus', name: 'URLhaus (abuse.ch)', coverage: 'URLs observed distributing malware. Does not aim to list phishing pages generally.' }
};

function base(id, extra) {
  return { id, name: PROVIDER_META[id].name, status: 'unavailable', queried: false, threats: [], evidence: null, reason: null, httpStatus: null, retryAfterSec: null, checkedAt: new Date().toISOString(), ...extra };
}

function retryAfter(headers) {
  const v = headers && headers.get && headers.get('retry-after');
  const n = Number(v);
  return Number.isFinite(n) && n > 0 && n < 86400 ? Math.ceil(n) : null;
}

export function parseCacheDuration(s) {
  const m = /^(\d+(?:\.\d+)?)s$/.exec(String(s || ''));
  return m ? Math.min(3600, Math.ceil(Number(m[1]))) : null;
}

// ---- Google Safe Browsing ---------------------------------------------------------------------

export function interpretGsb(status, json, parseFailed, headers) {
  const mk = (s, extra = {}) => base('gsb', { status: s, httpStatus: status, queried: s === 'match' || s === 'no_match', ...extra });
  if (status === 429) return mk('quota', { reason: 'Provider rate or quota limit reached', retryAfterSec: retryAfter(headers) });
  if (status >= 500) return mk('unavailable', { reason: `Provider returned HTTP ${status}` });
  if (status >= 400) {
    const err = isPlainObject(json) && isPlainObject(json.error) ? json.error : {};
    const reasons = Array.isArray(err.details) ? err.details.map((d) => d && d.reason).filter(Boolean) : [];
    if (status === 401 || status === 403 || reasons.includes('API_KEY_INVALID') || reasons.includes('API_KEY_SERVICE_BLOCKED') || err.status === 'PERMISSION_DENIED') {
      return mk('auth_error', { reason: 'Provider rejected the credentials or the API is not enabled for this key' });
    }
    if (err.status === 'RESOURCE_EXHAUSTED') return mk('quota', { reason: 'Provider quota exhausted', retryAfterSec: retryAfter(headers) });
    return mk('rejected', { reason: `Provider rejected the request (HTTP ${status})` });
  }
  if (status !== 200 || parseFailed || !isPlainObject(json)) return mk('unexpected_response', { reason: 'Provider returned an unexpected response body' });
  const keys = Object.keys(json);
  if (keys.length === 0) return mk('no_match'); // documented: an empty object means no match
  if (keys.length === 1 && keys[0] === 'matches' && Array.isArray(json.matches)) {
    if (json.matches.length === 0) return mk('no_match');
    const good = json.matches.every((m) => isPlainObject(m) && typeof m.threatType === 'string' && THREAT_TYPES.has(m.threatType));
    if (!good) return mk('unexpected_response', { reason: 'Provider match entries had an unexpected structure' });
    const types = [...new Set(json.matches.map((m) => m.threatType))];
    const platforms = [...new Set(json.matches.map((m) => m.platformType).filter((x) => typeof x === 'string'))];
    const cds = json.matches.map((m) => parseCacheDuration(m.cacheDuration)).filter((x) => x !== null);
    return mk('match', {
      threats: types.map((t) => `GSB:${t}`),
      evidence: { threatTypes: types, platformTypes: platforms, cacheDurationSec: cds.length ? Math.min(...cds) : null }
    });
  }
  return mk('unexpected_response', { reason: 'Provider returned an unrecognized response shape' });
}

export async function queryGsb({ fetchImpl, key, url, timeoutMs, maxBytes }) {
  if (!key) return base('gsb', { status: 'not_configured', reason: 'API key not configured on the server' });
  const payload = {
    client: { clientId: 'vainqueures-vanq-omni', clientVersion: '2.1.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url }]
    }
  };
  try {
    const r = await fetchJson(fetchImpl, `${GSB_ENDPOINT}?key=${encodeURIComponent(key)}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
    }, { timeoutMs, maxBytes });
    return interpretGsb(r.status, r.json, r.parseFailed, r.headers);
  } catch (err) {
    return mapError('gsb', err);
  }
}

// ---- URLhaus ----------------------------------------------------------------------------------

export function interpretUrlhaus(status, json, parseFailed, headers) {
  const mk = (s, extra = {}) => base('urlhaus', { status: s, httpStatus: status, queried: s === 'match' || s === 'no_match', ...extra });
  const qs = isPlainObject(json) && typeof json.query_status === 'string' ? json.query_status : null;
  if (qs === 'unknown_auth_key' || qs === 'no_auth_key' || status === 401 || status === 403) return mk('auth_error', { reason: 'Provider rejected the Auth-Key' });
  if (status === 429) return mk('quota', { reason: 'Provider rate limit reached', retryAfterSec: retryAfter(headers) });
  if (status >= 500) return mk('unavailable', { reason: `Provider returned HTTP ${status}` });
  if (status !== 200 || parseFailed || !isPlainObject(json) || qs === null) return mk('unexpected_response', { reason: 'Provider returned an unexpected response body' });
  if (qs === 'no_results') return mk('no_match');
  if (qs === 'invalid_url') return mk('rejected', { reason: 'Provider considered the URL invalid' });
  if (qs === 'ok') {
    const urlStatus = typeof json.url_status === 'string' ? json.url_status : null;
    const threat = typeof json.threat === 'string' ? json.threat : null;
    if (!urlStatus && !threat) return mk('unexpected_response', { reason: 'Provider "ok" response lacked listing fields' });
    const tags = Array.isArray(json.tags) ? json.tags.filter((t) => typeof t === 'string').slice(0, 10) : [];
    const ref = typeof json.urlhaus_reference === 'string' && json.urlhaus_reference.startsWith('https://urlhaus.abuse.ch/') ? json.urlhaus_reference : null;
    return mk('match', {
      threats: [`URLhaus:${threat || 'listed'}`],
      evidence: { urlStatus, threat, tags, dateAdded: typeof json.date_added === 'string' ? json.date_added : null, reference: ref }
    });
  }
  return mk('unexpected_response', { reason: 'Provider returned an unrecognized query_status' });
}

export async function queryUrlhaus({ fetchImpl, key, url, timeoutMs, maxBytes }) {
  if (!key) return base('urlhaus', { status: 'not_configured', reason: 'Auth-Key not configured on the server' });
  try {
    const r = await fetchJson(fetchImpl, URLHAUS_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Auth-Key': key },
      body: new URLSearchParams({ url }).toString()
    }, { timeoutMs, maxBytes });
    return interpretUrlhaus(r.status, r.json, r.parseFailed, r.headers);
  } catch (err) {
    return mapError('urlhaus', err);
  }
}

function mapError(id, err) {
  if (err instanceof ProviderError) {
    if (err.kind === 'timeout') return base(id, { status: 'timeout', reason: 'Provider request timed out' });
    if (err.kind === 'unexpected_response') return base(id, { status: 'unexpected_response', reason: 'Provider response was too large or malformed' });
  }
  return base(id, { status: 'network_error', reason: 'Could not reach the provider' });
}

/** Statuses that represent an answer from the provider (safe to cache). */
export const ANSWERED = new Set(['match', 'no_match']);
