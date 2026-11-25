// URL normalization, validation, host classification, sensitive-URL detection and redaction.
// Isomorphic (browser + Node) and used by BOTH the frontend and the gateway so they cannot drift.
// This module never fetches anything. It only parses and classifies strings.

import { classifyIpLiteral } from './ip.js';

export const MAX_URL_LENGTH = 2048;

/** Suffixes that are not publicly resolvable / are reserved for local or documentation use. */
export const RESERVED_SUFFIXES = [
  'localhost', 'local', 'localdomain', 'internal', 'home.arpa', 'arpa',
  'intranet', 'corp', 'test', 'example', 'invalid'
];

const CONTROL_RE = /[\u0000-\u001f\u007f]/;

function fail(code, message) {
  return { ok: false, code, message };
}

/** Lowercase, strip exactly one trailing dot, reject empty labels. Returns null if malformed. */
export function normalizeHostname(host) {
  if (typeof host !== 'string' || !host) return null;
  let h = host.toLowerCase();
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (!h || h.startsWith('.') || h.endsWith('.') || h.includes('..')) return null;
  return h;
}

/** Classify an already-normalized hostname (as produced by normalizeHostname). */
export function classifyHost(hostname) {
  const ip = classifyIpLiteral(hostname);
  if (ip.kind) {
    return { kind: ip.kind, reserved: ip.reserved, reason: ip.reason, embeddedIPv4: ip.embeddedIPv4 || null };
  }
  for (const suffix of RESERVED_SUFFIXES) {
    if (hostname === suffix || hostname.endsWith('.' + suffix)) {
      return { kind: 'domain', reserved: true, reason: `reserved or non-public name (.${suffix})` };
    }
  }
  if (!hostname.includes('.')) {
    return { kind: 'domain', reserved: true, reason: 'single-label hostname (not publicly resolvable)' };
  }
  return { kind: 'domain', reserved: false, reason: null };
}

function authorityOf(raw) {
  let s = raw.replace(/^[a-z][a-z0-9+.-]*:/i, '');
  s = s.replace(/^[\\/]+/, '');
  const end = s.search(/[\\/?#]/);
  return end === -1 ? s : s.slice(0, end);
}

/**
 * Parse and normalize a user-supplied target.
 * - http/https only; bare hosts get https:// (clearly flagged via inputHadScheme=false)
 * - userinfo (user:pass@) is REJECTED unless opts.allowUserinfo (used only for nested-destination analysis)
 * - never throws
 */
export function parseTarget(rawInput, opts = {}) {
  if (typeof rawInput !== 'string') return fail('empty', 'Please enter a URL or domain to scan.');
  const raw = rawInput.trim();
  if (!raw) return fail('empty', 'Please enter a URL or domain to scan.');
  if (raw.length > MAX_URL_LENGTH) return fail('too_long', `URL exceeds the maximum length of ${MAX_URL_LENGTH} characters.`);
  if (CONTROL_RE.test(raw)) return fail('control_chars', 'URL contains control characters, which are not allowed.');

  let candidate = raw;
  const hasScheme = /^https?:\/\//i.test(raw);
  if (!hasScheme) {
    const looksHostPort = /^[a-z0-9.-]+:\d{1,5}(?:[/?#]|$)/i.test(raw);
    if (!looksHostPort && /^[a-z][a-z0-9+.-]*:/i.test(raw)) {
      return fail('bad_scheme', 'Only http:// and https:// URLs are supported.');
    }
    candidate = 'https://' + raw.replace(/^\/\//, '');
  }

  let url;
  try {
    url = new URL(candidate);
  } catch {
    return fail('invalid_url', 'That does not look like a valid URL.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return fail('bad_scheme', 'Only http:// and https:// URLs are supported.');
  }

  const hasUserinfo = url.username !== '' || url.password !== '' || authorityOf(candidate).includes('@');
  if (hasUserinfo && !opts.allowUserinfo) {
    return fail('userinfo', 'URLs that contain a username or password (user:pass@host) are rejected. Remove the credentials and try again.');
  }

  const hostname = normalizeHostname(url.hostname);
  if (!hostname) return fail('bad_host', 'The URL has a missing or malformed hostname.');

  if (url.hostname !== hostname) {
    try { url.hostname = hostname; } catch { return fail('bad_host', 'The URL has a malformed hostname.'); }
  }
  if (hasUserinfo) { url.username = ''; url.password = ''; }

  const host = classifyHost(hostname);
  const ext = new URL(url.href);
  ext.hash = '';

  return {
    ok: true,
    url,
    href: url.href,
    hostname,
    hostKind: host.kind,
    reserved: host.reserved,
    reservedReason: host.reason,
    hasUserinfo,
    inputHadScheme: hasScheme,
    /** Canonical form used for provider submission: fragment removed, query and path preserved. */
    externalUrl: ext.href
  };
}

// ---------------------------------------------------------------------------------------------
// Sensitive-URL detection (best effort; cannot identify every secret)
// ---------------------------------------------------------------------------------------------

const SENSITIVE_PARAMS = new Set([
  'token', 'accesstoken', 'idtoken', 'refreshtoken', 'authtoken', 'bearer', 'jwt', 'apikey', 'key', 'secret',
  'clientsecret', 'password', 'passwd', 'pwd', 'pass', 'otp', 'tac', 'pin', 'session', 'sessionid', 'sid',
  'sessid', 'phpsessid', 'jsessionid', 'auth', 'authorization', 'signature', 'sig', 'xamzsignature',
  'xamzcredential', 'xamzsecuritytoken', 'credential', 'credentials', 'resettoken', 'magic', 'magiclink',
  'ticket', 'csrf', 'csrftoken', 'xsrf', 'verificationcode', 'confirmationcode'
]);
const PATH_KEYWORDS = new Set([
  'reset', 'resetpassword', 'reset-password', 'verify', 'confirm', 'activate', 'activation', 'invite', 'token',
  'magic', 'unsubscribe', 'share', 'password', 'signin', 'auth', 'callback', 'oauth', 'recover', 'claim'
]);
const VALUE_PATTERNS = [
  [/^eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*$/, 'JWT-shaped value'],
  [/^(AKIA|ASIA)[A-Z0-9]{16}$/, 'AWS access-key-shaped value'],
  [/^AIza[0-9A-Za-z_-]{35}$/, 'Google API-key-shaped value'],
  [/^gh[pousr]_[A-Za-z0-9]{36,}$/, 'GitHub-token-shaped value'],
  [/^xox[baprs]-[A-Za-z0-9-]{10,}$/, 'Slack-token-shaped value'],
  [/^sk_(live|test)_[A-Za-z0-9]{10,}$/, 'payment-key-shaped value'],
  [/^sk-[A-Za-z0-9_-]{20,}$/, 'secret-key-shaped value'],
  [/^[0-9a-f]{32,}$/i, 'long hexadecimal value']
];

export function shannonEntropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

function paramKey(name) {
  return String(name).toLowerCase().replace(/[-_.\s]/g, '');
}

function isSensitiveParamName(name) {
  const n = paramKey(name);
  return SENSITIVE_PARAMS.has(n) || /(token|secret|apikey|password)$/.test(n);
}

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function valueReason(v) {
  const d = safeDecode(v);
  for (const [re, label] of VALUE_PATTERNS) if (re.test(d)) return label;
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d)) return 'email address';
  if (d.length >= 32 && /^[A-Za-z0-9_\-+/=.]+$/.test(d) && /\d/.test(d) && /[A-Za-z]/.test(d) && shannonEntropy(d) >= 3.8) {
    return 'long high-entropy value';
  }
  return null;
}

function opaqueSegment(seg) {
  const d = safeDecode(seg);
  return d.length >= 16 && /^[A-Za-z0-9_\-=.]+$/.test(d) && /\d/.test(d) && /[A-Za-z]/.test(d) && shannonEntropy(d) >= 3.2;
}

function paramsOfFragment(hash) {
  const body = hash.replace(/^#/, '').replace(/^[?/]+/, '');
  if (!body.includes('=')) return [];
  try { return [...new URLSearchParams(body).entries()]; } catch { return []; }
}

/**
 * Best-effort detection. Reasons never contain the secret itself, only the location and kind.
 * Returns { likely, reasons: [{kind, where, detail}] }.
 */
export function detectSensitive(urlLike) {
  const url = urlLike instanceof URL ? urlLike : new URL(urlLike);
  const reasons = [];
  const params = [...url.searchParams.entries()];
  const hasState = params.some(([k]) => paramKey(k) === 'state');
  for (const [k, v] of params) {
    if (isSensitiveParamName(k) || (paramKey(k) === 'code' && hasState)) {
      reasons.push({ kind: 'param', where: k, detail: 'parameter name suggests a credential or token' });
    } else {
      const r = valueReason(v);
      if (r) reasons.push({ kind: 'value', where: k, detail: r });
    }
  }
  const segs = url.pathname.split('/').filter(Boolean);
  segs.forEach((seg, i) => {
    const prev = i > 0 ? paramKey(segs[i - 1]) : '';
    const kw = PATH_KEYWORDS.has(prev) || PATH_KEYWORDS.has(segs[i - 1] ? segs[i - 1].toLowerCase() : '');
    if ((kw && opaqueSegment(seg)) || valueReason(seg)) {
      reasons.push({ kind: 'path', where: `path segment ${i + 1}`, detail: kw ? 'opaque value after an account-flow keyword' : 'long opaque value in path' });
    }
  });
  for (const [k, v] of paramsOfFragment(url.hash)) {
    if (isSensitiveParamName(k) || paramKey(k) === 'code' || valueReason(v)) {
      reasons.push({ kind: 'fragment', where: k, detail: 'fragment carries a credential-like value' });
    }
  }
  return { likely: reasons.length > 0, reasons };
}

// ---------------------------------------------------------------------------------------------
// Redaction for display, history, logs and default exports
// ---------------------------------------------------------------------------------------------

const REDACTED = '[redacted]';

/**
 * Produce a display-safe string. Fragments are never shown, credentials never shown, flagged
 * path segments and query values are replaced. Safe to persist (subject to retention limits).
 */
export function redactUrl(urlLike, maxLen = 220, depth = 0) {
  const url = urlLike instanceof URL ? urlLike : new URL(urlLike);
  let redactions = 0;
  const segs = url.pathname.split('/');
  const pathParts = segs.map((seg, i) => {
    if (!seg) return seg;
    const prev = i > 0 ? segs[i - 1] : '';
    const kw = PATH_KEYWORDS.has(paramKey(prev)) || PATH_KEYWORDS.has(prev.toLowerCase());
    if ((kw && opaqueSegment(seg)) || valueReason(seg)) { redactions++; return REDACTED; }
    return seg;
  });
  const hasState = [...url.searchParams.keys()].some((k) => paramKey(k) === 'state');
  const q = [];
  for (const [k, v] of url.searchParams.entries()) {
    const flagged = isSensitiveParamName(k) || (paramKey(k) === 'code' && hasState) || valueReason(v);
    if (flagged) { redactions++; q.push(`${k}=${REDACTED}`); continue; }
    // URL-valued parameters (redirects) are redacted recursively so a nested token cannot leak via the outer value.
    const decoded = safeDecode(v);
    if (/^https?:\/\//i.test(decoded)) {
      if (depth >= 3) { redactions++; q.push(`${k}=${REDACTED}`); continue; }
      try {
        const inner = redactUrl(new URL(decoded), 120, depth + 1);
        redactions += inner.redactions;
        q.push(`${k}=${inner.display}`);
        continue;
      } catch { redactions++; q.push(`${k}=${REDACTED}`); continue; }
    }
    q.push(`${k}=${v.length > 64 ? v.slice(0, 64) + '…' : v}`);
  }
  let out = `${url.protocol}//${url.hostname}${url.port ? ':' + url.port : ''}${pathParts.join('/')}`;
  if (q.length) out += '?' + q.join('&');
  if (url.hash) out += '#[fragment omitted]';
  if (out.length > maxLen) out = out.slice(0, maxLen - 1) + '…';
  return { display: out, redactions };
}

/** Defang an already-redacted display string for safe copy/paste in reports. */
export function defang(display) {
  return String(display)
    .replace(/^http/i, 'hxxp')
    .replace(/^(hxxps?:\/\/)([^/?#:]+)/i, (_, p, h) => p + h.replace(/\./g, '[.]'));
}

/** Variant that drops the query string entirely (user-selected "less accurate" lookup option). */
export function withoutQuery(externalUrl) {
  const u = new URL(externalUrl);
  u.search = '';
  u.hash = '';
  return u.href;
}
