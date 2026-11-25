// Pure heuristic analysis of a parsed URL. No DOM, no network, no clock, no storage.
// Everything here is an INDICATOR derived from the URL string. Nothing is verified: TLS is not
// checked, DNS is not resolved, destinations are never fetched, and no threat feed is consulted.

import psl from 'psl';
import { parseTarget, redactUrl, defang, shannonEntropy, detectSensitive } from './shared/url-policy.js';
import { matchDemoFixture } from './data/demo-fixtures.js';
import * as R from './data/reference.js';

export const LIMITS = Object.freeze({
  maxParamsScanned: 40,
  maxDepth: 3,
  maxDestinations: 12,
  maxDecodeRounds: 3,
  maxTotalChars: 20000,
  maxMessageUrls: 10
});

export const BANDS = Object.freeze({ highAt: 50, suspiciousAt: 25 });

const GROUP_CAPS = { identity: 70, 'host-shape': 40, delivery: 35, lure: 40, encoding: 30, redirection: 50, transport: 10, hosting: 25, port: 10, structure: 10 };

// ---------------------------------------------------------------------------------------------
// Domain helpers (Public Suffix List via `psl`, which includes private suffixes such as github.io)
// ---------------------------------------------------------------------------------------------

export function registrableInfo(hostname, hostKind) {
  if (hostKind === 'ipv4' || hostKind === 'ipv6') {
    return { registrable: hostname, label: hostname, subdomains: 0, listed: false, suffix: null, isIp: true };
  }
  const p = psl.parse(hostname);
  if (p && p.domain) {
    const subs = p.subdomain ? p.subdomain.split('.').length : 0;
    return { registrable: p.domain, label: p.sld || '', subdomains: subs, listed: !!p.listed, suffix: p.tld, isIp: false };
  }
  const parts = hostname.split('.');
  return { registrable: parts.slice(-2).join('.'), label: parts.length > 1 ? parts[parts.length - 2] : parts[0], subdomains: Math.max(0, parts.length - 2), listed: false, suffix: null, isIp: false };
}

const hostMatches = (host, domain) => host === domain || host.endsWith('.' + domain);
export const isUgcHost = (host) => R.UGC_HOSTS.some((d) => hostMatches(host, d));

export function isTrustedHost(host, info) {
  return !isUgcHost(host) && R.TRUSTED_REGISTRABLE.includes(info.registrable);
}

function isKnownLegitBrand(host, info) {
  if (isTrustedHost(host, info)) return true;
  const all = [].concat(...Object.values(R.BRAND_DOMAINS), R.EXTRA_LEGIT_DOMAINS);
  return all.some((d) => hostMatches(host, d)) && !isUgcHost(host);
}

// On shared-hosting suffixes (e.g. github.io) the brand-like label belongs to the platform, not the page owner.
function stripUgcSuffix(host) {
  const d = R.UGC_HOSTS.find((u) => host.endsWith('.' + u));
  return d ? host.slice(0, -(d.length + 1)) : host;
}

function detectBrandAbuse(fullHost) {
  const host = stripUgcSuffix(fullHost);
  const tokens = host.split(/[.\-]/);
  for (const [brand, domains] of Object.entries(R.BRAND_DOMAINS)) {
    if (domains.some((d) => hostMatches(host, d))) continue;
    const mentioned = tokens.some((t) => t === brand || (t.startsWith(brand) && R.BRAND_SUFFIX.test(t.slice(brand.length))));
    const embedded = domains.some((d) => {
      const atBoundary = new RegExp('(^|[.\\-])' + d.replace(/\./g, '\\.')).test(host);
      return atBoundary || (d.split('.')[0].length >= 8 && host.includes(d));
    });
    if (mentioned || embedded) return { brand, embedded };
  }
  return null;
}

const skeletonize = (t) => t.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[1|]/g, 'l').replace(/0/g, 'o');

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[n];
}

function detectLookalike(host, info) {
  if (isKnownLegitBrand(host, info)) return null;
  const tokens = host.split(/[.\-]/).filter((t) => t.length >= 6 && !t.startsWith('xn--'));
  for (const t of tokens) {
    const sk = skeletonize(t);
    for (const target of R.LOOKALIKE_TARGETS) {
      if (t === target) continue;
      if (sk !== t && (sk === target || (sk.startsWith(target) && R.BRAND_SUFFIX.test(sk.slice(target.length))))) return { token: t, target, kind: 'homoglyph' };
      const limit = target.length >= 9 ? 2 : 1;
      const lenOk = target.length >= 8 ? Math.abs(t.length - target.length) <= limit : t.length === target.length;
      if (lenOk && levenshtein(t, target) <= limit) return { token: t, target, kind: 'typo' };
    }
  }
  return null;
}

function rawHostOf(raw) {
  let s = String(raw || '').replace(/^[a-z]+:\/\//i, '').replace(/^\/\//, '');
  s = s.split(/[\\/?#]/)[0] || '';
  if (s.includes('@')) s = s.slice(s.lastIndexOf('@') + 1);
  if (!s.startsWith('[')) s = s.replace(/:\d*$/, '');
  return s;
}

// ---------------------------------------------------------------------------------------------
// Nested-destination discovery (local string analysis only; destinations are never visited)
// ---------------------------------------------------------------------------------------------

const normName = (n) => String(n).toLowerCase().replace(/[-_.\s]/g, '');

export function decodeRounds(value, maxRounds = LIMITS.maxDecodeRounds) {
  let cur = String(value);
  let rounds = 0;
  for (; rounds < maxRounds; rounds++) {
    let next;
    try { next = decodeURIComponent(cur); } catch { break; }
    if (next === cur) break;
    cur = next;
  }
  return { value: cur, rounds };
}

function looksLikeUrl(d, redirectish) {
  const v = d.trim();
  if (/^https?:\/\//i.test(v) || /^www\./i.test(v) || /^\/\/[a-z0-9]/i.test(v)) return true;
  if (redirectish && /^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d{1,5})?([/?#].*)?$/i.test(v) && /\.[a-z]{2,}(:\d+)?([/?#]|$)/i.test(v)) return true;
  return false;
}

function candidatesFrom(url) {
  const out = [];
  let scanned = 0;
  const push = (source, value) => out.push({ source, value });
  for (const [k, v] of url.searchParams.entries()) {
    if (scanned++ >= LIMITS.maxParamsScanned) { out.truncatedParams = true; break; }
    const d = decodeRounds(v);
    if (looksLikeUrl(d.value, R.REDIRECT_PARAM_NAMES.includes(normName(k)))) push(`query:${k}`, d.value);
  }
  const body = url.hash.replace(/^#/, '').replace(/^[?/]+/, '');
  if (body) {
    let fp = [];
    try { fp = [...new URLSearchParams(body).entries()]; } catch { fp = []; }
    for (const [k, v] of fp.slice(0, 10)) {
      const d = decodeRounds(v);
      if (looksLikeUrl(d.value, R.REDIRECT_PARAM_NAMES.includes(normName(k)))) push(`fragment:${k}`, d.value);
    }
  }
  const dp = decodeRounds(url.pathname).value;
  const m = /\/(https?:\/\/[^\s]+)/i.exec(dp);
  if (m) push('path', m[1]);
  return out;
}

// ---------------------------------------------------------------------------------------------
// Rule evaluation
// ---------------------------------------------------------------------------------------------

function buildRules(ctx) {
  const { url, host, info, kind, raw, trusted, legit } = ctx;
  const pathname = url.pathname.toLowerCase();
  const search = url.search.toLowerCase();
  const rules = [];
  const add = (n, id, name, group, points, flagged, yes, no, extra = {}) =>
    rules.push({ n, id, name: `${n}. ${name}`, group, flagged: !!flagged, points: flagged ? points : 0, explanation: flagged ? yes : no, ...extra });
  const rep = (flag) => flag && !trusted; // reputation-style indicators are skipped for trusted, non-UGC hosts only

  const pathDepth = url.pathname.split('/').filter(Boolean).length;
  add(1, 'structure', 'URL Structure Anomalies', 'structure', 3, pathDepth > 7,
    'Unusually deep path (' + pathDepth + ' segments). Deep paths are common on legitimate sites too.', 'No unusual path depth.');
  add(26, 'userinfo', 'Credentials Embedded in URL (user:pass@)', 'identity', 25, ctx.hasUserinfo,
    'This URL embeds a username/password-style prefix, a technique used to disguise the real host.', 'No embedded credentials prefix.');

  const demo = matchDemoFixture(host);
  const decoy = /ap-my|gov-my|epf-claim/.test(host);
  add(2, 'demo-decoy', 'Demo Rule: Regional Decoy Pattern', 'identity', 25, decoy,
    'Hostname contains a pattern used by the project’s synthetic regional decoy example (demonstration rule, not a verified threat).', 'No demonstration decoy pattern.');

  const lookalike = detectLookalike(host, info);
  const pathTypo = pathname.includes('aplly') || pathname.includes('registar');
  const hostTypo = /cimbcllcks|maybnk|paypa1/.test(host);
  const typo = !!lookalike || pathTypo || hostTypo;
  add(3, 'typosquat', 'Possible Typosquatting / Homoglyphs', 'identity', 30, typo,
    lookalike ? (lookalike.kind === 'homoglyph' ? `Homoglyph-style substitution: '${lookalike.token}' resembles '${lookalike.target}'.` : `Near-miss spelling: '${lookalike.token}' resembles '${lookalike.target}'.`) : 'Contains a spelling pattern the demo rules associate with lure pages.',
    'No brand lookalike or common misspelling found.');

  const puny = host.startsWith('xn--') || host.includes('.xn--');
  add(4, 'idn', 'Punycode / Internationalized Hostname', 'host-shape', 10, puny,
    'Hostname uses punycode (xn--). Legitimate internationalized domains exist; this only means a look-alike is possible.', 'Hostname is plain ASCII.');

  const rawIp = kind === 'ipv4' || kind === 'ipv6';
  add(5, 'raw-ip', 'Raw IP Address Host', 'host-shape', 20, rawIp,
    'The URL targets an IP address rather than a domain name.', 'Host is a domain name.');
  const odd = url.port !== '' && url.port !== '80' && url.port !== '443';
  add(27, 'port', 'Non-standard Port', 'port', 10, odd,
    'Uses non-standard port ' + url.port + '. This is checked even for reputable domains.', 'Standard (or default) port.');

  const shortener = R.SHORTENERS.some((s) => hostMatches(host, s));
  add(6, 'shortener', 'URL Shortener', 'redirection', 15, shortener,
    'Known URL shortener: the final destination is hidden and was NOT resolved or visited by this tool.', 'Not a known shortener.');

  const brand = detectBrandAbuse(host);
  add(7, 'brand-stacking', 'Brand Name in Foreign Hostname', 'identity', brand && brand.embedded ? 55 : 35, rep(!!brand),
    brand ? (brand.embedded ? `A legitimate '${brand.brand}' domain string is embedded inside a different hostname.` : `Brand name '${brand.brand}' appears in a hostname not on the project’s list of that brand’s domains.`) : '',
    'No brand-name stacking found.');

  const enc = (ctx.href.match(/%[0-9a-f]{2}/gi) || []).length;
  const multi = ctx.href.includes('%25') || enc > 3;
  add(8, 'encoding', 'Heavy or Multiple Percent-Encoding', 'encoding', 12, multi,
    'Heavy or repeated percent-encoding can hide content from simple filters (also used legitimately for tracking parameters).', 'No unusual encoding.');

  const lure = R.LURE_WORDS.filter((w) => pathname.includes(w) || search.includes(w));
  add(9, 'lure-words', 'Marketing / Lure Keywords', 'lure', 15, lure.length > 0,
    `Contains words often used in incentive lures (${lure.join(', ')}). Many legitimate promotions use the same words.`, 'No lure keywords in path or query.');

  const tld = R.ABUSE_TLDS.some((t) => host.endsWith(t));
  add(10, 'tld', 'TLD Statistically Associated with Abuse', 'host-shape', 10, rep(tld),
    'This TLD is statistically over-represented in abuse reports; plenty of legitimate sites use it.', 'TLD is not on the project’s watch list.');

  const ext = R.DANGEROUS_EXTS.find((e) => pathname.endsWith(e));
  add(11, 'download-ext', 'Executable / Package File Extension', 'delivery', 20, !!ext,
    `Path ends in '${ext}', an executable or package type. A file extension is an indicator, not proof the file is malicious.`, 'No executable-type extension in path.');

  const tg = host === 't.me' || host === 'telegram.me';
  const tgFlag = tg && (/bot\b/.test(pathname) || /claim|angpao/.test(pathname));
  add(12, 'telegram', 'Telegram Link with Bot / Claim Wording', 'delivery', 15, tgFlag,
    'Telegram link whose name contains bot- or claim-style wording. Bot names are common and often legitimate; the bot’s behavior was not observed.', 'Not a Telegram bot/claim link.');

  const plain = url.protocol === 'http:';
  add(13, 'http', 'Plain HTTP (No Transport Encryption)', 'transport', 10, plain,
    'The URL uses http://, so traffic would not be encrypted.', url.protocol === 'https:' ? 'https:// syntax only. No certificate or TLS check was performed, and HTTPS alone does not establish trust.' : '');

  const redirParam = candidatesFrom(url).length > 0;
  add(14, 'url-param', 'URL-valued Parameter', 'redirection', 5, redirParam,
    'A query/fragment/path value contains another URL (possible redirect). Each such destination is analyzed separately below.', 'No URL-valued parameters found.');

  add(15, 'demo-fixture', 'Demonstration Fixture Match', 'identity', 35, !!demo,
    `Matches a hard-coded DEMONSTRATION fixture (${demo ? demo.note : ''}). This is not a verified threat-feed entry.`, 'No demonstration fixture match.');

  const ugc = isUgcHost(host);
  add(16, 'ugc', 'User-Generated Content / Shared Hosting', 'hosting', trusted || info.registrable === 'google.com' ? 20 : 12, ugc,
    'Anyone can publish pages on this platform, so the platform’s own reputation does not vouch for this page.', 'Not a known user-content hosting platform.');

  const gov = R.GOV.find((w) => host.split(/[.\-]/).some((t) => t === w || (t.startsWith(w) && R.BRAND_SUFFIX.test(t.slice(w.length)))));
  const regLegit = legit || R.REGLEGIT.some((d) => hostMatches(host, d));
  add(17, 'agency', 'Agency / Utility / Courier Name in Hostname', 'identity', 30, !!gov && !regLegit,
    `Hostname uses '${gov}' but is not a domain the project recognises for that organisation.`, 'No agency or courier name misuse found.');

  const cred = [...url.searchParams.keys()].map((k) => k.toLowerCase()).filter((k) => R.CRED_PARAMS.includes(k));
  add(18, 'cred-params', 'Credential-like Query Parameters', 'lure', 20, cred.length > 0 && !regLegit,
    'Query carries fields named ' + cred.join(', ') + '.', 'No credential-named query parameters.');

  const stuff = R.KEYSTUFF.filter((w) => host.includes(w));
  add(19, 'keyword-stuffing', 'Trust Words Stacked in Hostname', 'identity', 15, stuff.length >= 2 && !regLegit && !trusted,
    `Hostname stacks words like ${stuff.join(', ')}, a common phishing naming style (also used by some real services).`, 'No stacking of trust words in hostname.');

  const L = info.label.replace(/-/g, '');
  const digitHeavy = info.label.length >= 8 && info.label.replace(/[^0-9-]/g, '').length / info.label.length >= 0.4;
  const dga = !regLegit && !rawIp && !info.label.startsWith('xn--') && ((L.length >= 12 && shannonEntropy(L) >= 3.6) || digitHeavy);
  add(20, 'random-label', 'Random-looking Domain Label', 'host-shape', 15, rep(dga),
    `The registrable label '${info.label}' looks high-entropy or digit-heavy. This is a weak statistical signal.`, 'Registrable label looks human-readable.');

  add(21, 'subdomain-depth', 'Deep Subdomain Nesting', 'host-shape', 15, rep(info.subdomains >= 3 && !rawIp),
    `${info.subdomains} subdomain levels precede the registrable domain (${info.registrable}).`, `Normal subdomain depth (registrable domain: ${info.registrable}).`);

  const rh = rawHostOf(raw);
  const mixed = /[\u0400-\u04FF\u0370-\u03FF]/.test(rh) && /[a-z]/i.test(rh);
  const invis = /[\u200b-\u200f\u2060\ufeff\u00ad]/.test(raw || '');
  const obfIp = kind === 'ipv4' && rh !== '' && rh.toLowerCase() !== host;
  add(22, 'script-mixing', 'Script Mixing / Invisible Characters / Obfuscated IP', 'identity', 30, mixed || invis || obfIp,
    [mixed ? 'Mixed Latin and Cyrillic/Greek letters (possible homograph).' : '', invis ? 'Zero-width or invisible characters in the input.' : '', obfIp ? 'IP written in hex/octal/decimal form and normalized by the parser.' : ''].filter(Boolean).join(' '),
    'No script-mixing, invisible characters or obfuscated IP notation.');

  const blob = decodeRounds(url.search + url.hash).value.toLowerCase();
  const payload = /javascript:|data:text\/html|<script|vbscript:|base64,/.test(blob);
  const longUrl = url.href.length > 250;
  add(23, 'payload-length', 'Embedded Script/Data Payload or Very Long URL', 'encoding', payload ? 30 : 8, payload || longUrl,
    payload ? 'Query or fragment carries script/data-URI-like content.' : `URL is long (${url.href.length} characters). Length alone is a weak indicator.`, 'No embedded payload; URL length unremarkable.');

  return rules;
}

// ---------------------------------------------------------------------------------------------
// Scoring with correlated-finding discounting
// ---------------------------------------------------------------------------------------------

function applyGroups(findings) {
  const byGroup = new Map();
  for (const f of findings) if (f.flagged) { (byGroup.get(f.group) || byGroup.set(f.group, []).get(f.group)).push(f); }
  const groups = [];
  let total = 0;
  for (const [group, list] of byGroup) {
    list.sort((a, b) => b.points - a.points);
    let raw = 0;
    list.forEach((f, i) => { f.counted = i === 0 ? f.points : f.points * 0.5; raw += f.counted; });
    const cap = GROUP_CAPS[group] ?? 30;
    const scale = raw > cap ? cap / raw : 1;
    list.forEach((f) => { f.counted = Math.round(f.counted * scale * 10) / 10; });
    const score = Math.min(cap, raw);
    total += score;
    if (list.length > 1) {
      list.forEach((f) => { f.overlap = `Related to: ${list.filter((g) => g !== f).map((g) => g.name.replace(/^\d+\.\s*/, '')).join('; ')} (same underlying property; counted once at reduced weight).`; });
    }
    groups.push({ group, score: Math.round(score * 10) / 10, cap, findings: list.map((f) => f.id) });
  }
  return { groups, total };
}

export function bandFor(score, flaggedCount) {
  if (score >= BANDS.highAt) return 'high';
  if (score >= BANDS.suspiciousAt) return 'suspicious';
  return flaggedCount > 0 ? 'low' : 'none';
}

function mitre(findings, score) {
  const has = (...ids) => ids.some((id) => findings.some((f) => f.flagged && f.id === id));
  const out = [];
  if (score >= BANDS.suspiciousAt) out.push('T1566.002 Phishing: Spearphishing Link');
  if (has('demo-decoy', 'typosquat', 'brand-stacking', 'tld', 'agency', 'random-label', 'script-mixing')) out.push('T1583.001 Acquire Infrastructure: Domains');
  if (has('typosquat', 'brand-stacking', 'agency', 'script-mixing')) out.push('T1036.005 Masquerading: Match Legitimate Name or Location');
  if (has('lure-words', 'cred-params')) out.push('T1598.003 Phishing for Information: Spearphishing Link');
  if (has('download-ext')) out.push('T1204.002 User Execution: Malicious File');
  if (score >= BANDS.highAt) out.push('T1204.001 User Execution: Malicious Link');
  return out;
}

// ---------------------------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------------------------

function coreAnalyze(parsed, opts, state) {
  const url = parsed.url;
  const host = parsed.hostname;
  const info = registrableInfo(host, parsed.hostKind);
  const trusted = isTrustedHost(host, info);
  const legit = isKnownLegitBrand(host, info);
  const ctx = { url, host, info, kind: parsed.hostKind, raw: opts.raw || '', trusted, legit, hasUserinfo: parsed.hasUserinfo, href: parsed.href };
  const findings = buildRules(ctx);

  // Nested destinations
  const nestedEvidence = [];
  const depth = opts.depth || 0;
  const limitsHit = new Set();
  if (state.truncatedParams) limitsHit.add('max_params_scanned');
  const cands = candidatesFrom(url);
  if (cands.truncatedParams) limitsHit.add('max_params_scanned');
  for (const c of cands) {
    if (state.destinations >= LIMITS.maxDestinations) { limitsHit.add('max_destinations'); break; }
    if (depth + 1 > LIMITS.maxDepth) { limitsHit.add('max_depth'); break; }
    if (state.chars + c.value.length > LIMITS.maxTotalChars) { limitsHit.add('max_total_chars'); break; }
    state.chars += c.value.length;
    const p = parseTarget(c.value, { allowUserinfo: true });
    if (!p.ok) { nestedEvidence.push({ source: c.source, depth: depth + 1, status: 'unparseable', reason: p.code }); continue; }
    const key = p.externalUrl;
    if (state.visited.has(key)) { nestedEvidence.push({ source: c.source, depth: depth + 1, status: 'cycle_or_duplicate', host: p.hostname }); continue; }
    state.visited.add(key);
    state.destinations++;
    const sub = coreAnalyze(p, { raw: c.value, depth: depth + 1 }, state);
    sub.limitsHit.forEach((l) => limitsHit.add(l));
    nestedEvidence.push({
      source: c.source, depth: depth + 1, status: 'analyzed', host: p.hostname,
      display: redactUrl(p.url).display, score: sub.score, band: sub.band,
      flagged: sub.findings.filter((f) => f.flagged).map((f) => f.name.replace(/^\d+\.\s*/, '')),
      reserved: p.reserved, children: sub.nested
    });
  }
  const flatScores = [];
  (function walk(list) { for (const e of list) { if (e.status === 'analyzed') { flatScores.push(e.score); walk(e.children || []); } } })(nestedEvidence);
  const maxNested = flatScores.length ? Math.max(...flatScores) : 0;
  const np = maxNested >= BANDS.suspiciousAt ? Math.min(40, Math.round(maxNested * 0.6)) : 0;
  findings.push({
    n: 24, id: 'nested', name: '24. Nested Destination Analysis', group: 'redirection', flagged: np > 0, points: np,
    explanation: np > 0
      ? `${flatScores.length} embedded destination(s) analyzed; the highest local score among them is ${maxNested}/100. A harmless first destination does not hide a later one.`
      : (flatScores.length ? `${flatScores.length} embedded destination(s) analyzed; none reached the suspicious threshold locally.` : 'No embedded destination URLs found.'),
    evidenceCount: flatScores.length
  });

  if (opts.message) {
    const m = opts.message;
    const mp = m.cues.length >= 2 ? Math.min(25, m.cues.length * 7) : 0;
    findings.push({ n: 25, id: 'message', name: '25. Message Language Cues (SMS / Email)', group: 'lure', flagged: mp > 0, points: mp,
      explanation: mp > 0 ? 'Scam-style language categories in the pasted text: ' + m.cues.join(', ') + '. These cues are common in legitimate marketing too.' : 'No multi-category scam-language cues in the input text.' });
  } else {
    findings.push({ n: 25, id: 'message', name: '25. Message Language Cues (SMS / Email)', group: 'lure', flagged: false, points: 0, explanation: 'No message text supplied (URL-only input).' });
  }

  findings.sort((a, b) => a.n - b.n);
  const { groups, total } = applyGroups(findings);
  const score = Math.min(99, Math.round(total));
  const flaggedCount = findings.filter((f) => f.flagged).length;
  return { score, band: bandFor(score, flaggedCount), findings, groups, nested: nestedEvidence, limitsHit: [...limitsHit], info, trusted };
}

/**
 * Analyze a parsed target (result of parseTarget). Returns a plain JSON-safe object.
 * opts: { raw?: string (original input, for obfuscation checks), message?: { cues } }
 */
export function analyzeUrl(parsed, opts = {}) {
  const state = { destinations: 0, chars: 0, visited: new Set([parsed.externalUrl]) };
  const r = coreAnalyze(parsed, opts, state);
  const red = redactUrl(parsed.url);
  const sens = detectSensitive(parsed.url);
  const limitations = [
    'Local heuristics inspect only the URL text. No page was fetched, no DNS lookup or TLS/certificate check was made, and no destination was visited.',
    'The score is an uncalibrated sum of weak indicators, not a probability and not a malware verdict.'
  ];
  if (r.limitsHit.length) limitations.push('Inspection of nested destinations was truncated by safety limits (' + r.limitsHit.join(', ') + '); later destinations were not analyzed.');
  if (parsed.reserved) limitations.push(`Host is ${parsed.reservedReason}; it was analyzed locally only and never sent to external providers.`);
  return {
    score: r.score,
    band: r.band,
    findings: r.findings.map((f) => ({ n: f.n, id: f.id, name: f.name, group: f.group, flagged: f.flagged, points: f.points, counted: f.counted || 0, explanation: f.explanation, overlap: f.overlap || null })),
    groups: r.groups,
    nested: r.nested,
    nestedLimitsHit: r.limitsHit,
    registrableDomain: r.info.registrable,
    trustedExemptionApplied: r.trusted,
    suffixSource: 'Public Suffix List (psl package; ICANN and private sections)',
    mitre: { tentative: true, note: 'Possibly related ATT&CK techniques inferred from URL text alone; not confirmed.', techniques: mitre(r.findings, r.score) },
    display: red.display,
    redactions: red.redactions,
    defanged: defang(red.display),
    sensitive: { likely: sens.likely, reasons: sens.reasons },
    limitations
  };
}

// ---------------------------------------------------------------------------------------------
// Message helpers (SMS / email text containing one or more links)
// ---------------------------------------------------------------------------------------------

export function analyzeMessage(text) {
  return { cues: Object.keys(R.MESSAGE_CUES).filter((k) => R.MESSAGE_CUES[k].test(text)) };
}

export function extractUrls(text) {
  const t = String(text).slice(0, 5000);
  return (t.match(/(?:https?:\/\/|www\.)[^\s<>"')]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?:\/[^\s<>"')]*)?/gi) || [])
    .map((x) => x.replace(/[.,;!?]+$/, ''))
    .slice(0, LIMITS.maxMessageUrls);
}
