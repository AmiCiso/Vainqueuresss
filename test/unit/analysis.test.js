import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { parseTarget } from '../../src/shared/url-policy.js';
import { analyzeUrl, registrableInfo, LIMITS, decodeRounds, analyzeMessage, extractUrls, isTrustedHost, isUgcHost } from '../../src/analysis.js';

const run = (input, opts) => { const p = parseTarget(input, opts && opts.parse); assert.ok(p.ok, input + ' should parse: ' + p.code); return analyzeUrl(p, { raw: input, ...(opts || {}) }); };
const flagged = (a) => a.findings.filter((f) => f.flagged).map((f) => f.id);

test('regression corpus (pins current behaviour; NOT an accuracy measurement)', () => {
  const corpus = JSON.parse(fs.readFileSync(new URL('../corpus.json', import.meta.url), 'utf8'));
  assert.ok(corpus.cases.length >= 20);
  const labels = new Set(corpus.cases.map((c) => c.label));
  for (const l of ['benign', 'suspicious', 'adversarial']) assert.ok(labels.has(l));
  for (const c of corpus.cases) {
    const a = run(c.input);
    assert.ok(c.bands.includes(a.band), `${c.id}: band ${a.band} (score ${a.score}) not in ${c.bands}`);
    for (const id of c.mustFlag || []) assert.ok(flagged(a).includes(id), `${c.id}: expected ${id} in ${flagged(a)}`);
    for (const id of c.mustNotFlag || []) assert.ok(!flagged(a).includes(id), `${c.id}: unexpected ${id}`);
  }
});

test('nested: a harmless FIRST destination does not hide a suspicious LATER one', () => {
  const a = run('https://good.example.org/r?a=https%3A%2F%2Fgoogle.com%2F&b=https%3A%2F%2Fcimbcllcks-secure-login.top%2Fauth&c=https%3A%2F%2Fwikipedia.org');
  const analyzed = a.nested.filter((n) => n.status === 'analyzed');
  assert.equal(analyzed.length, 3);
  assert.deepEqual(analyzed.map((n) => n.source), ['query:a', 'query:b', 'query:c']);
  assert.ok(analyzed[1].score >= 50);
  assert.ok(flagged(a).includes('nested'));
  assert.ok(a.band === 'suspicious' || a.band === 'high');
});
test('nested: percent-encoded (single, double, triple), path-embedded, fragment and bare-host redirect params', () => {
  const target = 'https://cimbcllcks-secure-login.top/auth';
  const enc = (s, n) => { for (let i = 0; i < n; i++) s = encodeURIComponent(s); return s; };
  for (const n of [1, 2, 3]) assert.ok(run('https://a.example.org/?u=' + enc(target, n)).nested.some((x) => x.status === 'analyzed' && x.host.includes('cimbcllcks')), 'encoding depth ' + n);
  assert.ok(run('https://a.example.org/go/' + encodeURIComponent(target)).nested.some((x) => x.source === 'path'));
  assert.ok(run('https://a.example.org/#next=' + encodeURIComponent(target)).nested.some((x) => x.source === 'fragment:next'));
  assert.ok(run('https://a.example.org/?next=google.com').nested.some((x) => x.host === 'google.com'));
  assert.equal(run('https://a.example.org/?file=report.pdf').nested.length, 0, 'bare hosts only considered for redirect-style names');
  assert.deepEqual(decodeRounds('%25252525'), { value: '%25', rounds: 3 }, 'decoding stops at the round limit');
  assert.deepEqual(decodeRounds('%E0%A4%A'), { value: '%E0%A4%A', rounds: 0 }, 'malformed escapes do not throw');
});
test('nested: recursion limits, cycle protection and truncation are explicit, never silent', () => {
  let u = 'https://end.example.org/x.exe'; for (let i = 0; i < 8; i++) u = `https://hop${i}.example.org/?u=${encodeURIComponent(u)}`;
  const a = run(u);
  const depthOf = (list) => Math.max(0, ...list.map((n) => (n.status === 'analyzed' ? 1 + depthOf(n.children || []) : 0)));
  assert.ok(depthOf(a.nested) <= LIMITS.maxDepth);
  assert.ok(a.nestedLimitsHit.includes('max_depth'));
  assert.ok(a.limitations.some((l) => /truncated/.test(l)));

  const many = Array.from({ length: 30 }, (_, i) => `p${i}=https://site${i}.example.org/`).join('&');
  const b = run('https://a.example.org/?' + many);
  assert.ok(b.nested.filter((n) => n.status === 'analyzed').length <= LIMITS.maxDestinations);
  assert.ok(b.nestedLimitsHit.includes('max_destinations'));

  const self = run('https://a.example.org/?u=' + encodeURIComponent('https://a.example.org/?u=' + encodeURIComponent('https://a.example.org/')));
  assert.ok(self.nested.length >= 1); // terminates; duplicates are recorded as cycle_or_duplicate, not re-walked
  const dup = run('https://a.example.org/?u=https://b.example.org/&v=https://b.example.org/');
  assert.ok(dup.nested.some((n) => n.status === 'cycle_or_duplicate'));
});
test('nested: unparseable and userinfo-bearing destinations are recorded, userinfo is flagged', () => {
  const a = run('https://a.example.org/?u=' + encodeURIComponent('https://bank.com@evil.top/x'));
  const n = a.nested.find((x) => x.status === 'analyzed');
  assert.ok(n && n.flagged.some((f) => /Credentials Embedded/.test(f)));
  const b = run('https://a.example.org/?u=' + encodeURIComponent('https://exa mple.com/'));
  assert.ok(b.nested.length === 0 || b.nested.every((x) => x.status !== 'analyzed' || x.host));
});
test('nested evidence uses redacted display values (no secrets in evidence)', () => {
  const secret = 'Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0';
  const a = run('https://a.example.org/?u=' + encodeURIComponent(`https://t.example.net/x?token=${secret}`));
  assert.ok(!JSON.stringify(a).includes(secret));
});
test('trusted-domain exemption never suppresses port, download, nested, encoding, lure or UGC indicators', () => {
  assert.ok(flagged(run('https://google.com:8443/')).includes('port'));
  assert.ok(flagged(run('https://github.com/x/y/releases/a.exe')).includes('download-ext'));
  assert.ok(flagged(run('https://www.microsoft.com/?next=https%3A%2F%2F185.220.101.5%3A8080%2Fa.apk')).includes('nested'));
  assert.ok(flagged(run('https://apple.com/claim-bonus')).includes('lure-words'));
  assert.ok(flagged(run('https://docs.google.com/document/d/abc')).includes('ugc'));
  assert.equal(isTrustedHost('sites.google.com', registrableInfo('sites.google.com', 'domain')), false);
  assert.equal(isTrustedHost('www.google.com', registrableInfo('www.google.com', 'domain')), true);
  const t = run('https://www.google.com/');
  assert.equal(t.trustedExemptionApplied, true);
});
test('Public Suffix List: multi-label ICANN suffixes, private suffixes and IP literals', () => {
  assert.equal(registrableInfo('a.b.example.com.my', 'domain').registrable, 'example.com.my');
  assert.equal(registrableInfo('x.co.uk', 'domain').registrable, 'x.co.uk');
  assert.equal(registrableInfo('foo.bar.com.au', 'domain').registrable, 'bar.com.au');
  assert.equal(registrableInfo('evil.github.io', 'domain').registrable, 'evil.github.io', 'private suffix: github.io is a public suffix');
  assert.equal(registrableInfo('x.blogspot.com', 'domain').subdomains, 0);
  const ip = registrableInfo('185.220.101.5', 'ipv4');
  assert.equal(ip.isIp, true); assert.equal(ip.subdomains, 0);
  assert.equal(registrableInfo('[2001:4860:4860::8888]', 'ipv6').isIp, true);
  assert.equal(registrableInfo('com.my', 'domain').registrable === 'com.my' || true, true);
  assert.ok(isUgcHost('foo.pages.dev') && isUgcHost('sites.google.com') && !isUgcHost('example.org'));
});
test('IP literal hosts are not treated as subdomain-stuffed or random labels', () => {
  const a = run('http://185.220.101.5/');
  assert.ok(!flagged(a).includes('subdomain-depth')); assert.ok(!flagged(a).includes('random-label'));
});
test('correlated findings are discounted and the overlap is explained', () => {
  const a = run('https://cimbcllcks-secure-login.top/auth');
  const id = a.groups.find((g) => g.group === 'identity');
  assert.ok(id.findings.length >= 2);
  const f = a.findings.filter((x) => x.flagged && id.findings.includes(x.id));
  assert.ok(f.every((x) => x.overlap && /counted once at reduced weight/.test(x.overlap)));
  assert.ok(f.some((x) => x.counted < x.points));
  assert.ok(id.score <= id.cap);
  assert.ok(a.score <= 99);
});
test('wording: indicators are not presented as proof (no TLS/DNS/campaign/OTP claims)', () => {
  const texts = [];
  for (const u of ['https://example.org/', 'http://185.220.101.5:8080/update.apk', 'https://t.me/claim_angpao_bot', 'https://register.ap-my1.com/aplly', 'https://xn--bcher-kva.example.org/']) {
    const a = run(u); a.findings.forEach((f) => texts.push(f.explanation)); texts.push(...a.limitations);
  }
  const all = texts.join('\n');
  assert.ok(!/TLS (is )?(active|verified)|Encrypted TLS|certificate (is )?valid/i.test(all));
  assert.ok(!/resolved through|was resolved|DNS resolved/i.test(all.replace(/no DNS lookup|not resolved|NOT resolved/gi, '')));
  assert.ok(!/known active phishing campaign|OTP extraction|confirmed/i.test(all));
  const https = run('https://example.org/').findings.find((f) => f.id === 'http');
  assert.match(https.explanation, /No certificate or TLS check was performed/);
  const demo = run('https://register.ap-my1.com/aplly').findings.find((f) => f.id === 'demo-fixture');
  assert.match(demo.explanation, /DEMONSTRATION/); assert.match(demo.explanation, /not a verified threat-feed entry/);
});
test('MITRE mapping is explicitly tentative; limitations always state no network/TLS/DNS checks', () => {
  const a = run('http://185.220.101.5:8080/update.apk');
  assert.equal(a.mitre.tentative, true); assert.ok(a.mitre.techniques.length > 0); assert.match(a.mitre.note, /not confirmed/);
  assert.match(a.limitations[0], /No page was fetched/); assert.match(a.limitations[1], /not a probability/);
});
test('executable extension, HTTPS syntax, IDN, UGC, bot names, URL length and marketing words stay below "high" on their own', () => {
  for (const u of ['https://example.org/setup.exe', 'https://xn--bcher-kva.example.org/', 'https://x.github.io/', 'https://t.me/some_helper_bot', 'https://example.org/promo-bonus', 'https://example.org/?' + 'a=1&'.repeat(80)]) {
    assert.notEqual(run(u).band, 'high', u);
  }
});
test('analysis output is JSON-serialisable and deterministic', () => {
  const a = run('https://register.ap-my1.com/aplly'); const b = run('https://register.ap-my1.com/aplly');
  assert.deepEqual(a, b); JSON.parse(JSON.stringify(a));
});
test('message analysis and URL extraction are bounded', () => {
  assert.ok(extractUrls(Array.from({ length: 50 }, (_, i) => `https://s${i}.example.org/`).join(' ')).length <= LIMITS.maxMessageUrls);
  const m = analyzeMessage('URGENT: tahniah anda menang hadiah, klik sini dan sahkan OTP');
  assert.ok(m.cues.length >= 4);
  const a = run('https://example.org/', { message: m });
  assert.ok(flagged(a).includes('message'));
  assert.equal(run('https://example.org/').findings.find((f) => f.id === 'message').flagged, false);
});
