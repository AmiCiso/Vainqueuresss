import test from 'node:test';
import assert from 'node:assert/strict';
import { createScanService } from '../../server/scan-service.js';
import { ResultCache } from '../../server/cache.js';
import { Gate, Budget } from '../../server/guards.js';
import { buildConfig, parseTrustProxy } from '../../server/config.js';
import { corsDecision, buildCsp } from '../../server/policy.js';
import { jsonResponse, fakeFetch, gsbMatch, urlhausOk, testConfig } from './helpers.js';

const route = (f) => f; // readability
const providerFetch = ({ gsb = () => jsonResponse(200, {}), uh = () => jsonResponse(200, { query_status: 'no_results' }) } = {}) =>
  fakeFetch((url) => (url.includes('safebrowsing') ? gsb() : uh()));

test('request validation and status codes (service layer)', async () => {
  const s = createScanService(testConfig(), { fetchImpl: providerFetch() });
  assert.equal((await s.handleScan(null)).status, 400);
  assert.equal((await s.handleScan([])).status, 400);
  assert.equal((await s.handleScan({})).status, 400);
  assert.equal((await s.handleScan({ url: 5 })).status, 400);
  assert.equal((await s.handleScan({ url: '   ' })).status, 400);
  assert.equal((await s.handleScan({ url: 'https://example.com/' + 'a'.repeat(2100) })).json.error.code, 'too_long');
  assert.equal((await s.handleScan({ url: 'ftp://example.com' })).json.error.code, 'bad_scheme');
  assert.equal((await s.handleScan({ url: 'javascript:alert(1)' })).status, 400);
  const ui = await s.handleScan({ url: 'https://user:pw@example.com/' });
  assert.equal(ui.status, 400); assert.equal(ui.json.error.code, 'userinfo');
});

test('reserved / private / mapped-IPv6 / trailing-dot hosts are refused with 403 and never forwarded', async () => {
  const f = providerFetch();
  const s = createScanService(testConfig(), { fetchImpl: f });
  for (const u of ['http://127.0.0.1', 'http://localhost.', 'http://[::ffff:127.0.0.1]', 'http://[::ffff:7f00:1]', 'http://169.254.169.254/latest', 'http://10.0.0.5', 'http://[fd00::1]', 'http://0x7f.1', 'http://2130706433']) {
    const r = await s.handleScan({ url: u });
    assert.equal(r.status, 403, u); assert.equal(r.json.error.code, 'reserved_host');
  }
  assert.equal(f.calls.length, 0);
});

test('sensitive URLs require explicit acknowledgement (409), then are sent', async () => {
  const f = providerFetch();
  const s = createScanService(testConfig(), { fetchImpl: f });
  const url = 'https://example.com/reset/Ab3dE5gH7jK9mN1pQ2rS?token=abcdef123456';
  const r1 = await s.handleScan({ url });
  assert.equal(r1.status, 409); assert.equal(r1.json.error.code, 'sensitive_url_unacknowledged');
  assert.equal(f.calls.length, 0);
  const r2 = await s.handleScan({ url, acknowledgeSensitive: true });
  assert.equal(r2.status, 200); assert.equal(f.calls.length, 2);
  assert.equal((await s.handleScan({ url, acknowledgeSensitive: 'yes' })).status, 409);
});

test('fragment is never forwarded to providers; query and path are preserved', async () => {
  const f = providerFetch();
  const s = createScanService(testConfig(), { fetchImpl: f });
  await s.handleScan({ url: 'https://Example.com./a/b?x=1&y=2#secretfrag' });
  const gsbBody = JSON.parse(f.calls.find((c) => c.url.includes('safebrowsing')).init.body);
  assert.equal(gsbBody.threatInfo.threatEntries[0].url, 'https://example.com/a/b?x=1&y=2');
  assert.ok(!JSON.stringify(f.calls.map((c) => c.init.body)).includes('secretfrag'));
});

test('positive provider result + outage in the other provider keep individual outcomes visible', async () => {
  const f = providerFetch({ gsb: gsbMatch, uh: () => jsonResponse(503, {}) });
  const s = createScanService(testConfig(), { fetchImpl: f });
  const r = await s.handleScan({ url: 'https://example.com/' });
  assert.equal(r.status, 200);
  assert.equal(r.json.providers.gsb.status, 'match');
  assert.equal(r.json.providers.urlhaus.status, 'unavailable');
  assert.equal(r.json.coverage.matched, 1); assert.equal(r.json.coverage.complete, false);
  assert.equal(r.json.attribution.text, 'Advisory provided by Google');
});

test('unconfigured providers are reported as not_configured with partial coverage', async () => {
  const cfg = testConfig({ providers: { gsbKey: '', urlhausKey: 'K' } });
  const s = createScanService(cfg, { fetchImpl: providerFetch() });
  const r = await s.handleScan({ url: 'https://example.com/' });
  assert.equal(r.json.providers.gsb.status, 'not_configured');
  assert.equal(r.json.providers.urlhaus.status, 'no_match');
  assert.equal(r.json.coverage.complete, false);
  const none = createScanService(testConfig({ providers: { gsbKey: '', urlhausKey: '' } }), { fetchImpl: providerFetch() });
  const r2 = await none.handleScan({ url: 'https://example.com/' });
  assert.equal(r2.json.coverage.answered, 0); assert.equal(r2.json.coverage.configured, 0);
});

test('cache: answered results are cached, failures are not; keys are digests not URLs', async () => {
  const f = providerFetch();
  const s = createScanService(testConfig(), { fetchImpl: f });
  await s.handleScan({ url: 'https://example.com/path?secretish=1' });
  await s.handleScan({ url: 'https://example.com/path?secretish=1' });
  assert.equal(f.calls.length, 2, 'second scan served from cache for both providers');
  for (const k of s.cache.map.keys()) assert.match(k, /^[0-9a-f]{64}$/);
  assert.ok(!JSON.stringify([...s.cache.map.values()]).includes('secretish'));
  const bad = providerFetch({ gsb: () => jsonResponse(503, {}), uh: () => jsonResponse(503, {}) });
  const s2 = createScanService(testConfig(), { fetchImpl: bad });
  await s2.handleScan({ url: 'https://example.com/' }); await s2.handleScan({ url: 'https://example.com/' });
  assert.equal(bad.calls.length, 4, 'failures must not be cached');
});

test('request coalescing: concurrent identical lookups share one provider call', async () => {
  let release; const gate = new Promise((r) => { release = r; });
  const f = fakeFetch(async (url) => { await gate; return url.includes('safebrowsing') ? jsonResponse(200, {}) : jsonResponse(200, { query_status: 'no_results' }); });
  const s = createScanService(testConfig(), { fetchImpl: f });
  const ps = [1, 2, 3].map(() => s.handleScan({ url: 'https://example.com/x' }));
  await new Promise((r) => setTimeout(r, 20)); release();
  const rs = await Promise.all(ps);
  assert.equal(f.calls.length, 2);
  assert.ok(rs.every((r) => r.status === 200));
  assert.ok(rs.some((r) => r.json.providers.gsb.cache === 'coalesced'));
});

test('match TTL honours provider cacheDuration; no-match uses local TTL; cache is bounded', async () => {
  let now = 1_000_000;
  const f = providerFetch({ gsb: () => jsonResponse(200, { matches: [{ threatType: 'MALWARE', cacheDuration: '10s' }] }) });
  const s = createScanService(testConfig(), { fetchImpl: f, now: () => now });
  await s.handleScan({ url: 'https://example.com/' });
  now += 5000; await s.handleScan({ url: 'https://example.com/' });
  assert.equal(f.calls.filter((c) => c.url.includes('safebrowsing')).length, 1);
  now += 6000; await s.handleScan({ url: 'https://example.com/' });
  assert.equal(f.calls.filter((c) => c.url.includes('safebrowsing')).length, 2, 'expired after provider cacheDuration');
  const c = new ResultCache({ maxEntries: 3 });
  for (let i = 0; i < 10; i++) c.set('k' + i, i, 1000);
  assert.equal(c.size, 3);
});

test('global provider budget and busy gate produce quota/unavailable, never a clean result', async () => {
  const f = providerFetch();
  const s = createScanService(testConfig({ providers: { gsbBudgetPerMinute: 1, urlhausBudgetPerMinute: 100 } }), { fetchImpl: f });
  await s.handleScan({ url: 'https://one.example.org/' });
  const r = await s.handleScan({ url: 'https://two.example.org/' });
  assert.equal(r.json.providers.gsb.status, 'quota'); assert.ok(r.json.providers.gsb.retryAfterSec >= 1);
  assert.equal(r.json.providers.gsb.queried, false);
  const g = new Gate({ maxConcurrent: 1, maxQueue: 0 });
  const rel = await g.acquire();
  await assert.rejects(g.acquire(), { kind: 'busy' });
  rel(); await g.acquire();
  const b = new Budget({ limit: 2, windowMs: 1000, now: (() => { let t = 0; return () => t; })() });
  assert.ok(b.take().ok && b.take().ok); assert.equal(b.take().ok, false);
});

test('/api/providers never claims readiness from key presence alone', async () => {
  const s = createScanService(testConfig(), { fetchImpl: providerFetch() });
  const before = s.providersStatus().json;
  assert.equal(before.providers.gsb.configured, true);
  assert.equal(before.providers.gsb.state, 'configured_unverified');
  assert.ok(!JSON.stringify(before).includes('TESTKEY'));
  assert.ok(!/ready/i.test(JSON.stringify(before.providers)));
  await s.handleScan({ url: 'https://example.com/' });
  assert.equal(s.providersStatus().json.providers.gsb.state, 'last_lookup_answered');
  const bad = createScanService(testConfig(), { fetchImpl: providerFetch({ gsb: () => jsonResponse(403, { error: { status: 'PERMISSION_DENIED' } }) }) });
  await bad.handleScan({ url: 'https://example.com/' });
  assert.equal(bad.providersStatus().json.providers.gsb.state, 'last_lookup_auth_failed');
  const none = createScanService(testConfig({ providers: { gsbKey: '', urlhausKey: '' } }), {});
  assert.equal(none.providersStatus().json.providers.gsb.state, 'not_configured');
});

test('config: trust proxy is never blindly true; CORS defaults and decision', () => {
  assert.equal(parseTrustProxy(undefined), false);
  assert.equal(parseTrustProxy('1'), 1);
  assert.equal(parseTrustProxy('10.0.0.0/8, 192.168.0.1').length, 2);
  assert.throws(() => parseTrustProxy('true'));
  const dev = buildConfig({});
  for (const p of [3000, 5500, 5501]) assert.ok(dev.allowedOrigins.includes(`http://localhost:${p}`));
  const prod = buildConfig({ NODE_ENV: 'production' });
  assert.deepEqual(prod.allowedOrigins, []);
  assert.deepEqual(buildConfig({ NODE_ENV: 'production', PUBLIC_ORIGIN: 'https://v.example' }).allowedOrigins, ['https://v.example']);
  assert.equal(corsDecision(undefined, 'h', []).allowed, true);
  assert.equal(corsDecision('https://evil.example', 'v.example', ['https://v.example']).allowed, false);
  assert.equal(corsDecision('https://v.example', 'x', ['https://v.example']).allowed, true);
  assert.equal(corsDecision('https://same.example', 'same.example', []).allowed, true);
  assert.equal(corsDecision('not a url', 'h', []).allowed, false);
});

test('CSP is strict: no unsafe-inline/eval, scripts from self only', () => {
  const csp = buildCsp(testConfig());
  assert.ok(!/unsafe-inline|unsafe-eval/.test(csp));
  assert.match(csp, /script-src 'self'(;|$)/); assert.match(csp, /object-src 'none'/); assert.match(csp, /frame-ancestors 'none'/);
  assert.ok(!/upgrade-insecure/.test(csp));
  assert.match(buildCsp({ ...testConfig(), hsts: true }), /upgrade-insecure-requests/);
});
