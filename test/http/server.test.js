// HTTP integration tests against the REAL Express app (createApp). Providers are mocked; the network is never used.
// Requires `npm install` (express, express-rate-limit). These tests need no browser.
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApp } from '../../server/app.js';
import { fakeFetch, jsonResponse, testConfig } from '../unit/helpers.js';

const providers = (u) => (u.includes('safebrowsing') ? jsonResponse(200, {}) : jsonResponse(200, { query_status: 'no_results' }));

async function boot(over = {}, handler = providers) {
  const config = { ...testConfig(over.cfg || {}), ...(over.top || {}) };
  const { app } = await createApp(config, { fetchImpl: fakeFetch(handler) });
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  return { base: `http://127.0.0.1:${server.address().port}`, port: server.address().port, close: () => new Promise((r) => server.close(r)) };
}

/** Raw request so path-traversal strings are NOT normalized by fetch/URL. */
function raw(port, path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      let data = ''; res.on('data', (c) => { data += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}
const post = (base, body, headers = {}) => fetch(base + '/api/scan', { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });

let s;
before(async () => { s = await boot(); });
after(async () => { await s.close(); });

test('public assets are served', async () => {
  for (const [p, type] of [['/', 'text/html'], ['/index.html', 'text/html'], ['/assets/app.js', 'javascript'], ['/assets/app.css', 'text/css'], ['/vanquires.jpg', 'image/jpeg']]) {
    const r = await fetch(s.base + p);
    assert.equal(r.status, 200, p);
    assert.match(r.headers.get('content-type'), new RegExp(type), p);
  }
});

test('backend source, manifests, lockfiles, env files, tests and docs are NOT publicly accessible', async () => {
  const paths = ['/server.js', '/server/app.js', '/server/config.js', '/package.json', '/package-lock.json', '/README.md', '/.env', '/.env.example', '/.gitignore',
    '/test/corpus.json', '/test/unit/helpers.js', '/docs/REMEDIATION.md', '/src/main.js', '/src/analysis.js', '/scripts/build-js.mjs', '/node_modules/express/package.json', '/.git/config', '/public/index.html.bak', '/assets/.hidden'];
  for (const p of paths) {
    const r = await raw(s.port, p);
    assert.ok([403, 404].includes(r.status), `${p} -> ${r.status}`);
    assert.ok(!/express|createApp|SCAN_|"name":/.test(r.body), `${p} leaked content`);
  }
});

test('path traversal and encoded traversal never reach files outside public/', async () => {
  for (const p of ['/../server.js', '/..%2fserver.js', '/%2e%2e/server.js', '/assets/../../server.js', '/assets/%2e%2e/%2e%2e/package.json', '/..\\server.js', '/%00', '//etc/passwd']) {
    const r = await raw(s.port, p);
    assert.ok(r.status !== 200 || !/createApp|"name":/.test(r.body), `${p} -> ${r.status}`);
    assert.ok([400, 403, 404].includes(r.status), `${p} -> ${r.status}`);
  }
});

test('no directory listing; non-GET methods on static paths are not served', async () => {
  assert.equal((await raw(s.port, '/assets/')).status, 404);
  assert.equal((await raw(s.port, '/assets')).status, 404);
  assert.ok([404, 405].includes((await raw(s.port, '/', { method: 'POST' })).status));
});

test('security headers: strict CSP, nosniff, framing and referrer policy; no x-powered-by; HSTS only when configured', async () => {
  const r = await fetch(s.base + '/');
  const csp = r.headers.get('content-security-policy');
  assert.match(csp, /script-src 'self'(;|$)/); assert.ok(!/unsafe-inline|unsafe-eval/.test(csp)); assert.match(csp, /frame-ancestors 'none'/); assert.match(csp, /object-src 'none'/);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.ok(r.headers.get('referrer-policy')); assert.ok(r.headers.get('permissions-policy'));
  assert.equal(r.headers.get('x-powered-by'), null);
  assert.equal(r.headers.get('strict-transport-security'), null, 'HSTS is opt-in (HSTS=on) and only on secure requests');
  assert.equal((await fetch(s.base + '/api/providers')).headers.get('cache-control'), 'no-store');
});

test('API validation status codes: 400 malformed JSON, 413 oversized, 415 wrong type, 405 wrong method, 404 unknown', async () => {
  assert.equal((await post(s.base, '{not json')).status, 400);
  assert.equal((await post(s.base, 'null')).status, 400);
  assert.equal((await post(s.base, { url: 'x'.repeat(20000) })).status, 413);
  assert.equal((await fetch(s.base + '/api/scan', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'url=x' })).status, 415);
  assert.equal((await fetch(s.base + '/api/scan')).status, 405);
  assert.equal((await fetch(s.base + '/api/nope')).status, 404);
  assert.equal((await post(s.base, {})).status, 400);
  assert.equal((await post(s.base, { url: 'https://admin:pw@example.com/' })).status, 400);
  assert.equal((await post(s.base, { url: 'ftp://example.com' })).status, 400);
  assert.equal((await post(s.base, { url: 'https://example.com/' + 'a'.repeat(2100) })).status, 400);
  for (const u of ['http://127.0.0.1', 'http://localhost.', 'http://[::ffff:127.0.0.1]', 'http://[::ffff:7f00:1]']) assert.equal((await post(s.base, { url: u })).status, 403, u);
  assert.equal((await post(s.base, { url: 'https://example.org/reset/Ab3dE5gH7jK9mN1pQ2rS?token=abcdef123456' })).status, 409);
  const ok = await post(s.base, { url: 'https://example.org/' });
  assert.equal(ok.status, 200);
  const body = await ok.json();
  assert.equal(body.ok, true); assert.equal(body.providers.gsb.status, 'no_match');
});

test('error responses are JSON, generic, and never leak internals', async () => {
  const r = await post(s.base, '{bad'); const t = await r.text();
  assert.match(r.headers.get('content-type'), /json/);
  assert.ok(!/SyntaxError|at JSON|node_modules|stack/i.test(t));
});

test('CORS: allowlisted origin gets headers, preflight 204, disallowed origin 403, same-host origin allowed', async () => {
  const good = await post(s.base, { url: 'https://example.org/' }, { origin: 'http://localhost:3000' });
  assert.equal(good.status, 200); assert.equal(good.headers.get('access-control-allow-origin'), 'http://localhost:3000'); assert.match(good.headers.get('vary'), /Origin/i);
  const pre = await fetch(s.base + '/api/scan', { method: 'OPTIONS', headers: { origin: 'http://localhost:3000', 'access-control-request-method': 'POST' } });
  assert.equal(pre.status, 204); assert.match(pre.headers.get('access-control-allow-methods'), /POST/);
  const bad = await post(s.base, { url: 'https://example.org/' }, { origin: 'https://evil.example' });
  assert.equal(bad.status, 403); assert.equal(bad.headers.get('access-control-allow-origin'), null);
  assert.equal((await post(s.base, { url: 'https://example.org/' }, { origin: s.base })).status, 200);
});

test('/api/providers exposes configuration state without secrets or readiness claims', async () => {
  const j = await (await fetch(s.base + '/api/providers')).json();
  assert.equal(j.providers.gsb.state, 'configured_unverified');
  assert.ok(!JSON.stringify(j).includes('TESTKEY'));
});

test('rate limiting: 429 with Retry-After and JSON body; X-Forwarded-For cannot bypass it when trust proxy is off', async () => {
  const lim = await boot({ cfg: { rateLimit: { limit: 3 } } });
  const codes = [];
  for (let i = 0; i < 5; i++) {
    const r = await fetch(lim.base + '/api/providers', { headers: { 'x-forwarded-for': `10.0.0.${i + 1}` } });
    codes.push(r.status);
    if (r.status === 429) { assert.ok(Number(r.headers.get('retry-after')) >= 1); assert.equal((await r.json()).error.code, 'rate_limited'); }
  }
  assert.deepEqual(codes, [200, 200, 200, 429, 429]);
  await lim.close();
});

test('trust proxy = 1 keys the limiter on the proxy-appended client address, not on client-forged leftmost values', async () => {
  const lim = await boot({ cfg: { rateLimit: { limit: 2 } }, top: { trustProxy: 1 } });
  const hit = (xff) => fetch(lim.base + '/api/providers', { headers: { 'x-forwarded-for': xff } }).then((r) => r.status);
  assert.equal(await hit('203.0.113.9'), 200); assert.equal(await hit('203.0.113.9'), 200); assert.equal(await hit('203.0.113.9'), 429);
  assert.equal(await hit('198.51.100.7'), 200, 'a different real client (last hop) has its own budget');
  assert.equal(await hit('6.6.6.6, 203.0.113.9'), 429, 'forged leftmost entries do not reset the budget');
  await lim.close();
});
