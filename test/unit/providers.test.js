import test from 'node:test';
import assert from 'node:assert/strict';
import { interpretGsb, interpretUrlhaus, queryGsb, queryUrlhaus, GSB_ENDPOINT, URLHAUS_ENDPOINT, parseCacheDuration } from '../../server/providers.js';
import { fetchJson } from '../../server/net.js';
import { jsonResponse, fakeFetch, gsbMatch, urlhausOk } from './helpers.js';

const H = new Headers();

test('GSB: legitimate empty-object response is a no-match', () => {
  const r = interpretGsb(200, {}, false, H);
  assert.equal(r.status, 'no_match'); assert.equal(r.queried, true);
});
test('GSB: unrelated malformed 200 shapes are NOT clean results', () => {
  for (const body of [{ foo: 1 }, [], 'ok', null, { matches: 'x' }, { matches: [{ nope: 1 }] }, { error: {} }, { matches: [], extra: 1 }]) {
    const r = interpretGsb(200, body, false, H);
    assert.equal(r.status, 'unexpected_response', JSON.stringify(body));
    assert.equal(r.queried, false);
  }
  assert.equal(interpretGsb(200, null, true, H).status, 'unexpected_response');
});
test('GSB: match preserves threat types and provider cache duration', () => {
  const r = interpretGsb(200, { matches: [{ threatType: 'MALWARE', platformType: 'WINDOWS', cacheDuration: '120.5s' }, { threatType: 'SOCIAL_ENGINEERING', cacheDuration: '300s' }] }, false, H);
  assert.equal(r.status, 'match');
  assert.deepEqual(r.evidence.threatTypes, ['MALWARE', 'SOCIAL_ENGINEERING']);
  assert.equal(r.evidence.cacheDurationSec, 121);
  assert.deepEqual(r.threats, ['GSB:MALWARE', 'GSB:SOCIAL_ENGINEERING']);
});
test('GSB: failure classes are distinguished', () => {
  assert.equal(interpretGsb(429, {}, false, new Headers({ 'retry-after': '30' })).retryAfterSec, 30);
  assert.equal(interpretGsb(429, {}, false, H).status, 'quota');
  assert.equal(interpretGsb(403, { error: { status: 'PERMISSION_DENIED' } }, false, H).status, 'auth_error');
  assert.equal(interpretGsb(400, { error: { details: [{ reason: 'API_KEY_INVALID' }] } }, false, H).status, 'auth_error');
  assert.equal(interpretGsb(400, { error: { status: 'INVALID_ARGUMENT' } }, false, H).status, 'rejected');
  assert.equal(interpretGsb(503, null, false, H).status, 'unavailable');
});
test('URLhaus: ok/no_results/invalid_url/auth/quota/unexpected', () => {
  const ok = interpretUrlhaus(200, { query_status: 'ok', url_status: 'offline', threat: 'malware_download', tags: ['a', 5], date_added: 'd', urlhaus_reference: 'https://urlhaus.abuse.ch/url/9/' }, false, H);
  assert.equal(ok.status, 'match'); assert.equal(ok.evidence.urlStatus, 'offline'); assert.deepEqual(ok.evidence.tags, ['a']);
  assert.equal(interpretUrlhaus(200, { query_status: 'no_results' }, false, H).status, 'no_match');
  assert.equal(interpretUrlhaus(200, { query_status: 'invalid_url' }, false, H).status, 'rejected');
  assert.equal(interpretUrlhaus(403, { query_status: 'unknown_auth_key' }, false, H).status, 'auth_error');
  assert.equal(interpretUrlhaus(401, null, false, H).status, 'auth_error');
  assert.equal(interpretUrlhaus(429, null, false, H).status, 'quota');
  assert.equal(interpretUrlhaus(200, { query_status: 'surprise' }, false, H).status, 'unexpected_response');
  assert.equal(interpretUrlhaus(200, {}, false, H).status, 'unexpected_response');
  assert.equal(interpretUrlhaus(200, { query_status: 'ok' }, false, H).status, 'unexpected_response');
  assert.equal(interpretUrlhaus(200, [], false, H).status, 'unexpected_response');
});
test('URLhaus: untrusted reference links are dropped', () => {
  const r = interpretUrlhaus(200, { query_status: 'ok', url_status: 'online', urlhaus_reference: 'https://evil.example/x' }, false, H);
  assert.equal(r.evidence.reference, null);
});
test('parseCacheDuration', () => {
  assert.equal(parseCacheDuration('300.000s'), 300);
  assert.equal(parseCacheDuration('bogus'), null);
  assert.equal(parseCacheDuration('99999s'), 3600);
});

test('adapters call only the fixed endpoints, with keys server-side and data in the body', async () => {
  const f = fakeFetch(() => jsonResponse(200, {}));
  await queryGsb({ fetchImpl: f, key: 'K1', url: 'https://example.com/a', timeoutMs: 500, maxBytes: 65536 });
  assert.ok(f.calls[0].url.startsWith(GSB_ENDPOINT + '?key=K1'));
  assert.equal(f.calls[0].init.method, 'POST');
  assert.equal(f.calls[0].init.redirect, 'error');
  assert.equal(JSON.parse(f.calls[0].init.body).threatInfo.threatEntries[0].url, 'https://example.com/a');
  const g = fakeFetch(() => jsonResponse(200, { query_status: 'no_results' }));
  await queryUrlhaus({ fetchImpl: g, key: 'K2', url: 'https://example.com/a', timeoutMs: 500, maxBytes: 65536 });
  assert.equal(g.calls[0].url, URLHAUS_ENDPOINT);
  assert.equal(g.calls[0].init.headers['Auth-Key'], 'K2');
  assert.equal(new URLSearchParams(g.calls[0].init.body).get('url'), 'https://example.com/a');
});
test('missing keys -> not_configured (never a clean result)', async () => {
  const f = fakeFetch(() => { throw new Error('should not be called'); });
  const a = await queryGsb({ fetchImpl: f, key: '', url: 'https://example.com/' });
  const b = await queryUrlhaus({ fetchImpl: f, key: '', url: 'https://example.com/' });
  assert.equal(a.status, 'not_configured'); assert.equal(b.status, 'not_configured');
  assert.equal(a.queried, false); assert.equal(f.calls.length, 0);
});
test('timeout and network failure are distinct statuses', async () => {
  const hang = fakeFetch((url, init) => new Promise((_, rej) => init.signal.addEventListener('abort', () => rej(Object.assign(new Error('aborted'), { name: 'AbortError' })))));
  assert.equal((await queryGsb({ fetchImpl: hang, key: 'K', url: 'https://example.com/', timeoutMs: 40, maxBytes: 1000 })).status, 'timeout');
  const down = fakeFetch(() => { throw new TypeError('fetch failed'); });
  assert.equal((await queryUrlhaus({ fetchImpl: down, key: 'K', url: 'https://example.com/', timeoutMs: 40, maxBytes: 1000 })).status, 'network_error');
});
test('abort timer stays active while the response BODY is being read', async () => {
  const stall = fakeFetch((url, init) => {
    const body = new ReadableStream({ start(c) { init.signal.addEventListener('abort', () => c.error(Object.assign(new Error('aborted'), { name: 'AbortError' }))); } });
    return new Response(body, { status: 200 });
  });
  const t0 = Date.now();
  const r = await queryGsb({ fetchImpl: stall, key: 'K', url: 'https://example.com/', timeoutMs: 60, maxBytes: 1000 });
  assert.equal(r.status, 'timeout');
  assert.ok(Date.now() - t0 < 1000);
});
test('oversized provider responses are rejected, not parsed', async () => {
  const big = fakeFetch(() => new Response('{"x":"' + 'a'.repeat(5000) + '"}', { status: 200 }));
  const r = await queryGsb({ fetchImpl: big, key: 'K', url: 'https://example.com/', timeoutMs: 500, maxBytes: 1000 });
  assert.equal(r.status, 'unexpected_response');
});
test('fetchJson never throws on unparseable JSON', async () => {
  const f = fakeFetch(() => new Response('<html>', { status: 200 }));
  const r = await fetchJson(f, 'https://x/', {}, { timeoutMs: 200, maxBytes: 1000 });
  assert.equal(r.parseFailed, true);
});
test('helper fixtures are well-formed', () => {
  assert.equal(interpretGsb(200, JSON.parse('{"matches":[{"threatType":"SOCIAL_ENGINEERING","cacheDuration":"300.000s"}]}'), false, H).status, 'match');
  assert.ok(gsbMatch() instanceof Response && urlhausOk() instanceof Response);
});
