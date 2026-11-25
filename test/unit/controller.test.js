import test from 'node:test';
import assert from 'node:assert/strict';
import { createScanController, PHASES } from '../../src/scan-controller.js';
import { createHistoryStore, HISTORY_KEY } from '../../src/history.js';
import * as R from '../../src/report.js';
import { memoryStorage, deferredFetch, gatewayBody, pNoMatch, pMatch, pFail, okResp, tick } from './helpers.js';

const LOW = 'https://example.org/about';                    // no local indicators
const HIGH = 'https://cimbcllcks-secure-login.top/auth';       // high heuristic risk
const SECRET = 'Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0';

function setup({ fetchImpl, storage = memoryStorage(), timeoutMs = 2000 } = {}) {
  let n = 0; let clock = Date.parse('2026-06-01T00:00:00Z');
  const history = createHistoryStore({ storage, now: () => clock });
  history.load();
  const events = [];
  const ctl = createScanController({ history, fetchImpl, now: () => (clock += 1000), newId: () => 'scan-' + (++n), onChange: (s) => events.push(s), timeoutMs });
  return { ctl, history, storage, events };
}

test('provider-positive result overrides low local risk; heuristic score is preserved as a separate measurement', async () => {
  const f = deferredFetch(); const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' });
  let s = ctl.getState();
  assert.equal(s.report.verdict.level, 'no_local_indicators'); assert.equal(s.report.verdict.provisional, true);
  assert.equal(s.phase, PHASES.LOOKUP);
  f.calls[0].resolve(okResp(gatewayBody(pMatch(), pNoMatch())));
  await tick(5);
  s = ctl.getState();
  assert.equal(s.report.verdict.level, 'threat_reported');
  assert.equal(s.report.verdict.label, 'Threat reported by provider');
  assert.equal(s.report.heuristic.score, 0, 'original heuristic score stays untouched');
  assert.equal(s.report.heuristic.band, 'none');
  assert.equal(s.report.verdict.provisional, false);
  assert.equal(s.phase, PHASES.DONE);
});

test('a successful no-match never erases strong heuristic findings', async () => {
  const f = deferredFetch(); const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(HIGH, { lookup: 'external' });
  f.calls[0].resolve(okResp(gatewayBody(pNoMatch(), pNoMatch())));
  await tick(5);
  const r = ctl.getState().report;
  assert.equal(r.verdict.level, 'high_heuristic_risk');
  assert.equal(r.lookup.state, 'complete');
  assert.match(r.verdict.externalNote, /does not clear the local indicators/);
});

test('UI report, history record and export agree; enrichment updates the SAME history record (no duplicate)', async () => {
  const f = deferredFetch(); const { ctl, history, storage } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' });
  assert.equal(history.list().length, 1); assert.equal(history.list()[0].lookupState, 'pending');
  assert.equal(ctl.exportCurrent(), null, 'export unavailable while pending');
  assert.equal(ctl.getState().exportReady, false);
  f.calls[0].resolve(okResp(gatewayBody(pMatch('URLhaus:malware_download'), pNoMatch())));
  await tick(5);
  const s = ctl.getState();
  assert.equal(history.list().length, 1, 'still one record');
  const h = history.list()[0]; const exp = ctl.exportCurrent();
  assert.equal(h.scanId, s.report.scanId); assert.equal(exp.report.scanId, s.report.scanId);
  assert.equal(h.verdictLevel, s.report.verdict.level); assert.equal(exp.report.verdict.level, s.report.verdict.level);
  assert.equal(h.lookupState, 'complete'); assert.equal(exp.exportStatus, 'final');
  assert.equal(h.heuristicScore, s.report.heuristic.score);
  assert.equal(h.providers.gsb.status, s.report.providers.gsb.status);
  assert.deepEqual(JSON.parse(storage.getItem(HISTORY_KEY)).map((e) => e.scanId), [s.report.scanId]);
  assert.equal(R.isThreatFlag(h.verdictLevel), true);
});

test('toExport marks a pending report as incomplete even if called directly', () => {
  const f = deferredFetch(); const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' });
  const e = R.toExport(ctl.getState().report, Date.now());
  assert.equal(e.exportStatus, 'incomplete'); assert.match(e.incompleteReason, /still in progress/);
});

test('provider states: pending, partial, unavailable and unconfigured are never presented as clean', async () => {
  const cases = [
    [pNoMatch(), pFail('not_configured'), 'partial', /incomplete/],
    [pFail('not_configured'), pFail('not_configured'), 'failed', /failed|not a clean result/],
    [pFail('timeout'), pNoMatch(), 'partial', /incomplete/],
    [pFail('quota'), pFail('unavailable'), 'failed', /not a clean result/],
    [pFail('auth_error'), pNoMatch(), 'partial', /incomplete/],
    [pFail('unexpected_response'), pFail('network_error'), 'failed', /not a clean result/]
  ];
  for (const [g, u, state, re] of cases) {
    const f = deferredFetch(); const { ctl } = setup({ fetchImpl: f });
    ctl.startScan(LOW, { lookup: 'external' });
    f.calls[0].resolve(okResp(gatewayBody(g, u))); await tick(5);
    const r = ctl.getState().report;
    assert.equal(r.lookup.state, state, `${g.status}/${u.status}`);
    assert.match(r.verdict.externalNote, re);
    assert.ok(!/reported no match/.test(r.verdict.externalNote.replace(/Both providers answered and reported no match/, '')) || state === 'complete');
  }
  const f = deferredFetch(); const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' });
  assert.equal(ctl.getState().report.providers.gsb.status, 'pending');
  assert.equal(ctl.getState().report.lookup.state, 'pending');
});

test('individual provider outcomes stay visible when coverage is partial', async () => {
  const f = deferredFetch(); const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' });
  f.calls[0].resolve(okResp(gatewayBody(pMatch(), pFail('timeout', 'Provider request timed out')))); await tick(5);
  const r = ctl.getState().report;
  assert.equal(r.providers.gsb.status, 'match'); assert.equal(r.providers.urlhaus.status, 'timeout');
  assert.equal(r.lookup.state, 'partial'); assert.equal(r.verdict.level, 'threat_reported');
});

test('STALE success from scan A never overwrites scan B (banner, badges, report, history, loading state)', async () => {
  const f = deferredFetch(); const { ctl, history } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' });             // scan A (scan-1)
  const idA = ctl.getState().report.scanId;
  ctl.startScan(HIGH, { lookup: 'external' });            // scan B (scan-2)
  const idB = ctl.getState().report.scanId;
  assert.equal(f.calls[0].aborted, true, 'obsolete request aborted');
  // A "late" success arrives anyway (fake ignores the abort for resolve ordering)
  f.calls[0].resolve = f.calls[0].resolve; // no-op: reject already happened via abort
  f.calls[1].resolve(okResp(gatewayBody(pNoMatch(), pNoMatch()))); await tick(5);
  const s = ctl.getState();
  assert.equal(s.report.scanId, idB); assert.equal(s.report.verdict.level, 'high_heuristic_risk');
  assert.equal(s.phase, PHASES.DONE);
  const hA = history.list().find((h) => h.scanId === idA);
  assert.equal(hA.lookupState, 'interrupted'); assert.notEqual(hA.verdictLevel, 'threat_reported');
  assert.equal(history.list().length, 2);
});

test('STALE success that ignores abort (misbehaving transport) is still dropped', async () => {
  let calls = [];
  const f = (url, init) => new Promise((resolve) => { calls.push(resolve); }); // never honors abort
  const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' });
  ctl.startScan(HIGH, { lookup: 'external' });
  calls[0](okResp(gatewayBody(pMatch(), pMatch()))); await tick(5);   // A answers late with a threat
  let s = ctl.getState();
  assert.equal(s.report.verdict.level, 'high_heuristic_risk', 'B untouched');
  assert.equal(s.phase, PHASES.LOOKUP, 'B still genuinely pending');
  assert.equal(s.report.providers.gsb.status, 'pending');
  calls[1](okResp(gatewayBody(pNoMatch(), pNoMatch()))); await tick(5);
  assert.equal(ctl.getState().phase, PHASES.DONE);
});

test('STALE failure from scan A (timeout/outage) never marks scan B failed', async () => {
  const rejecters = [];
  const f = (url, init) => new Promise((_, reject) => { rejecters.push(reject); });
  const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' });
  ctl.startScan(HIGH, { lookup: 'external' });
  rejecters[0](new TypeError('fetch failed')); await tick(5);
  const s = ctl.getState();
  assert.equal(s.report.providers.gsb.status, 'pending'); assert.equal(s.report.lookup.error, null); assert.equal(s.phase, PHASES.LOOKUP);
});

test('all provider badges are reset when a new scan begins', async () => {
  const f = deferredFetch(); const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' });
  f.calls[0].resolve(okResp(gatewayBody(pMatch(), pMatch()))); await tick(5);
  assert.equal(ctl.getState().report.providers.gsb.status, 'match');
  ctl.startScan(LOW, { lookup: 'external' });
  const r = ctl.getState().report;
  assert.equal(r.providers.gsb.status, 'pending'); assert.equal(r.providers.urlhaus.status, 'pending');
  assert.equal(r.providers.gsb.threats.length, 0);
  ctl.startScan(LOW, { lookup: 'local' });
  assert.equal(ctl.getState().report.providers.gsb.status, 'not_requested');
});

test('HTTP 429 is explicit, preserves Retry-After, and is NOT retried automatically', async () => {
  let n = 0;
  const f = async () => { n++; return okResp({ ok: false, error: { code: 'rate_limited' } }, 429, { 'retry-after': '42' }); };
  const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' }); await tick(10);
  const r = ctl.getState().report;
  assert.equal(n, 1);
  assert.equal(r.providers.gsb.status, 'quota'); assert.equal(r.lookup.error.code, 'rate_limited'); assert.equal(r.lookup.retryAfterSec, 42);
  assert.equal(r.lookup.state, 'failed'); assert.match(r.verdict.externalNote, /not a clean result/);
  assert.equal(ctl.getState().canRetryLookup, true);
  assert.equal(n, 1);
});

test('backend down, malformed responses, validation failures, 5xx and busy are each explicit', async () => {
  const scenarios = [
    [() => { throw new TypeError('Failed to fetch'); }, 'unreachable', 'network_error'],
    [async () => new Response('<html>', { status: 200 }), 'malformed', 'unexpected_response'],
    [async () => okResp({ ok: true, providers: { gsb: { status: 'weird' }, urlhaus: pNoMatch() } }), 'malformed', 'unexpected_response'],
    [async () => okResp({ ok: true }), 'malformed', 'unexpected_response'],
    [async () => okResp({ ok: true, providers: [] }), 'malformed', 'unexpected_response'],
    [async () => okResp({ ok: false, error: { code: 'invalid_url' } }, 400), 'rejected', 'rejected'],
    [async () => okResp({}, 500), 'server_error', 'unavailable'],
    [async () => okResp({}, 503, { 'retry-after': '5' }), 'busy', 'unavailable'],
    [async () => okResp({ ok: false, error: { code: 'origin_not_allowed' } }, 403), 'origin_not_allowed', 'rejected'],
    [async () => okResp({ ok: false, error: { code: 'reserved_host' } }, 403), 'rejected', 'rejected']
  ];
  for (const [fn, code, status] of scenarios) {
    const { ctl } = setup({ fetchImpl: fn });
    ctl.startScan(LOW, { lookup: 'external' }); await tick(10);
    const r = ctl.getState().report;
    assert.equal(r.lookup.error.code, code, code);
    assert.equal(r.providers.gsb.status, status, code);
    assert.equal(r.lookup.state, 'failed');
    assert.notEqual(r.verdict.level, 'threat_reported');
    assert.match(r.verdict.externalNote, /not a clean result/);
    assert.equal(ctl.getState().phase, PHASES.DONE, 'no loading indicator left behind');
  }
});

test('timeout covers the response BODY read as well as the request', async () => {
  const f = (url, init) => {
    const body = new ReadableStream({ start(c) { init.signal.addEventListener('abort', () => c.error(Object.assign(new Error('aborted'), { name: 'AbortError' }))); } });
    return Promise.resolve(new Response(body, { status: 200 }));
  };
  const { ctl } = setup({ fetchImpl: f, timeoutMs: 60 });
  ctl.startScan(LOW, { lookup: 'external' }); await tick(250);
  const r = ctl.getState().report;
  assert.equal(r.lookup.error.code, 'timeout'); assert.equal(r.providers.gsb.status, 'timeout'); assert.equal(ctl.getState().phase, PHASES.DONE);
});

test('no timer-based fake completion: pending state persists until a real answer', async () => {
  const f = deferredFetch(); const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' });
  await tick(400);
  const s = ctl.getState();
  assert.equal(s.phase, PHASES.LOOKUP); assert.equal(s.report.lookup.state, 'pending'); assert.equal(s.exportReady, false);
});

test('local-only mode and sample presets never touch the network', () => {
  let calls = 0; const f = async () => { calls++; return okResp({}); };
  const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(HIGH, { lookup: 'local' });
  assert.equal(ctl.getState().report.lookup.state, 'not_requested');
  assert.equal(ctl.getState().report.providers.gsb.status, 'not_requested');
  assert.match(ctl.getState().report.verdict.externalNote, /not requested/);
  ctl.startScan(HIGH, { lookup: 'external', sample: true });
  assert.equal(ctl.getState().report.providers.gsb.status, 'not_requested');
  assert.match(ctl.getState().report.providers.gsb.reason, /Sample presets/);
  assert.equal(calls, 0);
});

test('reserved hosts are analyzed locally and skipped (not sent)', () => {
  let calls = 0; const f = async () => { calls++; return okResp({}); };
  for (const u of ['http://127.0.0.1/', 'http://localhost./', 'http://[::ffff:127.0.0.1]/', 'http://[::ffff:7f00:1]/']) {
    const { ctl } = setup({ fetchImpl: f });
    assert.equal(ctl.startScan(u, { lookup: 'external' }).ok, true);
    const r = ctl.getState().report;
    assert.equal(r.lookup.state, 'skipped', u); assert.equal(r.providers.gsb.status, 'skipped');
    assert.match(r.providers.gsb.reason, /Not sent/);
    assert.ok(r.heuristic.score >= 0);
  }
  assert.equal(calls, 0);
});

test('userinfo URLs are rejected before analysis, history or network', () => {
  let calls = 0; const f = async () => { calls++; return okResp({}); };
  const { ctl, history } = setup({ fetchImpl: f });
  const r = ctl.startScan('https://admin:hunter2@example.com/', { lookup: 'external' });
  assert.equal(r.ok, false); assert.match(r.error, /username or password/);
  assert.equal(history.list().length, 0); assert.equal(calls, 0);
  assert.equal(ctl.getState().phase, PHASES.IDLE);
  assert.ok(!JSON.stringify(ctl.getState()).includes('hunter2'));
});

test('sensitive URL: external lookup waits for an informed choice and sends nothing before it', async () => {
  const f = deferredFetch(); const { ctl, history, storage } = setup({ fetchImpl: f });
  const url = `https://example.org/reset/${SECRET}/done?token=${SECRET}&lang=en#access_token=${SECRET}`;
  ctl.startScan(url, { lookup: 'external' });
  let s = ctl.getState();
  assert.equal(s.phase, PHASES.AWAITING_CONSENT); assert.equal(s.report.lookup.state, 'awaiting_consent');
  assert.equal(f.calls.length, 0);
  assert.equal(s.exportReady, false);
  assert.equal(s.report.input.sensitive.likely, true);
  assert.match(s.report.verdict.externalNote, /Nothing has been sent/);
  // nothing sensitive in state, history, storage or export
  const dump = JSON.stringify(s) + storage.dump();
  assert.ok(!dump.includes(SECRET), 'raw secret must not be persisted or placed in report/history');
  assert.ok(s.report.input.display.includes('[redacted]'));
  // choose: send without the query string
  ctl.resolveConsent('send_no_query');
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].body.acknowledgeSensitive, true);
  assert.ok(!f.calls[0].body.url.includes('token'), 'query removed'); assert.ok(!f.calls[0].body.url.includes('#'), 'fragment removed');
  assert.equal(ctl.getState().report.lookup.disclosure.queryRemoved, true);
  f.calls[0].resolve(okResp(gatewayBody(pNoMatch(), pNoMatch()))); await tick(5);
  assert.equal(ctl.getState().report.lookup.state, 'complete');
  const exp = JSON.stringify(ctl.exportCurrent());
  assert.ok(!exp.includes(SECRET)); assert.ok(!storage.dump().includes(SECRET)); assert.ok(!JSON.stringify(history.list()).includes(SECRET));
  assert.ok(ctl.getState().report.limitations.some((l) => /query string was removed/.test(l)));
});

test('sensitive URL: "send anyway" sends exact URL minus fragment with acknowledgement; "local only" sends nothing', async () => {
  const f = deferredFetch(); const { ctl } = setup({ fetchImpl: f });
  const url = `https://example.org/cb?access_token=${SECRET}&x=1#frag`;
  ctl.startScan(url, { lookup: 'external' });
  ctl.resolveConsent('send_full');
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].body.url, `https://example.org/cb?access_token=${SECRET}&x=1`);
  assert.equal(f.calls[0].body.acknowledgeSensitive, true);
  ctl.startScan(url, { lookup: 'external' });
  ctl.resolveConsent('local_only');
  assert.equal(f.calls.length, 1, 'no second request');
  const r = ctl.getState().report;
  assert.equal(r.lookup.state, 'not_requested'); assert.equal(r.providers.gsb.status, 'not_requested'); assert.equal(ctl.getState().phase, PHASES.DONE);
});

test('server-side sensitivity verdict (409) moves a non-flagged scan to awaiting consent without leaking', async () => {
  let calls = 0;
  const f = async () => { calls++; return okResp({ ok: false, error: { code: 'sensitive_url_unacknowledged' } }, 409); };
  const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' }); await tick(10);
  assert.equal(ctl.getState().phase, PHASES.AWAITING_CONSENT);
  assert.equal(calls, 1);
  assert.equal(ctl.getState().report.providers.gsb.status, 'awaiting_consent');
});

test('invalid input is not a scan: previous report remains, no spinner, error is set', () => {
  const f = deferredFetch(); const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'local' });
  const id = ctl.getState().report.scanId;
  const r = ctl.startScan('ftp://nope', { lookup: 'external' });
  assert.equal(r.ok, false);
  assert.equal(ctl.getState().report.scanId, id); assert.equal(ctl.getState().phase, PHASES.DONE); assert.ok(ctl.getState().error);
});

test('pasted message: all links analyzed, highest local score is primary, others listed redacted', () => {
  const { ctl } = setup({ fetchImpl: async () => okResp({}) });
  ctl.startScan('URGENT klik sini https://example.org/a dan https://cimbcllcks-secure-login.top/auth?token=' + SECRET + ' sekarang', { lookup: 'local' });
  const r = ctl.getState().report;
  assert.equal(r.input.kind, 'message'); assert.equal(r.input.host, 'cimbcllcks-secure-login.top');
  assert.equal(r.input.message.otherLinks.length, 1);
  assert.ok(!JSON.stringify(r).includes(SECRET));
});

test('manual retry after failure re-runs exactly once per click and resets badges', async () => {
  let n = 0;
  const f = async () => { n++; return n === 1 ? okResp({}, 503) : okResp(gatewayBody(pNoMatch(), pNoMatch())); };
  const { ctl } = setup({ fetchImpl: f });
  ctl.startScan(LOW, { lookup: 'external' }); await tick(10);
  assert.equal(ctl.getState().report.lookup.state, 'failed');
  assert.equal(ctl.retryLookup(), true); await tick(10);
  assert.equal(n, 2); assert.equal(ctl.getState().report.lookup.state, 'complete');
  assert.equal(ctl.retryLookup(), false);
});
