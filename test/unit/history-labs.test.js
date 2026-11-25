import test from 'node:test';
import assert from 'node:assert/strict';
import { parseHistory, createHistoryStore, validateEntry, safeStorage, HISTORY_KEY, MAX_ENTRIES, MAX_AGE_MS } from '../../src/history.js';
import * as L from '../../src/labs-logic.js';
import { curriculumData } from '../../src/data/academy.js';
import { rtRoadmapData } from '../../src/data/redteam.js';
import { memoryStorage } from './helpers.js';

const NOW = Date.parse('2026-06-15T00:00:00Z');
const entry = (over = {}) => ({ schemaVersion: 1, scanId: 'a1', createdAt: '2026-06-14T00:00:00Z', updatedAt: '2026-06-14T00:00:00Z', display: 'https://example.org/', host: 'example.org', mode: 'local_only', heuristicScore: 0, heuristicBand: 'none', verdictLevel: 'no_local_indicators', verdictLabel: 'No local indicators detected', lookupState: 'not_requested', providers: { gsb: { status: 'not_requested', threats: [] }, urlhaus: { status: 'not_requested', threats: [] } }, redactions: 0, sensitiveLikely: false, ...over });

test('parseHistory survives null, {}, arrays of junk, wrong types and non-JSON', () => {
  for (const raw of ['null', '{}', '[]', '[null]', '[1,"x",[],{}]', '[{"scanId":1}]', '"s"', '42', 'true', 'not json', '', '[{"scanId":"a","createdAt":"bad"}]']) {
    assert.deepEqual(parseHistory(raw, NOW), [], raw);
  }
  const mixed = JSON.stringify([null, 5, entry(), { scanId: 'b' }, entry({ scanId: 'c', heuristicScore: 500 }), entry({ scanId: 'd', verdictLevel: 'bogus' })]);
  assert.deepEqual(parseHistory(mixed, NOW).map((e) => e.scanId), ['a1']);
});
test('entries are sanitized: pending states become interrupted, oversize strings are capped, extra fields dropped', () => {
  const v = validateEntry(entry({ lookupState: 'pending', display: 'x'.repeat(1000), evil: '<script>', providers: { gsb: { status: 'pending', threats: ['t', 5] } } }), NOW);
  assert.equal(v.lookupState, 'interrupted'); assert.equal(v.providers.gsb.status, 'interrupted'); assert.equal(v.display.length, 300);
  assert.equal(v.evil, undefined); assert.deepEqual(v.providers.urlhaus, { status: 'lookup_failed', threats: [] });
});
test('retention: max entries and max age are enforced on load; legacy raw-URL keys are purged', () => {
  const many = Array.from({ length: 40 }, (_, i) => entry({ scanId: 's' + i }));
  assert.equal(parseHistory(JSON.stringify(many), NOW).length, MAX_ENTRIES);
  const old = entry({ scanId: 'old', createdAt: new Date(NOW - MAX_AGE_MS - 1000).toISOString() });
  assert.equal(parseHistory(JSON.stringify([old]), NOW).length, 0);
  const st = memoryStorage({ vr_scan_history: '[{"url":"https://x/?token=1"}]', vr_scan_total: '3', vr_threat_total: '1', [HISTORY_KEY]: JSON.stringify([entry()]) });
  const store = createHistoryStore({ storage: st, now: () => NOW }); store.load();
  assert.equal(st.getItem('vr_scan_history'), null); assert.equal(st.getItem('vr_scan_total'), null);
  assert.equal(store.list().length, 1);
});
test('upsert never duplicates a scan and clear removes everything', () => {
  const store = createHistoryStore({ storage: memoryStorage(), now: () => NOW }); store.load();
  store.upsert(entry({ lookupState: 'pending' })); store.upsert(entry({ lookupState: 'complete', verdictLevel: 'threat_reported', verdictLabel: 'Threat reported by provider' }));
  assert.equal(store.list().length, 1); assert.equal(store.list()[0].verdictLevel, 'threat_reported');
  assert.equal(store.upsert({ scanId: 'bad' }), false);
  store.clear(); assert.equal(store.list().length, 0);
});
test('storage failures (blocked reads/writes, null storage) never throw', () => {
  for (const st of [memoryStorage({}, { failWrites: true }), memoryStorage({}, { failReads: true }), null]) {
    const store = createHistoryStore({ storage: st, now: () => NOW });
    assert.doesNotThrow(() => { store.load(); store.upsert(entry()); store.clear(); });
  }
  const throwing = { get localStorage() { throw new Error('denied'); } };
  assert.equal(safeStorage(throwing), null);
});

test('DMARC: passes with aligned SPF OR aligned DKIM; DKIM failure alone is not a DMARC failure; unaligned SPF pass is not enough', () => {
  const base = { policy: 'reject' };
  assert.equal(L.evaluateDmarc({ ...base, spfPass: true, spfAligned: true, dkimPass: false, dkimAligned: false }).pass, true);
  assert.equal(L.evaluateDmarc({ ...base, spfPass: false, spfAligned: false, dkimPass: true, dkimAligned: true }).pass, true);
  assert.equal(L.evaluateDmarc({ ...base, spfPass: true, spfAligned: false, dkimPass: false, dkimAligned: false }).pass, false);
  assert.equal(L.evaluateDmarc({ ...base, spfPass: false, spfAligned: false, dkimPass: true, dkimAligned: false }).pass, false);
  assert.equal(L.evaluateDmarc({ ...base, spfPass: false, spfAligned: false, dkimPass: false, dkimAligned: false }).requestedAction, 'reject');
  assert.equal(L.checkEmailAnswer('aligned', 'pass').ok, true); assert.equal(L.checkEmailAnswer('aligned', 'reject').ok, false);
  assert.equal(L.checkEmailAnswer('spoofed', 'reject').ok, true);
  assert.match(L.checkEmailAnswer('aligned', 'pass').explanation, /only one aligned mechanism/);
});
test('phishing quiz: each question counts once no matter how often it is answered', () => {
  const q = L.createPhishQuiz();
  for (let i = 0; i < L.PH_ITEMS.length; i++) { for (let k = 0; k < 5; k++) q.answer(L.PH_ITEMS[i][1]); q.next(); }
  assert.equal(q.state.score, L.PH_ITEMS.length); assert.equal(q.finished, true);
  assert.equal(q.answer(1).counted, false);
  q.restart(); q.answer(1 - L.PH_ITEMS[0][1]); q.answer(L.PH_ITEMS[0][1]); assert.equal(q.state.score, 0, 'a later correct answer cannot overwrite a counted wrong one');
  q.next(); q.next(); assert.equal(q.state.i, 1, 'cannot skip unanswered questions');
});
test('SQL-injection lab accepts normalized classic payloads and rejects others', () => {
  for (const p of ["' OR 1=1--", "' or 1=1 --", "'OR'1'='1", "' OR 1=1#"]) assert.equal(L.checkTextLab(4, p).ok, true, p);
  for (const p of ['', 'admin', "' AND 1=2--", 'OR 1=1']) assert.equal(L.checkTextLab(4, p).ok, false, p);
  assert.equal(L.checkTextLab(99, 'x').ok, false);
});
test('password demo: never presents patterned passwords as strong; labels assumptions', () => {
  const weak = L.passwordDemo('Summer2024!'); assert.ok(weak.patterns.length > 0); assert.equal(weak.reliable, false); assert.match(weak.assumptions, /uniformly at random/);
  assert.ok(L.passwordDemo('password123').patterns.length > 0); assert.ok(L.passwordDemo('aaaaaaaaaa').patterns.length > 0);
  assert.equal(L.passwordDemo('xK9#mQ2$vL7!').patterns.length, 0); assert.equal(L.passwordDemo('correct horse battery staple').looksLikePassphrase, true);
});
test('hash workbench: SHA-256, Base64, hex, ROT13, URL decode, and invalid-input handling', async () => {
  assert.equal(await L.hashOp('sha', 'hello'), '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  assert.equal(await L.hashOp('b64e', 'hello'), 'aGVsbG8='); assert.equal(await L.hashOp('b64d', 'aGVsbG8='), 'hello');
  assert.equal(await L.hashOp('hex', 'hi'), '68 69'); assert.equal(await L.hashOp('rot', 'Hello'), 'Uryyb'); assert.equal(await L.hashOp('url', 'a%20b'), 'a b');
  assert.match(await L.hashOp('b64d', '!!!not base64'), /^Error/);
  assert.equal(await L.hashOp('b64d', 'VlJ7ZW5jb2RpbmdfaXNfbm90X2VuY3J5cHRpb259'), L.FLAG_ENCODING);
});
test('academy and RT progress: keyed (no inflation), invalid stored data ignored, storage failures tolerated', () => {
  const st = memoryStorage({ vr_done: JSON.stringify({ '0-0': 1, '99-1': 1, 'zz': 1, '0-99': 1 }) });
  const p = L.createAcademyProgress(st, curriculumData);
  assert.equal(p.completedCount(), 1);
  const lesson = curriculumData[0].lessons[1];
  for (let i = 0; i < 5; i++) assert.equal(p.answer(0, 1, lesson.quiz.correct).correct, true);
  assert.equal(p.completedCount(), 2); assert.equal(p.answer(0, 1, lesson.quiz.correct).newlyCompleted, false);
  assert.equal(p.answer(1, 0, (curriculumData[1].lessons[0].quiz.correct + 1) % curriculumData[1].lessons[0].quiz.opts.length).correct, false);
  assert.equal(p.completedCount(), 2);
  for (const bad of ['null', '[]', '{', '"x"', '7']) assert.equal(L.createAcademyProgress(memoryStorage({ vr_done: bad }), curriculumData).completedCount(), 0, bad);
  assert.doesNotThrow(() => L.createAcademyProgress(memoryStorage({}, { failWrites: true, failReads: true }), curriculumData).answer(0, 0, curriculumData[0].lessons[0].quiz.correct));
  const rt = L.createRtProgress(memoryStorage(), rtRoadmapData); rt.toggle(1, 0); assert.ok(rt.percent(1) > 0); rt.toggle(1, 0); assert.equal(rt.percent(1), 0);
  assert.equal(L.createRtProgress(memoryStorage({ vr_rt: '{"9-9":1,"1-0":1}' }), rtRoadmapData).percent(1) > 0, true);
});
