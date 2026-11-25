// Real-browser tests (Playwright/Chromium). Providers are MOCKED; no real URL or token leaves the machine.
// The UI talks to a harness server that uses the real scan-service logic (Express layer: see test/http/).
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startHarness, loadPlaywright } from './harness.js';
import { fakeFetch, jsonResponse, gsbMatch } from '../unit/helpers.js';

const SECRET = 'Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0';
const FONT = /fonts\.(googleapis|gstatic)\.com|ERR_NAME_NOT_RESOLVED|ERR_INTERNET_DISCONNECTED/;
let pw; let browser;

before(async () => { pw = await loadPlaywright(); browser = await pw.chromium.launch(); });
after(async () => { await browser.close(); });

const okProviders = (u) => (u.includes('safebrowsing') ? jsonResponse(200, {}) : jsonResponse(200, { query_status: 'no_results' }));

async function open({ handler = okProviders, viewport = { width: 1280, height: 900 }, init } = {}) {
  const h = await startHarness({ fetchImpl: fakeFetch(handler) });
  const ctx = await browser.newContext({ viewport, acceptDownloads: true });
  const page = await ctx.newPage();
  page.setDefaultTimeout(4000);
  const problems = [];
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
  page.on('console', (m) => { if (['error', 'warning'].includes(m.type()) && !FONT.test(m.text())) problems.push(m.type() + ': ' + m.text()); });
  await page.addInitScript(() => { window.__csp = []; document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI)); });
  if (init) await page.addInitScript(init.fn, init.arg);
  await page.goto(h.base + '/', { waitUntil: 'load' });
  return { h, ctx, page, problems, done: async () => { await ctx.close(); await h.close(); } };
}
const toScanner = (page) => page.click('#navBtn-scanner');
const scan = async (page, text, external = false) => {
  await page.fill('#targetScanInput', text);
  if (external) await page.check('#modeExternal'); else await page.check('#modeLocal');
  await page.click('#scanSubmitBtn');
};

test('desktop navigation reaches every section; exactly one view visible; aria-current follows', async () => {
  const s = await open();
  for (const v of ['home', 'scanner', 'assistant', 'academy', 'labs', 'redteam']) {
    await s.page.click(`#navBtn-${v}`);
    const visible = await s.page.$$eval('.page-view', (els) => els.filter((e) => !e.classList.contains('hidden')).map((e) => e.id));
    assert.deepEqual(visible, ['view-' + v]);
    assert.equal(await s.page.getAttribute(`#navBtn-${v}`, 'aria-current'), 'page');
  }
  assert.deepEqual(s.problems, []);
  assert.deepEqual(await s.page.evaluate(() => window.__csp), [], 'no CSP violations');
  await s.done();
});

test('mobile: desktop nav is hidden, mobile nav works for every section, no horizontal overflow', async () => {
  const s = await open({ viewport: { width: 390, height: 800 } });
  assert.equal(await s.page.isVisible('#navBtn-scanner'), false);
  for (const v of ['scanner', 'assistant', 'academy', 'labs', 'redteam', 'home']) {
    await s.page.click(`#mnavBtn-${v}`);
    assert.equal(await s.page.isVisible('#view-' + v), true, v);
    assert.equal(await s.page.getAttribute(`#mnavBtn-${v}`, 'aria-current'), 'page');
    const overflow = await s.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflow <= 1, `${v}: horizontal overflow ${overflow}px`);
  }
  await s.done();
});

test('local-only scan: no network call, honest labels, export is final and redacted', async () => {
  const s = await open();
  await toScanner(s.page);
  await scan(s.page, `https://cimbcllcks-secure-login.top/auth?token=${SECRET}`);
  await s.page.waitForSelector('#scanResultsCard:not(.hidden)');
  assert.equal(await s.page.textContent('#verdictTitle'), 'High heuristic risk');
  assert.match(await s.page.textContent('#verdictBadge'), /LOCAL ONLY/);
  assert.match(await s.page.textContent('[data-provider-status="gsb"]'), /Not requested/);
  assert.equal(s.h.log.length, 0, 'no /api/scan call in local-only mode');
  assert.ok(!(await s.page.content()).includes(SECRET), 'secret not rendered anywhere in the DOM');
  const [dl] = await Promise.all([s.page.waitForEvent('download'), s.page.click('#exportBtn')]);
  const body = await (await import('node:fs/promises')).readFile(await dl.path(), 'utf8');
  const data = JSON.parse(body);
  assert.equal(data.exportStatus, 'final'); assert.ok(!body.includes(SECRET));
  assert.match(dl.suggestedFilename(), /final\.json$/);
  assert.equal(data.report.verdict.level, 'high_heuristic_risk');
  await s.done();
});

test('provider-positive result overrides a low local score; banner, cards, history, counters and export agree', async () => {
  const s = await open({ handler: (u) => (u.includes('safebrowsing') ? gsbMatch() : jsonResponse(200, { query_status: 'no_results' })) });
  await toScanner(s.page);
  await scan(s.page, 'https://example.org/about', true);
  await s.page.waitForSelector('#verdictTitle:text("Threat reported by provider")');
  assert.match(await s.page.textContent('#verdictScore'), /^0 \/ 100/);
  assert.match(await s.page.textContent('[data-provider-status="gsb"]'), /Threat reported/);
  assert.match(await s.page.textContent('[data-provider-status="urlhaus"]'), /No match reported/);
  assert.match(await s.page.textContent('#gsbAttribution'), /Advisory provided by Google/);
  assert.match(await s.page.textContent('#verdictBadge'), /FINAL/);
  const rows = await s.page.$$('#historyTableBody tr[data-scan]');
  assert.equal(rows.length, 1);
  assert.match(await rows[0].textContent(), /Threat reported by provider/);
  assert.match(await rows[0].textContent(), /complete/);
  await s.page.click('#navBtn-home');
  assert.equal(await s.page.textContent('#stat-scans-count'), '1');
  assert.equal(await s.page.textContent('#stat-threats-count'), '1');
  await s.page.click('#navBtn-scanner');
  const [dl] = await Promise.all([s.page.waitForEvent('download'), s.page.click('#exportBtn')]);
  const data = JSON.parse(await (await import('node:fs/promises')).readFile(await dl.path(), 'utf8'));
  assert.equal(data.report.verdict.level, 'threat_reported'); assert.equal(data.report.heuristic.score, 0);
  assert.equal(data.report.providers.gsb.status, 'match');
  await s.done();
});

test('pending state is honest: provisional banner, export disabled, no fake 100% completion', async () => {
  let release; const gate = new Promise((r) => { release = r; });
  const s = await open({ handler: async (u) => { await gate; return okProviders(u); } });
  await toScanner(s.page);
  await scan(s.page, 'https://example.org/about', true);
  await s.page.waitForSelector('#verdictBadge:text("PROVISIONAL")');
  assert.equal(await s.page.isDisabled('#exportBtn'), true);
  assert.match(await s.page.textContent('[data-provider-status="gsb"]'), /Checking/);
  assert.equal(await s.page.isVisible('#indeterminate'), true);
  await s.page.waitForTimeout(1200);
  const text = await s.page.textContent('#scanProgressCard');
  assert.ok(!/100\s*%/.test(text) && !/\d+\s*%/.test(text), 'no percentage shown while pending: ' + text);
  assert.match(await s.page.textContent('#stepLookup'), /Waiting for provider answers/);
  release();
  await s.page.waitForSelector('#verdictBadge:text("FINAL")');
  assert.equal(await s.page.isDisabled('#exportBtn'), false);
  assert.equal(await s.page.isVisible('#indeterminate'), false);
  await s.done();
});

test('stale response from scan A cannot overwrite scan B (UI and history)', async () => {
  let release; const gate = new Promise((r) => { release = r; });
  let n = 0;
  const s = await open({ handler: async (u) => { n += 1; if (n <= 2) { await gate; return gsbMatch(); } return okProviders(u); } });
  await toScanner(s.page);
  await scan(s.page, 'https://example.org/about', true);                 // A: held at the provider
  await s.page.waitForSelector('#verdictBadge:text("PROVISIONAL")');
  await scan(s.page, 'https://cimbcllcks-secure-login.top/auth');          // B: local-only
  await s.page.waitForSelector('#verdictTitle:text("High heuristic risk")');
  release(); await s.page.waitForTimeout(400);                             // A's provider answers late (a match!)
  assert.equal(await s.page.textContent('#verdictTitle'), 'High heuristic risk');
  assert.match(await s.page.textContent('#verdictBadge'), /LOCAL ONLY/);
  assert.match(await s.page.textContent('[data-provider-status="gsb"]'), /Not requested/);
  const rows = await s.page.$$eval('#historyTableBody tr[data-scan]', (r) => r.map((x) => x.textContent));
  assert.equal(rows.length, 2);
  assert.ok(rows.some((t) => /interrupted/.test(t)) && !rows.some((t) => /Threat reported/.test(t)));
  await s.done();
});

test('sensitive URL: external lookup waits for consent and nothing is sent; local-only choice keeps it local', async () => {
  const s = await open();
  await toScanner(s.page);
  await scan(s.page, `https://example.org/reset/${SECRET}?token=${SECRET}`, true);
  await s.page.waitForSelector('#consentPanel:not(.hidden)');
  assert.equal(s.h.log.length, 0);
  assert.match(await s.page.textContent('#verdictBadge'), /PROVISIONAL/);
  assert.equal(await s.page.isDisabled('#exportBtn'), true);
  assert.ok(!(await s.page.content()).includes(SECRET));
  await s.page.click('[data-consent="local_only"]');
  await s.page.waitForSelector('#consentPanel.hidden', { state: 'attached' });
  assert.equal(s.h.log.length, 0);
  assert.match(await s.page.textContent('#verdictBadge'), /LOCAL ONLY/);
  const stored = await s.page.evaluate(() => JSON.stringify({ ...localStorage }));
  assert.ok(!stored.includes(SECRET), 'nothing sensitive in localStorage');
  await s.done();
});

test('sample presets never trigger an external lookup, even when external mode is selected', async () => {
  const s = await open();
  await toScanner(s.page);
  await s.page.check('#modeExternal');
  await s.page.click('[data-sample="https://cimbcllcks-secure-login.top/auth"]');
  await s.page.waitForSelector('#scanResultsCard:not(.hidden)');
  assert.equal(s.h.log.length, 0);
  assert.match(await s.page.textContent('[data-provider="gsb"]'), /Sample presets are always analyzed locally/);
  await s.done();
});

test('userinfo URLs and invalid input show an inline error, no scan, no network', async () => {
  const s = await open();
  await toScanner(s.page);
  await scan(s.page, 'https://admin:hunter2@example.com/', true);
  assert.match(await s.page.textContent('#scanInputError'), /username or password/);
  assert.equal(await s.page.isVisible('#scanResultsCard'), false);
  assert.equal(s.h.log.length, 0);
  await scan(s.page, 'ftp://x.example.org');
  assert.match(await s.page.textContent('#scanInputError'), /http/);
  await s.done();
});

test('backend failures are explicit and never clean (429, outage)', async () => {
  const s = await open({ handler: () => jsonResponse(200, {}) });
  await s.page.route('**/api/scan', (r) => r.fulfill({ status: 429, headers: { 'retry-after': '30', 'content-type': 'application/json' }, body: JSON.stringify({ ok: false, error: { code: 'rate_limited' } }) }));
  await toScanner(s.page);
  await scan(s.page, 'https://example.org/about', true);
  await s.page.waitForSelector('#verdictBadge:text("EXTERNAL LOOKUP FAILED")');
  assert.match(await s.page.textContent('[data-provider-status="gsb"]'), /Rate \/ quota limited/);
  assert.match(await s.page.textContent('#verdictExternal'), /not a clean result/);
  assert.equal(await s.page.isVisible('#retryLookupBtn'), true);
  await s.page.unroute('**/api/scan');
  await s.page.route('**/api/scan', (r) => r.abort('connectionrefused'));
  await scan(s.page, 'https://example.org/about', true);
  await s.page.waitForSelector('#verdictBadge:text("EXTERNAL LOOKUP FAILED")');
  assert.match(await s.page.textContent('[data-provider-status="urlhaus"]'), /unreachable/i);
  await s.done();
});

const corrupt = (v) => ({ fn: (val) => { localStorage.setItem('vq_scan_history_v2', val); localStorage.setItem('vr_done', val); localStorage.setItem('vr_rt', val); }, arg: v });
for (const bad of ['null', '{}', '[null,5,"x",{"scanId":1},{"scanId":"a","createdAt":"nope"}]', 'not json at all', '"string"', '[[]]']) {
  test(`corrupted localStorage (${bad.slice(0, 24)}) does not crash the app`, async () => {
    const s = await open({ init: corrupt(bad) });
    await toScanner(s.page);
    assert.match(await s.page.textContent('#historyTableBody'), /No scans/);
    await s.page.click('#navBtn-academy'); await s.page.click('#navBtn-redteam'); await s.page.click('#navBtn-labs');
    assert.deepEqual(s.problems, []);
    await toScanner(s.page);
    await scan(s.page, 'https://example.org/about');
    assert.equal(await s.page.$$eval('#historyTableBody tr[data-scan]', (r) => r.length), 1);
    await s.done();
  });
}

test('blocked/failing storage degrades gracefully', async () => {
  const s = await open({ init: { fn: () => { Storage.prototype.setItem = () => { throw new Error('QuotaExceededError'); }; Storage.prototype.getItem = () => { throw new Error('SecurityError'); }; } } });
  await toScanner(s.page);
  await scan(s.page, 'https://example.org/about');
  assert.equal(await s.page.$$eval('#historyTableBody tr[data-scan]', (r) => r.length), 1);
  assert.deepEqual(s.problems, []);
  await s.done();
});

test('legacy localStorage keys holding raw URLs are purged', async () => {
  const s = await open({ init: { fn: () => { localStorage.setItem('vr_scan_history', JSON.stringify([{ url: 'https://x.test/?token=abc' }])); localStorage.setItem('vr_scan_total', '9'); } } });
  assert.equal(await s.page.evaluate(() => localStorage.getItem('vr_scan_history')), null);
  assert.equal(await s.page.evaluate(() => localStorage.getItem('vr_scan_total')), null);
  await s.done();
});

test('Lab 04: the SQL-injection button is a well-formed element, bound programmatically, and works', async () => {
  const s = await open();
  await s.page.click('#navBtn-labs'); await s.page.click('#labTab-4');
  const btns = await s.page.$$('#activeLabWorkspace button[data-action="submit-text"]');
  assert.equal(btns.length, 1);
  assert.equal(await btns[0].getAttribute('onclick'), null);
  assert.equal(await btns[0].getAttribute('data-lab-id'), '4');
  const stray = await btns[0].evaluate((b) => [...b.attributes].map((a) => a.name));
  assert.deepEqual(stray.sort(), ['class', 'data-action', 'data-lab-id', 'type']);
  await s.page.fill('#labInput-4', 'admin');
  await btns[0].click();
  assert.match(await s.page.textContent('#labResult-4'), /Incorrect/);
  await s.page.fill('#labInput-4', "' OR 1=1--");
  await btns[0].click();
  assert.match(await s.page.textContent('#labResult-4'), /Challenge solved/);
  assert.match(await s.page.textContent('#labResult-4'), /VR\{LAB4_SUCCESS\}/);
  assert.deepEqual(s.problems, []);
  await s.done();
});

test('all nine labs render and respond', async () => {
  const s = await open();
  await s.page.click('#navBtn-labs');
  for (let i = 1; i <= 9; i++) { await s.page.click(`#labTab-${i}`); assert.ok((await s.page.textContent('#activeLabWorkspace')).length > 50, 'lab ' + i); }
  await s.page.click('#labTab-1'); await s.page.fill('#labInput-1', '/aplly'); await s.page.click('[data-action="submit-text"][data-lab-id="1"]');
  assert.match(await s.page.textContent('#labResult-1'), /solved/);
  await s.page.click('#labTab-3'); await s.page.click('[data-action="choose-port"][data-value="22"]'); assert.match(await s.page.textContent('#labResult-3'), /Correct/);
  await s.page.click('#labTab-6'); await s.page.fill('#hIn', 'hello'); await s.page.click('[data-op="sha"]');
  assert.equal(await s.page.textContent('#hOut'), '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  await s.page.click('[data-op="b64e"]'); assert.equal(await s.page.textContent('#hOut'), 'aGVsbG8=');
  await s.page.fill('#hIn', 'VlJ7ZW5jb2RpbmdfaXNfbm90X2VuY3J5cHRpb259'); await s.page.click('[data-op="b64d"]');
  assert.equal(await s.page.textContent('#hOut'), 'VR{encoding_is_not_encryption}');
  await s.page.click('#labTab-9'); await s.page.click('[data-action="count-log"]'); assert.match(await s.page.textContent('#logTbl'), /203\.0\.113\.77 : 6 failed/);
  await s.page.fill('#logIn', '203.0.113.77'); await s.page.click('[data-action="submit-log"]'); assert.match(await s.page.textContent('#logRes'), /Correct/);
  assert.deepEqual(s.problems, []);
  await s.done();
});

test('Lab 05 teaches DMARC correctly (aligned SPF OR aligned DKIM; DKIM failure alone is not a DMARC failure)', async () => {
  const s = await open();
  await s.page.click('#navBtn-labs'); await s.page.click('#labTab-5');
  const text = await s.page.textContent('#activeLabWorkspace');
  assert.match(text, /either<\/strong>|either/i); assert.match(text, /aligned/);
  await s.page.click('[data-scenario="spoofed"][data-value="reject"]');
  assert.match(await s.page.textContent('#labResult-5-spoofed'), /not aligned/);
  await s.page.click('[data-scenario="aligned"][data-value="reject"]');
  assert.match(await s.page.textContent('#labResult-5-aligned'), /Not quite/);
  await s.page.click('[data-scenario="aligned"][data-value="pass"]');
  assert.match(await s.page.textContent('#labResult-5-aligned'), /DMARC needs only one aligned mechanism/);
  await s.done();
});

test('Lab 08 phishing quiz: answering the same question repeatedly never inflates the score', async () => {
  const s = await open();
  await s.page.click('#navBtn-labs'); await s.page.click('#labTab-8');
  const answers = [1, 0, 1, 0, 1];
  for (let q = 0; q < 5; q++) {
    const correct = `[data-action="ph-answer"][data-value="${answers[q]}"]`;
    for (let k = 0; k < 4; k++) await s.page.evaluate((sel) => document.querySelector(sel)?.click(), correct); // programmatic repeats, even if disabled
    await s.page.click('[data-action="ph-next"]');
  }
  assert.match(await s.page.textContent('#phBox'), /Score: 5 \/ 5/);
  await s.page.click('[data-action="ph-restart"]');
  for (let k = 0; k < 6; k++) await s.page.evaluate(() => document.querySelector('[data-action="ph-answer"][data-value="0"]')?.click()); // wrong answer, repeated
  await s.page.click('[data-action="ph-next"]');
  assert.match(await s.page.textContent('#phBox'), /Question 2 of 5 · score 0/);
  await s.done();
});

test('Lab 07 does not present a naive length x log2(pool) number as strength for predictable passwords', async () => {
  const s = await open();
  await s.page.click('#navBtn-labs'); await s.page.click('#labTab-7');
  await s.page.fill('#pwIn', 'Summer2024!');
  const t1 = await s.page.textContent('#pwOut');
  assert.match(t1, /Predictable pattern/); assert.ok(!/bits/.test(t1), 'no bit count for a patterned password'); assert.match(t1, /Assumptions/);
  await s.page.fill('#pwIn', 'xK9#mQ2$vL7!');
  assert.match(await s.page.textContent('#pwOut'), /Random-model figure/);
  assert.match(await s.page.textContent('#pwOut'), /usually overstates/);
  await s.done();
});

test('Academy: repeated correct answers cannot inflate progress; invalid stored keys are ignored', async () => {
  const s = await open({ init: { fn: () => localStorage.setItem('vr_done', JSON.stringify({ '0-0': 1, '99-99': 1, 'x': 1, '0-77': 1 })) } });
  await s.page.click('#navBtn-academy');
  assert.match(await s.page.textContent('#academyProgress'), /^Quiz progress: 1 \/ 24/);
  await s.page.click('[data-lesson="0"]');
  const correct = await s.page.evaluate(() => null);
  void correct;
  // find and click the correct option by trying each; the correct one reports ✓
  const n = (await s.page.$$('[data-quiz]')).length;
  for (let r = 0; r < 3; r++) for (let i = 0; i < n; i++) await s.page.click(`[data-quiz="${i}"]`);
  assert.match(await s.page.textContent('#academyProgress'), /^Quiz progress: 1 \/ 24/);
  await s.done();
});

test('Academy: a new lesson completes once; search filters; 12 categories', async () => {
  const s = await open();
  await s.page.click('#navBtn-academy');
  assert.equal((await s.page.$$('#categoriesMenuContainer [data-cat]')).length, 12);
  await s.page.fill('#curriculumSearchInput', 'dns');
  assert.ok((await s.page.$$('#categoriesMenuContainer [data-cat]')).length >= 1);
  await s.page.fill('#curriculumSearchInput', 'zzzz-no-match');
  assert.match(await s.page.textContent('#categoriesMenuContainer'), /No matching topics/);
  await s.page.fill('#curriculumSearchInput', '');
  await s.page.click('#categoriesMenuContainer [data-cat="1"]');
  const n = (await s.page.$$('[data-quiz]')).length;
  for (let r = 0; r < 2; r++) for (let i = 0; i < n; i++) await s.page.click(`[data-quiz="${i}"]`);
  assert.match(await s.page.textContent('#academyProgress'), /^Quiz progress: 1 \/ 24/);
  await s.done();
});

test('RT roadmap: five stages, milestone progress persists, bar width set without inline style attributes', async () => {
  const s = await open();
  await s.page.click('#navBtn-redteam');
  for (let i = 1; i <= 5; i++) { await s.page.click(`#rtStageBtn-${i}`); assert.ok((await s.page.textContent('#rtRoadmapDetailBox')).includes('STAGE 0' + i)); }
  await s.page.click('#rtStageBtn-1');
  await s.page.check('[data-rt-tick="1-0"]');
  assert.notEqual(await s.page.textContent('#rtPct'), '0%');
  assert.ok(await s.page.$eval('#rtBar', (b) => parseFloat(b.style.width) > 0));
  assert.equal(await s.page.getAttribute('#rtBar', 'style').then((x) => /width/.test(x || '')), true);
  await s.page.reload(); await s.page.click('#navBtn-redteam');
  assert.equal(await s.page.isChecked('[data-rt-tick="1-0"]'), true);
  assert.deepEqual(s.problems, []);
  assert.deepEqual(await s.page.evaluate(() => window.__csp), []);
  await s.done();
});

test('assistant is rule-based, answers, and a link quick-scan makes no network call', async () => {
  const s = await open();
  await s.page.click('#navBtn-assistant');
  await s.page.fill('#assistantInput', 'What is phishing?'); await s.page.keyboard.press('Enter');
  assert.match(await s.page.textContent('#chatMessagesBox'), /Rule-based answer/);
  await s.page.fill('#assistantInput', 'check https://cimbcllcks-secure-login.top/auth'); await s.page.click('#assistantSendBtn');
  assert.match(await s.page.textContent('#chatMessagesBox'), /Local quick scan of/);
  assert.match(await s.page.textContent('#chatMessagesBox'), /hxxps:\/\//);
  assert.equal(s.h.log.length, 0);
  await s.page.click('[data-prompt="Tell me more"]');
  await s.done();
});

test('contact form is honest: it says nothing was sent', async () => {
  const s = await open();
  await s.page.fill('#cName', 'A B'); await s.page.fill('#cEmail', 'a@b.co'); await s.page.fill('#cMessage', 'hello');
  await s.page.click('#contactForm button[type="submit"]');
  assert.match(await s.page.textContent('#contactStatus'), /Not sent/);
  assert.match(await s.page.textContent('#contactStatus'), /nothing was transmitted/);
  await s.done();
});

test('copy no longer claims autonomous AI, live telemetry or unimplemented capability', async () => {
  const s = await open();
  const all = (await s.page.evaluate(() => document.body.innerText)).toLowerCase();
  for (const bad of ['autonomous ai protection', 'elite cybersecurity', 'deep threat inspection', 'zero fabricated', '9 curricular']) assert.ok(!all.includes(bad), bad);
  assert.match(all, /rule-based/); assert.match(all, /not available \(future ambitions only\)/);
  await s.done();
});

test('accessibility basics: language, skip link, labelled controls, alt text, headings, keyboard submit', async () => {
  const s = await open();
  assert.equal(await s.page.getAttribute('html', 'lang'), 'en');
  const w = () => s.page.$eval('a[href="#main-content"]', (a) => a.getBoundingClientRect().width);
  assert.ok((await w()) <= 1, 'skip link is visually hidden until focused');
  await s.page.keyboard.press('Tab');
  assert.equal(await s.page.evaluate(() => document.activeElement.getAttribute('href')), '#main-content');
  assert.ok((await w()) > 20, 'skip link becomes visible on focus');
  for (const v of ['scanner', 'assistant', 'academy', 'labs', 'redteam', 'home']) {
    await s.page.click(`#navBtn-${v}`);
    const unnamed = await s.page.evaluate((id) => [...document.querySelectorAll(`#view-${id} input:not([type=hidden]), #view-${id} select, #view-${id} textarea`)].filter((el) => {
      const lab = el.id && document.querySelector(`label[for="${el.id}"]`);
      const wrapped = el.closest('label');
      return !(lab || wrapped || el.getAttribute('aria-label') || el.getAttribute('aria-labelledby'));
    }).map((el) => el.outerHTML.slice(0, 80)), v);
    assert.deepEqual(unnamed, [], `unlabelled controls in ${v}`);
    const noText = await s.page.evaluate((id) => [...document.querySelectorAll(`#view-${id} button`)].filter((b) => !(b.textContent.trim() || b.getAttribute('aria-label'))).length, v);
    assert.equal(noText, 0);
    assert.ok(await s.page.$(`#view-${v} h1, #view-${v} h2`), 'heading in ' + v);
  }
  assert.equal(await s.page.$$eval('img', (i) => i.filter((x) => !x.hasAttribute('alt')).length), 0);
  await s.page.click('#navBtn-scanner');
  await s.page.focus('#targetScanInput'); await s.page.keyboard.type('https://example.org/about'); await s.page.keyboard.press('Enter');
  await s.page.waitForSelector('#scanResultsCard:not(.hidden)');
  assert.equal(await s.page.getAttribute('#scanInputError', 'role'), 'alert');
  await s.done();
});

test('no page loads third-party scripts; external requests are limited to Google Fonts', async () => {
  const s = await open();
  const reqs = [];
  s.page.on('request', (r) => reqs.push(r.url()));
  await s.page.reload();
  for (const v of ['scanner', 'assistant', 'academy', 'labs', 'redteam']) await s.page.click(`#navBtn-${v}`);
  const external = reqs.filter((u) => !u.startsWith(s.h.base) && !u.startsWith('data:') && !u.startsWith('blob:'));
  assert.ok(external.every((u) => /^https:\/\/fonts\.(googleapis|gstatic)\.com\//.test(u)), external.join('\n'));
  await s.done();
});
