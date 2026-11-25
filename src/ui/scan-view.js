// Renders controller state into the scanner DOM. All dynamic values go through textContent.
import { h, $, show, clear } from './dom.js';
import * as R from '../report.js';
import { PHASES } from '../scan-controller.js';

const TONES = {
  danger: { banner: 'p-6 rounded-3xl border flex flex-col sm:flex-row items-center justify-between gap-4 bg-rose-50 border-rose-200', icon: 'w-14 h-14 rounded-2xl flex items-center justify-center font-bold text-2xl shadow-md shrink-0 bg-rose-600 text-white', glyph: '!' },
  warn: { banner: 'p-6 rounded-3xl border flex flex-col sm:flex-row items-center justify-between gap-4 bg-amber-50 border-amber-200', icon: 'w-14 h-14 rounded-2xl flex items-center justify-center font-bold text-2xl shadow-md shrink-0 bg-amber-500 text-white', glyph: '?' },
  neutral: { banner: 'p-6 rounded-3xl border flex flex-col sm:flex-row items-center justify-between gap-4 bg-white border-apple-border', icon: 'w-14 h-14 rounded-2xl flex items-center justify-center font-bold text-2xl shadow-md shrink-0 bg-neutral-200 text-neutral-700', glyph: 'i' }
};
const STATUS_CLASS = {
  match: 'text-rose-700', no_match: 'text-emerald-700', pending: 'text-amber-700', awaiting_consent: 'text-amber-700',
  not_requested: 'text-neutral-500', skipped: 'text-neutral-500'
};
const BADGES = {
  not_requested: ['LOCAL ONLY', 'bg-neutral-100 text-neutral-700'], skipped: ['LOCAL ONLY (lookup skipped)', 'bg-neutral-100 text-neutral-700'],
  awaiting_consent: ['PROVISIONAL: waiting for your choice', 'bg-amber-100 text-amber-800'], pending: ['PROVISIONAL: lookup in progress', 'bg-amber-100 text-amber-800'],
  complete: ['FINAL', 'bg-emerald-100 text-emerald-800'], partial: ['PARTIAL EXTERNAL COVERAGE', 'bg-amber-100 text-amber-800'], failed: ['EXTERNAL LOOKUP FAILED', 'bg-amber-100 text-amber-800']
};
const BAND_TEXT = { none: 'none', low: 'low', suspicious: 'suspicious', high: 'high' };

export function initScanView({ controller, doc = document, onPrefChange = () => {}, loadPref = () => 'local' }) {
  const el = (id) => $(id, doc);
  const form = el('scanForm'); const input = el('targetScanInput');
  const radios = () => [...form.querySelectorAll('input[name="lookupMode"]')];
  const mode = () => (radios().find((r) => r.checked) || { value: 'local' }).value;
  const pref = loadPref();
  radios().forEach((r) => { r.checked = r.value === pref; r.addEventListener('change', () => onPrefChange(mode())); });
  if (!radios().some((r) => r.checked)) el('modeLocal').checked = true;

  function showError(msg) { const e = el('scanInputError'); e.textContent = msg || ''; show(e, Boolean(msg)); input.setAttribute('aria-invalid', msg ? 'true' : 'false'); }

  form.addEventListener('submit', (ev) => { ev.preventDefault(); const r = controller.startScan(input.value, { lookup: mode() === 'external' ? 'external' : 'local' }); showError(r.ok ? '' : r.error); });
  doc.addEventListener('click', (ev) => {
    const s = ev.target.closest('[data-sample]');
    if (s) { input.value = s.dataset.sample; const r = controller.startScan(s.dataset.sample, { lookup: 'local', sample: true }); showError(r.ok ? '' : r.error); return; }
    const c = ev.target.closest('[data-consent]');
    if (c) { controller.resolveConsent(c.dataset.consent); return; }
  });
  el('exportBtn').addEventListener('click', () => {
    const data = controller.exportCurrent();
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = h('a', { href: url, download: `vanq-report-${data.report.scanId.slice(0, 8)}-${data.exportStatus}.json` });
    doc.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  el('retryLookupBtn').addEventListener('click', () => controller.retryLookup());
  el('clearHistoryBtn').addEventListener('click', () => controller.clearHistory());

  function providerCard(p, attribution) {
    const evidence = [];
    if (p.status === 'match') {
      const ev = p.evidence || {};
      if (ev.threatTypes && ev.threatTypes.length) evidence.push('Threat types: ' + ev.threatTypes.join(', '));
      if (ev.platformTypes && ev.platformTypes.length) evidence.push('Platforms: ' + ev.platformTypes.join(', '));
      if (ev.threat) evidence.push('Threat: ' + ev.threat);
      if (ev.urlStatus) evidence.push('Listing status: ' + ev.urlStatus + (ev.urlStatus === 'offline' ? ' (listed, currently offline)' : ''));
      if (ev.tags && ev.tags.length) evidence.push('Tags: ' + ev.tags.join(', '));
      if (ev.dateAdded) evidence.push('Added: ' + ev.dateAdded);
    }
    if (p.reason && p.status !== 'match' && p.status !== 'no_match') evidence.push(p.reason);
    if (p.retryAfterSec) evidence.push(`Retry after about ${p.retryAfterSec}s`);
    if (p.checkedAt && (p.status === 'match' || p.status === 'no_match')) evidence.push('Checked: ' + new Date(p.checkedAt).toLocaleString() + (p.cache && p.cache !== 'miss' ? ` (${p.cache === 'hit' ? 'cached' : 'shared lookup'})` : ''));
    const children = [h('span', { class: 'text-neutral-500 block' }, p.name), h('span', { class: 'font-bold ' + (STATUS_CLASS[p.status] || 'text-amber-700'), 'data-provider-status': p.id }, R.STATUS_TEXT[p.status] || p.status)];
    for (const line of evidence) children.push(h('span', { class: 'block text-neutral-600 mt-1 break-words' }, line));
    if (p.status === 'match' && p.evidence && p.evidence.reference) children.push(h('a', { href: p.evidence.reference, rel: 'noopener noreferrer', target: '_blank', class: 'block mt-1 underline text-rose-700' }, 'View URLhaus entry'));
    children.push(h('span', { class: 'block text-[10px] text-neutral-400 mt-1 font-sans' }, R.PROVIDER_COVERAGE[p.id]));
    return h('div', { class: 'p-2.5 rounded-xl bg-apple-surface border border-apple-border', 'data-provider': p.id }, children);
  }

  function renderIndicators(report) {
    const list = clear(el('indicatorsList'));
    let anyOverlap = false;
    const row = (f) => {
      anyOverlap = anyOverlap || Boolean(f.overlap);
      const head = h('div', { class: 'flex items-start justify-between gap-2' },
        h('span', { class: 'font-bold ' + (f.flagged ? 'text-rose-700' : 'text-neutral-600') }, f.name),
        h('span', { class: 'shrink-0 px-2 py-0.5 rounded font-bold ' + (f.flagged ? 'bg-rose-100 text-rose-700' : 'bg-neutral-100 text-neutral-500') }, f.flagged ? `FLAGGED +${f.counted}${f.counted !== f.points ? ` (nominal ${f.points})` : ''}` : 'not flagged'));
      const r = h('div', { class: 'p-3 rounded-xl border ' + (f.flagged ? 'bg-rose-50 border-rose-200' : 'bg-white border-apple-border'), 'data-finding': f.id }, head, h('p', { class: 'text-neutral-600 mt-1 font-sans' }, f.explanation));
      if (f.overlap) r.append(h('p', { class: 'text-[11px] text-neutral-500 mt-1 font-sans italic' }, f.overlap));
      return r;
    };
    const flagged = report.heuristic.findings.filter((f) => f.flagged);
    const clean = report.heuristic.findings.filter((f) => !f.flagged);
    if (!flagged.length) list.append(h('p', { class: 'text-neutral-600 font-sans' }, 'No indicator fired. This is not proof that the URL is safe.'));
    flagged.forEach((f) => list.append(row(f)));
    if (clean.length) {
      const body = h('div', { class: 'space-y-2 mt-2' }, clean.map(row));
      list.append(h('details', { class: 'mt-2' }, h('summary', { class: 'cursor-pointer font-sans font-semibold text-neutral-600' }, `${clean.length} indicator${clean.length > 1 ? 's' : ''} evaluated that did not fire`), body));
    }
    const gn = el('groupNote'); show(gn, anyOverlap);
    gn.textContent = anyOverlap ? 'Findings that describe the same underlying property are grouped; the strongest counts in full and the others at half weight, with a cap per group, to avoid double counting.' : '';
    const t = report.heuristic.mitre;
    if (t && t.techniques.length) list.append(h('p', { class: 'text-[11px] text-neutral-500 font-sans mt-2' }, 'Possibly related ATT&CK techniques (tentative, inferred from URL text only, not confirmed): ' + t.techniques.join('; ')));
  }

  function renderNested(report) {
    const card = el('nestedCard'); const list = clear(el('nestedList'));
    const nested = report.heuristic.nested;
    show(card, nested.length > 0);
    const add = (e, depth) => {
      const pad = { class: 'p-3 rounded-xl border bg-white border-apple-border', style: null };
      const line = e.status === 'analyzed'
        ? `${e.source} → ${e.display} · local score ${e.score}/100 (${BAND_TEXT[e.band]})${e.flagged.length ? ' · ' + e.flagged.join('; ') : ''}`
        : `${e.source} → ${e.status === 'cycle_or_duplicate' ? 'duplicate or cycle, not analyzed again' : 'could not be parsed (' + e.reason + ')'}`;
      const row = h('div', { class: pad.class, 'data-depth': depth }, line);
      row.classList.add(['ml-0', 'ml-4', 'ml-8', 'ml-12'][Math.min(depth, 3)]);
      list.append(row);
      (e.children || []).forEach((c) => add(c, depth + 1));
    };
    nested.forEach((e) => add(e, 0));
    if (report.heuristic.nestedLimitsHit.length) list.append(h('p', { class: 'text-amber-700' }, 'Inspection stopped at safety limits: ' + report.heuristic.nestedLimitsHit.join(', ') + '. Later destinations were not analyzed.'));
  }

  function renderReport(state) {
    const report = state.report; const v = report.verdict; const tone = TONES[v.tone];
    el('verdictBanner').className = tone.banner;
    el('verdictIconContainer').className = tone.icon; el('verdictIconContainer').textContent = tone.glyph;
    el('verdictTitle').textContent = v.label;
    const badge = BADGES[report.lookup.state] || BADGES.not_requested;
    el('verdictBadge').textContent = badge[0]; el('verdictBadge').className = 'px-2.5 py-0.5 rounded-full text-xs font-mono font-bold ' + badge[1];
    el('verdictSubtitle').textContent = v.headline; el('verdictExternal').textContent = v.externalNote;
    el('verdictScore').textContent = `${report.heuristic.score} / 100`;
    el('reportTarget').textContent = report.input.display; el('reportDefanged').textContent = report.input.defanged;
    const red = el('reportRedactions'); show(red, report.input.redactions > 0 || report.input.sensitive.likely);
    red.textContent = report.input.sensitive.likely ? `Likely sensitive content detected (${report.input.sensitive.reasons.map((r) => r.where).join(', ')}); values are hidden in this report, history and exports.` : '';
    const msg = el('reportMessage'); show(msg, report.input.kind === 'message');
    msg.textContent = report.input.kind === 'message' ? `Pasted text: highest-scoring link shown. ${report.input.message.otherLinks.length} other link(s) analyzed locally. Scam-language categories: ${report.input.message.cues.join(', ') || 'none'}.` : '';
    el('scanTimestamp').textContent = new Date(report.createdAt).toLocaleString() + (report.completedAt ? '' : ' (in progress)');
    el('scanIdLabel').textContent = 'Scan ' + report.scanId.slice(0, 8);

    const grid = clear(el('providerGrid'));
    for (const id of R.PROVIDER_IDS) grid.append(providerCard(report.providers[id]));
    grid.append(h('div', { class: 'p-2.5 rounded-xl bg-apple-surface border border-apple-border' }, h('span', { class: 'text-neutral-500 block' }, 'VirusTotal'), h('span', { class: 'font-bold text-neutral-500' }, 'Not integrated'), h('span', { class: 'block text-[10px] text-neutral-400 mt-1 font-sans' }, 'No VirusTotal lookup is performed.')));
    grid.append(h('div', { class: 'p-2.5 rounded-xl bg-apple-surface border border-apple-border' }, h('span', { class: 'text-neutral-500 block' }, 'VanQ Omni (local heuristics)'), h('span', { class: 'font-bold text-emerald-700' }, 'Complete'), h('span', { class: 'block text-[10px] text-neutral-400 mt-1 font-sans' }, `Heuristic ${report.heuristic.score}/100, band: ${BAND_TEXT[report.heuristic.band]}. Indicators only.`)));

    const attr = el('gsbAttribution'); const showAttr = report.providers.gsb.status === 'match' && report.attribution; show(attr, Boolean(showAttr)); clear(attr);
    if (showAttr) attr.append(h('a', { href: report.attribution.href, rel: 'noopener noreferrer', target: '_blank', class: 'underline' }, report.attribution.text));

    renderIndicators(report); renderNested(report);
    const lim = clear(el('limitationsList')); report.limitations.forEach((l) => lim.append(h('li', {}, l)));
    el('recommendationText').textContent = R.recommendation(report);

    const exp = el('exportBtn'); exp.disabled = !state.exportReady;
    el('exportHint').textContent = state.exportReady ? (report.lookup.state === 'partial' || report.lookup.state === 'failed' ? 'Export reflects incomplete external coverage.' : '') : 'Available when the external lookup finishes or you choose local-only.';
    show(el('retryLookupBtn'), state.canRetryLookup);
  }

  function renderProgress(state) {
    const card = el('scanProgressCard'); const r = state.report;
    show(card, Boolean(r));
    if (!r) return;
    const s = r.lookup.state;
    el('stepLookup').textContent = { not_requested: 'Not requested (local-only)', skipped: 'Skipped (not sent)', awaiting_consent: 'Waiting for your choice', pending: 'Waiting for provider answers…', complete: 'Complete: both providers answered', partial: 'Finished with incomplete coverage', failed: 'Failed: no provider answered' }[s];
    show(el('indeterminate'), s === 'pending');
  }

  function renderConsent(state) {
    const p = el('consentPanel'); const on = state.phase === PHASES.AWAITING_CONSENT && state.report;
    const wasHidden = p.classList.contains('hidden');
    show(p, Boolean(on));
    if (on) {
      el('consentReasons').textContent = state.report.input.sensitive.reasons.map((r) => `${r.where} (${r.detail})`).join('; ') || 'a value that looks like a secret';
      if (wasHidden) { const b = p.querySelector('button'); if (b) b.focus(); }
    }
  }

  const LOOKUP_TEXT = { not_requested: 'local only', skipped: 'skipped', awaiting_consent: 'waiting', pending: 'pending', complete: 'complete', partial: 'partial', failed: 'failed', interrupted: 'interrupted' };
  const ROW_CLASS = { threat_reported: 'text-rose-700 font-bold', high_heuristic_risk: 'text-rose-700 font-bold', suspicious: 'text-amber-700 font-bold' };

  function renderHistory(state) {
    const body = clear(el('historyTableBody'));
    if (!state.history.length) { body.append(h('tr', {}, h('td', { class: 'p-3 text-neutral-400', colspan: '5' }, 'No scans in this browser yet.'))); return; }
    for (const e of state.history) {
      body.append(h('tr', { 'data-scan': e.scanId },
        h('td', { class: 'p-3 break-all' }, e.display),
        h('td', { class: 'p-3 ' + (ROW_CLASS[e.verdictLevel] || '') }, e.verdictLabel),
        h('td', { class: 'p-3' }, `${e.heuristicScore}/100`),
        h('td', { class: 'p-3' }, LOOKUP_TEXT[e.lookupState] || e.lookupState),
        h('td', { class: 'p-3 whitespace-nowrap' }, new Date(e.createdAt).toLocaleString())));
    }
  }

  function render(state) {
    if (state.error) showError(state.error); else showError('');
    show(el('scanResultsCard'), Boolean(state.report));
    if (state.report) renderReport(state);
    renderProgress(state); renderConsent(state); renderHistory(state);
    const busy = state.phase === PHASES.LOOKUP;
    el('scanSubmitBtn').setAttribute('aria-busy', busy ? 'true' : 'false');
  }
  return { render, getMode: mode };
}
