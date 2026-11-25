// Scan orchestration as an explicit state machine with a generation token.
// Every asynchronous completion is checked against `generation`; stale completions are dropped silently,
// so scan A can never overwrite scan B's banner, provider badges, report, history record or loading state.

import { parseTarget, withoutQuery } from './shared/url-policy.js';
import { analyzeUrl, analyzeMessage, extractUrls } from './analysis.js';
import { requestLookup, LookupError, FAILURE_STATUS } from './providers-client.js';
import * as R from './report.js';

export const PHASES = Object.freeze({ IDLE: 'idle', AWAITING_CONSENT: 'awaiting_consent', LOOKUP: 'lookup_pending', DONE: 'done' });

export function createScanController({ history, fetchImpl, apiBase = '', now = () => Date.now(), timeoutMs = 12000, onChange = () => {}, newId = R.newScanId }) {
  let generation = 0;
  let abort = null;
  const state = { phase: PHASES.IDLE, report: null, error: null, exportReady: false, transient: null };

  const snapshot = () => ({
    phase: state.phase,
    report: state.report,
    error: state.error,
    exportReady: state.report ? R.isExportReady(state.report) : false,
    canRetryLookup: Boolean(state.transient && state.transient.externalUrl && state.report && ['failed', 'partial'].includes(state.report.lookup.state)),
    awaitingConsent: state.phase === PHASES.AWAITING_CONSENT,
    history: history.list()
  });
  const emit = () => onChange(snapshot());

  function commit(gen, report, phase) {
    if (gen !== generation) return false; // stale completion: ignore entirely
    state.report = report;
    state.phase = phase;
    history.upsert(R.toHistoryEntry(report));
    emit();
    return true;
  }

  function cancelInFlight() {
    if (abort) { abort.abort(); abort = null; }
  }

  /** A scan replaced before its lookup finished is recorded honestly as interrupted (never as complete or clean). */
  function recordInterrupted() {
    const r = state.report;
    if (!r || !['pending', 'awaiting_consent'].includes(r.lookup.state)) return;
    const e = R.toHistoryEntry(r);
    e.lookupState = 'interrupted';
    for (const id of R.PROVIDER_IDS) e.providers[id] = { status: 'interrupted', threats: [] };
    history.upsert(e);
  }

  function buildDisclosure({ queryRemoved = false, acknowledged = false } = {}) {
    return { sharedWith: [R.PROVIDER_LABELS.gsb, R.PROVIDER_LABELS.urlhaus], via: 'this site’s server', fragmentRemoved: true, queryRemoved, sensitiveAcknowledged: acknowledged };
  }

  function chooseTarget(raw) {
    const text = String(raw ?? '').trim();
    if (!text) return { error: 'Please enter a URL or domain to scan.' };
    if (!/\s/.test(text)) {
      const p = parseTarget(text);
      if (!p.ok) return { error: p.message };
      return { kind: 'url', parsed: p, raw: text };
    }
    // Pasted message text: analyze every link (bounded) and keep the highest-scoring one as primary.
    const urls = extractUrls(text);
    const msg = analyzeMessage(text);
    const cands = [];
    for (const u of urls) {
      const p = parseTarget(u);
      if (p.ok) cands.push({ parsed: p, raw: u, analysis: analyzeUrl(p, { raw: u, message: msg }) });
    }
    if (!cands.length) return { error: 'No valid http(s) link was found in that text.' };
    let best = 0;
    cands.forEach((c, i) => { if (c.analysis.score > cands[best].analysis.score) best = i; });
    const primary = cands[best];
    return {
      kind: 'message', parsed: primary.parsed, raw: primary.raw, analysis: primary.analysis,
      message: { cues: msg.cues, otherLinks: cands.filter((_, i) => i !== best).map((c) => ({ display: c.analysis.display, score: c.analysis.score, band: c.analysis.band })) }
    };
  }

  async function runLookup(gen, externalUrl, acknowledgeSensitive) {
    cancelInFlight();
    abort = new AbortController();
    const mine = abort;
    let next;
    try {
      const res = await requestLookup({ url: externalUrl, acknowledgeSensitive, signal: mine.signal, apiBase, fetchImpl, timeoutMs });
      if (gen !== generation) return;
      next = R.applyProviderResults(state.report, res, now());
    } catch (err) {
      if (gen !== generation) return;
      if (err instanceof LookupError && err.code === 'aborted') return;
      if (err instanceof LookupError && err.code === 'consent_required' && !acknowledgeSensitive) {
        // The server judged the URL sensitive even though the client did not: ask the user, send nothing.
        state.transient = { externalUrl, ack: false };
        const providers = { ...state.report.providers };
        for (const id of R.PROVIDER_IDS) providers[id] = { ...providers[id], status: 'awaiting_consent', reason: null };
        commit(gen, R.finalize({ ...state.report, providers, input: { ...state.report.input, sensitive: { ...state.report.input.sensitive, likely: true } } }, now()), PHASES.AWAITING_CONSENT);
        return;
      }
      const failure = err instanceof LookupError
        ? { code: err.code, message: err.message, retryAfterSec: err.retryAfterSec, providerStatus: FAILURE_STATUS[err.code] }
        : { code: 'unexpected', message: 'Unexpected error during lookup.', providerStatus: 'lookup_failed' };
      next = R.applyLookupFailure(state.report, failure, now());
    }
    if (abort === mine) abort = null;
    commit(gen, next, PHASES.DONE);
  }

  /** opts: { lookup: 'local'|'external', sample?: boolean } */
  function startScan(raw, opts = {}) {
    recordInterrupted();
    generation += 1;
    const gen = generation;
    cancelInFlight();
    state.transient = null;
    const target = chooseTarget(raw);
    if (target.error) {
      state.error = target.error;
      // A rejected input is not a scan: leave the previous report as it is, but never leave a spinner behind.
      state.phase = state.report ? PHASES.DONE : PHASES.IDLE;
      emit();
      return { ok: false, error: target.error };
    }
    state.error = null;
    const { parsed } = target;
    const analysis = target.analysis || analyzeUrl(parsed, { raw: target.raw });
    const wantsExternal = opts.lookup === 'external' && !opts.sample;

    let plan;
    if (!wantsExternal) plan = { mode: 'local_only', providerStatus: 'not_requested', reason: opts.sample ? 'Sample presets are always analyzed locally.' : null };
    else if (parsed.reserved) plan = { mode: 'external', providerStatus: 'skipped', reason: `Not sent: host is ${parsed.reservedReason}`, disclosure: null };
    else if (analysis.sensitive.likely) plan = { mode: 'external', providerStatus: 'awaiting_consent', disclosure: buildDisclosure() };
    else plan = { mode: 'external', providerStatus: 'pending', disclosure: buildDisclosure() };

    let report = R.createReport({ scanId: newId(), now: now(), parsed, analysis, kind: target.kind, message: target.message || null, lookupPlan: plan });
    if (target.kind === 'message' && wantsExternal && target.message.otherLinks.length) {
      report.limitations.push('Only the highest-scoring link in the pasted text is eligible for external lookup; other links were analyzed locally only.');
    }
    if (plan.providerStatus === 'pending') report = R.markPending(report, now());
    state.transient = { externalUrl: parsed.externalUrl, ack: false };

    const phase = plan.providerStatus === 'pending' ? PHASES.LOOKUP : plan.providerStatus === 'awaiting_consent' ? PHASES.AWAITING_CONSENT : PHASES.DONE;
    commit(gen, report, phase);
    if (phase === PHASES.LOOKUP) runLookup(gen, parsed.externalUrl, false);
    return { ok: true, scanId: report.scanId };
  }

  /** choice: 'send_full' | 'send_no_query' | 'local_only' */
  function resolveConsent(choice) {
    if (state.phase !== PHASES.AWAITING_CONSENT || !state.report || !state.transient) return false;
    const gen = generation;
    if (choice === 'local_only') {
      const next = R.resetToLocalOnly(state.report, now(), 'You chose local-only analysis for this URL.');
      state.transient = null;
      commit(gen, next, PHASES.DONE);
      return true;
    }
    const noQuery = choice === 'send_no_query';
    const url = noQuery ? withoutQuery(state.transient.externalUrl) : state.transient.externalUrl;
    state.transient = { externalUrl: url, ack: true };
    let report = { ...state.report, lookup: { ...state.report.lookup, disclosure: buildDisclosure({ queryRemoved: noQuery, acknowledged: true }) } };
    if (noQuery) report.limitations = [...report.limitations, 'The query string was removed before external lookup at your request; providers checked a different (less specific) URL than the one analyzed locally.'];
    report = R.markPending(report, now());
    commit(gen, report, PHASES.LOOKUP);
    runLookup(gen, url, true);
    return true;
  }

  /** Manual, user-initiated retry (never automatic). */
  function retryLookup() {
    if (!state.transient || !state.transient.externalUrl || !state.report) return false;
    if (!['failed', 'partial'].includes(state.report.lookup.state)) return false;
    generation += 1;
    const gen = generation;
    const report = R.markPending(state.report, now());
    commit(gen, report, PHASES.LOOKUP);
    runLookup(gen, state.transient.externalUrl, Boolean(state.transient.ack));
    return true;
  }

  function exportCurrent() {
    if (!state.report || !R.isExportReady(state.report)) return null;
    return R.toExport(state.report, now());
  }

  function clearHistory() {
    history.clear();
    emit();
  }

  function dispose() { generation += 1; cancelInFlight(); }

  return { startScan, resolveConsent, retryLookup, exportCurrent, clearHistory, getState: snapshot, dispose };
}
