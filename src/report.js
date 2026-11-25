// The ONE authoritative scan-report model. Banner, provider cards, history, counters and export are all
// derived from a report object produced here. Pure functions only (no DOM, storage or network).

export const REPORT_SCHEMA = 1;

export const PROVIDER_IDS = ['gsb', 'urlhaus'];
export const PROVIDER_LABELS = {
  gsb: 'Google Safe Browsing',
  urlhaus: 'URLhaus (abuse.ch)'
};
export const PROVIDER_COVERAGE = {
  gsb: 'Google-maintained lists of phishing, malware and unwanted-software URLs. Not exhaustive.',
  urlhaus: 'URLs observed distributing malware. Not a general phishing detector.'
};

/** Statuses that count as an actual answer from a provider. */
export const ANSWERED = new Set(['match', 'no_match']);
/** Statuses that mean "no external check happened (yet)" and must never read as clean. */
export const STATUS_TEXT = {
  not_requested: 'Not requested (local-only)',
  awaiting_consent: 'Waiting for your choice',
  skipped: 'Skipped',
  pending: 'Checking…',
  match: 'Threat reported',
  no_match: 'No match reported',
  not_configured: 'Not configured on server',
  auth_error: 'Credentials rejected',
  quota: 'Rate / quota limited',
  timeout: 'Timed out',
  network_error: 'Provider unreachable',
  unavailable: 'Provider unavailable',
  unexpected_response: 'Unexpected response',
  rejected: 'Request rejected',
  lookup_failed: 'Lookup failed'
};
export const NOT_ANSWERED_OK = new Set(Object.keys(STATUS_TEXT));

export function newScanId() {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') return globalThis.crypto.randomUUID();
  return 'scan-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
}

function blankProvider(id, status, reason = null) {
  return { id, name: PROVIDER_LABELS[id], status, reason, threats: [], evidence: null, httpStatus: null, retryAfterSec: null, checkedAt: null, cache: null };
}

/**
 * Create the initial report immediately after local analysis. `lookup` describes what will happen next.
 * input: { parsed, analysis, kind, messageCues?, otherLinks? }
 */
export function createReport({ scanId, now, parsed, analysis, kind = 'url', message = null, lookupPlan }) {
  const t = new Date(now).toISOString();
  const providerStatus = lookupPlan.providerStatus; // 'not_requested' | 'awaiting_consent' | 'skipped' | 'pending'
  const providers = {};
  for (const id of PROVIDER_IDS) providers[id] = blankProvider(id, providerStatus, lookupPlan.reason || null);
  const report = {
    schemaVersion: REPORT_SCHEMA,
    scanId,
    createdAt: t,
    updatedAt: t,
    completedAt: null,
    input: {
      kind,
      display: analysis.display,
      defanged: analysis.defanged,
      host: parsed.hostname,
      hostKind: parsed.hostKind,
      registrableDomain: analysis.registrableDomain,
      reserved: parsed.reserved,
      reservedReason: parsed.reservedReason,
      redactions: analysis.redactions,
      sensitive: { likely: analysis.sensitive.likely, reasons: analysis.sensitive.reasons.map((r) => ({ kind: r.kind, where: r.where, detail: r.detail })) },
      message
    },
    heuristic: {
      score: analysis.score,
      band: analysis.band,
      scale: '0-99 sum of weak indicators; not a probability',
      findings: analysis.findings,
      groups: analysis.groups,
      nested: analysis.nested,
      nestedLimitsHit: analysis.nestedLimitsHit,
      trustedExemptionApplied: analysis.trustedExemptionApplied,
      mitre: analysis.mitre,
      suffixSource: analysis.suffixSource
    },
    lookup: {
      mode: lookupPlan.mode, // 'local_only' | 'external'
      state: 'not_requested',
      startedAt: null,
      finishedAt: null,
      disclosure: lookupPlan.disclosure || null,
      error: null,
      retryAfterSec: null
    },
    providers,
    verdict: null,
    limitations: [...analysis.limitations]
  };
  return finalize(report, now);
}

export function computeLookupState(report) {
  const list = PROVIDER_IDS.map((id) => report.providers[id]);
  if (list.some((p) => p.status === 'awaiting_consent')) return 'awaiting_consent';
  if (list.some((p) => p.status === 'pending')) return 'pending';
  const requested = list.filter((p) => p.status !== 'not_requested' && p.status !== 'skipped');
  if (requested.length === 0) return list.every((p) => p.status === 'skipped') ? 'skipped' : 'not_requested';
  const answered = requested.filter((p) => ANSWERED.has(p.status)).length;
  if (answered === requested.length && requested.length === list.length) return 'complete';
  if (answered > 0) return 'partial';
  return 'failed';
}

export function deriveVerdict(report) {
  const h = report.heuristic;
  const providers = PROVIDER_IDS.map((id) => report.providers[id]);
  const matches = providers.filter((p) => p.status === 'match');
  const state = report.lookup.state;
  const provisional = state === 'pending' || state === 'awaiting_consent';

  let level; let label; let tone; let headline;
  if (matches.length) {
    level = 'threat_reported'; tone = 'danger'; label = 'Threat reported by provider';
    const names = matches.map((m) => m.name).join(' and ');
    headline = `${names} reported this URL. Treat it as dangerous and do not open it.`;
  } else if (h.band === 'high') {
    level = 'high_heuristic_risk'; tone = 'danger'; label = 'High heuristic risk';
    headline = 'Several local indicators point to a deceptive or risky URL. This is a heuristic assessment, not confirmed malware.';
  } else if (h.band === 'suspicious') {
    level = 'suspicious'; tone = 'warn'; label = 'Suspicious';
    headline = 'Some local indicators are present. Verify the destination through an independent channel before interacting.';
  } else if (h.band === 'low') {
    level = 'low_indicators'; tone = 'neutral'; label = 'Minor indicators (low heuristic risk)';
    headline = 'Only low-weight indicators were found. This does not make the URL safe.';
  } else {
    level = 'no_local_indicators'; tone = 'neutral'; label = 'No local indicators detected';
    headline = 'None of the local checks fired. This is not a safety guarantee.';
  }

  let externalNote;
  const problems = providers.filter((p) => !ANSWERED.has(p.status) && !['not_requested', 'skipped', 'awaiting_consent', 'pending'].includes(p.status));
  switch (state) {
    case 'not_requested': externalNote = 'External lookup was not requested (local-only analysis).'; break;
    case 'skipped': externalNote = `External lookup was skipped${report.providers.gsb.reason ? ': ' + report.providers.gsb.reason : ''}. Local analysis only.`; break;
    case 'awaiting_consent': externalNote = 'External lookup is waiting for your decision. Nothing has been sent.'; break;
    case 'pending': externalNote = 'External lookup in progress. This result may change when providers answer.'; break;
    case 'complete':
      externalNote = matches.length ? 'Providers answered; see provider cards for evidence.' : 'Both providers answered and reported no match. That does not clear the local indicators above and is not a guarantee of safety.';
      break;
    case 'partial':
      externalNote = `External coverage is incomplete (${problems.map((p) => `${p.name}: ${STATUS_TEXT[p.status] || p.status}`).join('; ')}). A missing answer is not a clean result.`;
      break;
    default:
      externalNote = `External lookup failed${report.lookup.error ? ' (' + report.lookup.error.message + ')' : ''}. No provider answered. This is not a clean result.`;
  }
  return { level, label, tone, headline, externalNote, provisional, providerMatches: matches.map((m) => m.id) };
}

/** Recompute derived fields. Always call after mutating providers/lookup. */
export function finalize(report, now) {
  const next = { ...report };
  next.lookup = { ...report.lookup, state: computeLookupState(report) };
  next.verdict = deriveVerdict(next);
  next.updatedAt = new Date(now).toISOString();
  const done = !['pending', 'awaiting_consent'].includes(next.lookup.state);
  next.completedAt = done ? (report.completedAt || next.updatedAt) : null;
  return next;
}

export function markPending(report, now) {
  const providers = { ...report.providers };
  for (const id of PROVIDER_IDS) providers[id] = blankProvider(id, 'pending');
  return finalize({ ...report, providers, lookup: { ...report.lookup, startedAt: new Date(now).toISOString(), error: null } }, now);
}

export function applyProviderResults(report, lookupResponse, now) {
  const providers = { ...report.providers };
  for (const id of PROVIDER_IDS) {
    const r = lookupResponse.providers[id];
    providers[id] = { ...blankProvider(id, r.status), ...r, name: PROVIDER_LABELS[id] };
  }
  return finalize({ ...report, providers, lookup: { ...report.lookup, finishedAt: new Date(now).toISOString(), error: null, retryAfterSec: lookupResponse.retryAfterSec || null }, attribution: lookupResponse.attribution || null }, now);
}

/** A whole-request failure (429, outage, timeout, malformed...) maps onto every provider; never a clean result. */
export function applyLookupFailure(report, failure, now) {
  const providers = { ...report.providers };
  const status = failure.providerStatus || 'lookup_failed';
  for (const id of PROVIDER_IDS) providers[id] = { ...blankProvider(id, status, failure.message), retryAfterSec: failure.retryAfterSec || null };
  return finalize({ ...report, providers, lookup: { ...report.lookup, finishedAt: new Date(now).toISOString(), error: { code: failure.code, message: failure.message }, retryAfterSec: failure.retryAfterSec || null } }, now);
}

export function resetToLocalOnly(report, now, reason) {
  const providers = {};
  for (const id of PROVIDER_IDS) providers[id] = blankProvider(id, 'not_requested', reason || null);
  return finalize({ ...report, providers, lookup: { ...report.lookup, mode: 'local_only', error: null } }, now);
}

export function isThreatFlag(verdictLevel) {
  return verdictLevel === 'threat_reported' || verdictLevel === 'high_heuristic_risk' || verdictLevel === 'suspicious';
}

/** Compact record for persistence. Contains only redacted display values. */
export function toHistoryEntry(report) {
  const providers = {};
  for (const id of PROVIDER_IDS) providers[id] = { status: report.providers[id].status, threats: report.providers[id].threats.slice(0, 5) };
  return {
    schemaVersion: REPORT_SCHEMA,
    scanId: report.scanId,
    createdAt: report.createdAt,
    updatedAt: report.updatedAt,
    display: report.input.display,
    host: report.input.host,
    mode: report.lookup.mode,
    heuristicScore: report.heuristic.score,
    heuristicBand: report.heuristic.band,
    verdictLevel: report.verdict.level,
    verdictLabel: report.verdict.label,
    lookupState: report.lookup.state,
    providers,
    redactions: report.input.redactions,
    sensitiveLikely: report.input.sensitive.likely
  };
}

export function isExportReady(report) {
  return !['pending', 'awaiting_consent'].includes(report.lookup.state);
}

/** Default export: redacted display values only, never the exact normalized URL. */
export function toExport(report, now) {
  const ready = isExportReady(report);
  return {
    exportedAt: new Date(now).toISOString(),
    exportStatus: ready ? 'final' : 'incomplete',
    incompleteReason: ready ? null : (report.lookup.state === 'pending' ? 'External provider lookup was still in progress when this file was exported.' : 'External lookup was waiting for a user decision when this file was exported.'),
    coverage: report.lookup.state,
    privacy: 'URL shown redacted (tokens, credentials, fragments removed). The exact submitted URL is never included in default exports.',
    report: JSON.parse(JSON.stringify(report))
  };
}

export function recommendation(report) {
  const v = report.verdict;
  if (v.level === 'threat_reported') return 'Do not open the link or enter any information. If you already did, change affected passwords from a different device and enable multi-factor authentication. Report the page to the impersonated organization.';
  if (v.level === 'high_heuristic_risk') return 'Do not open or enter credentials. Navigate to the organization through a bookmark or an app you already trust. Provider databases may simply not have seen this URL yet.';
  if (v.level === 'suspicious') return 'Verify the sender and destination through a separate channel before interacting. Do not enter passwords, OTPs or card details.';
  return 'No strong local indicators, but heuristics cannot prove a URL is safe. Keep normal precautions: check the exact domain, avoid unexpected downloads, and use multi-factor authentication.';
}
