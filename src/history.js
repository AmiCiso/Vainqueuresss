// Privacy-aware local history. Stores ONLY redacted display values and verdict metadata, with explicit
// retention limits. Parsing is defensive: any JSON shape (null, {}, arrays of junk) must not crash the app.

export const HISTORY_KEY = 'vq_scan_history_v2';
export const LEGACY_KEYS = ['vr_scan_history', 'vr_scan_total', 'vr_threat_total'];
export const MAX_ENTRIES = 20;
export const MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

const LOOKUP_STATES = new Set(['not_requested', 'skipped', 'awaiting_consent', 'pending', 'complete', 'partial', 'failed', 'interrupted']);
const LEVELS = new Set(['threat_reported', 'high_heuristic_risk', 'suspicious', 'low_indicators', 'no_local_indicators']);
const BANDS = new Set(['none', 'low', 'suspicious', 'high']);
const PSTATUS = new Set(['not_requested', 'awaiting_consent', 'skipped', 'pending', 'match', 'no_match', 'not_configured', 'auth_error', 'quota', 'timeout', 'network_error', 'unavailable', 'unexpected_response', 'rejected', 'lookup_failed', 'interrupted']);

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const cap = (v, n) => String(v).slice(0, n);

export function safeStorage(win = globalThis) {
  try {
    const s = win.localStorage;
    const probe = '__vq_probe__';
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null; // blocked, full, or disabled
  }
}

/** Returns a sanitized entry or null. Never throws. */
export function validateEntry(e, now = Date.now()) {
  if (!isObj(e)) return null;
  if (typeof e.scanId !== 'string' || !e.scanId || e.scanId.length > 80) return null;
  const created = Date.parse(e.createdAt);
  if (!Number.isFinite(created) || created > now + 86400000) return null;
  const updated = Number.isFinite(Date.parse(e.updatedAt)) ? e.updatedAt : e.createdAt;
  if (typeof e.display !== 'string' || !e.display) return null;
  if (!LEVELS.has(e.verdictLevel) || !BANDS.has(e.heuristicBand)) return null;
  const score = Number(e.heuristicScore);
  if (!Number.isFinite(score) || score < 0 || score > 99) return null;
  let lookupState = LOOKUP_STATES.has(e.lookupState) ? e.lookupState : 'interrupted';
  if (lookupState === 'pending' || lookupState === 'awaiting_consent') lookupState = 'interrupted'; // tab closed mid-lookup
  const providers = {};
  for (const id of ['gsb', 'urlhaus']) {
    const p = isObj(e.providers) && isObj(e.providers[id]) ? e.providers[id] : {};
    let status = PSTATUS.has(p.status) ? p.status : 'lookup_failed';
    if (status === 'pending' || status === 'awaiting_consent') status = 'interrupted';
    providers[id] = { status, threats: Array.isArray(p.threats) ? p.threats.filter((t) => typeof t === 'string').slice(0, 5).map((t) => cap(t, 80)) : [] };
  }
  return {
    schemaVersion: 1, scanId: e.scanId, createdAt: new Date(created).toISOString(), updatedAt: cap(updated, 40),
    display: cap(e.display, 300), host: typeof e.host === 'string' ? cap(e.host, 253) : '',
    mode: e.mode === 'external' ? 'external' : 'local_only', heuristicScore: Math.round(score), heuristicBand: e.heuristicBand,
    verdictLevel: e.verdictLevel, verdictLabel: typeof e.verdictLabel === 'string' ? cap(e.verdictLabel, 80) : e.verdictLevel,
    lookupState, providers, redactions: Number.isFinite(e.redactions) ? Math.max(0, Math.min(999, e.redactions)) : 0, sensitiveLikely: e.sensitiveLikely === true
  };
}

export function parseHistory(raw, now = Date.now()) {
  let data;
  try { data = JSON.parse(raw); } catch { return []; }
  if (!Array.isArray(data)) return [];
  const out = [];
  for (const item of data) {
    const v = validateEntry(item, now);
    if (v && now - Date.parse(v.createdAt) <= MAX_AGE_MS) out.push(v);
    if (out.length >= MAX_ENTRIES) break;
  }
  return out;
}

export function createHistoryStore({ storage = safeStorage(), now = () => Date.now() } = {}) {
  let memory = [];
  const available = Boolean(storage);

  function persist() {
    if (!storage) return false;
    try { storage.setItem(HISTORY_KEY, JSON.stringify(memory)); return true; } catch { return false; }
  }
  function purgeLegacy() {
    if (!storage) return;
    for (const k of LEGACY_KEYS) { try { storage.removeItem(k); } catch { /* ignore */ } }
  }
  function load() {
    purgeLegacy(); // legacy builds stored complete URLs; remove them
    let raw = null;
    try { raw = storage ? storage.getItem(HISTORY_KEY) : null; } catch { raw = null; }
    memory = raw ? parseHistory(raw, now()) : [];
    persist(); // writes back the pruned/sanitized list
    return list();
  }
  function list() { return memory.slice(); }
  /** Insert or update by scanId (never duplicates a scan when enrichment completes). */
  function upsert(entry) {
    const v = validateEntry(entry, now() + 1);
    if (!v) return false;
    // keep pending states as authored during the active session
    v.lookupState = entry.lookupState;
    v.providers = entry.providers;
    const i = memory.findIndex((m) => m.scanId === v.scanId);
    if (i >= 0) memory[i] = { ...memory[i], ...entry, createdAt: memory[i].createdAt };
    else memory.unshift({ ...entry });
    memory = memory.filter((m) => now() - Date.parse(m.createdAt) <= MAX_AGE_MS).slice(0, MAX_ENTRIES);
    persist();
    return true;
  }
  function clear() {
    memory = [];
    if (storage) { try { storage.removeItem(HISTORY_KEY); } catch { /* ignore */ } }
    purgeLegacy();
  }
  return { load, list, upsert, clear, get available() { return available; } };
}
