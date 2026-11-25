// DOM-free logic for the interactive labs, quizzes and progress tracking (unit-testable).

// ---- Lab answers ------------------------------------------------------------------------------
const norm = (s) => String(s).toLowerCase().replace(/\s+/g, '');

export const TEXT_LABS = {
  1: { accept: ['/aplly'], flag: 'VR{LAB1_SUCCESS}', hint: 'Check your spelling or review the prompt.' },
  2: { accept: ['vainqueures-red-team'], flag: 'VR{LAB2_SUCCESS}', hint: 'Decode the Base64 string and type the plaintext.' },
  4: { accept: ["'or1=1--", "'or1=1#", "'or'1'='1", "'or1=1--'", "'or1=1/*"], flag: 'VR{LAB4_SUCCESS}', hint: 'Think of a payload that closes the quote and makes the condition always true.' }
};

export function checkTextLab(labId, value) {
  const lab = TEXT_LABS[labId];
  if (!lab) return { ok: false, message: 'Unknown lab.' };
  const ok = lab.accept.includes(norm(value));
  return ok ? { ok: true, message: 'Challenge solved!', flag: lab.flag } : { ok: false, message: 'Incorrect. ' + lab.hint };
}

export function checkPortLab(port) {
  if (Number(port) === 22) return { ok: true, message: 'Correct! Port 22 is assigned to SSH (Secure Shell).', flag: 'VR{SSH_PORT_22}' };
  return { ok: false, message: `Incorrect. Port ${Number(port)} is the default for web traffic (HTTP/HTTPS), not SSH.` };
}

// ---- Email authentication (SPF / DKIM / DMARC) -----------------------------------------------
/**
 * DMARC passes when EITHER an aligned SPF pass OR an aligned DKIM pass exists.
 * A DKIM failure alone does not imply a DMARC failure, and an SPF pass alone is not enough unless the
 * domain that passed SPF (Return-Path / MAIL FROM) is aligned with the visible From: domain.
 */
export function evaluateDmarc({ spfPass, spfAligned, dkimPass, dkimAligned, policy }) {
  const alignedSpf = Boolean(spfPass && spfAligned);
  const alignedDkim = Boolean(dkimPass && dkimAligned);
  const pass = alignedSpf || alignedDkim;
  return { pass, alignedSpf, alignedDkim, requestedAction: pass ? 'none (DMARC passes)' : policy, policy };
}

export const EMAIL_SCENARIOS = {
  spoofed: {
    headers: ['From: billing@bank.example', 'Return-Path: bounce@mailer.example.net', 'SPF: pass (for mailer.example.net, sender IP authorized there)', 'DKIM: fail (signature does not verify)', 'DMARC record for bank.example: p=reject'],
    input: { spfPass: true, spfAligned: false, dkimPass: false, dkimAligned: false, policy: 'reject' }
  },
  aligned: {
    headers: ['From: billing@bank.example', 'Return-Path: bounce@bank.example', 'SPF: pass (for bank.example, sender IP authorized)', 'DKIM: fail (signature broken in transit)', 'DMARC record for bank.example: p=reject'],
    input: { spfPass: true, spfAligned: true, dkimPass: false, dkimAligned: false, policy: 'reject' }
  }
};

export function checkEmailAnswer(scenarioKey, answer) {
  const sc = EMAIL_SCENARIOS[scenarioKey];
  const r = evaluateDmarc(sc.input);
  const expected = r.pass ? 'pass' : 'reject';
  const ok = answer === expected;
  const why = r.pass
    ? 'SPF passed for a domain that is aligned with the From: domain, so DMARC passes even though DKIM failed. DMARC needs only one aligned mechanism. (Other spam filtering can still apply.)'
    : 'SPF passed, but for mailer.example.net, which is not aligned with bank.example, and DKIM failed. With no aligned SPF or aligned DKIM pass, DMARC fails, and the published policy p=reject asks receivers to reject the message. Receivers usually honor this but may apply local policy.';
  return { ok, expected, explanation: why, flag: ok ? (r.pass ? 'VR{DMARC_NEEDS_ONE_ALIGNED_PASS}' : 'VR{DMARC_REJECT_ENFORCED}') : null };
}

// ---- Phishing triage quiz (cannot be double counted) -----------------------------------------
export const PH_ITEMS = [
  ['SMS: "LHDN: Tahniah, anda layak refund RM1,240. Klik http://lhdn-refund.top/claim dalam 24 jam."', 1, '.top domain, not .gov.my, reward + urgency lure.'],
  ['Email from accounts.google.com: "New sign-in on Windows. If this was you, no action needed." No links asking for a password.', 0, 'Official domain, no credential request, no pressure.'],
  ['Call: "Saya pegawai PDRM. Akaun anda terlibat jenayah. Pindahkan wang ke akaun selamat."', 1, 'Classic Macau scam: authority + fear + money transfer.'],
  ['SMS from your courier app: "Parcel delivered. Track inside the official app." No link.', 0, 'No link, directs you to the official app.'],
  ['WhatsApp: "Install this APK to get your free Touch n Go bonus."', 1, 'Sideloaded APK = banking trojan risk.']
];

export function createPhishQuiz(items = PH_ITEMS) {
  const st = { i: 0, score: 0, answered: false, lastCorrect: null };
  return {
    state: st,
    get finished() { return st.i >= items.length; },
    get total() { return items.length; },
    current() { return st.i < items.length ? items[st.i] : null; },
    /** A question can be scored once; later answers to the same question are ignored. */
    answer(a) {
      if (st.i >= items.length || st.answered) return { counted: false, correct: st.lastCorrect };
      st.answered = true;
      st.lastCorrect = Number(a) === items[st.i][1];
      if (st.lastCorrect) st.score += 1;
      return { counted: true, correct: st.lastCorrect, explanation: items[st.i][2] };
    },
    next() { if (st.answered && st.i < items.length) { st.i += 1; st.answered = false; st.lastCorrect = null; } },
    restart() { st.i = 0; st.score = 0; st.answered = false; st.lastCorrect = null; }
  };
}

// ---- Log hunt ---------------------------------------------------------------------------------
export const LOG_LINES = [
  'Oct 13 09:01:12 sshd: Failed password for root from 198.51.100.8',
  'Oct 13 09:01:15 sshd: Accepted publickey for deploy from 192.0.2.10',
  'Oct 13 09:02:01 sshd: Failed password for admin from 203.0.113.77',
  'Oct 13 09:02:03 sshd: Failed password for root from 203.0.113.77',
  'Oct 13 09:02:05 sshd: Failed password for test from 203.0.113.77',
  'Oct 13 09:02:07 sshd: Failed password for ubuntu from 203.0.113.77',
  'Oct 13 09:02:09 sshd: Failed password for oracle from 203.0.113.77',
  'Oct 13 09:02:30 sshd: Failed password for deploy from 192.0.2.10',
  'Oct 13 09:03:11 sshd: Accepted publickey for deploy from 192.0.2.10',
  'Oct 13 09:04:44 sshd: Failed password for guest from 203.0.113.77'
];
export function countFailuresByIp(lines = LOG_LINES) {
  const c = {};
  for (const l of lines) { if (/Failed/.test(l)) { const m = /from (\S+)/.exec(l); if (m) c[m[1]] = (c[m[1]] || 0) + 1; } }
  return Object.entries(c).sort((a, b) => b[1] - a[1]);
}
export const checkLogAnswer = (v) => String(v).trim() === '203.0.113.77';

// ---- Hash / encoding workbench ----------------------------------------------------------------
const hex = (bytes) => [...bytes].map((x) => x.toString(16).padStart(2, '0'));
export const FLAG_ENCODING = 'VR{encoding_is_not_encryption}';
export async function hashOp(op, v, cryptoImpl = globalThis.crypto) {
  try {
    const enc = new TextEncoder();
    if (op === 'sha') return hex(new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', enc.encode(v)))).join('');
    if (op === 'b64e') return btoa(String.fromCharCode(...enc.encode(v)));
    if (op === 'b64d') { const bin = atob(v.trim()); return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))); }
    if (op === 'hex') return hex(enc.encode(v)).join(' ');
    if (op === 'rot') return v.replace(/[a-zA-Z]/g, (c) => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26));
    if (op === 'url') return decodeURIComponent(v);
    return '';
  } catch {
    return 'Error: input is not valid for this operation.';
  }
}
export const checkFlag = (v) => String(v).trim() === FLAG_ENCODING;

// ---- Password demonstration -------------------------------------------------------------------
const COMMON = /password|123456|qwerty|admin|letmein|iloveyou|malaysia|welcome|abc123|monkey|dragon|football|sunshine|master|login/i;
const SEASONS = /^(spring|summer|autumn|fall|winter|january|february|march|april|may|june|july|august|september|october|november|december)/i;

/**
 * DEMONSTRATION ONLY. The "random-model" figure assumes every character is drawn independently and uniformly
 * from the detected character classes. That model does not describe human-chosen passwords, which attackers
 * guess from wordlists, names, dates and substitution patterns. Predictable patterns are flagged and the
 * random-model number is withheld as a meaningful strength estimate in that case.
 */
export function passwordDemo(p) {
  const s = String(p);
  const pool = (/[a-z]/.test(s) ? 26 : 0) + (/[A-Z]/.test(s) ? 26 : 0) + (/\d/.test(s) ? 10 : 0) + (/[^A-Za-z0-9]/.test(s) ? 33 : 0);
  const randomBits = s.length * Math.log2(pool || 1);
  const patterns = [];
  if (COMMON.test(s)) patterns.push('contains a very common word or sequence');
  if (SEASONS.test(s) || /^[A-Za-z]+(19|20)\d{2}[^A-Za-z0-9]?$/.test(s) || /^[A-Z][a-z]+\d{1,4}[^A-Za-z0-9]?$/.test(s)) patterns.push('follows a common word + number + symbol pattern');
  if (/(.)\1{2,}/.test(s)) patterns.push('repeats characters');
  if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|qwer|asdf)/i.test(s)) patterns.push('contains a keyboard or numeric sequence');
  const looksLikePassphrase = /^([A-Za-z]{3,10}[ \-_.]){3,}[A-Za-z]{3,10}$/.test(s);
  const guessesPerSecond = 1e10;
  const seconds = Math.pow(2, randomBits) / guessesPerSecond / 2;
  return {
    length: s.length, pool, randomBits: Math.round(randomBits), patterns, looksLikePassphrase,
    randomModelTime: humanTime(seconds),
    reliable: false,
    assumptions: 'Assumes characters chosen uniformly at random and an offline attacker making 10 billion guesses per second against a fast, unsalted hash. Real systems use slow, salted hashes; real attackers use wordlists and patterns.'
  };
}
export function humanTime(s) {
  if (!Number.isFinite(s) || s < 1) return 'under a second';
  if (s < 60) return Math.round(s) + ' seconds';
  if (s < 3600) return Math.round(s / 60) + ' minutes';
  if (s < 86400) return Math.round(s / 3600) + ' hours';
  if (s < 3.15e7) return Math.round(s / 86400) + ' days';
  if (s < 3.15e9) return Math.round(s / 3.15e7) + ' years';
  return 'more than a century';
}

// ---- Progress storage (validated; never throws) ----------------------------------------------
function readMap(storage, key, valid) {
  let raw = null;
  try { raw = storage ? storage.getItem(key) : null; } catch { return {}; }
  if (!raw) return {};
  let data;
  try { data = JSON.parse(raw); } catch { return {}; }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) return {};
  const out = {};
  for (const [k, v] of Object.entries(data)) if (valid(k, v)) out[k] = 1;
  return out;
}
function writeMap(storage, key, map) {
  try { if (storage) storage.setItem(key, JSON.stringify(map)); return true; } catch { return false; }
}

/** Academy quiz progress, keyed `${cat}-${lesson}` so repeated correct answers cannot inflate the count. */
export function createAcademyProgress(storage, curriculum) {
  const valid = (k, v) => {
    const m = /^(\d+)-(\d+)$/.exec(k);
    return Boolean(m && v && curriculum[Number(m[1])] && curriculum[Number(m[1])].lessons[Number(m[2])]);
  };
  return {
    done: () => readMap(storage, 'vr_done', valid),
    total: () => curriculum.reduce((a, c) => a + c.lessons.length, 0),
    completedCount() { return Object.keys(this.done()).length; },
    /** Returns { correct, newlyCompleted }. */
    answer(cat, lesson, picked) {
      const correct = picked === curriculum[cat].lessons[lesson].quiz.correct;
      let newlyCompleted = false;
      if (correct) {
        const d = this.done();
        const k = `${cat}-${lesson}`;
        if (!d[k]) { d[k] = 1; newlyCompleted = true; writeMap(storage, 'vr_done', d); }
      }
      return { correct, newlyCompleted };
    }
  };
}

export function createRtProgress(storage, roadmap) {
  const valid = (k, v) => {
    const m = /^(\d+)-(\d+)$/.exec(k);
    return Boolean(m && v && roadmap[Number(m[1])] && roadmap[Number(m[1])].benchmarks[Number(m[2])] !== undefined);
  };
  return {
    map: () => readMap(storage, 'vr_rt', valid),
    toggle(stage, i) {
      const m = this.map(); const k = `${stage}-${i}`;
      if (m[k]) delete m[k]; else m[k] = 1;
      writeMap(storage, 'vr_rt', m);
      return Boolean(m[k]);
    },
    percent(stage) {
      const d = roadmap[stage]; const m = this.map();
      return Math.round(d.benchmarks.filter((_, i) => m[`${stage}-${i}`]).length / d.benchmarks.length * 100);
    }
  };
}
