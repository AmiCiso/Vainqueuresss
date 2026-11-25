// Interactive labs. Static templates + a single delegated click/input handler (no inline handlers).
import { escapeHtml, $, show } from './dom.js';
import * as L from '../labs-logic.js';

const inp = 'class="w-full px-3 py-2 rounded-xl border border-apple-border font-mono text-xs"';
const btn = 'class="px-4 py-2 bg-black text-white rounded-xl font-bold text-xs"';
const opt = 'class="px-4 py-2.5 rounded-xl bg-apple-surface hover:bg-apple-surfaceHover border border-apple-border font-mono font-bold"';
const result = (id) => `<div id="${id}" role="status" aria-live="polite" class="hidden text-xs p-3 rounded-xl"></div>`;
const textRow = (n, placeholder, label) => `<div class="flex gap-2"><label class="sr-only" for="labInput-${n}">Answer</label><input type="text" id="labInput-${n}" placeholder="${escapeHtml(placeholder)}" class="px-3 py-2 rounded-xl bg-apple-surface border border-apple-border text-xs font-mono flex-grow"><button type="button" data-action="submit-text" data-lab-id="${n}" ${btn}>${label}</button></div>`;

export const LABS = {
  1: { title: 'Lab 01: Deconstruct Phishing Anatomy', desc: 'Examine a suspected phishing link: <code>https://register.ap-my1.com/aplly?user=victim</code> (a synthetic training example). Identify which element matches the typo-squatted lure.',
    render: () => `<div class="space-y-4 text-xs"><p class="text-neutral-600">Select the suspicious token in this target URI:</p><div class="flex flex-wrap gap-2 font-mono"><span class="p-2 rounded bg-apple-surface border">https://</span><span class="p-2 rounded bg-apple-surface border">register.</span><span class="p-2 rounded bg-apple-surface border">ap-my1.com</span><span class="p-2 rounded bg-rose-100 border border-rose-300 text-rose-800 font-bold">/aplly</span><span class="p-2 rounded bg-apple-surface border">?user=victim</span></div><p class="text-neutral-700">Type the misspelled path token below to verify comprehension:</p>${textRow(1, 'e.g. /aplly', 'Submit')}${result('labResult-1')}</div>` },
  2: { title: 'Lab 02: Base64 Obfuscation Analysis', desc: 'Malware often conceals commands using Base64. Decode this string to read the hidden text: <code>dmFpbnF1ZXJlcy1yZWQtdGVhbQ==</code>',
    render: () => `<div class="space-y-4 text-xs"><p class="text-neutral-600">Enter the decoded plaintext value below:</p>${textRow(2, 'Decoded string...', 'Decode &amp; Verify')}${result('labResult-2')}</div>` },
  3: { title: 'Lab 03: Protocol Assignment Verification', desc: 'Match this service with its default assigned TCP port: <strong>Secure Shell (SSH)</strong>.',
    render: () => `<div class="space-y-4 text-xs"><p class="text-neutral-600">Select the correct port number:</p><div class="flex gap-3">${[22, 80, 443].map((p) => `<button type="button" data-action="choose-port" data-value="${p}" ${opt}>Port ${p}</button>`).join('')}</div>${result('labResult-3')}</div>` },
  4: { title: 'Lab 04: SQL Injection Filter Bypass', desc: 'An insecure login field executes: <code>SELECT * FROM users WHERE user = \'USER_INPUT\' AND pass = \'...\'</code>. Which classic payload turns the WHERE clause into an always-true condition? (Educational: this lab is a text-matching exercise against a fictional query.)',
    render: () => `<div class="space-y-4 text-xs"><p class="text-neutral-600">Enter the boolean SQL injection snippet (for example the classic always-true quote payload):</p>${textRow(4, "' OR 1=1--", 'Submit')}${result('labResult-4')}</div>` },
  5: { title: 'Lab 05: Email Authentication (SPF, DKIM, DMARC)', desc: 'DMARC passes when <strong>either</strong> SPF <em>or</em> DKIM passes <em>and is aligned</em> with the visible From: domain. A DKIM failure alone does not mean DMARC fails. Work through two messages.',
    render: () => ['spoofed', 'aligned'].map((key, i) => `<div class="space-y-3 text-xs ${i ? 'pt-5 mt-5 border-t border-apple-border' : ''}"><p class="font-bold text-black">Message ${i + 1}</p><pre class="p-3 rounded-xl bg-neutral-900 text-neutral-100 overflow-x-auto text-[11px]">${escapeHtml(L.EMAIL_SCENARIOS[key].headers.join('\n'))}</pre><p class="text-neutral-600">What is the DMARC outcome?</p><div class="flex flex-wrap gap-2"><button type="button" data-action="email-answer" data-scenario="${key}" data-value="reject" ${opt}>DMARC fails: policy says reject</button><button type="button" data-action="email-answer" data-scenario="${key}" data-value="pass" ${opt}>DMARC passes</button></div>${result('labResult-5-' + key)}</div>`).join('') },
  6: { title: 'Lab 06: Hash & Encoding Workbench', desc: 'Encode, decode and hash text locally in your browser. Challenge: decode <code>VlJ7ZW5jb2RpbmdfaXNfbm90X2VuY3J5cHRpb259</code> and submit the flag.',
    render: () => `<div class="space-y-3 text-xs"><label class="sr-only" for="hIn">Input text</label><textarea id="hIn" rows="3" ${inp} placeholder="Type or paste text"></textarea><div class="flex flex-wrap gap-2">${[['sha', 'SHA-256'], ['b64e', 'Base64 encode'], ['b64d', 'Base64 decode'], ['hex', 'Hex'], ['rot', 'ROT13'], ['url', 'URL decode']].map((o) => `<button type="button" data-action="hash-op" data-op="${o[0]}" class="px-3 py-1.5 rounded-lg bg-white border border-apple-border font-bold">${o[1]}</button>`).join('')}</div><pre id="hOut" aria-live="polite" class="p-3 rounded-xl bg-apple-surface border border-apple-border whitespace-pre-wrap break-all min-h-[2.5rem]"></pre><div class="flex gap-2"><label class="sr-only" for="hFlag">Flag</label><input id="hFlag" ${inp} placeholder="VR{...}"><button type="button" data-action="check-flag" class="px-4 rounded-xl bg-black text-white font-bold">Check flag</button></div><div id="hRes" role="status" class="hidden text-xs p-3 rounded-xl"></div></div>` },
  7: { title: 'Lab 07: Password Patterns (demonstration)', desc: 'See why length and unpredictability matter. This is a simplified teaching model, not a password-strength meter. Do not type a real password.',
    render: () => `<div class="space-y-3 text-xs"><label class="sr-only" for="pwIn">Practice password</label><input id="pwIn" autocomplete="off" ${inp} placeholder="Try: Summer2024! vs correct horse battery staple"><div id="pwOut" aria-live="polite" class="p-3 rounded-xl bg-apple-surface border border-apple-border space-y-2">Type to see the demonstration.</div></div>` },
  8: { title: 'Lab 08: Phish or Legit? Inbox Triage', desc: 'Classify five message examples and learn the tell-tale signs. Each question counts once.', render: () => '<div class="space-y-3 text-xs"><div id="phBox" class="space-y-3"></div></div>' },
  9: { title: 'Lab 09: Log Hunt - Find the Brute-Force Attacker', desc: 'Review this SSH auth log (documentation-range IP addresses) and identify the attacking IP.',
    render: () => `<div class="space-y-3 text-xs"><pre class="p-3 rounded-xl bg-neutral-900 text-neutral-100 overflow-x-auto text-[11px]">${escapeHtml(L.LOG_LINES.join('\n'))}</pre><button type="button" data-action="count-log" class="px-3 py-1.5 rounded-lg bg-white border border-apple-border font-bold">Count failures per IP</button><div id="logTbl" class="space-y-1"></div><div class="flex gap-2"><label class="sr-only" for="logIn">Attacker IP</label><input id="logIn" ${inp} placeholder="Attacker IP"><button type="button" data-action="submit-log" class="px-4 rounded-xl bg-black text-white font-bold">Submit</button></div><div id="logRes" role="status" class="hidden text-xs p-3 rounded-xl"></div></div>` }
};

const GOOD = 'text-xs p-3 rounded-xl border bg-emerald-50 text-emerald-800 border-emerald-200';
const BAD = 'text-xs p-3 rounded-xl border bg-rose-50 text-rose-800 border-rose-200';

function showResult(el, ok, message, flag) {
  show(el, true);
  el.className = ok ? GOOD : BAD;
  el.textContent = '';
  const b = document.createElement('strong');
  b.textContent = (ok ? '✓ ' : '✗ ') + message;
  el.append(b);
  if (flag) { el.append(' Flag: '); const c = document.createElement('code'); c.className = 'bg-emerald-200 px-1.5 py-0.5 rounded text-emerald-950 font-bold'; c.textContent = flag; el.append(c); }
}

export function initLabs(root = document) {
  const workspace = $('activeLabWorkspace', root);
  const tabsOf = () => [...root.querySelectorAll('[data-lab]')];
  let quiz = L.createPhishQuiz();

  function renderPhish() {
    const box = $('phBox', root);
    if (!box) return;
    box.textContent = '';
    if (quiz.finished) {
      const p = document.createElement('p'); p.className = 'font-bold'; p.textContent = `Score: ${quiz.state.score} / ${quiz.total}`;
      const b = document.createElement('button'); b.type = 'button'; b.dataset.action = 'ph-restart'; b.className = 'px-3 py-1.5 rounded-lg bg-black text-white'; b.textContent = 'Restart';
      box.append(p, b); return;
    }
    const [text] = quiz.current();
    const q = document.createElement('p'); q.className = 'p-3 rounded-xl bg-apple-surface border border-apple-border'; q.textContent = text;
    const row = document.createElement('div'); row.className = 'flex gap-2';
    const mk = (label, val, cls) => { const b = document.createElement('button'); b.type = 'button'; b.dataset.action = 'ph-answer'; b.dataset.value = val; b.className = `px-3 py-1.5 rounded-lg text-white ${cls}`; b.textContent = label; return b; };
    row.append(mk('Phishing', '1', 'bg-rose-600'), mk('Legit', '0', 'bg-neutral-700'));
    const fb = document.createElement('div'); fb.id = 'phFb'; fb.setAttribute('aria-live', 'polite');
    const prog = document.createElement('p'); prog.className = 'text-[11px] text-neutral-500 font-mono'; prog.textContent = `Question ${quiz.state.i + 1} of ${quiz.total} · score ${quiz.state.score}`;
    box.append(prog, q, row, fb);
  }

  function loadLab(id) {
    tabsOf().forEach((tab) => {
      const on = Number(tab.dataset.lab) === id;
      tab.className = on ? 'p-4 rounded-2xl bg-black text-white text-left transition border border-black shadow-sm' : 'p-4 rounded-2xl bg-white hover:bg-apple-surfaceHover text-left transition border border-apple-border';
      if (on) tab.setAttribute('aria-current', 'true'); else tab.removeAttribute('aria-current');
    });
    const lab = LABS[id];
    if (!workspace || !lab) return;
    workspace.innerHTML = `<div class="space-y-4"><div class="border-b border-apple-border pb-3 flex justify-between items-center"><h3 class="text-xl font-bold text-black">${escapeHtml(lab.title)}</h3><span class="text-xs font-mono text-emerald-700 font-bold">Guided sandbox</span></div><p class="text-xs text-neutral-700 leading-relaxed">${lab.desc}</p><div class="pt-2">${lab.render()}</div></div>`;
    if (id === 8) { quiz = L.createPhishQuiz(); renderPhish(); }
  }

  root.addEventListener('click', async (e) => {
    const tab = e.target.closest('[data-lab]');
    if (tab) { loadLab(Number(tab.dataset.lab)); return; }
    const el = e.target.closest('[data-action]');
    if (!el || !workspace || !workspace.contains(el)) return;
    const a = el.dataset.action;
    if (a === 'submit-text') { const n = Number(el.dataset.labId); const r = L.checkTextLab(n, $(`labInput-${n}`, root).value); showResult($(`labResult-${n}`, root), r.ok, r.message, r.flag); }
    else if (a === 'choose-port') { const r = L.checkPortLab(el.dataset.value); showResult($('labResult-3', root), r.ok, r.message, r.flag); }
    else if (a === 'email-answer') { const r = L.checkEmailAnswer(el.dataset.scenario, el.dataset.value); showResult($('labResult-5-' + el.dataset.scenario, root), r.ok, (r.ok ? 'Correct. ' : 'Not quite. ') + r.explanation, r.flag); }
    else if (a === 'hash-op') { $('hOut', root).textContent = await L.hashOp(el.dataset.op, $('hIn', root).value); }
    else if (a === 'check-flag') { const ok = L.checkFlag($('hFlag', root).value); const r = $('hRes', root); show(r, true); r.className = ok ? GOOD : BAD; r.textContent = ok ? 'Correct. Encoding is reversible by anyone, so it protects nothing.' : 'Not yet. Try the Base64 decode operation on the challenge string.'; }
    else if (a === 'ph-answer') {
      const r = quiz.answer(el.dataset.value);
      const fb = $('phFb', root);
      if (r.counted && fb) {
        fb.textContent = '';
        const p = document.createElement('p'); p.className = 'p-3 rounded-xl ' + (r.correct ? 'bg-emerald-50 text-emerald-800' : 'bg-rose-50 text-rose-800'); p.textContent = (r.correct ? 'Correct. ' : 'Not quite. ') + r.explanation;
        const nx = document.createElement('button'); nx.type = 'button'; nx.dataset.action = 'ph-next'; nx.className = 'mt-2 px-3 py-1.5 rounded-lg bg-black text-white'; nx.textContent = 'Next';
        fb.append(p, nx);
        workspace.querySelectorAll('[data-action="ph-answer"]').forEach((b) => { b.disabled = true; b.classList.add('opacity-50'); });
      }
    }
    else if (a === 'ph-next') { quiz.next(); renderPhish(); }
    else if (a === 'ph-restart') { quiz.restart(); renderPhish(); }
    else if (a === 'count-log') {
      const t = $('logTbl', root); t.textContent = '';
      for (const [ip, n] of L.countFailuresByIp()) { const d = document.createElement('div'); d.className = 'font-mono'; d.textContent = `${ip} : ${n} failed`; t.append(d); }
    }
    else if (a === 'submit-log') { const ok = L.checkLogAnswer($('logIn', root).value); const r = $('logRes', root); show(r, true); r.className = ok ? GOOD : BAD; r.textContent = ok ? 'Correct. Many failed logins across different usernames within seconds is a classic brute-force / password-spray pattern. Block the IP and prefer key-only SSH.' : 'Not that one. Count failed attempts per IP.'; }
  });

  root.addEventListener('input', (e) => {
    if (e.target && e.target.id === 'pwIn') renderPassword(e.target.value, $('pwOut', root));
  });

  return { loadLab };
}

export function renderPassword(value, out) {
  out.textContent = '';
  if (!value) { out.textContent = 'Type to see the demonstration.'; return; }
  const r = L.passwordDemo(value);
  const line = (txt, cls = '') => { const p = document.createElement('p'); if (cls) p.className = cls; p.textContent = txt; out.append(p); };
  if (r.patterns.length) {
    line('Predictable pattern: ' + r.patterns.join('; ') + '.', 'font-bold text-rose-700');
    line('Attackers try patterns like this early, so treat it as weak regardless of length. A bit-count would be misleading here and is not shown.');
  } else if (r.looksLikePassphrase) {
    line('Looks like a multi-word passphrase. If the words were chosen randomly (for example with dice), four or more words can be strong. Phrases you invent yourself are often guessable.', 'font-bold');
  } else {
    line(`Random-model figure: about ${r.randomBits} bits, if each of the ${r.length} characters were chosen uniformly at random from a pool of ${r.pool}. Under that assumption, offline guessing would take ${r.randomModelTime}.`, 'font-bold');
    line('Human-chosen passwords are rarely random, so this number usually overstates real strength.');
  }
  line('Assumptions: ' + r.assumptions, 'text-[11px] text-neutral-500');
  line('Use a password manager and unique, randomly generated passwords; turn on multi-factor authentication or passkeys.', 'text-[11px] text-neutral-600');
}
