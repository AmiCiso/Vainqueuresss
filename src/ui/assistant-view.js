// Rule-based assistant. No generative model, no external calls. Link quick-scans are local-only.
import { KB } from '../data/assistant-kb.js';
import { parseTarget } from '../shared/url-policy.js';
import { analyzeUrl, extractUrls } from '../analysis.js';
import { escapeHtml, $ } from './dom.js';

const BAND_LABEL = { high: 'High heuristic risk', suspicious: 'Suspicious', low: 'Minor indicators', none: 'No local indicators detected' };

export function createAssistant() {
  let ctx = -1;
  const chips = (a) => '<div class="flex flex-wrap gap-1 pt-1">' + a.map((f) => `<button type="button" class="px-2 py-1 rounded-lg bg-white border border-apple-border text-[11px] hover:bg-apple-surfaceHover" data-prompt="${escapeHtml(f)}">${escapeHtml(f)}</button>`).join('') + '</div>';

  function reply(query, depth, onOpenScanner = () => {}) {
    const q = query.toLowerCase();
    const bm = /\b(apa|macam mana|bagaimana|kenapa|boleh|saya|aku|tak|nak|yang|dan|tolong)\b/.test(q);
    const intro = bm ? '<p class="text-[11px] text-neutral-500">Jawapan (istilah teknikal dalam English):</p>' : '';

    const links = (query.match(/(?:https?:\/\/|www\.)\S+/gi) || []).map((x) => x.replace(/[.,;!?]+$/, ''));
    if (links.length) {
      const p = parseTarget(links[0]);
      if (p.ok) {
        const r = analyzeUrl(p, { raw: links[0] });
        const flagged = r.findings.filter((f) => f.flagged).map((f) => f.name.replace(/^\d+\.\s*/, ''));
        return intro + `<p><strong>Local quick scan of <code>${escapeHtml(r.defanged)}</code>:</strong> ${BAND_LABEL[r.band]} (heuristic ${r.score}/100, uncalibrated)</p><p class="text-xs">${flagged.length ? escapeHtml(flagged.join('; ')) : 'No local rule matched, which is not proof of safety.'}</p><p class="text-[11px] text-neutral-500">Local heuristics only: no external provider was contacted and the link was not opened.</p>` + chips(['Open the Threat Scanner for the full report', 'Phishing tips']);
      }
      if (p.code === 'userinfo') return '<p>That link contains a username/password prefix (<code>user:pass@host</code>), which is a common disguise technique. I did not analyze it. Remove the prefix and treat the original link with suspicion.</p>';
    }
    if (/^(hi|hello|hai|salam|help|tolong)\b/.test(q)) return '<p>Hi! I am a rule-based assistant: I match keywords to a built-in knowledge base. Ask about phishing, passwords, passkeys, ransomware, web security, cloud, Linux, scams in Malaysia and more. Paste a link and I will run a local quick scan.</p>' + chips(KB.slice(0, 8).map((t) => t[1]));
    if (/threat scanner|open the threat scanner/.test(q)) { onOpenScanner(); return '<p>Opening the VanQ Threat Scanner for you.</p>'; }

    let best = -1; let bs = 0;
    KB.forEach((t, i) => { const m = q.match(new RegExp(t[0], 'gi')); const s = m ? m.join('').length : 0; if (s > bs) { bs = s; best = i; } });
    if (best < 0 && ctx >= 0 && /^(why|kenapa|how|macam mana|more|lagi|detail|explain|elaborate|terangkan|contoh|example|steps|tell me more)/.test(q) && q.split(/\s+/).length <= 4) {
      const t = KB[ctx];
      return `<p><strong>${escapeHtml(t[1])} (deeper):</strong></p><p>${escapeHtml(t[3])}</p>` + chips(t[4]);
    }
    if (best < 0) return '<p>I could not match that to a topic yet. Try one of these, or rephrase with a keyword:</p>' + chips(KB.filter((_, i) => i % 3 === 0).map((t) => t[1]));
    ctx = best;
    const t = KB[best];
    return intro + `<p><strong>${escapeHtml(t[1])}:</strong></p><p>${escapeHtml(t[2])}</p>` + (depth === 'beginner' ? '' : `<p><strong>Technical:</strong> ${escapeHtml(t[3])}</p>`) + chips(['Tell me more'].concat(t[4]));
  }
  return { reply, extractUrls };
}

export function initAssistant(onOpenScanner, root = document) {
  const a = createAssistant();
  const input = $('assistantInput', root); const box = $('chatMessagesBox', root); const depthSel = $('assistantDepth', root);
  if (!input || !box) return a;

  function send(text) {
    const t = String(text).trim(); if (!t) return;
    const wrap = document.createElement('div'); wrap.className = 'flex items-start justify-end gap-3';
    const bub = document.createElement('div'); bub.className = 'p-4 rounded-2xl bg-black text-white max-w-xl text-xs sm:text-sm'; bub.textContent = t;
    const av = document.createElement('div'); av.className = 'w-8 h-8 rounded-xl bg-neutral-200 text-neutral-800 flex items-center justify-center font-bold text-xs shrink-0'; av.textContent = 'YOU';
    wrap.append(bub, av); box.append(wrap);
    input.value = '';
    const depth = depthSel ? depthSel.value : 'beginner';
    const html = a.reply(t, depth, onOpenScanner);
    const bot = document.createElement('div'); bot.className = 'flex items-start gap-3';
    bot.innerHTML = `<div class="w-8 h-8 rounded-xl bg-black text-white flex items-center justify-center font-bold text-xs shrink-0">VR</div><div class="p-4 rounded-2xl bg-apple-surface border border-apple-border max-w-2xl text-apple-textPrimary space-y-2 text-xs sm:text-sm"><div class="flex items-center justify-between"><span class="font-bold text-xs text-black">Vainqueures AI Security [${escapeHtml(depth.toUpperCase())}]</span><span class="text-[10px] font-mono text-neutral-400">Rule-based answer</span></div><div class="leading-relaxed space-y-2">${html}</div></div>`;
    box.append(bot);
    box.scrollTop = box.scrollHeight;
  }

  const sendBtn = $('assistantSendBtn', root);
  if (sendBtn) sendBtn.addEventListener('click', () => send(input.value));
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); send(input.value); } });
  root.addEventListener('click', (e) => {
    const p = e.target.closest('[data-prompt]');
    if (p && p.dataset.prompt) send(p.dataset.prompt);
  });
  return { ...a, send };
}
