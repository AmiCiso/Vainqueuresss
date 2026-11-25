import { rtRoadmapData, ENR } from '../data/redteam.js';
import { createRtProgress } from '../labs-logic.js';
import { escapeHtml, $ } from './dom.js';

export function initRedTeam(storage, root = document) {
  const progress = createRtProgress(storage, rtRoadmapData);
  const box = $('rtRoadmapDetailBox', root);
  let current = 1;
  const card = (t, v) => `<div class="p-4 rounded-2xl bg-apple-surface border border-apple-border"><span class="text-xs font-mono font-bold text-black block mb-1">${t}</span><p class="text-xs text-neutral-700">${v}</p></div>`;

  function load(num) {
    const d = rtRoadmapData[num]; if (!d || !box) return;
    current = num;
    const e = ENR[num] || {}; const m = progress.map(); const pct = progress.percent(num);
    for (let i = 1; i <= 5; i++) {
      const b = $('rtStageBtn-' + i, root); if (!b) continue;
      b.className = i === num ? 'p-5 rounded-2xl bg-black text-white text-left transition border border-black shadow-md' : 'p-5 rounded-2xl bg-white hover:bg-apple-surfaceHover text-left transition border border-apple-border';
      if (i === num) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current');
    }
    box.innerHTML = `<div class="space-y-4">
      <div class="flex items-center justify-between border-b border-apple-border pb-3"><span class="text-xs font-mono font-bold text-apple-red">${escapeHtml(d.stage)}</span><span class="text-xs font-mono text-neutral-400">${escapeHtml(e.dur || '')}</span></div>
      <h3 class="text-2xl font-bold text-apple-textPrimary">${escapeHtml(d.title)}</h3>
      <p class="text-sm text-apple-textSecondary leading-relaxed">${d.desc}</p>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
        ${card('Tools and topics to study', '<span class="font-mono">' + escapeHtml(d.tools) + '</span>')}
        ${card('Prerequisites', escapeHtml(e.pre || '-'))}
        ${card('Capstone project (self-directed)', escapeHtml(e.cap || '-'))}
        ${card('Blue-team counterpart', escapeHtml(e.det || '-'))}
        ${card('Related role', escapeHtml(e.role || '-'))}
        <div class="p-4 rounded-2xl bg-apple-surface border border-apple-border"><span class="text-xs font-mono font-bold text-black block mb-1">Milestones (tick when done)</span>
          ${d.benchmarks.map((b, i) => `<label class="flex items-start gap-2 text-xs text-neutral-700 py-0.5 cursor-pointer"><input type="checkbox" data-rt-tick="${num}-${i}" ${m[num + '-' + i] ? 'checked' : ''} class="mt-0.5">${escapeHtml(b)}</label>`).join('')}
        </div>
      </div>
      <div><div class="flex justify-between text-[11px] font-mono text-neutral-500 mb-1"><span>Stage progress (self-tracked, stored in this browser)</span><span id="rtPct">${pct}%</span></div>
        <div class="w-full h-2 bg-neutral-200 rounded-full overflow-hidden"><div id="rtBar" class="h-2 bg-black rounded-full transition-all duration-300"></div></div></div>
    </div>`;
    const bar = $('rtBar', root); if (bar) bar.style.width = pct + '%'; // CSSOM write: allowed under a strict CSP
  }

  root.addEventListener('click', (e) => {
    const b = e.target.closest('[data-rt-stage]');
    if (b) load(Number(b.dataset.rtStage));
  });
  root.addEventListener('change', (e) => {
    const t = e.target && e.target.dataset && e.target.dataset.rtTick;
    if (!t) return;
    const [stage, i] = t.split('-').map(Number);
    progress.toggle(stage, i);
    const pct = progress.percent(stage);
    const bar = $('rtBar', root); if (bar) bar.style.width = pct + '%';
    const lab = $('rtPct', root); if (lab) lab.textContent = pct + '%';
  });
  return { load, progress, get current() { return current; } };
}
