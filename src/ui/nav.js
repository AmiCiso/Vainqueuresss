import { $ } from './dom.js';

export const VIEWS = ['home', 'scanner', 'assistant', 'academy', 'labs', 'redteam'];

export function initNav(hooks = {}, doc = document) {
  const visited = new Set();
  function switchView(id, { scrollTo = null } = {}) {
    if (!VIEWS.includes(id)) return;
    doc.querySelectorAll('.page-view').forEach((v) => v.classList.add('hidden'));
    const active = $('view-' + id, doc);
    if (active) active.classList.remove('hidden');
    for (const v of VIEWS) {
      const on = v === id;
      const d = $('navBtn-' + v, doc); const m = $('mnavBtn-' + v, doc);
      if (d) { d.classList.toggle('bg-black', on); d.classList.toggle('text-white', on); d.classList.toggle('shadow-sm', on); d.classList.toggle('text-apple-textSecondary', !on); if (on) d.setAttribute('aria-current', 'page'); else d.removeAttribute('aria-current'); }
      if (m) { m.classList.toggle('bg-black', on); m.classList.toggle('text-white', on); m.classList.toggle('text-apple-textSecondary', !on); if (on) m.setAttribute('aria-current', 'page'); else m.removeAttribute('aria-current'); }
    }
    if (scrollTo) { const t = $(scrollTo, doc); if (t) t.scrollIntoView({ behavior: 'smooth' }); }
    else window.scrollTo({ top: 0 });
    if (!visited.has(id)) { visited.add(id); if (hooks[id]) hooks[id](); }
    if (hooks.always) hooks.always(id);
  }
  doc.addEventListener('click', (e) => {
    const b = e.target.closest('[data-view]');
    if (!b) return;
    switchView(b.dataset.view, { scrollTo: b.dataset.scroll || null });
  });
  return { switchView };
}
