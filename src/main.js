// Application entry. Wires explicit modules together; no globals, no inline handlers.
import { createHistoryStore, safeStorage } from './history.js';
import { createScanController } from './scan-controller.js';
import { resolveApiBase } from './providers-client.js';
import { isThreatFlag } from './report.js';
import { initScanView } from './ui/scan-view.js';
import { initNav } from './ui/nav.js';
import { initLabs } from './ui/labs-view.js';
import { initAcademy } from './ui/academy-view.js';
import { initRedTeam } from './ui/redteam-view.js';
import { initAssistant } from './ui/assistant-view.js';
import { initContact } from './ui/contact.js';
import { $ } from './ui/dom.js';

function boot() {
  const storage = safeStorage();
  const history = createHistoryStore({ storage });
  history.load();

  const PREF_KEY = 'vq_lookup_pref';
  const loadPref = () => { try { return storage && storage.getItem(PREF_KEY) === 'external' ? 'external' : 'local'; } catch { return 'local'; } };
  const savePref = (v) => { try { if (storage) storage.setItem(PREF_KEY, v === 'external' ? 'external' : 'local'); } catch { /* ignore */ } };

  let view;
  const controller = createScanController({
    history,
    apiBase: resolveApiBase(),
    onChange: (s) => { if (view) view.render(s); updateCounters(s.history); }
  });

  function updateCounters(list) {
    const a = $('stat-scans-count'); const b = $('stat-threats-count');
    if (a) a.textContent = String(list.length);
    if (b) b.textContent = String(list.filter((e) => isThreatFlag(e.verdictLevel)).length);
  }

  view = initScanView({ controller, onPrefChange: savePref, loadPref });
  view.render(controller.getState());
  updateCounters(history.list());
  const note = $('historyNotice');
  if (note && !history.available) note.textContent = 'Local storage is unavailable in this browser, so scan history is kept for this page visit only.';

  const labs = initLabs();
  const academy = initAcademy(storage);
  const rt = initRedTeam(storage);
  const nav = initNav({ academy: () => academy.render(), labs: () => labs.loadLab(1), redteam: () => rt.load(1) });
  initAssistant(() => nav.switchView('scanner'));
  initContact();
  $('verdictBanner').setAttribute('aria-live', 'polite');

  // Logo fallback without third-party hosts: hide a broken image and rely on its alt text/background.
  document.querySelectorAll('img[data-logo]').forEach((img) => img.addEventListener('error', () => { img.style.visibility = 'hidden'; }, { once: true }));
  academy.render();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
