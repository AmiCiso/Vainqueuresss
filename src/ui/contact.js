import { $, show } from './dom.js';

export function buildInquiryText(form) {
  const v = (id) => (form.querySelector('#' + id) ? form.querySelector('#' + id).value.trim() : '');
  return `Name: ${v('cName')}\nEmail: ${v('cEmail')}\nTopic: ${v('cDivision')}\nTimeline: ${v('cTimeline')}\n\n${v('cMessage')}`;
}

export function initContact(root = document) {
  const form = $('contactForm', root); const status = $('contactStatus', root);
  if (!form || !status) return;
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!form.checkValidity()) { form.reportValidity(); return; }
    const text = buildInquiryText(form);
    status.textContent = '';
    show(status, true);
    status.className = 'text-xs p-4 rounded-2xl border bg-amber-50 text-amber-900 border-amber-300 space-y-2';
    const p = document.createElement('p'); p.className = 'font-bold'; p.textContent = 'Not sent. This site has no delivery service connected, so nothing was transmitted anywhere.';
    const p2 = document.createElement('p'); p2.textContent = 'Your inquiry is still in the form. Copy it and send it through a channel of your own.';
    const b = document.createElement('button'); b.type = 'button'; b.className = 'px-3 py-1.5 rounded-lg bg-black text-white font-bold'; b.textContent = 'Copy inquiry text';
    b.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(text); b.textContent = 'Copied to clipboard'; }
      catch { const ta = document.createElement('textarea'); ta.value = text; document.body.append(ta); ta.select(); try { document.execCommand('copy'); b.textContent = 'Copied'; } catch { b.textContent = 'Copy failed: select the form text manually'; } ta.remove(); }
    });
    status.append(p, p2, b);
  });
}
