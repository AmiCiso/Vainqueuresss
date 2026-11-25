// Bounded JSON fetch: one AbortController covers connection, headers AND body reading/parsing.
export class ProviderError extends Error {
  constructor(kind, extra = {}) { super(kind); this.kind = kind; Object.assign(this, extra); }
}

async function readCapped(res, maxBytes) {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) throw new ProviderError('unexpected_response', { why: 'response too large' });
  if (!res.body || typeof res.body.getReader !== 'function') {
    const t = await res.text();
    if (t.length > maxBytes) throw new ProviderError('unexpected_response', { why: 'response too large' });
    return t;
  }
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) { try { await reader.cancel(); } catch { /* ignore */ } throw new ProviderError('unexpected_response', { why: 'response too large' }); }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks.map((c) => Buffer.from(c))));
}

/** Returns { status, headers, json|null, parseFailed }. Throws ProviderError('timeout'|'network_error'|...). */
export async function fetchJson(fetchImpl, url, init, { timeoutMs, maxBytes }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { ...init, signal: controller.signal, redirect: 'error' });
    const text = await readCapped(res, maxBytes); // still under the abort timer
    let json = null; let parseFailed = false;
    if (text) { try { json = JSON.parse(text); } catch { parseFailed = true; } }
    return { status: res.status, headers: res.headers, json, parseFailed };
  } catch (err) {
    if (err instanceof ProviderError) throw err;
    if (err && (err.name === 'AbortError' || controller.signal.aborted)) throw new ProviderError('timeout');
    throw new ProviderError('network_error');
  } finally {
    clearTimeout(timer);
  }
}
