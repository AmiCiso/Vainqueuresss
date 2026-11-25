// Bounded, privacy-aware result cache with request coalescing.
// Keys are HMAC-SHA256 digests (per-process random key) of provider+URL, so raw URLs are never stored
// as keys. Values contain only provider verdict metadata, never the submitted URL.
import crypto from 'node:crypto';

export class ResultCache {
  constructor({ maxEntries = 1000, now = () => Date.now() } = {}) {
    this.max = maxEntries;
    this.now = now;
    this.map = new Map();
    this.inflight = new Map();
    this.secret = crypto.randomBytes(32);
  }

  key(providerId, url) {
    return crypto.createHmac('sha256', this.secret).update(providerId + '\n' + url).digest('hex');
  }

  get(k) {
    const e = this.map.get(k);
    if (!e) return undefined;
    if (e.expires <= this.now()) { this.map.delete(k); return undefined; }
    this.map.delete(k); this.map.set(k, e); // LRU touch
    return e.value;
  }

  set(k, value, ttlMs) {
    if (!(ttlMs > 0)) return;
    this.map.delete(k);
    this.map.set(k, { value, expires: this.now() + ttlMs });
    while (this.map.size > this.max) this.map.delete(this.map.keys().next().value);
  }

  /** compute() -> value; ttlFor(value) -> ms (0 = do not cache). Concurrent identical requests share one compute. */
  async getOrCompute(k, compute, ttlFor) {
    const hit = this.get(k);
    if (hit !== undefined) return { value: hit, cached: true, coalesced: false };
    if (this.inflight.has(k)) return { value: await this.inflight.get(k), cached: false, coalesced: true };
    const p = (async () => {
      const v = await compute();
      this.set(k, v, ttlFor(v));
      return v;
    })();
    this.inflight.set(k, p);
    try { return { value: await p, cached: false, coalesced: false }; }
    finally { this.inflight.delete(k); }
  }

  get size() { return this.map.size; }
}
