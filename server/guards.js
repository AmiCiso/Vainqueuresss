// Bounded concurrency and per-instance provider budgets. These protect the provider quota and the server.
export class Gate {
  constructor({ maxConcurrent = 8, maxQueue = 32 } = {}) {
    this.max = maxConcurrent; this.maxQueue = maxQueue; this.active = 0; this.queue = [];
  }
  /** Resolves a release() function, or rejects with {kind:'busy'} when the queue is full. */
  acquire() {
    if (this.active < this.max) { this.active++; return Promise.resolve(() => this.#release()); }
    if (this.queue.length >= this.maxQueue) return Promise.reject(Object.assign(new Error('busy'), { kind: 'busy' }));
    return new Promise((resolve) => this.queue.push(resolve));
  }
  #release() {
    const next = this.queue.shift();
    if (next) next(() => this.#release()); else this.active--;
  }
}

export class Budget {
  constructor({ limit, windowMs = 60000, now = () => Date.now() }) {
    this.limit = limit; this.windowMs = windowMs; this.now = now; this.start = now(); this.used = 0;
  }
  /** Returns { ok:true } or { ok:false, retryAfterSec }. */
  take() {
    const t = this.now();
    if (t - this.start >= this.windowMs) { this.start = t; this.used = 0; }
    if (this.used >= this.limit) return { ok: false, retryAfterSec: Math.max(1, Math.ceil((this.start + this.windowMs - t) / 1000)) };
    this.used++;
    return { ok: true };
  }
}
