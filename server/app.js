// Express wiring only. Request logic lives in scan-service.js; policy lives in src/shared/.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import rateLimit from 'express-rate-limit';
import { createScanService } from './scan-service.js';
import { buildCsp, corsDecision } from './policy.js';

export const PUBLIC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

export { buildCsp, corsDecision };

const jsonError = (res, status, code, message, headers = {}) => {
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  return res.status(status).json({ ok: false, error: { code, message } });
};

async function buildRateLimitStore(rl) {
  if (rl.store !== 'redis') return undefined;
  if (!rl.redisUrl) throw new Error('RATE_LIMIT_STORE=redis requires REDIS_URL');
  const [{ default: RedisStore }, { createClient }] = await Promise.all([import('rate-limit-redis'), import('redis')]);
  const client = createClient({ url: rl.redisUrl });
  client.on('error', (e) => console.error('[redis] error', (e && (e.code || e.name)) || 'unknown'));
  await client.connect();
  return new RedisStore({ sendCommand: (...args) => client.sendCommand(args), prefix: 'vq:rl:' });
}

export async function createApp(config, deps = {}) {
  const app = express();
  const service = createScanService(config, deps);
  const csp = buildCsp(config);

  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);

  app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', csp);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    if (config.hsts && req.secure) res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
    next();
  });

  const api = express.Router();
  api.use((req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

  api.use((req, res, next) => {
    const d = corsDecision(req.headers.origin, req.headers.host, config.allowedOrigins);
    if (!d.allowed) return jsonError(res, 403, 'origin_not_allowed', 'Origin not permitted by CORS policy.');
    if (d.origin) {
      res.setHeader('Access-Control-Allow-Origin', d.origin);
      res.setHeader('Vary', 'Origin');
      if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        res.setHeader('Access-Control-Max-Age', '600');
        return res.sendStatus(204);
      }
    }
    next();
  });

  const store = await buildRateLimitStore(config.rateLimit);
  api.use(rateLimit({
    windowMs: config.rateLimit.windowMs,
    limit: config.rateLimit.limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    store,
    handler: (req, res) => {
      const reset = req.rateLimit && req.rateLimit.resetTime ? new Date(req.rateLimit.resetTime).getTime() : Date.now() + config.rateLimit.windowMs;
      const retry = Math.max(1, Math.ceil((reset - Date.now()) / 1000));
      return jsonError(res, 429, 'rate_limited', 'Too many requests. Please wait before trying again.', { 'Retry-After': String(retry) });
    }
  }));

  api.use(express.json({ limit: config.bodyLimit }));

  api.get('/providers', (req, res) => {
    const r = service.providersStatus();
    res.status(r.status).json(r.json);
  });

  api.post('/scan', async (req, res, next) => {
    try {
      if (!req.is('application/json')) return jsonError(res, 415, 'unsupported_media_type', 'Content-Type must be application/json.');
      const r = await service.handleScan(req.body);
      const retry = r.json && r.json.retryAfterSec;
      if (retry) res.setHeader('Retry-After', String(retry));
      res.status(r.status).json(r.json);
    } catch (err) { next(err); }
  });

  api.all('/scan', (req, res) => jsonError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST, OPTIONS' }));
  api.use((req, res) => jsonError(res, 404, 'not_found', 'Unknown API endpoint.'));

  api.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    if (err && err.type === 'entity.too.large') return jsonError(res, 413, 'payload_too_large', 'Request body is too large.');
    if (err && (err.type === 'entity.parse.failed' || (err instanceof SyntaxError && err.status === 400))) return jsonError(res, 400, 'invalid_json', 'Request body is not valid JSON.');
    if (err && (err.type === 'charset.unsupported' || err.type === 'encoding.unsupported')) return jsonError(res, 415, 'unsupported_media_type', 'Unsupported charset or encoding.');
    console.error('[error]', (err && (err.code || err.name)) || 'unknown'); // never log request bodies or URLs
    return jsonError(res, 500, 'internal_error', 'Unexpected server error.');
  });

  app.use('/api', api);

  // Only the dedicated public/ directory is served. Dotfiles are ignored (404) and never listed.
  app.use(express.static(PUBLIC_DIR, {
    dotfiles: 'ignore',
    index: 'index.html',
    redirect: false,
    setHeaders(res, filePath) {
      res.setHeader('Cache-Control', filePath.endsWith('.html') ? 'no-cache' : 'public, max-age=3600');
    }
  }));

  app.use((req, res) => res.status(404).type('text/plain').send('Not found'));
  return { app, service };
}
