// Lightweight harness for browser tests: serves public/ over node:http and routes /api/* to the REAL
// scan-service logic with mocked providers. (The Express layer itself is covered by test/http/.)
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createScanService } from '../../server/scan-service.js';
import { buildCsp } from '../../server/policy.js';
import { testConfig } from '../unit/helpers.js';

const PUBLIC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.jpg': 'image/jpeg', '.png': 'image/png', '.svg': 'image/svg+xml' };

export async function startHarness({ fetchImpl, config = testConfig() } = {}) {
  const service = createScanService(config, { fetchImpl });
  const csp = buildCsp({ ...config, cspConnectExtra: [] });
  const log = [];
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Security-Policy', csp); // same policy the Express app sends
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', async () => {
        let out;
        try {
          if (req.method === 'POST' && url.pathname === '/api/scan') { log.push('scan'); out = await service.handleScan(JSON.parse(body || 'null')); }
          else if (req.method === 'GET' && url.pathname === '/api/providers') out = service.providersStatus();
          else out = { status: 404, headers: {}, json: { ok: false, error: { code: 'not_found' } } };
        } catch { out = { status: 400, headers: {}, json: { ok: false, error: { code: 'invalid_json' } } }; }
        res.writeHead(out.status, { 'Content-Type': 'application/json', ...out.headers });
        res.end(JSON.stringify(out.json));
      });
      return;
    }
    let rel = decodeURIComponent(url.pathname); if (rel === '/') rel = '/index.html';
    const file = path.join(PUBLIC, path.normalize(rel));
    if (!file.startsWith(PUBLIC) || path.basename(file).startsWith('.') || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, service, log, close: () => new Promise((r) => server.close(r)) };
}

export async function loadPlaywright() {
  try { return await import('playwright'); } catch { /* fall through */ }
  const { createRequire } = await import('node:module');
  const req = createRequire(import.meta.url);
  const p = process.env.PLAYWRIGHT_PATH;
  if (!p) throw new Error('playwright is not installed (npm install, then npx playwright install chromium)');
  return req(p);
}
