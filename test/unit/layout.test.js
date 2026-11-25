import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { checkLayout } from '../../scripts/check-public-layout.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

test('public/ holds only browser assets; backend, manifests, tests and docs live outside it', () => {
  const { files, problems } = checkLayout();
  assert.deepEqual(problems, []);
  assert.ok(files.includes('index.html'));
  for (const outside of ['server.js', 'package.json', '.env.example', 'README.md', 'server/app.js', 'test/corpus.json', 'docs/REMEDIATION.md']) {
    assert.ok(fs.existsSync(path.join(ROOT, outside)), outside + ' should exist at project root');
    assert.ok(!files.includes(outside), outside + ' must not be inside public/');
  }
});

test('layout checker flags dotfiles, backend files, source maps and unexpected types', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'vq-layout-'));
  for (const f of ['index.html', 'assets/app.js', 'assets/app.css']) { fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true }); fs.writeFileSync(path.join(d, f), 'x'); }
  assert.deepEqual(checkLayout(d).problems, []);
  for (const bad of ['.env', 'server.js', 'package.json', 'assets/app.js.map', 'notes.txt']) fs.writeFileSync(path.join(d, bad), 'x');
  const p = checkLayout(d).problems.join('\n');
  for (const bad of ['.env', 'server.js', 'package.json', 'app.js.map', 'notes.txt']) assert.ok(p.includes(bad), bad);
});

test('index.html has no inline scripts, inline event handlers or third-party script/style hosts besides Google Fonts', () => {
  const html = fs.readFileSync(path.join(ROOT, 'public/index.html'), 'utf8');
  assert.ok(!/<script(?![^>]*\ssrc=)[^>]*>/i.test(html), 'inline <script> found');
  assert.ok(!/\son[a-z]+\s*=\s*["']/i.test(html), 'inline event handler found');
  assert.ok(!/\sstyle\s*=/.test(html), 'inline style attribute found');
  assert.ok(!/<style[\s>]/i.test(html), 'inline <style> found');
  const hosts = [...html.matchAll(/(?:src|href)=["'](https?:\/\/[^"']+)/gi)].map((m) => new URL(m[1]).host);
  for (const h of hosts) assert.ok(['fonts.googleapis.com', 'fonts.gstatic.com'].includes(h), 'unexpected external host in markup: ' + h);
  assert.ok(!html.includes('cdn.tailwindcss.com'));
});

test('built bundle exists, is non-trivial, and does not reference the Tailwind CDN or eval', () => {
  const js = fs.readFileSync(path.join(ROOT, 'public/assets/app.js'), 'utf8');
  const css = fs.readFileSync(path.join(ROOT, 'public/assets/app.css'), 'utf8');
  assert.ok(js.length > 50000 && css.length > 5000);
  assert.ok(!js.includes('cdn.tailwindcss.com'));
  assert.ok(!/\beval\(|new Function\(/.test(js), 'bundle must not use eval/new Function (strict CSP)');
});
