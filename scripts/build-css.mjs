// Production CSS via the Tailwind CSS v4 compiler API (no CDN, no runtime compilation).
// Candidates are collected by a simple token scan of the HTML and JS sources, so classes must appear as
// literal strings in those files (never assembled dynamically).
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { compile } from 'tailwindcss';
import { transform } from 'esbuild';

const require = createRequire(import.meta.url);
const root = process.cwd();
const inputPath = path.join(root, 'src/styles/app.css');

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(html|js)$/.test(e.name) && !p.includes(path.join('public', 'assets'))) out.push(p);
  }
  return out;
}

const sources = [...walk(path.join(root, 'src')), path.join(root, 'public/index.html')];
const candidates = new Set();
for (const f of sources) {
  for (const t of fs.readFileSync(f, 'utf8').match(/[^\s"'`<>={}(),;]+/g) || []) candidates.add(t);
}

async function loadStylesheet(id, base) {
  let file;
  if (id === 'tailwindcss') file = require.resolve('tailwindcss/index.css');
  else if (id.startsWith('tailwindcss/')) file = require.resolve(id);
  else file = path.resolve(base, id);
  return { path: file, base: path.dirname(file), content: fs.readFileSync(file, 'utf8') };
}

const compiler = await compile(fs.readFileSync(inputPath, 'utf8'), { base: path.dirname(inputPath), loadStylesheet });
const css = compiler.build([...candidates]);
const min = await transform(css, { loader: 'css', minify: true, target: ['chrome111', 'safari16', 'firefox111'] });
fs.mkdirSync('public/assets', { recursive: true });
fs.writeFileSync('public/assets/app.css', min.code);
console.log(`[build:css] public/assets/app.css ${(min.code.length / 1024).toFixed(1)} KiB from ${candidates.size} candidate tokens`);
