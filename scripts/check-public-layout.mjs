// Verifies that public/ (the ONLY directory served over HTTP) contains nothing but browser assets.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC = path.join(ROOT, 'public');
const ALLOWED_EXT = new Set(['.html', '.css', '.js', '.jpg', '.jpeg', '.png', '.svg', '.ico', '.webp', '.woff2']);

export function checkLayout(publicDir = PUBLIC) {
  const problems = [];
  const files = [];
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isSymbolicLink()) { problems.push('symlink in public/: ' + path.relative(publicDir, p)); continue; }
      if (e.isDirectory()) { walk(p); continue; }
      const rel = path.relative(publicDir, p);
      files.push(rel);
      if (e.name.startsWith('.')) problems.push('dotfile in public/: ' + rel);
      if (!ALLOWED_EXT.has(path.extname(e.name).toLowerCase())) problems.push('unexpected file type in public/: ' + rel);
      if (/\.map$/.test(e.name)) problems.push('source map in public/: ' + rel);
      if (/(^|\/)(server|package|package-lock|README|\.env)/i.test(rel)) problems.push('sensitive-looking file in public/: ' + rel);
    }
  })(publicDir);
  for (const must of ['index.html', 'assets/app.js', 'assets/app.css']) if (!files.includes(must)) problems.push('missing build output: public/' + must + ' (run npm run build)');
  return { files, problems };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { files, problems } = checkLayout();
  console.log('public/ contains:', files.join(', '));
  if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
  console.log('layout OK: only browser assets are in the served directory');
}
