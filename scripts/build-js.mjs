// Bundles src/main.js (and the `psl` Public Suffix List dependency) into one self-contained file.
import { build } from 'esbuild';
import fs from 'node:fs';

fs.mkdirSync('public/assets', { recursive: true });
const result = await build({
  entryPoints: ['src/main.js'],
  bundle: true,
  minify: true,
  format: 'iife',
  target: ['es2020'],
  outfile: 'public/assets/app.js',
  legalComments: 'none',
  sourcemap: false,
  metafile: true,
  logLevel: 'warning'
});
const bytes = fs.statSync('public/assets/app.js').size;
console.log(`[build:js] public/assets/app.js ${(bytes / 1024).toFixed(1)} KiB (${Object.keys(result.metafile.inputs).length} modules)`);
