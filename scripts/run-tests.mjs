// Portable test runner: node --test with explicit file lists (directory/glob args differ across Node 20/22).
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const dirs = process.argv.slice(2);
const files = dirs.flatMap((d) => fs.existsSync(d) ? fs.readdirSync(d).filter((f) => f.endsWith('.test.js')).sort().map((f) => path.join(d, f)) : []);
if (!files.length) { console.error('No test files found in:', dirs.join(', ')); process.exit(1); }
const r = spawnSync(process.execPath, ['--test', '--test-reporter=spec', ...files], { stdio: 'inherit' });
process.exit(r.status ?? 1);
