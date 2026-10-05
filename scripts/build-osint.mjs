import { build } from 'esbuild';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const orchestratorDir = path.join(rootDir, 'osint-orchestrator');
const distDir = path.join(orchestratorDir, 'dist');

await fs.rm(distDir, { recursive: true, force: true });
await fs.mkdir(distDir, { recursive: true });

await build({
  entryPoints: [path.join(orchestratorDir, 'src', 'cli.ts')],
  outfile: path.join(distDir, 'cli.js'),
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: ['node20'],
  sourcemap: 'inline',
  logLevel: 'info'
});

console.log(`Built OSINT orchestrator into ${path.relative(rootDir, distDir)}`);
