import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { seal } from './evidence.mjs';
if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('Confidential preflight requires Windows x64.');
const root = join(process.env.RUNNER_TEMP, 'synthetic-private');
const out = join(process.env.RUNNER_TEMP, 'synthetic-sealed');
await mkdir(root);
await mkdir(out);
await writeFile(join(root, 'probe.bin'), Buffer.from('SYNTHETIC-CONFIDENTIAL-PREFLIGHT\u0000\u00ff'));
const context = { repository: process.env.GITHUB_REPOSITORY, sourceSha: process.env.WOIA_COMMIT,
  workflowSha: process.env.GITHUB_SHA, runId: process.env.GITHUB_RUN_ID,
  runAttempt: process.env.GITHUB_RUN_ATTEMPT, job: `platform-${process.platform}` };
await seal(root, join(out, `${process.platform}.wci`), await readFile('verification/evidence-public.pem', 'utf8'), context);
console.log('Synthetic encrypted transport passed.');
