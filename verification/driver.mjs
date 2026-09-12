import { spawn } from 'node:child_process';
import { mkdir, open, writeFile, readFile, readdir, copyFile, lstat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { seal, unseal, validateContext } from './evidence.mjs';

export function privateEnvironment(base, directory) {
  const env = Object.fromEntries(Object.entries(base).filter(([name]) =>
    !/TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY|READ_KEY|EVIDENCE_KEY|^ACTIONS_/i.test(name)));
  for (const name of ['GITHUB_STEP_SUMMARY', 'GITHUB_OUTPUT', 'GITHUB_ENV', 'GITHUB_PATH', 'GITHUB_STATE'])
    env[name] = join(directory, `${name}.txt`);
  return env;
}
export async function quiet(executable, args, cwd, log, env, timeoutMs) {
  const fd = await open(log, 'wx', 0o600);
  try {
    const child = spawn(executable, args, { cwd, env, stdio: ['ignore', fd.fd, fd.fd], windowsHide: true });
    let expired = false;
    const timer = setTimeout(() => { expired = true; child.kill('SIGKILL'); }, timeoutMs);
    const code = await new Promise((done, reject) => { child.once('error', reject); child.once('close', done); }).finally(() => clearTimeout(timer));
    if (expired || code !== 0) throw new Error('Private step failed; inspect encrypted evidence.');
  } finally { await fd.close(); }
}
function configuration() {
  const env = process.env;
  const job = env.WOIA_JOB;
  const context = validateContext({ job, repository: env.GITHUB_REPOSITORY, sourceSha: env.WOIA_COMMIT,
    workflowSha: env.WOIA_WORKFLOW_COMMIT, runId: env.GITHUB_RUN_ID, runAttempt: env.GITHUB_RUN_ATTEMPT });
  if (env.RUNNER_DEBUG === '1' || env.ACTIONS_STEP_DEBUG === 'true' || env.ACTIONS_RUNNER_DEBUG === 'true') throw new Error('Debug logging is not supported for private verification.');
  if (env.GITHUB_ACTIONS !== 'true' || env.GITHUB_SHA !== context.workflowSha || env.GITHUB_EVENT_NAME !== 'workflow_dispatch')
    throw new Error('Publication identity rejected.');
  if (!/^0\.1\.0-(alpha|beta|rc)\.(0|[1-9][0-9]{0,5})$/.test(env.WOIA_RELEASE_VERSION) || !['0.1.4', '0.1.6'].includes(env.WOIA_BRIDGE_VERSION))
    throw new Error('Publication input rejected.');
  const root = resolve(env.GITHUB_WORKSPACE, 'source');
  const data = resolve(env.RUNNER_TEMP, 'woia-private');
  return { env, context, root, data };
}
async function run() {
  const c = configuration();
  const logs = join(c.data, 'logs', c.context.job);
  await mkdir(logs, { recursive: true });
  await mkdir(join(c.data, 'metadata'), { recursive: true });
  await writeFile(join(c.data, 'metadata', `${c.context.job}.json`), JSON.stringify(c.context, null, 2) + '\n', { flag: 'wx' });
  const env = privateEnvironment(c.env, logs);
  // The public workflow SHA remains unchanged. Verify the distinct private checkout explicitly.
  await quiet('git', ['rev-parse', 'HEAD'], c.root, join(logs, 'source-sha.log'), env, 10000);
  if ((await readFile(join(logs, 'source-sha.log'), 'utf8')).trim() !== c.context.sourceSha) throw new Error('Source SHA differs.');
  await quiet('git', ['status', '--porcelain'], c.root, join(logs, 'source-status.log'), env, 10000);
  if ((await readFile(join(logs, 'source-status.log'), 'utf8')).trim()) throw new Error('Source is dirty.');
  await quiet('git', ['config', '--local', '--list'], c.root, join(logs, 'source-config.log'), env, 10000);
  if (/^(core\.sshcommand|http\..*extraheader)=/im.test(await readFile(join(logs, 'source-config.log'), 'utf8'))) throw new Error('Checkout credentials remain configured.');
  // Pinned checkout removes temporary auth before returning; fail closed if its key remains.
  for (const name of await readdir(c.env.RUNNER_TEMP)) {
    const path = join(c.env.RUNNER_TEMP, name);
    const info = await lstat(path);
    if (info.isFile() && info.size < 20000 && (await readFile(path)).includes(Buffer.from('-----BEGIN OPENSSH PRIVATE KEY-----')))
      throw new Error('Temporary checkout key remains.');
  }
  const command = (id, args, extra = {}, timeout = 600000) => quiet('bun', args, c.root, join(logs, `${id}.log`), { ...env, ...extra }, timeout);
  await command('install', ['install', '--frozen-lockfile']);
  const paths = Object.fromEntries(['release', 'conformance', 'runtime', 'tests', 'evidence'].map((p) => [p, join(c.data, p)]));
  for (const path of Object.values(paths)) await mkdir(path, { recursive: true });
  const tests = { WOIA_CI_TEST_PROFILE: 'publication', WOIA_REPORTS_ROOT: paths.tests };
  if (c.context.job === 'static') {
    await command('static', ['run', 'check:static'], {}, 300000);
  } else if (c.context.job.startsWith('platform-')) {
    if (c.context.job !== `platform-${process.platform}`) throw new Error('Native platform differs.');
    const label = { linux: 'Linux', darwin: 'macOS', win32: 'Windows' }[process.platform];
    await command('conformance', ['run', 'conformance', 'run', '--output', join(paths.conformance, `${label}.conformance.json`)], {}, 1200000);
    await command('build', ['tooling/release/ci.ts'], {
      WOIA_RELEASE_OUTPUT: join(paths.release, `${label}.tar.gz`), WOIA_RELEASE_REPORT: join(paths.release, `${label}.release.json`),
      WOIA_RUNTIME_OUTPUT: paths.runtime, WOIA_PREDECESSOR_RUN: '', WOIA_PREDECESSOR_DIGESTS: '',
    }, 1200000);
    if (process.platform !== 'win32') await command('tests', ['run', 'test:ci'], tests, 3600000);
  } else if (c.context.job.startsWith('windows-')) {
    if (process.platform !== 'win32') throw new Error('Windows runner required.');
    await command('tests', ['run', 'test:ci', `${c.context.job.slice(8)}/8`], tests, 3600000);
  } else if (c.context.job === 'verified') {
    await command('matrix', ['run', 'conformance', 'matrix', '--reports', paths.conformance, '--output', join(paths.evidence, 'conformance-matrix.json')]);
    await command('coverage', ['tooling/check/ci-evidence.ts', 'release'], tests);
    await command('release-matrix', ['run', 'release', 'matrix', '--reports', paths.release, '--conformance', paths.conformance, '--output', join(paths.evidence, 'release-matrix.json')]);
    await command('receipt', ['tooling/release/ci.ts', 'receipt'], {
      ...tests, WOIA_RELEASE_REPORTS: paths.release, WOIA_CONFORMANCE_REPORTS: paths.conformance,
      WOIA_RECEIPT_OUTPUT: join(paths.evidence, 'publication-verification.json'),
      WOIA_RUNTIME_REPORTS: paths.runtime, WOIA_RUNTIME_RECEIPT: join(paths.evidence, 'runtime-verification.json'),
    });
  }
  console.log('Private verification stage passed.');
}
async function encrypt() {
  const c = configuration();
  const out = join(c.env.RUNNER_TEMP, 'woia-sealed');
  await mkdir(out, { recursive: true });
  await seal(c.data, join(out, `${c.context.job}.wci`), await readFile(join(c.env.GITHUB_WORKSPACE, 'verification', 'evidence-public.pem'), 'utf8'), c.context);
  console.log('Authenticated encrypted evidence prepared.');
}
async function decrypt() {
  const c = configuration();
  if (c.context.job !== 'verified') throw new Error('Aggregation job required.');
  const input = join(c.env.RUNNER_TEMP, 'woia-sealed-input');
  const decoded = join(c.env.RUNNER_TEMP, 'woia-decoded');
  await mkdir(decoded);
  const expectedJobs = ['static', 'platform-linux', 'platform-darwin', 'platform-win32', ...Array.from({ length: 8 }, (_, n) => `windows-${n + 1}`)];
  const names = (await readdir(input)).sort();
  if (JSON.stringify(names) !== JSON.stringify(expectedJobs.map((j) => `${j}.wci`).sort())) throw new Error('Evidence job inventory differs.');
  const { job: _job, ...expected } = c.context;
  for (const name of names) {
    const job = name.slice(0, -4);
    const destination = join(decoded, job);
    await unseal(join(input, name), destination, c.env.WOIA_EVIDENCE_PRIVATE_KEY, { ...expected, job });
    for (const group of ['release', 'conformance', 'runtime', 'tests', 'metadata']) {
      let files;
      try { files = await readdir(join(destination, group), { withFileTypes: true }); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
      await mkdir(join(c.data, group), { recursive: true });
      for (const file of files) {
        if (!file.isFile()) throw new Error('Unexpected evidence member.');
        await copyFile(join(destination, group, file.name), join(c.data, group, file.name), constants.COPYFILE_EXCL);
      }
    }
  }
  console.log('Evidence authenticated for both revisions and this run/attempt.');
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 3) throw new Error('Usage rejected.');
    const mode = process.argv[2];
    if (mode === 'run') await run();
    else if (mode === 'seal') await encrypt();
    else if (mode === 'unseal') await decrypt();
    else throw new Error('Usage rejected.');
  } catch {
    console.error('Verification failed; preserve encrypted evidence for the maintainer.');
    process.exitCode = 1;
  }
}
