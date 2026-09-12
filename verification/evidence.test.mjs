import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, realpath, mkdir, writeFile, readFile, rm, symlink, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { seal, unseal } from './evidence.mjs';
import { quiet, privateEnvironment } from './driver.mjs';

const keys = generateKeyPairSync('rsa', { modulusLength: 3072, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const wrong = generateKeyPairSync('rsa', { modulusLength: 3072, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const context = { repository: 'Therenovatioai/woia-releases', sourceSha: 'a'.repeat(40), workflowSha: 'b'.repeat(40), runId: '1', runAttempt: '1', job: 'static' };
async function fixture(run) {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'woia-cipher-test-'));
  try {
    const input = join(root, 'input');
    await mkdir(input);
    await writeFile(join(input, 'private.txt'), 'PRIVATE-SYNTHETIC-MARKER');
    await writeFile(join(input, 'binary.dat'), Buffer.from([0, 255, 13, 10]));
    await run({ root, input, output: join(root, 'evidence.wci'), key: keys });
  } finally { await rm(root, { recursive: true, force: true }); }
}
test('authenticated binary round trip conceals plaintext and restores exact bytes', () => fixture(async ({root,input,output,key}) => {
  await seal(input, output, key.publicKey, context);
  assert.equal((await readFile(output)).includes(Buffer.from('PRIVATE-SYNTHETIC-MARKER')), false);
  const dest = join(root, 'decoded');
  assert.deepEqual(await unseal(output, dest, key.privateKey, context), context);
  assert.deepEqual(await readFile(join(dest, 'binary.dat')), await readFile(join(input, 'binary.dat')));
  assert.deepEqual(await readFile(join(dest, 'private.txt')), await readFile(join(input, 'private.txt')));
}));
test('wrong key and tampering fail before destination creation', () => fixture(async ({root,input,output,key}) => {
  await seal(input, output, key.publicKey, context);
  const dest = join(root, 'decoded');
  await assert.rejects(unseal(output, dest, wrong.privateKey, context));
  await assert.rejects(stat(dest));
  const bytes = await readFile(output);
  bytes[bytes.length - 1] ^= 1;
  await writeFile(join(root, 'tampered.wci'), bytes);
  await assert.rejects(unseal(join(root, 'tampered.wci'), dest, key.privateKey, context));
  await assert.rejects(stat(dest));
}));
test('different source, workflow or attempt cannot reuse an envelope', () => fixture(async ({root,input,output,key}) => {
  await seal(input, output, key.publicKey, context);
  for (const changed of [{sourceSha:'c'.repeat(40)}, {workflowSha:'c'.repeat(40)}, {runAttempt:'2'}])
    await assert.rejects(unseal(output, join(root, 'decoded'), key.privateKey, {...context,...changed}));
  await assert.rejects(stat(join(root, 'decoded')));
}));
test('encryption and decryption never overwrite prior outputs', () => fixture(async ({root,input,output,key}) => {
  await seal(input, output, key.publicKey, context);
  const bytes = await readFile(output);
  await assert.rejects(seal(input, output, key.publicKey, context));
  assert.deepEqual(await readFile(output), bytes);
  const dest = join(root, 'decoded');
  await mkdir(dest);
  await writeFile(join(dest, 'keep.txt'), 'keep');
  await assert.rejects(unseal(output, dest, key.privateKey, context));
  assert.equal(await readFile(join(dest, 'keep.txt'), 'utf8'), 'keep');
}));
test('symbolic directory input is rejected', () => fixture(async ({root,input,output,key}) => {
  const link = join(root, 'link');
  await symlink(input, link, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(seal(link, output, key.publicKey, context));
  await assert.rejects(stat(output));
}));
test('private command channels stay in files and failures propagate', () => fixture(async ({root}) => {
  const env = privateEnvironment({...process.env, GITHUB_TOKEN:'synthetic-token', WOIA_EVIDENCE_KEY:'synthetic-key', GITHUB_SHA:'a'.repeat(40)}, root);
  assert.equal(env.GITHUB_TOKEN, undefined);
  assert.equal(env.WOIA_EVIDENCE_KEY, undefined);
  assert.equal(env.GITHUB_SHA, 'a'.repeat(40));
  const log = join(root, 'quiet.log');
  await assert.rejects(quiet(process.execPath, ['-e', 'console.log("PRIVATE-SYNTHETIC-MARKER");require("node:fs").writeFileSync(process.env.GITHUB_STEP_SUMMARY,"PRIVATE-SUMMARY");process.exit(7)'], root, log, env, 10000));
  assert.match(await readFile(log, 'utf8'), /PRIVATE-SYNTHETIC-MARKER/);
  assert.equal(await readFile(env.GITHUB_STEP_SUMMARY, 'utf8'), 'PRIVATE-SUMMARY');
}));
test('Git checkout subjects and Git errors remain in captured private logs', () => fixture(async ({root,input}) => {
  const env = privateEnvironment(process.env, root);
  const git = (name, args) => quiet('git', args, input, join(root, `${name}.log`), env, 10000);
  await git('init', ['init', '--quiet']);
  await git('commit', ['-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid', 'commit', '--allow-empty', '-m', 'PRIVATE-COMMIT-SUBJECT']);
  await git('checkout', ['checkout', '--detach', 'HEAD']);
  assert.match(await readFile(join(root, 'checkout.log'), 'utf8'), /PRIVATE-COMMIT-SUBJECT/);
  await assert.rejects(git('error', ['checkout', 'PRIVATE-MISSING-REF']));
  assert.match(await readFile(join(root, 'error.log'), 'utf8'), /PRIVATE-MISSING-REF/);
}));
