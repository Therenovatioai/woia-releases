import { createCipheriv, createDecipheriv, randomBytes, publicEncrypt, privateDecrypt, createPublicKey, constants } from 'node:crypto';
import { lstat, readdir, readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';

const LIMIT = 512 * 1024 * 1024;
const MAGIC = Buffer.from('WOIACI02');
const fail = () => { throw new Error('Evidence rejected.'); };
const require = (ok) => { if (!ok) fail(); };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
function pathValid(path) {
  return typeof path === 'string' && path.length <= 512 &&
    path.split('/').every((s) => /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/.test(s) &&
      !s.endsWith('.') && !/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(s));
}
export function validateContext(c) {
  require(c && Object.keys(c).sort().join() === 'job,repository,runAttempt,runId,sourceSha,workflowSha');
  require(c.repository === 'Therenovatioai/woia-releases');
  require([c.sourceSha, c.workflowSha].every((s) => /^[a-f0-9]{40}$/.test(s)));
  require([c.runId, c.runAttempt].every((s) => /^[1-9][0-9]{0,19}$/.test(s)));
  require(/^(static|platform-(linux|darwin|win32)|windows-[1-8]|verified)$/.test(c.job));
  return c;
}
function publicKey(pem) {
  const key = createPublicKey(pem);
  require(key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails.modulusLength >= 3072);
  return key;
}
async function directory(path) {
  const absolute = resolve(path);
  let current = absolute;
  while (true) {
    const info = await lstat(current);
    require(info.isDirectory() && !info.isSymbolicLink());
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return absolute;
}
async function collect(root, prefix = '') {
  const result = [];
  for (const name of (await readdir(join(root, prefix))).sort()) {
    const path = prefix ? `${prefix}/${name}` : name;
    require(pathValid(path));
    const info = await lstat(join(root, path));
    require(!info.isSymbolicLink());
    if (info.isDirectory()) result.push(...await collect(root, path));
    else {
      require(info.isFile() && info.size <= LIMIT);
      result.push({ path, size: info.size });
    }
    require(result.length <= 2048);
  }
  return result;
}
export async function seal(root, output, publicPem, context) {
  validateContext(context);
  root = await directory(root);
  const files = await collect(root);
  require(files.length > 0 && files.reduce((n, f) => n + f.size, 0) <= LIMIT);
  const seen = new Set();
  const parts = [u32(files.length)];
  for (const file of files) {
    require(!seen.has(file.path.toLowerCase()));
    seen.add(file.path.toLowerCase());
    const bytes = await readFile(join(root, file.path));
    require(bytes.length === file.size);
    const name = Buffer.from(file.path);
    parts.push(u32(name.length), name, u32(bytes.length), bytes);
  }
  const contentKey = randomBytes(32);
  const wrappedKey = publicEncrypt({ key: publicKey(publicPem), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, contentKey).toString('base64');
  const header = Buffer.from(JSON.stringify({ context, wrappedKey }));
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', contentKey, nonce);
  cipher.setAAD(header);
  const encrypted = Buffer.concat([cipher.update(Buffer.concat(parts)), cipher.final()]);
  await directory(dirname(resolve(output)));
  await writeFile(output, Buffer.concat([MAGIC, u32(header.length), header, nonce, cipher.getAuthTag(), encrypted]), { flag: 'wx', mode: 0o600 });
}
export async function unseal(input, output, privatePem, expected) {
  const info = await lstat(input);
  require(info.isFile() && !info.isSymbolicLink() && info.size > 40 && info.size <= LIMIT + 4 * 1024 * 1024);
  const bytes = await readFile(input);
  require(bytes.subarray(0, 8).equals(MAGIC));
  const length = bytes.readUInt32BE(8);
  require(length <= 2048 && bytes.length > 40 + length);
  const header = bytes.subarray(12, 12 + length);
  const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(header));
  require(parsed && Object.keys(parsed).sort().join() === 'context,wrappedKey' && typeof parsed.wrappedKey === 'string' && /^[A-Za-z0-9+/]+={0,2}$/.test(parsed.wrappedKey));
  const context = validateContext(parsed.context);
  require(Object.entries(expected).every(([name, value]) => context[name] === value));
  const contentKey = privateDecrypt({ key: privatePem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(parsed.wrappedKey, 'base64'));
  require(contentKey.length === 32);
  const decipher = createDecipheriv('aes-256-gcm', contentKey, bytes.subarray(12 + length, 24 + length));
  decipher.setAAD(header);
  decipher.setAuthTag(bytes.subarray(24 + length, 40 + length));
  const plain = Buffer.concat([decipher.update(bytes.subarray(40 + length)), decipher.final()]);
  let at = 0;
  const take = (n) => { require(n >= 0 && at + n <= plain.length); const b = plain.subarray(at, at + n); at += n; return b; };
  const integer = () => take(4).readUInt32BE();
  const count = integer();
  require(count > 0 && count <= 2048);
  const files = [];
  const seen = new Set();
  for (let n = 0; n < count; n++) {
    const nameLength = integer();
    require(nameLength > 0 && nameLength <= 512);
    const path = new TextDecoder('utf-8', { fatal: true }).decode(take(nameLength));
    require(pathValid(path) && !seen.has(path.toLowerCase()));
    seen.add(path.toLowerCase());
    files.push({ path, bytes: take(integer()) });
  }
  require(at === plain.length);
  // Authenticate and validate every path before creating anything; destination is create-only.
  await directory(dirname(resolve(output)));
  await mkdir(output);
  for (const file of files) {
    const destination = resolve(output, ...file.path.split('/'));
    require(destination.startsWith(resolve(output) + sep));
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, file.bytes, { flag: 'wx', mode: 0o600 });
  }
  return context;
}
