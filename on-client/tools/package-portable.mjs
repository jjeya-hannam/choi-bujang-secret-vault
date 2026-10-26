// Student source bundle; this is not the course's approved runtime packager.
import { lstat, readdir, realpath, mkdtemp, writeFile, rename, rm, open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, dirname, basename, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { execFileSync } from 'node:child_process';

const roots = ['public', 'src', 'vendor', 'student'];
const extensions = /\.(?:mjs|js|json|html|css|webp|png|svg|ico)$/i;
const excluded = /^(?:\.|node_modules$|outputs?$|artifacts$|(?:credentials?|vault)(?:$|\.json$))|(?:\.sqlite(?:-|$)|\.log$|\.env)/i;
const secret = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:sb_secret_|sk_live_|sk-(?:(?:proj|ant|on|svcacct)-)?)[A-Za-z0-9_-]{16,}|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw new Error(code); };
const exists = async path => { try { await lstat(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } };
const within = (parent, child) => child === parent || child.startsWith(parent + sep);
function revision(source) {
  try {
    const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: source, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (!/^[a-f0-9]{40,64}$/.test(commit)) return { commit: null, workingTreeDirty: null };
    const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=normal', '--', '.'], { cwd: source, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return { commit, workingTreeDirty: dirty.length > 0 };
  } catch { return { commit: null, workingTreeDirty: null }; }
}

function tarEntry(name, bytes, mode = 0o644) {
  if (!/^[A-Za-z0-9._/-]+$/.test(name) || name.split('/').includes('..') || Buffer.byteLength(name) > 100) fail('PACKAGE_PATH_UNSUPPORTED');
  const header = Buffer.alloc(512);
  const field = (offset, length, value) => header.write(value, offset, length, 'ascii');
  const octal = (offset, length, value) => field(offset, length, value.toString(8).padStart(length - 1, '0') + '\0');
  field(0, 100, name); octal(100, 8, mode); octal(108, 8, 0); octal(116, 8, 0);
  octal(124, 12, bytes.length); octal(136, 12, 0); field(148, 8, '        ');
  field(156, 1, '0'); field(257, 6, 'ustar\0'); field(263, 2, '00');
  const sum = header.reduce((a, b) => a + b, 0);
  field(148, 8, sum.toString(8).padStart(6, '0') + '\0 ');
  return Buffer.concat([header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512)]);
}

export async function packagePortable({ source = fileURLToPath(new URL('../', import.meta.url)), out } = {}) {
  if (typeof out !== 'string' || !out.trim()) fail('PACKAGE_OUTPUT_REQUIRED');
  const givenSource = resolve(source);
  if ((await lstat(givenSource)).isSymbolicLink()) fail('PACKAGE_SYMLINK_REJECTED');
  source = await realpath(givenSource);
  const parent = await realpath(dirname(resolve(out)));
  out = resolve(parent, basename(resolve(out)));
  if (within(source, out) || within(out, source)) fail('PACKAGE_OUTPUT_OVERLAPS_SOURCE');
  if (await exists(out)) fail('PACKAGE_OUTPUT_EXISTS');
  const lockPath = out + '.portable-lock';
  const lock = await open(lockPath, 'wx').catch(() => fail('PACKAGE_OUTPUT_LOCKED'));
  let stage;
  try {
    if (await exists(out)) fail('PACKAGE_OUTPUT_EXISTS');
    const files = [];
    async function collect(path) {
      if (path.length > 100 || files.length > 10000) fail('PACKAGE_SOURCE_LIMIT');
      const absolute = resolve(source, path);
      const stat = await lstat(absolute);
      if (stat.isSymbolicLink()) fail('PACKAGE_SYMLINK_REJECTED');
      if (path.split('/').some(part => excluded.test(part))) return;
      if (stat.isDirectory()) {
        for (const name of (await readdir(absolute)).sort()) await collect(path + '/' + name);
      } else if (stat.isFile() && extensions.test(path)) files.push(path);
    }
    for (const path of roots) await collect(path);
    files.push('package.json', 'tools/start-portable.cmd', 'tools/start-portable.sh', 'tools/check-environment.mjs');
    if (await exists(resolve(source, 'tools/create-shortcut.ps1'))) files.push('tools/create-shortcut.ps1');
    if (!['src/server.mjs', 'student/extension.mjs', 'student/pc-server.mjs', 'student/pc-status.mjs', 'student/pc-view.mjs'].every(path => files.includes(path))) fail('PACKAGE_SOURCE_INCOMPLETE');
    const entries = [];
    let total = 0;
    for (const path of files.sort()) {
      const absolute = resolve(source, path);
      if ((await lstat(absolute)).isSymbolicLink()) fail('PACKAGE_SYMLINK_REJECTED');
      const canonical = await realpath(absolute);
      if (!within(source, canonical) || canonical !== absolute) fail('PACKAGE_SYMLINK_REJECTED');
      const handle = await open(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      let bytes;
      try {
        const stat = await handle.stat();
        if (!stat.isFile() || stat.size > 10 * 1024 * 1024) fail('PACKAGE_FILE_INVALID');
        bytes = await handle.readFile();
      } finally { await handle.close(); }
      total += bytes.length;
      if (total > 50 * 1024 * 1024) fail('PACKAGE_TOO_LARGE');
      if (!/\.(?:webp|png|ico)$/i.test(path) && secret.test(bytes.toString('utf8'))) fail('PACKAGE_SECRET_PATTERN_REJECTED');
      entries.push({ path, bytes, mode: path.endsWith('.sh') ? 0o755 : 0o644 });
    }
    const run = Buffer.from('# Student source bundle\n\nThis is not an approved course runtime or final submission package.\nRequires Node.js 24.19.0 or a later Node.js 24.x installed separately. Run npm run environment:check before starting. No administrator rights are needed.\n\nExtract source-app.tar.gz into a new folder. In on-client, run:\n\n  node student/pc-server.mjs --demo\n\nOpen http://127.0.0.1:5189. Security lesson data is synthetic; click the local PC read button for real CPU, memory, disk and interface counts. Windows-only observations remain unknown on other platforms. For disconnected mode run node student/pc-server.mjs. Stop with Ctrl+C.\nWindows: double-click tools/start-portable.cmd. macOS: sh tools/start-portable.sh. Both launch demo mode and require installed Node.js.\nOn Windows, run tools/create-shortcut.ps1 from PowerShell to create a current-user desktop shortcut; existing shortcuts are not overwritten. Windows execution is not verified here. These launchers are not an installer or approved course host. Account/AI credentials are not included.\nThe existing server binds only to 127.0.0.1. No security settings are changed.\n');
    entries.push({ path: 'SOURCE_RUN.md', bytes: run, mode: 0o644 });
    const tar = Buffer.concat([...entries.map(e => tarEntry('on-client/' + e.path, e.bytes, e.mode)), Buffer.alloc(1024)]);
    const archive = gzipSync(tar, { level: 9 });
    const manifest = { format: 'student-portable-source.v1', approvedCourseRuntime: false, nodeRequired: '>=24.19.0 <25', referenceNode: '24.19.0', sourceRevision: revision(source), includedCredentials: false,
      credentialPolicy: 'known private paths and credential patterns excluded; manual source review required',
      archive: { name: 'source-app.tar.gz', bytes: archive.length, sha256: sha256(archive) },
      exclusions: ['.env and .env.example', 'credentials and databases', 'logs', 'Git', 'node_modules', 'outputs', 'test and developer docs'],
      files: entries.map(e => ({ path: e.path, bytes: e.bytes.length, sha256: sha256(e.bytes) })) };
    stage = await mkdtemp(resolve(parent, '.portable-stage-'));
    await writeFile(resolve(stage, 'source-app.tar.gz'), archive, { flag: 'wx', mode: 0o600 });
    await writeFile(resolve(stage, 'PORTABLE_SOURCE_MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    await writeFile(resolve(stage, 'SOURCE_RUN.md'), run, { flag: 'wx', mode: 0o600 });
    if (await exists(out)) fail('PACKAGE_OUTPUT_EXISTS');
    await rename(stage, out); stage = null;
    return { output: out, fileCount: entries.length, archiveSha256: manifest.archive.sha256, approvedCourseRuntime: false };
  } finally {
    if (stage) await rm(stage, { recursive: true, force: true });
    await lock.close(); await rm(lockPath, { force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2); const options = {};
    while (args.length) {
      const key = args.shift();
      if (!['--source', '--out'].includes(key) || !args.length || args[0].startsWith('--')) fail('PACKAGE_ARGUMENT_INVALID');
      options[key.slice(2)] = args.shift();
    }
    const result = await packagePortable(options);
    console.log(JSON.stringify({ ok: true, fileCount: result.fileCount, archiveSha256: result.archiveSha256, approvedCourseRuntime: false }));
  } catch (e) {
    console.error(['PACKAGE_', 'ENOENT', 'EACCES'].some(prefix => e.message.startsWith(prefix)) ? e.message.split(/[\s:]/)[0] : 'PACKAGE_FAILED');
    process.exitCode = 1;
  }
}
