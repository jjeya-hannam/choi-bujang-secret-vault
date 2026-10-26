import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { packagePortable } from '../tools/package-portable.mjs';

async function fixture(t) {
  const root = await mkdtemp(resolve(tmpdir(), 'portable-check-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = resolve(root, 'source'); await mkdir(source);
  for (const dir of ['public', 'src', 'vendor', 'student', 'tools']) await mkdir(resolve(source, dir));
  for (const [name, content] of Object.entries({ 'package.json': '{"type":"module"}', 'src/server.mjs': 'export const demo = true;', 'student/extension.mjs': 'export function createStudentView() {}', 'student/pc-server.mjs': '// student server', 'student/pc-status.mjs': '// read only', 'student/pc-view.mjs': '// view', 'public/index.html': '<p>demo</p>', 'vendor/a.mjs': '// public helper', 'tools/start-portable.cmd': '@echo demo', 'tools/start-portable.sh': '#!/bin/sh\necho demo' })) await writeFile(resolve(source, name), content);
  return { root, source, out: resolve(root, 'bundle') };
}
function unpack(bytes) {
  const tar = gunzipSync(bytes); const files = new Map();
  for (let offset = 0; offset < tar.length && tar[offset] !== 0;) {
    const header = tar.subarray(offset, offset + 512);
    const name = header.subarray(0, 100).toString().replace(/\0.*$/, '');
    const size = parseInt(header.subarray(124, 136).toString().replace(/\0.*$/, ''), 8);
    const expected = parseInt(header.subarray(148, 156).toString().replace(/\0.*$/, ''), 8);
    const copy = Buffer.from(header); copy.fill(32, 148, 156);
    assert.equal(copy.reduce((a, b) => a + b, 0), expected);
    files.set(name, tar.subarray(offset + 512, offset + 512 + size));
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return files;
}
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
test('source bundle hashes all files, excludes private data and identifies itself honestly', async t => {
  const f = await fixture(t);
  for (const name of ['.env', '.env.example', 'credentials.json', 'notes.sqlite', 'session.log']) await writeFile(resolve(f.source, 'student', name), 'synthetic confidential fixture');
  const result = await packagePortable(f);
  const bytes = await readFile(resolve(f.out, 'source-app.tar.gz'));
  const manifest = JSON.parse(await readFile(resolve(f.out, 'PORTABLE_SOURCE_MANIFEST.json')));
  const files = unpack(bytes);
  assert.equal(manifest.approvedCourseRuntime, false); assert.equal(result.approvedCourseRuntime, false);
  assert.deepEqual(manifest.sourceRevision, { commit: null, workingTreeDirty: null });
  assert.equal(manifest.archive.sha256, hash(bytes));
  for (const entry of manifest.files) { const data = files.get('on-client/' + entry.path); assert.ok(data); assert.equal(hash(data), entry.sha256); assert.equal(data.length, entry.bytes); }
  assert.equal(files.size, manifest.files.length);
  assert.ok([...files.keys()].every(name => !/\.env|credentials|sqlite|session\.log/.test(name)));
  assert.match(files.get('on-client/SOURCE_RUN.md').toString(), /not an approved/);
  assert.deepEqual((await readdir(f.root)).sort(), ['bundle', 'source']);
});
test('existing output and source-overlapping output are rejected without modifying them', async t => {
  const f = await fixture(t); await mkdir(f.out); await writeFile(resolve(f.out, 'preserve'), 'original');
  await assert.rejects(packagePortable(f), /PACKAGE_OUTPUT_EXISTS/);
  assert.equal(await readFile(resolve(f.out, 'preserve'), 'utf8'), 'original');
  await assert.rejects(packagePortable({ source: f.source, out: resolve(f.source, 'bundle') }), /PACKAGE_OUTPUT_OVERLAPS_SOURCE/);
});
test('source symlinks are rejected and failures leave no output, staging folder or lock', async t => {
  const f = await fixture(t); const outside = resolve(f.root, 'outside.mjs'); await writeFile(outside, '// outside');
  await symlink(outside, resolve(f.source, 'student', 'link.mjs'));
  await assert.rejects(packagePortable(f), /PACKAGE_SYMLINK_REJECTED/);
  assert.deepEqual((await readdir(f.root)).sort(), ['outside.mjs', 'source']);
});
test('unsupported tar path and secret-like source abort before publishing output', async t => {
  const f = await fixture(t); await writeFile(resolve(f.source, 'student', 'unsafe name.mjs'), '// source');
  await assert.rejects(packagePortable(f), /PACKAGE_PATH_UNSUPPORTED/);
  await rm(resolve(f.source, 'student', 'unsafe name.mjs'));
  await writeFile(resolve(f.source, 'student', 'unsafe.mjs'), 'const key = "sb_secret_' + 'x'.repeat(20) + '";');
  await assert.rejects(packagePortable(f), /PACKAGE_SECRET_PATTERN_REJECTED/);
  assert.deepEqual(await readdir(f.root), ['source']);
});
test('output lock rejects concurrent packaging and is preserved by rejected invocation', async t => {
  const f = await fixture(t); await writeFile(f.out + '.portable-lock', 'owner', { flag: 'wx' });
  await assert.rejects(packagePortable(f), /PACKAGE_OUTPUT_LOCKED/);
  assert.equal(await readFile(f.out + '.portable-lock', 'utf8'), 'owner');
});
test('credential-like source literals with known key prefixes are rejected', async t => {
  const f = await fixture(t);
  for (const prefix of ['sk-proj-', 'sk-ant-', 'sk-on-', 'sk-svcacct-', 'sk-']) {
    await writeFile(resolve(f.source, 'student', 'literal.mjs'), 'const key = "' + prefix + 'x'.repeat(20) + '";');
    await assert.rejects(packagePortable(f), /PACKAGE_SECRET_PATTERN_REJECTED/);
    assert.deepEqual(await readdir(f.root), ['source']);
  }
});

test('bundle refuses a missing PC runtime used by its launchers', async t => {
  const f = await fixture(t);
  await rm(resolve(f.source, 'student/pc-server.mjs'));
  await assert.rejects(packagePortable(f), /PACKAGE_SOURCE_INCOMPLETE/);
  assert.deepEqual(await readdir(f.root), ['source']);
});
