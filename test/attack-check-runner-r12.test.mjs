// Synthetic redaction fixtures are assembled only during tests; no credential source is read.
const syntheticText = (...parts) => parts.join('');
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, cp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';

const root = new URL('../', import.meta.url);
const config = { step: 11, publicAppUrl: 'https://student-defense.vercel.app', sampleMarker: 'SAMPLE_NOTE_1' };

async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'vault-standalone-checker-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
async function standalone(t) {
  const dir = await directory(t);
  const entry = join(dir, 'attack-check.mjs');
  // Exactly one source file: no scripts, src helpers, config, snapshots or node_modules.
  await cp(new URL('../src/attack-check.mjs', import.meta.url), entry);
  return await import(pathToFileURL(entry));
}
async function run(checker, noteError = 'AUTH_REQUIRED') {
  const original = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (url, options) => {
      calls.push({ pathname: new URL(url).pathname, options });
      const responses = {
        '/api/notes': [401, noteError === 'AUTH_REQUIRED' ? { error: noteError }
          : { error: noteError, notes: [{ body: 'private_note_sentinel' }] }],
        '/manifest.webmanifest': [200, { display: 'standalone', name: 'Synthetic', icons: [{}, {}] }],
        '/api/auth': [200, { signedIn: false, deviceStatus: 'unrequested' }],
      };
      const selected = responses[new URL(url).pathname];
      if (!selected) throw new Error('unexpected_checker_endpoint');
      return new Response(JSON.stringify(selected[1]), { status: selected[0], headers: { 'content-type': 'application/json' } });
    };
    return { attempts: await checker.runAttackChecks(config), calls };
  } finally { globalThis.fetch = original; }
}

test('기존 제출 checker는 단일 파일 격리 환경에서 상대 의존성을 찾지 못한다', async t => {
  const dir = await directory(t);
  const previous = execFileSync('git', ['show', 'd61151c8711462a38cc73827d4903c2e7af0678c:src/attack-check.mjs'],
    { cwd: root, encoding: 'utf8' });
  const entry = join(dir, 'previous-checker.mjs');
  await writeFile(entry, previous);
  await assert.rejects(import(pathToFileURL(entry)), error => error.code === 'ERR_MODULE_NOT_FOUND');
});

test('11단계 checker는 단일 파일만 import/run하며 실제 HTTP 세 요청과 bundle 세 필드를 유지한다', async t => {
  const checker = await standalone(t);
  const { attempts, calls } = await run(checker);
  assert.ok(attempts.length >= 1 && attempts.length <= 20);
  assert.equal(new Set(attempts.map(row => row.attackId)).size, attempts.length);
  for (const row of attempts) {
    assert.deepEqual(Object.keys(row).sort(), ['attackId', 'expected', 'observed']);
    assert.match(row.attackId, /^[a-z0-9][a-z0-9_.-]{0,79}$/iu);
    for (const field of ['expected', 'observed']) assert.ok(typeof row[field] === 'string' && row[field].trim() && row[field].length <= 300);
  }
  assert.deepEqual(calls.map(row => row.pathname).sort(), ['/api/auth', '/api/notes', '/manifest.webmanifest']);
  assert.ok(calls.every(row => row.options.redirect === 'error' && row.options.credentials === 'omit' && row.options.cache === 'no-store'));
  for (const id of ['anonymous_note_read', 'live_pwa_manifest', 'live_unsigned_device_status']) {
    assert.match(attempts.find(row => row.attackId === id)?.observed ?? '', /result=passed/u);
  }
});

test('11단계 익명 오류에 본문·토큰 문자열이 있어도 점검 출력에 반사하지 않는다', async t => {
  const checker = await standalone(t);
  const { attempts } = await run(checker, syntheticText("Bearer p", "rivate_t", "oken_sen", "tinel"));
  const text = JSON.stringify(attempts);
  assert.equal(text.includes('private_note_sentinel'), false);
  assert.equal(text.includes('private_token_sentinel'), false);
  assert.equal(text.includes('Bearer '), false);
});

test('12단계는 실제 요청 없이 정확 열 행의 미실행 계획과 bundle 세 필드를 반환한다', async t => {
  const checker = await standalone(t);
  const original = globalThis.fetch;
  let calls = 0;
  try {
    globalThis.fetch = async () => { calls += 1; throw new Error('unexpected_stage12_request'); };
    const attempts = await checker.runAttackChecks({ ...config, step: 12 });
    assert.equal(calls, 0);
    assert.equal(attempts.length, 10);
    assert.ok(attempts.length <= 20);
    assert.equal(new Set(attempts.map(row => row.attackId)).size, 10);
    assert.deepEqual(attempts.map(row => row.attackId).sort(), ['anonymous_note_read', 'live_step_up_verification',
      'live_resource_accounts', 'live_detection_revocation', 'live_restore', 'live_pwa_manifest',
      'live_unsigned_device_status', 'live_approved_student_browser', 'live_operations_summary', 'official_campaign_41'].sort());
    for (const row of attempts) {
      assert.deepEqual(Object.keys(row).sort(), ['attackId', 'expected', 'observed']);
      assert.equal(row.observed, 'not_run');
      assert.match(row.attackId, /^[a-z0-9][a-z0-9_.-]{0,79}$/iu);
      assert.ok(typeof row.expected === 'string' && row.expected.trim() && row.expected.length <= 300);
    }
  } finally { globalThis.fetch = original; }
});

test('11단계 네트워크 실패는 HTTP 세 항목을 포함해 모두 exact not_run으로 반환한다', async t => {
  const checker = await standalone(t);
  const original = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async url => { calls.push(new URL(url).pathname); throw new Error('network_unavailable_sentinel'); };
    const attempts = await checker.runAttackChecks(config);
    assert.deepEqual(calls.sort(), ['/api/auth', '/api/notes', '/manifest.webmanifest']);
    assert.equal(attempts.length, 8);
    assert.ok(attempts.every(row => row.observed === 'not_run'));
    assert.equal(JSON.stringify(attempts).includes('network_unavailable_sentinel'), false);
  } finally { globalThis.fetch = original; }
});
