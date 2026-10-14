import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, cp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { buildOperationsReport } from '../src/operations-report.mjs';
import policyManifest from '../policy-backups/stage9/manifest.json' with { type: 'json' };

const root = new URL('../', import.meta.url);
const config = { step: 12, publicAppUrl: 'https://student-defense.vercel.app', sampleMarker: 'SAMPLE_NOTE_1' };
const operation = () => ({ ...buildOperationsReport({ schema: 'aleph.operations.v1', checkedCommit: 'a'.repeat(40),
  generatedAt: '2026-10-14T00:00:00.000Z',
  checks: [{ id: 'signed_fixture_read', stage: 8, kind: 'normal', category: 'api', expected: 'HTTP_200',
    actual: 'HTTP_200', requestId: 'student_check_001', checkedAt: '2026-10-14T00:00:00.000Z', source: 'local_api', status: 'passed' }],
  campaign: { total: 41, executed: 0, notRun: 41, coverageBasis: 'official_campaign_results_not_available' },
}, policyManifest), deployedCommit: 'a'.repeat(40) });

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
async function run(checker, payload = operation(), noteError = 'AUTH_REQUIRED') {
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
        '/api/operations': [200, payload],
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

test('새 checker는 단일 파일만 import/run하며 공식 bundle의 1~20개 정확 세 필드 계약을 유지한다', async t => {
  const checker = await standalone(t);
  const { attempts, calls } = await run(checker);
  assert.ok(attempts.length >= 1 && attempts.length <= 20);
  assert.equal(new Set(attempts.map(row => row.attackId)).size, attempts.length);
  for (const row of attempts) {
    assert.deepEqual(Object.keys(row).sort(), ['attackId', 'expected', 'observed']);
    assert.match(row.attackId, /^[a-z0-9][a-z0-9_.-]{0,79}$/iu);
    for (const field of ['expected', 'observed']) assert.ok(typeof row[field] === 'string' && row[field].trim() && row[field].length <= 300);
  }
  assert.deepEqual(calls.map(row => row.pathname).sort(), ['/api/auth', '/api/notes', '/api/operations', '/manifest.webmanifest']);
  assert.ok(calls.every(row => row.options.redirect === 'error' && row.options.credentials === 'omit' && row.options.cache === 'no-store'));
  for (const id of ['anonymous_note_read', 'live_pwa_manifest', 'live_unsigned_device_status', 'live_operations_summary']) {
    assert.match(attempts.find(row => row.attackId === id)?.observed ?? '', /result=passed/u);
  }
});

test('잘못된 operations JSON은 확인 성공으로 바꾸거나 원문을 출력하지 않는다', async t => {
  const checker = await standalone(t);
  const valid = await run(checker);
  const invalid = await run(checker, { schema: 'unsupported', body: 'private_note_sentinel', token: 'private_token_sentinel' });
  const match = row => /operations?/u.test(row.attackId);
  assert.ok(valid.attempts.some(match));
  assert.ok(invalid.attempts.some(match));
  assert.notDeepEqual(invalid.attempts.filter(match).map(row => row.observed), valid.attempts.filter(match).map(row => row.observed));
  const text = JSON.stringify(invalid.attempts);
  assert.equal(text.includes('private_note_sentinel'), false);
  assert.equal(text.includes('private_token_sentinel'), false);
});

test('익명 오류에 본문·토큰 문자열이 있어도 점검 출력에 반사하지 않는다', async t => {
  const checker = await standalone(t);
  const { attempts } = await run(checker, operation(), 'Bearer private_token_sentinel');
  const text = JSON.stringify(attempts);
  assert.equal(text.includes('private_note_sentinel'), false);
  assert.equal(text.includes('private_token_sentinel'), false);
  assert.equal(text.includes('Bearer '), false);
});
