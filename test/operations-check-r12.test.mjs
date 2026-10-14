import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runOperationsChecks, trustedBase, writeOperationsReport } from '../scripts/operations-check.mjs';
import { buildOperationsReport } from '../src/operations-report.mjs';
import { createOperationsHandler } from '../api/operations.js';
import policyManifest from '../policy-backups/stage9/manifest.json' with { type: 'json' };

test('실제 로컬 exported API 검사는 정상 소유자와 타인 거부를 기록하고 41종 실행으로 집계하지 않는다', async () => {
  const report = await runOperationsChecks({ includeLive: false, checkedCommit: 'a'.repeat(40) });
  assert.equal(report.summary.availability, 'available');
  assert.equal(report.checks.find(row => row.id === 'stage8_signed_fixture_owner_read').actual, 'HTTP_200');
  assert.equal(report.checks.find(row => row.id === 'stage8_signed_fixture_other_owner_denied').actual, 'HTTP_404');
  assert.equal(report.checks.find(row => row.id === 'stage11_fixture_pending_browser_denied').actual, 'HTTP_403');
  assert.equal(report.checks.some(row => row.status === 'failed'), false);
  assert.deepEqual(report.campaign, { total: 41, executed: 0, notRun: 41, coverageBasis: 'official_campaign_results_not_available' });
  assert.equal(report.summary.revocation, 'not_run');
  assert.equal(report.summary.recovery, 'not_run');
  const text = JSON.stringify(report);
  for (const value of ['Synthetic', 'learner_fixture', 'Bearer ', 'access_token', 'refresh_token', 'owner_id', 'userId', 'device_id']) {
    assert.equal(text.includes(value), false);
  }
  for (const row of report.checks.filter(row => row.status === 'passed')) assert.match(row.requestId, /^student_check_/u);
});

test('live 결과는 실제 HTTP 상태만 수집하고 cookie·Authorization·응답 내용을 저장하지 않는다', async () => {
  const requested = [];
  const statuses = { '/': 200, '/data.json': 404, '/api/notes': 401, '/aleph.json': 200,
    '/api/restore': 401, '/manifest.webmanifest': 200, '/api/auth': 200 };
  const report = await runOperationsChecks({ checkedCommit: 'b'.repeat(40), fetchImpl: async (url, options) => {
    requested.push({ url, options });
    return new Response('private-response-sentinel', { status: statuses[new URL(url).pathname] });
  } });
  assert.equal(requested.length, 7);
  assert.ok(requested.every(row => row.options.credentials === 'omit' && row.options.redirect === 'error' && row.options.headers === undefined));
  assert.equal(JSON.stringify(report).includes('private-response-sentinel'), false);
  assert.equal(report.summary.liveApi, 'confirmed');
});

test('네트워크 실패와 예상과 다른 상태는 성공으로 바꾸지 않는다', async () => {
  const report = await runOperationsChecks({ checkedCommit: 'c'.repeat(40), fetchImpl: async url => {
    if (new URL(url).pathname === '/api/notes') throw new Error('private-network-error-sentinel');
    return new Response(null, { status: 500 });
  } });
  const failed = report.checks.find(row => row.id === 'stage1_public_shell');
  assert.equal(failed.status, 'failed'); assert.equal(failed.actual, 'HTTP_500');
  const unavailable = report.checks.find(row => row.id === 'stage3_anonymous_notes_denied');
  assert.equal(unavailable.status, 'unavailable');
  assert.equal(unavailable.actual, null); assert.equal(unavailable.requestId, null); assert.equal(unavailable.checkedAt, null);
  assert.equal(JSON.stringify(report).includes('private-network-error-sentinel'), false);
});

test('외부 기본 URL과 workspace 밖 결과 파일을 거부한다', async () => {
  assert.throws(() => trustedBase('https://other.vercel.app'), /untrusted_operations_base/u);
  await assert.rejects(writeOperationsReport('/tmp/operations.json', {}), /invalid_operations_output/u);
});

test('생성→파일 저장→실제 API projection은 computed snapshot을 evidence와 분리해 available을 유지한다', async t => {
  const archive = resolve(dirname(fileURLToPath(import.meta.url)), '../../agents/stage12/stage8_review');
  await mkdir(archive, { recursive: true });
  const dir = await mkdtemp(join(archive, 'roundtrip-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const generated = await runOperationsChecks({ includeLive: false, checkedCommit: 'd'.repeat(40) });
  assert.equal(Object.hasOwn(generated, 'policySnapshot'), true);
  const path = join(dir, 'evidence.json');
  await writeOperationsReport(path, generated);
  const stored = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(Object.hasOwn(stored, 'policySnapshot'), false);
  const projected = buildOperationsReport(stored, policyManifest);
  assert.equal(projected.summary.availability, 'available');
  assert.equal(projected.policySnapshot.availability, 'available');
  assert.deepEqual(projected.checks, generated.checks);
  assert.deepEqual(projected.campaign, generated.campaign);
  assert.equal(projected.checkedCommit, generated.checkedCommit);
  const res = { setHeader() {}, status(code) { this.statusCode = code; return this; }, json(value) { this.body = value; return this; } };
  await createOperationsHandler(() => stored, 'd'.repeat(40), () => policyManifest)({ method: 'GET' }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.summary.availability, 'available');
  assert.deepEqual(res.body.checks, generated.checks);
  assert.equal(res.body.policySnapshot.availability, 'available');
});
