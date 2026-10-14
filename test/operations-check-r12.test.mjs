import test from 'node:test';
import assert from 'node:assert/strict';
import { runOperationsChecks, trustedBase, writeOperationsReport } from '../scripts/operations-check.mjs';

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
