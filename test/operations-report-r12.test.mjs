import test from 'node:test';
import assert from 'node:assert/strict';
import { RULE_IDS } from '../src/decider.mjs';
import { buildOperationsReport, unavailableOperationsReport, buildPolicySnapshot } from '../src/operations-report.mjs';
import policyManifest from '../policy-backups/stage9/manifest.json' with { type: 'json' };
import operationsHandler, { createOperationsHandler } from '../api/operations.js';

const commit = 'a'.repeat(40), now = '2026-10-14T00:00:00.000Z';
const check = overrides => ({ id: 'student_check_s08_get', stage: 8, kind: 'normal', category: 'api',
  expected: 'HTTP_200', actual: 'HTTP_200', requestId: 'student_check_001', checkedAt: now,
  source: 'live_http', status: 'passed', ...overrides });
const report = checks => ({ schema: 'aleph.operations.v1', checkedCommit: commit, generatedAt: now, checks,
  campaign: { total: 41, executed: 0, notRun: 41, coverageBasis: 'official_campaign_results_not_available' } });
function response() { return { headers: {}, setHeader(name,value) { this.headers[name]=value; },
  status(value) { this.statusCode=value;return this; }, json(value) { this.body=value;return this; } }; }

test('public summary distinguishes real HTTP, local checks, historical judge and unexecuted evidence', () => {
  const result = buildOperationsReport(report([
    check(), check({ id: 'student_check_s09_detect', stage: 9, category: 'detection', source: 'local_decider',
      expected: 'propose_revocation', actual: 'propose_revocation', requestId: null }),
    check({ id: 'historical_judge_s06', stage: 6, category: 'policy', source: 'judge', status: 'historical',
      expected: 'JUDGE_SCORE_100', actual: 'JUDGE_SCORE_100', requestId: null, checkedAt: null }),
    check({ id: 'unrun_revocation', stage: 9, category: 'revocation', kind: 'forbidden', source: 'not_run',
      status: 'not_run', expected: 'deny', actual: null, requestId: null, checkedAt: null }),
  ]));
  assert.deepEqual(result.rules, [...RULE_IDS]);
  assert.equal(result.engineOrigin, 'ALEPH SDP engine');
  assert.deepEqual(result.summary, { availability: 'available', liveApi: 'confirmed', detection: 'not_run', revocation: 'not_run', recovery: 'not_run' });
  assert.equal(result.checks[1].source, 'local_decider'); assert.equal(result.checks[2].status, 'historical');
  assert.deepEqual(result.campaign, { total: 41, executed: 0, notRun: 41, coverageBasis: 'official_campaign_results_not_available' });
});

test('untrusted text, unsupported fields, invalid provenance and inflated campaigns fail closed', () => {
  for (const input of [null, {}, { ...report([]), noteBody: 'private fixture note' },
    report([check({ actual: 'private fixture note' })]), report([check({ body: 'private fixture note' })]),
    report([check({ requestId: 'header.payload.signature' })]), report([check({ checkedAt: '2026-02-31T00:00:00Z' })]),
    report([check({ source: 'not_run' })]), report([check({ status: 'passed', actual: 'HTTP_401' })]),
    report([check({ status: 'failed', actual: 'HTTP_200' })]), report([check({ status: 'not_run' })]),
    report([check(), check()]), { ...report([]), campaign: { total: 41, executed: 41, notRun: 0, coverageBasis: 'local_tests' } },
  ]) assert.deepEqual(buildOperationsReport(input), unavailableOperationsReport());
});

test('reported synthetic and historical attacks never become official campaign executions', () => {
  const input = report([
    check({ kind: 'attack', source: 'local_api' }),
    check({ id: 'historical_attack', kind: 'attack', source: 'judge', status: 'historical',
      expected: 'JUDGE_SCORE_100', actual: 'JUDGE_SCORE_100', checkedAt: null, requestId: null }),
    check({ id: 'generic_live_negative', kind: 'attack', expected: 'HTTP_403', actual: 'HTTP_403' }),
  ]);
  const result = buildOperationsReport(input);
  assert.equal(result.summary.availability, 'available');
  assert.equal(result.campaign.executed, 0); assert.equal(result.campaign.notRun, 41);
});

test('operations endpoint is GET-only, no-store, publicly redacted and binds deployment only to runtime', async () => {
  const handler = createOperationsHandler(() => report([check()]), 'b'.repeat(40));
  const result = response(); await handler({ method: 'GET', headers: { 'x-vercel-git-commit-sha': 'c'.repeat(40) } }, result);
  assert.equal(result.statusCode, 200); assert.equal(result.headers['Cache-Control'], 'no-store');
  assert.equal(result.body.checkedCommit, commit); assert.equal(result.body.deployedCommit, 'b'.repeat(40));
  const rejected = response(); await handler({ method: 'POST' }, rejected);
  assert.equal(rejected.statusCode, 405); assert.equal(rejected.headers.Allow, 'GET');
  const missing = response(); await createOperationsHandler(() => { throw new Error('private fixture detail'); }, 'not_a_commit', () => null)({ method: 'GET' }, missing);
  assert.deepEqual(missing.body, { ...unavailableOperationsReport(), deployedCommit: null });
  assert.equal(JSON.stringify(missing.body).includes('private fixture'), false);
});

test('actual default handler uses packaged evidence through the same redaction boundary', async () => {
  const result = response(); await operationsHandler({ method: 'GET', headers: {} }, result);
  assert.equal(result.statusCode, 200); assert.equal(result.body.schema, 'aleph.operations.v1');
  assert.deepEqual(result.body.rules, [...RULE_IDS]);
  assert.equal(result.body.campaign.executed, 0); assert.equal(result.body.campaign.notRun, 41);
  assert.deepEqual(Object.keys(result.body).sort(), ['campaign', 'checkedCommit', 'checks', 'deployedCommit', 'engineOrigin', 'generatedAt', 'policySnapshot', 'rules', 'schema', 'summary']);
  assert.deepEqual(result.body.policySnapshot, buildPolicySnapshot(policyManifest));
});

test('policy version comes from the actual manifest and never claims database or policy restoration', () => {
  const result = buildOperationsReport(report([check({ category: 'recovery', stage: 10,
    source: 'local_sql', expected: 'SQL_ASSERTIONS_PASSED', actual: 'SQL_ASSERTIONS_PASSED' })]), policyManifest);
  assert.deepEqual(result.policySnapshot, { availability: 'available', scope: 'policy_code_snapshot',
    source: 'policy-backups/stage9/manifest.json', version: policyManifest.version, commit: policyManifest.commit,
    fileCount: policyManifest.files.length, verification: 'manifest_metadata_only' });
  assert.equal(result.summary.recovery, 'not_run');
  assert.equal(result.policySnapshot.restored, undefined);
  assert.equal(result.policySnapshot.files, undefined);
  assert.equal(result.policySnapshot.restoredAt, undefined);
});

test('invalid or absent policy metadata fails independently without losing valid operations evidence', async () => {
  for (const manifest of [null, {}, { ...policyManifest, noteBody: 'private fixture body' },
    { ...policyManifest, version: 'private fixture version' },
    { ...policyManifest, files: [...policyManifest.files.slice(1), policyManifest.files[1]] },
    { ...policyManifest, files: [{ path: '/private/user/credential', sha256: 'a'.repeat(64) }, ...policyManifest.files.slice(1)] },
    { ...policyManifest, files: [{ ...policyManifest.files[0], sha256: 'invalid' }, ...policyManifest.files.slice(1)] },
  ]) {
    const result = buildOperationsReport(report([check()]), manifest);
    assert.equal(result.summary.availability, 'available'); assert.equal(result.checks.length, 1);
    assert.equal(result.policySnapshot.availability, 'unavailable');
    assert.equal(result.policySnapshot.version, null); assert.equal(result.policySnapshot.commit, null);
    assert.equal(JSON.stringify(result).includes('private fixture'), false);
  }
  const result = response(); await createOperationsHandler(() => report([check()]), null,
    () => { throw new Error('private fixture missing manifest'); })({ method: 'GET' }, result);
  assert.equal(result.body.summary.availability, 'available'); assert.equal(result.body.policySnapshot.availability, 'unavailable');
  const invalidEvidence = response(); await createOperationsHandler(() => null, null,
    () => policyManifest)({ method: 'GET' }, invalidEvidence);
  assert.equal(invalidEvidence.body.summary.availability, 'unavailable');
  assert.equal(invalidEvidence.body.policySnapshot.availability, 'available');
  assert.equal(invalidEvidence.body.summary.recovery, 'not_run');
});
