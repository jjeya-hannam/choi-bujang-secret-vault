import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { respondFixture } from '../xdr/shared/respond-fixture.mjs';
import { evaluateDenyRules } from '../xdr/ztna-overlay.mjs';
const now = new Date('2026-10-14T00:00:00.000Z');
async function rootFor(t) {
  const root = await mkdtemp(join(tmpdir(), 'xdr-fixture-'));
  await mkdir(join(root, 'xdr')); t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}
function sample(moduleKey) {
  const actions = ['block', 'alert', 'record', 'block', 'record'];
  const ips = ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4', '192.0.2.4'];
  return { moduleKey, reasons: ['compound_evidence'], now,
    fixture: { schema: 'aleph.xdr.fixture.v1', moduleKey, alerts: actions.map((_, i) => ({
      id: 'example-' + i, data: { srcip: ips[i], srcuser: 'PRIVATE_SENTINEL', token: 'PRIVATE_SENTINEL' },
      rule: { level: actions[i] === 'record' ? 2 : 12, mitre: actions[i] === 'record' ? [] : ['T0000'] },
    })) },
    result: { schema: 'aleph.xdr.result.v1', moduleKey, counts: { block: 2, alert: 1, record: 2 },
      decisions: actions.map((action, i) => ({ alertId: 'example-' + i, action,
        confidence: action === 'block' ? .9 : action === 'alert' ? .6 : .1,
        reason: action === 'record' ? 'no_matching_pattern' : 'compound_evidence' })) },
  };
}
for (const moduleKey of ['persistence', 'privilege', 'exfiltration']) {
  test(`${moduleKey}: 만료·정상공유주소 보호·중복방지·타 모듈 보존`, async t => {
    const root = await rootFor(t), data = sample(moduleKey);
    const other = { moduleKey: 'known-cve', action: 'deny', sourceAddress: '198.51.100.1',
      expiresAt: '2026-10-13T00:00:00.000Z', evidenceAlertIds: ['old-evidence'] };
    await writeFile(join(root, 'xdr/deny-rules.json'), JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules: [other] }));
    await respondFixture({ root, ...data });
    const first = await readFile(join(root, 'xdr/deny-rules.json'), 'utf8');
    const rules = JSON.parse(first).rules;
    assert.deepEqual(rules[0], other); assert.equal(rules.length, 2);
    assert.deepEqual(rules[1].evidenceAlertIds, ['example-0']);
    assert.equal(evaluateDenyRules('192.0.2.1', rules, now).blocked, true);
    assert.equal(evaluateDenyRules('192.0.2.4', rules, now).blocked, false);
    assert.equal(evaluateDenyRules('192.0.2.1', rules, new Date(rules[1].expiresAt)).blocked, false);
    const log = await readFile(join(root, 'xdr/alerts.log'), 'utf8');
    assert.equal(log.trim().split('\n').length, 3); assert.equal(log.includes('PRIVATE_SENTINEL'), false);
    await respondFixture({ root, ...data, now: new Date(now.getTime() + 1000) });
    assert.equal(await readFile(join(root, 'xdr/deny-rules.json'), 'utf8'), first);
    assert.equal(await readFile(join(root, 'xdr/alerts.log'), 'utf8'), log);
  });
}
test('알 수 없는 모듈·잘못된 counts·실제 IP·이유 누출은 쓰기 전에 거부', async t => {
  const root = await rootFor(t);
  for (const mutate of [
    x => { x.moduleKey = 'unknown'; },
    x => { x.result.counts.block = 3; },
    x => { x.fixture.alerts[0].data.srcip = '8.8.8.8'; },
    x => { x.result.decisions[0].reason = 'token=PRIVATE_SENTINEL'; },
  ]) {
    const data = sample('persistence'); mutate(data);
    await assert.rejects(respondFixture({ root, ...data }), /INVALID_FIXTURE_RESPONSE/);
  }
  await assert.rejects(readFile(join(root, 'xdr/deny-rules.json')), { code: 'ENOENT' });
});


test('달력에 없는 만료 시각은 정규화하지 않고 기존 파일을 보존한다', async t => {
  const root = await rootFor(t);
  const existing = JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules: [{
    moduleKey: 'known-cve', action: 'deny', sourceAddress: '192.0.2.10',
    expiresAt: '2026-02-30T00:00:00.000Z', evidenceAlertIds: ['existing-1'],
  }] });
  await writeFile(join(root, 'xdr/deny-rules.json'), existing);
  await assert.rejects(respondFixture({ root, ...sample('privilege') }), /INVALID_FIXTURE_RESPONSE/);
  assert.equal(await readFile(join(root, 'xdr/deny-rules.json'), 'utf8'), existing);
  await assert.rejects(readFile(join(root, 'xdr/alerts.log')), { code: 'ENOENT' });
});
