import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

test('등록 기기의 엔진 요청은 원래 요청 ID와 다섯 항목 계약으로 허용한다', async () => {
  const { normal } = fixtureRequests();
  const before = structuredClone(normal);
  assert.deepEqual(await decide(normal), {
    schema: 'aleph.decision.v1', requestId: normal.requestId,
    decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered'],
  });
  assert.deepEqual(normal, before);
  assert.deepEqual(RULE_IDS, ['device_registered']);
});

test('미등록 또는 미확인 상태는 truthy 값으로 허용하지 않는다', async () => {
  for (const state of [false, undefined, null, 'true', 'false', 1, 0, {}, []]) {
    const { normal } = fixtureRequests();
    normal.deviceRegistered = state;
    assert.deepEqual(await decide(normal), {
      schema: 'aleph.decision.v1', requestId: normal.requestId,
      decision: 'deny', reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    });
  }
  const { normal } = fixtureRequests();
  delete normal.deviceRegistered;
  assert.equal((await decide(normal)).decision, 'deny');
});
