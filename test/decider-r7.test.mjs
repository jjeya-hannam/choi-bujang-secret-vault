import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

test('정상 allow, 복합 가상 사건 step_up 및 계약 보존', async () => {
  const { normal, suspicious } = fixtureRequests();
  const original = structuredClone(suspicious);
  assert.equal((await decide(normal)).decision, 'allow');
  const result = await decide(suspicious);
  assert.deepEqual(Object.keys(result).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  assert.equal(result.requestId, suspicious.requestId);
  assert.equal(result.decision, 'step_up');
  assert.equal(result.reasonCode, 'step_up_required');
  assert.deepEqual(result.ruleIds, ['device_registered', 'step_up_required']);
  assert.deepEqual(suspicious, original);
  assert.deepEqual(RULE_IDS, ['device_registered', 'step_up_required', 'resource_route']);
});

test('지역 단독 또는 복합 조건 하나가 빠진 사건은 영구 차단하지 않는다', async () => {
  const { normal, suspicious } = fixtureRequests();
  for (const request of [
    { ...normal, signals: { ...normal.signals, region: 'foreign' } },
    { ...suspicious, signals: { ...suspicious.signals, hour: 14 } },
    { ...suspicious, signals: { ...suspicious.signals, network: 'usual' } },
    { ...suspicious, recentEvents: [] },
    { ...suspicious, recentEvents: [{ kind: 'risk_signal', count: 20, ageSeconds: 301 }] },
    { ...suspicious, recentEvents: [{ kind: 'risk_signal', count: 19, ageSeconds: 60 }] },
  ]) assert.equal((await decide(request)).decision, 'allow');
});

test('출처 없는 실제 신호는 변경하지 않고 클라이언트 헤더는 신뢰하지 않는다', async () => {
  const { suspicious } = fixtureRequests();
  const request = { ...suspicious, path: '/api/notes', route: 'GET /api/notes', signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 3 },
    headers: { 'x-region': 'foreign', 'x-network': 'unusual' } };
  const original = structuredClone(request);
  assert.equal((await decide(request)).decision, 'allow');
  assert.deepEqual(request, original);
  assert.equal((await decide({ ...request, signals: { ...suspicious.signals, source: 'client_header' } })).decision, 'allow');
});

test('가상 재확인 나이의 유효성 및 미등록 기기 거부 우선순위', async () => {
  const { suspicious } = fixtureRequests();
  for (const age of [0, 60, 900]) {
    assert.equal((await decide({ ...suspicious, stepUp: { verified: true, authAgeSeconds: age } })).decision, 'allow');
  }
  for (const age of [null, -1, 901, '60', NaN]) {
    assert.equal((await decide({ ...suspicious, stepUp: { verified: true, authAgeSeconds: age } })).decision, 'step_up');
  }
  const denied = await decide({ ...suspicious, deviceRegistered: false, stepUp: { verified: true, authAgeSeconds: 60 } });
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.reasonCode, 'device_not_registered');
});
