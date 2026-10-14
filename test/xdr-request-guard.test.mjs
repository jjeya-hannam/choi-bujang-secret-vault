import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequestGuard } from '../xdr/shared/request-guard.mjs';

const NOW = Date.parse('2026-10-14T00:00:00.000Z');
const snapshot = rules => ({ schema: 'aleph.xdr.deny-rules.v1', rules });
const rule = (sourceAddress = '192.0.2.9', expiresAt = '2026-10-14T01:00:00.000Z') => ({
  moduleKey: 'known-cve', action: 'deny', sourceAddress, expiresAt, evidenceAlertIds: ['kcve-01'],
});
const ctx = remoteAddress => ({ socket: { remoteAddress }, headers: {} });
const create = (rules = [], overrides = {}) => createRequestGuard({
  resolveTrustedSource: context => context.socket.remoteAddress,
  loadRules: () => snapshot(rules), clock: () => new Date(NOW), ...overrides,
});
const result = (actual, status, reason) => assert.deepEqual(actual, { status, reason });

test('신뢰된 정상 주소는 pass, 활성 known-cve는 deny, 정확 만료 시각은 pass다', async () => {
  const guard = create([rule()]);
  result(await guard(ctx('192.0.2.8')), 'pass', 'no_active_deny_rule');
  result(await guard(ctx('192.0.2.9')), 'deny', 'active_deny_rule');
  result(await create([rule()], { clock: () => NOW + 3600000 })(ctx('192.0.2.9')), 'pass', 'no_active_deny_rule');
  // pass means only that this overlay found no active deny. Existing app
  // authentication/authorization must still be enforced by the caller.
  result(await create()(Object.assign(ctx('192.0.2.8'), { existingAuthorization: 'deny' })), 'pass', 'no_active_deny_rule');
});

test('IPv6 표기 차이와 mapped IPv4 별칭은 같은 규칙에 매칭된다', async () => {
  result(await create([rule('2001:db8::1')])(ctx('2001:0DB8:0000:0:0:0:0:1')), 'deny', 'active_deny_rule');
  result(await create([rule()])(ctx('::ffff:192.0.2.9')), 'deny', 'active_deny_rule');
  result(await create([rule('::ffff:c000:0209')])(ctx('192.0.2.9')), 'deny', 'active_deny_rule');
});

test('비동기 정책 조회 중 만료되면 조회 완료 뒤의 시각으로 pass를 판정한다', async () => {
  let current = NOW;
  const guard = create([rule()], {
    clock: () => current,
    async loadRules() {
      await Promise.resolve();
      current = NOW + 3600000;
      return snapshot([rule()]);
    },
  });
  result(await guard(ctx('192.0.2.9')), 'pass', 'no_active_deny_rule');
});

test('원격 출처 오류·XFF 목록·포트·호스트는 고정 unavailable로 끝난다', async () => {
  for (const source of [null, undefined, [], '192.0.2.9, 198.51.100.2', 'for=192.0.2.9', '192.0.2.9:443', 'example.test', ' 192.0.2.9']) {
    result(await create([], { resolveTrustedSource: () => source })(ctx('192.0.2.8')), 'unavailable', 'source_unavailable');
  }
  result(await create([], { resolveTrustedSource() { throw new Error('PRIVATE_ERROR_SENTINEL'); } })(ctx('192.0.2.8')), 'unavailable', 'source_unavailable');
});

test('loader·시계 실패 또는 잘못된 정책을 무시해 pass하지 않는다', async () => {
  for (const policy of [null, [], {}, { schema: 'wrong', rules: [] }, snapshot([{}]),
    snapshot([rule('not_an_ip')]), snapshot([{ ...rule(), evidenceAlertIds: [] }]),
    snapshot([{ ...rule(), expiresAt: '2026-02-31T00:00:00.000Z' }])]) {
    result(await create([], { loadRules: () => policy })(ctx('192.0.2.8')), 'unavailable', 'rules_unavailable');
  }
  result(await create([], { loadRules() { throw new Error('PRIVATE_ERROR_SENTINEL'); } })(ctx('192.0.2.8')), 'unavailable', 'rules_unavailable');
  for (const clock of [() => new Date(NaN), () => NaN, () => null, () => '2026-10-14T00:00:00.000Z', () => { throw new Error('PRIVATE_ERROR_SENTINEL'); }]) {
    result(await create([], { clock })(ctx('192.0.2.8')), 'unavailable', 'clock_unavailable');
  }
});

test('클라이언트 헤더·객체의 콜백이 정책을 고르지 못하고 앱 인스턴스는 분리된다', async () => {
  const blocked = create([rule()]), normal = create();
  const hostile = ctx('192.0.2.9');
  hostile.headers = { 'x-forwarded-for': '192.0.2.8', 'x-app-id': 'other-app', authorization: 'PRIVATE_TOKEN_SENTINEL' };
  hostile.loadRules = () => snapshot([]); hostile.clock = () => NOW + 99999999;
  hostile.resolveTrustedSource = () => '192.0.2.8';
  const originalFetch = globalThis.fetch; let fetched = 0;
  try {
    globalThis.fetch = () => { fetched += 1; throw new Error('unexpected_fetch'); };
    const denied = await blocked(hostile), passed = await normal(hostile);
    result(denied, 'deny', 'active_deny_rule'); result(passed, 'pass', 'no_active_deny_rule');
    const text = JSON.stringify([denied, passed]);
    assert.equal(/PRIVATE_|192\.0\.2|other-app|authorization/u.test(text), false);
    assert.equal(fetched, 0);
  } finally { globalThis.fetch = originalFetch; }
});
