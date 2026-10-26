import test from 'node:test';
import assert from 'node:assert/strict';
import { createPcPanel, validatePcStatus } from '../student/pc-view.mjs';
class Element {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attributes = {}; this.listeners = {}; this._text = ''; this.isConnected = true; this.disabled = false; }
  set textContent(text) { this._text = String(text); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { throw Error('HTML sink'); }
  appendChild(node) { this.children.push(node); return node; }
  replaceChildren(...nodes) { this._text = ''; this.children = nodes; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  async fire(name) { if (!this.disabled) return this.listeners[name]?.(); }
}
globalThis.document = { createElement: tag => new Element(tag) };
const walk = node => [node, ...node.children.flatMap(walk)];
const at = '2026-10-26T01:02:03.000Z';
function fixture() {
  const metric = (unit, observed) => ({ status: 'observed', code: 'OK', unit, checkedAt: at, observed });
  return { ok: true, data: { schema: 'student.pc-status.v1', source: 'local_pc', checkedAt: at, platform: 'darwin',
    cpu: metric('percent', 12.5), memory: metric('bytes', { total: 8 * 1024 ** 3, free: 3 * 1024 ** 3 }), disk: metric('bytes', { total: 100 * 1024 ** 3, free: 40 * 1024 ** 3 }), network: metric('count', { interfaces: 2 }),
    firewall: { status: 'unknown', code: 'UNSUPPORTED_PLATFORM', checkedAt: at, unit: 'profiles', observed: null }, eventLogs: { status: 'unknown', code: 'UNSUPPORTED_PLATFORM', checkedAt: at, unit: 'count', observed: null } } };
}
const response = data => ({ ok: true, status: 200, json: async () => data });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
test('PC panel only fetches after explicit read, labels numeric source, units and unknowns', async () => {
  const calls = []; const panel = createPcPanel({ fetcher: async (...args) => { calls.push(args); return response(fixture()); } });
  assert.equal(calls.length, 0); assert.ok(!panel.element.textContent.includes('12.5'));
  await panel.refresh(); assert.equal(calls.length, 1);
  assert.equal(calls[0][0], '/api/student/pc-status'); assert.equal(calls[0][1].headers['x-student-pc-read'], '1'); assert.equal(calls[0][1].credentials, 'same-origin'); assert.equal(calls[0][1].cache, 'no-store');
  const text = panel.element.textContent;
  for (const value of ['12.5 %', '5.00 GiB', '40.00 GiB', '2개', at, '확인 불가', '공격 탐지 결과가 아닙니다', 'SDP']) assert.ok(text.includes(value), value);
  const cards = walk(panel.element).filter(n => n.getAttribute('data-student-pc-card'));
  assert.equal(cards.length, 4); assert.ok(walk(panel.element).every(n => n.getAttribute('style') === null));
});
test('failures remove current values, keep only labeled history and never echo error data', async () => {
  let fail = false; const panel = createPcPanel({ fetcher: async () => { if (fail) throw Error('private@example.test'); return response(fixture()); } });
  await panel.refresh(); fail = true; await panel.refresh();
  assert.ok(!walk(panel.element).some(n => n.getAttribute('data-student-pc-card')));
  assert.match(panel.element.textContent, /확인 불가/); assert.match(panel.element.textContent, /이력 · 현재 상태가 아님/);
  assert.ok(!panel.element.textContent.includes('private@example.test'));
});
test('removed root, host generation change and cancellation discard late observations', async () => {
  for (const method of ['removed', 'host', 'cancel']) {
    const pending = deferred(); let current = true; const history = [];
    const panel = createPcPanel({ fetcher: () => pending.promise, history, isCurrent: () => current });
    const wait = panel.refresh();
    if (method === 'removed') panel.element.isConnected = false;
    else if (method === 'host') current = false;
    else panel.cancel();
    pending.resolve(response(fixture())); await wait;
    assert.equal(history.length, 0); assert.ok(!panel.element.textContent.includes('12.5 %'));
  }
});
test('pending reads disable repeated requests and timeout even if fetch ignores abort', async () => {
  let count = 0; const panel = createPcPanel({ fetcher: () => { count++; return new Promise(() => {}); }, timeoutMs: 5 });
  const wait = panel.refresh(); await panel.refresh();
  assert.equal(walk(panel.element).find(n => n.textContent === '내 PC 상태 다시 조회').disabled, true);
  await wait; assert.equal(count, 1); assert.match(panel.element.textContent, /시간이 초과/);
  assert.equal(walk(panel.element).find(n => n.textContent === '내 PC 상태 다시 조회').disabled, false);
});
test('history retains at most eight validated observations and no invented missing values', async () => {
  const history = []; const panel = createPcPanel({ fetcher: async () => response(fixture()), history });
  for (let i = 0; i < 10; i++) await panel.refresh();
  assert.equal(history.length, 8); assert.match(panel.element.textContent, /최대 8회/);
  assert.ok(history.every(row => row.checkedAt === at));
});
test('schema, units, source, range and unknown reasons are checked without string reflection', async () => {
  const variants = [];
  for (const mutate of [d => d.source = 'demo', d => d.cpu.unit = 'bytes', d => d.cpu.observed = 101, d => d.memory.observed.free = d.memory.observed.total + 1, d => d.network.observed.interfaces = -1, d => d.firewall.code = '<img onerror=x>', d => d.checkedAt = 'secret@example.test']) { const value = fixture(); mutate(value.data); variants.push(value); }
  for (const value of variants) { assert.equal(validatePcStatus(value), null); const panel = createPcPanel({ fetcher: async () => response(value) }); await panel.refresh(); assert.match(panel.element.textContent, /형식이나 측정 단위/); assert.ok(!panel.element.textContent.includes('secret@example.test')); assert.ok(!panel.element.textContent.includes('<img')); }
  const value = fixture(); value.data.cpu.rawCommand = 'do-not-reflect'; const captured = validatePcStatus(value); assert.ok(captured); assert.ok(!JSON.stringify(captured).includes('do-not-reflect'));
});
test('old original host 404 is an explicit unavailable state without synthetic readings', async () => {
  const panel = createPcPanel({ fetcher: async () => ({ ok: false, status: 404 }) }); await panel.refresh();
  assert.match(panel.element.textContent, /학생 PC 실행기/); assert.match(panel.element.textContent, /확인 불가/); assert.ok(!panel.element.textContent.includes('12.5 %'));
});
test('Windows event totals have a fixed period and explicit non-detection explanation', async () => {
  const value = fixture(); value.data.platform = 'win32'; value.data.eventLogs = { status: 'observed', code: 'OK', checkedAt: at, unit: 'count', observed: { system: 3, application: 5, windowHours: 24 } };
  const panel = createPcPanel({ fetcher: async () => response(value) }); await panel.refresh();
  assert.match(panel.element.textContent, /System 3건 \/ Application 5건 · 최근 24시간 경고·오류 합계/); assert.match(panel.element.textContent, /침해나 공격 탐지 결과가 아닙니다/);
});
