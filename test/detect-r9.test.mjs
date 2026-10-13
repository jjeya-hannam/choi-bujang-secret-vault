import test from 'node:test';
import assert from 'node:assert/strict';
import { detect } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1);
const SUBJECT = 'learner_fixture';
const observe = { action: 'observe' };
const revoke = subject => ({ action: 'propose_revocation', reasonCode: 'burst_read', subject });
const event = (offset, subject = SUBJECT, method = 'GET') => ({
  at: new Date(START + offset).toISOString(), method, identity: { sub: subject },
});
const reads = (count, subject = SUBJECT, offset = 0, interval = 1) =>
  Array.from({ length: count }, (_, index) => event(offset + index * interval, subject));

test('9단계 빈 사건과 정확 120건은 observe이며 121건부터 회수 제안한다', () => {
  assert.deepEqual(detect([]), observe);
  assert.deepEqual(detect(reads(120)), observe);
  assert.deepEqual(detect(reads(121)), revoke(SUBJECT));
});

test('10분 양끝을 포함하고 1ms를 초과한 앞 사건은 제외한다', () => {
  const middle = Array.from({ length: 119 }, (_, index) => event((index + 1) * 5000));
  assert.deepEqual(detect([event(0), ...middle, event(600000)]), revoke(SUBJECT));
  assert.deepEqual(detect([event(0), ...middle, event(600001)]), observe);
});

test('고정 시간 칸이 아닌 임의의 연속 10분 구간을 탐지한다', () => {
  assert.deepEqual(detect(reads(121, SUBJECT, 590000, 1000)), revoke(SUBJECT));
  assert.deepEqual(detect(reads(200, SUBJECT, 0, 7000)), observe);
});

test('첫 구간 밖에 있어도 뒤의 폭주 구간을 탐지한다', () => {
  assert.deepEqual(detect([event(0), ...reads(121, SUBJECT, 900000, 1000)]), revoke(SUBJECT));
});

test('정렬되지 않은 입력과 동일 시각 사건도 정확히 세며 입력을 바꾸지 않는다', () => {
  const unsorted = reads(121, SUBJECT, 0, 1000).reverse();
  const original = structuredClone(unsorted);
  for (const row of unsorted) { Object.freeze(row.identity); Object.freeze(row); }
  Object.freeze(unsorted);
  assert.deepEqual(detect(unsorted), revoke(SUBJECT));
  assert.deepEqual(unsorted, original);
  assert.deepEqual(detect(reads(121, SUBJECT, 0, 0)), revoke(SUBJECT));
});

test('다른 주체를 합산하지 않고 실제 폭주한 주체를 돌려준다', () => {
  assert.deepEqual(detect([...reads(100), ...reads(100, 'other_fixture')]), observe);
  assert.deepEqual(detect([...reads(120), ...reads(121, 'other_fixture')]), revoke('other_fixture'));
});

test('GET 외 요청과 소문자 get은 조회 건수에 넣지 않는다', () => {
  const others = ['POST', 'PUT', 'DELETE', 'HEAD', 'get'].flatMap(method =>
    reads(121).map(row => ({ ...row, method })));
  assert.deepEqual(detect(others), observe);
  assert.deepEqual(detect([...reads(120), ...others]), observe);
});

test('깨진 행은 카운트하지 않고 유효 사건의 회수 제안을 방해하지 않는다', () => {
  const invalid = [null, undefined, {}, [], 'event',
    { at: 'invalid', method: 'GET', identity: { sub: SUBJECT } },
    { at: 0, method: 'GET', identity: { sub: SUBJECT } },
    { at: new Date(START).toISOString(), method: 'GET', identity: null },
    { at: new Date(START).toISOString(), method: 'GET', identity: {} },
    { at: new Date(START).toISOString(), method: 'GET', identity: { sub: '' } },
    { at: new Date(START).toISOString(), method: 'GET', identity: { sub: 1 } },
  ];
  assert.deepEqual(detect(invalid), observe);
  assert.deepEqual(detect([...reads(120), ...invalid]), observe);
  assert.deepEqual(detect([...invalid, ...reads(121)]), revoke(SUBJECT));
});

test('비배열 인자는 기존의 명시적인 TypeError를 유지한다', () => {
  for (const input of [undefined, null, {}, 'events', 121]) {
    assert.throws(() => detect(input), { name: 'TypeError', message: 'invalid_detection_events' });
  }
});

test('관찰 결과는 한 키, 회수 제안은 세 키이며 사건 자료를 담지 않는다', () => {
  assert.deepEqual(Object.keys(detect(reads(120))).sort(), ['action']);
  assert.deepEqual(Object.keys(detect(reads(121))).sort(), ['action', 'reasonCode', 'subject']);
});
