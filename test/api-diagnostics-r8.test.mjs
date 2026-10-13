import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createNotesHandler, createAnnouncementHandler } from '../src/notes-api.mjs';

const id = '11111111-1111-4111-8111-111111111111';
const response = () => Object.assign(new EventEmitter(), {
  statusCode: 0, setHeader() {}, status(code) { this.statusCode = code; return this; },
  json(body) { this.body = body; this.emit('finish'); return this; }, end() { this.emit('finish'); return this; },
});
const dbWith = row => ({ from() { return { select() { return this; }, eq() { return this; },
  async maybeSingle() { return { data: row, error: null }; } }; } });
const request = (method = 'GET', resource = 'notes') => ({
  method, url: `/api/${resource}/${id}`, headers: { authorization: 'private fixture authorization', 'x-user': 'private fixture user' },
  body: { role: 'instructor', body: 'private fixture body' },
});

for (const [name, identity, row, status, kind, judgeLabel] of [
  ['허용', { kind: 'judge', identity: 'a', userId: 'private fixture user', runId: 'private fixture run' },
    { note_id: id, owner_id: 'private fixture user', title: 'private title', content: 'private body' }, 200, 'judge', 'a'],
  ['소유자 거부', { kind: 'judge', identity: 'b', userId: 'private fixture user' }, null, 404, 'judge', 'b'],
  ['인증 거부', null, null, 401, 'none', undefined],
  ['승인된 학생 소유자 거부', { kind: 'student', identity: 'a', userId: 'private fixture user', deviceRegistered: true }, null, 404, 'student', undefined],
  ['미승인 학생 기기 거부', { kind: 'student', userId: 'private fixture user' }, null, 403, 'student', undefined],
  ['알 수 없는 신원 종류', { kind: 'untrusted-kind', identity: 'a', userId: 'private fixture user' }, null, 401, 'none', undefined],
  ['알 수 없는 심판 라벨', { kind: 'judge', identity: 'private fixture label', userId: 'private fixture user' }, null, 401, 'judge', undefined],
]) {
  test(`finish 진단 ${name}: 상태·검증 enum만 기록`, async () => {
    const entries = [];
    const handler = createNotesHandler(() => ({ verify: async () => identity, db: dbWith(row) }), line => entries.push(JSON.parse(line)));
    const res = response();
    await handler(request(), res, id);
    assert.equal(res.statusCode, status);
    const expected = { event: 'notes_response', method: 'GET', resource: 'notes_item', status, verifiedKind: kind };
    if (judgeLabel !== undefined) expected.syntheticJudgeIdentity = judgeLabel;
    assert.deepEqual(entries, [expected]);
    res.emit('finish');
    assert.equal(entries.length, 1);
    assert.doesNotMatch(JSON.stringify(entries), /private|11111111|authorization|userId|runId|title|body|\/api/u);
  });
}

test('공지 finish 진단과 진단 함수 예외는 응답을 바꾸지 않는다', async () => {
  const entries = [];
  const services = () => ({ verify: async () => ({ kind: 'judge', identity: 'b', userId: 'private fixture user' }) });
  const handler = createAnnouncementHandler(services, line => entries.push(JSON.parse(line)));
  const res = response();
  await handler(request('PUT', 'announcements'), res);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(entries, [{ event: 'notes_response', method: 'PUT', resource: 'announcement_item', status: 403, verifiedKind: 'judge', syntheticJudgeIdentity: 'b' }]);
  const throwing = createAnnouncementHandler(services, () => { throw new Error('diagnostic failure'); });
  const denied = response();
  await throwing(request('PUT', 'announcements'), denied);
  assert.equal(denied.statusCode, 403);
  assert.equal(denied.body.error, 'INSTRUCTOR_AUTHORITY_REQUIRED');
  const notesThrowing = createNotesHandler(() => ({ verify: async () => null }), () => { throw new Error('diagnostic failure'); });
  const unauthenticated = response();
  await notesThrowing(request(), unauthenticated, id);
  assert.equal(unauthenticated.statusCode, 401);
});

test('finish 지원 없는 mock과 알려지지 않은 method/resource는 진단 실패 없이 처리', async () => {
  const entries = [];
  const handler = createNotesHandler(() => ({ verify: async () => null }), line => entries.push(JSON.parse(line)));
  const noEvents = { setHeader() {}, status(code) { this.statusCode = code; return this; }, json() { return this; } };
  await handler(request(), noEvents, id);
  assert.equal(noEvents.statusCode, 401);
  assert.equal(entries.length, 0);
  const res = response();
  await handler({ ...request(), method: 'private-method', url: '/private-path' }, res, id);
  assert.deepEqual(entries, [{ event: 'notes_response', method: 'OTHER', resource: 'unknown', status: 401, verifiedKind: 'none' }]);
});
