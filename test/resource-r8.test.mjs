import test from 'node:test';
import assert from 'node:assert/strict';
import { decide } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { createNotesHandler, createAnnouncementHandler } from '../src/notes-api.mjs';
import { RESOURCE_IDS } from '../src/resource-policy.mjs';

const noteId = '11111111-1111-4111-8111-111111111111';
function response() {
  return { statusCode: 0, data: null, setHeader() {}, status(code) { this.statusCode = code; return this; },
    json(data) { this.data = data; return this; }, end() { return this; } };
}
function database() {
  const row = { note_id: noteId, owner_id: 'student_a', title: 'fixture', content: 'fixture' };
  return { row, from(table) {
    assert.equal(table, 'notes');
    const filters = [];
    let update;
    return { select() { return this; }, eq(key, value) { filters.push([key, value]); return this; },
      update(fields) { update = fields; return this; },
      async maybeSingle() {
        const found = filters.every(([key, value]) => row[key] === value);
        if (found && update) Object.assign(row, update);
        return { data: found ? row : null, error: null };
      } };
  } };
}

test('메모와 강사 공지의 자원 ID는 다르다', () => assert.notEqual(RESOURCE_IDS.notes, RESOURCE_IDS.announcements));

test('판정기는 정확 경로/method/구역을 검사하고 기능 경로와 쿼리를 거부한다', async () => {
  const { normal } = fixtureRequests();
  for (const [method, path, route] of [
    ['GET', '/api/notes', 'GET /api/notes'], ['POST', '/api/notes', 'POST /api/notes'],
    ['GET', `/api/notes/${noteId}`, 'GET /api/notes/:id'], ['PUT', `/api/notes/${noteId}`, 'PUT /api/notes/:id'],
  ]) assert.equal((await decide({ ...normal, method, path, route })).decision, 'allow');
  for (const request of [
    { ...normal, path: '/api/notes/export', route: 'GET /api/notes/:id' },
    { ...normal, path: '/api/notes/unknown', route: 'GET /api/notes/:id' },
    { ...normal, path: '/api/notes', route: 'PUT /api/notes' },
    { ...normal, path: '/api/notes', route: 'GET /api/notes', queryLength: 14 },
    { ...normal, method: 'PUT', path: `/api/announcements/${noteId}`, route: 'PUT /api/announcements/:id', role: 'instructor' },
    { ...normal, path: `/api/notes/${noteId}/export`, route: 'GET /api/notes/:id' },
  ]) assert.equal((await decide(request)).decision, 'deny');
});

test('API에서 A의 자기 메모 읽기/수정은 허용하고 B의 A 메모 읽기/수정은 거부한다', async () => {
  const db = database();
  let current = 'student_a';
  const handler = createNotesHandler(() => ({ db, verify: async () => ({ kind: 'student', userId: current }) }));
  for (const method of ['GET', 'PUT']) {
    const res = response();
    await handler({ url: `/api/notes/${noteId}`, method, headers: {}, body: { title: 'updated', body: 'fixture', owner_id: 'student_b', role: 'instructor' } }, res, noteId);
    assert.equal(res.statusCode, 200);
    assert.equal(db.row.owner_id, 'student_a');
  }
  current = 'student_b';
  for (const method of ['GET', 'PUT']) {
    const res = response();
    await handler({ url: `/api/notes/${noteId}`, method, headers: {}, body: { title: 'stolen', body: 'fixture', owner_id: 'student_a', role: 'instructor' } }, res, noteId);
    assert.equal(res.statusCode, 404);
  }
  assert.equal(db.row.title, 'updated');
});

test('API에서 body role 공지 수정·쿼리 기능·export 별칭을 거부한다', async () => {
  const getServices = () => ({ db: database(), verify: async () => ({ kind: 'student', userId: 'student_a' }) });
  const announcement = createAnnouncementHandler(getServices);
  const res = response();
  await announcement({ url: `/api/announcements/${noteId}`, method: 'PUT', headers: { 'x-role': 'instructor' }, body: { role: 'instructor' } }, res);
  assert.equal(res.statusCode, 403);
  assert.equal(res.data.error, 'INSTRUCTOR_AUTHORITY_REQUIRED');
  const notes = createNotesHandler(getServices);
  for (const url of [`/api/notes/${noteId}?action=export`, '/api/notes/export', `/api/notes/${noteId}/export`]) {
    const denied = response();
    await notes({ url, method: 'GET', headers: {} }, denied, noteId);
    assert.equal(denied.statusCode, 403);
  }
});
