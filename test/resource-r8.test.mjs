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

test('가상 demo 자원은 서버 정책의 소유 주체만 허용하고 같은 경로의 다른 주체를 거부한다', async () => {
  const { normal, suspicious } = fixtureRequests();
  assert.equal((await decide(normal)).decision, 'allow');
  assert.equal((await decide(suspicious)).decision, 'step_up');
  for (const subjectId of ['other_fixture', 'learner_fixture_other', '', undefined]) {
    const request = { ...normal, subjectId };
    const before = structuredClone(request);
    assert.deepEqual(await decide(request), {
      schema: 'aleph.decision.v1', requestId: request.requestId,
      decision: 'deny', reasonCode: 'policy_denied',
      ruleIds: ['device_registered', 'resource_scope'],
    });
    assert.deepEqual(request, before);
  }
  // Additional verification does not confer ownership of another fixture zone.
  assert.equal((await decide({ ...suspicious, subjectId: 'other_fixture',
    stepUp: { verified: true, authAgeSeconds: 60 } })).decision, 'deny');
  // Risk-signal provenance cannot change the server-defined resource ownership.
  assert.equal((await decide({ ...normal, signals: { ...normal.signals, source: 'none' } })).decision, 'allow');
  assert.equal((await decide({ ...normal, subjectId: 'other_fixture',
    signals: { ...normal.signals, source: 'none' } })).decision, 'deny');
  const unregistered = await decide({ ...normal, subjectId: 'other_fixture', deviceRegistered: false });
  assert.equal(unregistered.reasonCode, 'device_not_registered');
});

test('판정기는 정확 경로/method/구역을 검사하고 기능 경로와 쿼리를 거부한다', async () => {
  const { normal } = fixtureRequests();
  for (const [method, path, route] of [
    ['POST', '/api/notes', 'POST /api/notes'],
  ]) assert.equal((await decide({ ...normal, method, path, route })).decision, 'allow');
  for (const request of [
    { ...normal, path: '/api/notes', route: 'GET /api/notes' },
    { ...normal, path: '/api/notes/export', route: 'GET /api/notes/:id' },
    { ...normal, path: '/api/notes/unknown', route: 'GET /api/notes/:id' },
    { ...normal, path: '/api/notes', route: 'PUT /api/notes' },
    { ...normal, path: '/api/notes', route: 'GET /api/notes', queryLength: 14 },
    { ...normal, method: 'PUT', path: `/api/announcements/${noteId}`, route: 'PUT /api/announcements/:id', role: 'instructor' },
    { ...normal, path: `/api/notes/${noteId}/export`, route: 'GET /api/notes/:id' },
  ]) assert.equal((await decide(request)).decision, 'deny');
});

test('엔진과 배포 경로의 UUID 자원은 소유권 연결 없으면 거부하고 정확 route만 지원한다', async () => {
  const { normal } = fixtureRequests();
  for (const prefix of ['/notes', '/api/notes']) {
    for (const subjectId of ['learner_fixture', 'other_fixture']) {
      for (const method of ['GET', 'PUT', 'DELETE']) {
        const request = { ...normal, subjectId, method, path: `${prefix}/${noteId}`,
          route: `${method} ${prefix}/:id`, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 14 } };
        assert.equal((await decide(request)).decision, 'deny');
        const otherPrefix = prefix === '/notes' ? '/api/notes' : '/notes';
        assert.equal((await decide({ ...request, route: `${method} ${otherPrefix}/:id` })).decision, 'deny');
      }
    }
    for (const method of ['GET', 'POST']) {
      assert.equal((await decide({ ...normal, path: prefix, method, route: `${method} ${prefix}` })).decision, method === 'GET' ? 'deny' : 'allow');
    }
    for (const path of [`${prefix}/export`, `${prefix}/${noteId}/export`, `${prefix}/unknown`, `${prefix}?action=export`]) {
      assert.equal((await decide({ ...normal, path, route: `GET ${prefix}/:id` })).decision, 'deny');
    }
  }
});

test('엔진의 미확인 UUID 거부와 API 소유자 필터를 각각 확인한다', async () => {
  const { normal } = fixtureRequests();
  for (const prefix of ['/notes', '/api/notes']) {
    const db = database();
    let userId = 'student_a';
    const handler = createNotesHandler(() => ({ db, verify: async () => ({ kind: 'student', deviceRegistered: true, userId }) }));
    for (const [subjectId, verifiedUser, expectedStatus] of [
      ['engine_pseudonym_a', 'student_a', 200], ['engine_pseudonym_b', 'student_b', 404],
    ]) {
      userId = verifiedUser;
      for (const method of ['GET', 'PUT']) {
        // An engine pseudonym and a JWT user ID are separate trusted inputs, not compared to each other.
        const admission = await decide({ ...normal, subjectId, method,
          path: `${prefix}/${noteId}`, route: `${method} ${prefix}/:id` });
        // Unknown UUID owner binding must not be interpreted as authorized by the engine.
        assert.equal(admission.decision, 'deny');
        const before = structuredClone(db.row);
        const res = response();
        await handler({ url: `/api/notes/${noteId}`, method, headers: {},
          body: { title: verifiedUser === 'student_a' ? 'owner_update' : 'forbidden_update', body: 'fixture', owner_id: 'student_a', role: 'instructor' } }, res, noteId);
        assert.equal(res.statusCode, expectedStatus);
        if (verifiedUser === 'student_b') assert.deepEqual(db.row, before);
        else assert.equal(db.row.owner_id, 'student_a');
      }
    }
  }
});

test('API에서 A의 자기 메모 읽기/수정은 허용하고 B의 A 메모 읽기/수정은 거부한다', async () => {
  const db = database();
  let current = 'student_a';
  const handler = createNotesHandler(() => ({ db, verify: async () => ({ kind: 'student', deviceRegistered: true, userId: current }) }));
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
  const getServices = () => ({ db: database(), verify: async () => ({ kind: 'student', deviceRegistered: true, userId: 'student_a' }) });
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

test('DB가 잘못된 소유자나 ID의 행을 돌려줘도 단건을 내보내지 않는다', async () => {
  for (const row of [
    { note_id: noteId, owner_id: 'student_b' },
    { note_id: noteId },
    { note_id: '22222222-2222-4222-8222-222222222222', owner_id: 'student_a' },
  ]) {
    const db = { from() { return { select() { return this; }, eq() { return this; }, update() { return this; },
      async maybeSingle() { return { data: {...row, title:'fixture', content:'fixture'}, error:null }; } }; } };
    const handler = createNotesHandler(() => ({ db, verify: async () => ({kind:'student',deviceRegistered:true,userId:'student_a'}) }));
    for (const method of ['GET','PUT']) {
      const res = response();
      await handler({url:`/api/notes/${noteId}`, method, headers:{}, body:{title:'fixture',body:'fixture'}},res,noteId);
      assert.equal(res.statusCode,404);
      assert.equal(res.data.error,'NOTE_NOT_FOUND');
    }
  }
});

test('목록은 반환 소유자를 재검사하고 응답에서 소유자를 제외한다', async () => {
  const rows = [
    {note_id:noteId,owner_id:'student_a',title:'fixture',content:'fixture'},
    {note_id:noteId,owner_id:'student_b',title:'other',content:'other'},
    {note_id:noteId,title:'missing',content:'missing'},
  ];
  const db = {from(){return {select(){return this;},eq(){return this;},async order(){return {data:rows,error:null};}};}};
  const handler=createNotesHandler(()=>({db,verify:async()=>({kind:'student',deviceRegistered:true,userId:'student_a'})}));
  const res=response(); await handler({url:'/api/notes',method:'GET',headers:{}},res);
  assert.equal(res.statusCode,200); assert.equal(res.data.notes.length,1);
  assert.deepEqual(Object.keys(res.data.notes[0]).sort(),['body','id','title']);
});

test('대문자 UUID 요청도 저장된 소문자 UUID와 같은 자료로 대조한다', async () => {
  const canonical = 'abcdefab-abcd-4abc-8abc-abcdefabcdef';
  const db={from(){return {select(){return this;},eq(){return this;},async maybeSingle(){return {data:{note_id:canonical,owner_id:'student_a',title:'fixture',content:'fixture'},error:null};}};}};
  const handler=createNotesHandler(()=>({db,verify:async()=>({kind:'student',deviceRegistered:true,userId:'student_a'})}));
  const res=response(); await handler({url:`/api/notes/${canonical.toUpperCase()}`,method:'GET',headers:{}},res,canonical.toUpperCase());
  assert.equal(res.statusCode,200); assert.equal(res.data.id,canonical);
});
