import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { createNotesHandler, createAnnouncementHandler } from '../src/notes-api.mjs';

const config = {
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  publicAppUrl: 'https://student-defense.vercel.app',
  identityProvider: { issuer: 'https://student-project.supabase.co/auth/v1',
    audience: 'authenticated', jwksUrl: 'https://student-project.supabase.co/auth/v1/.well-known/jwks.json' },
};

function response() {
  return Object.assign(new EventEmitter(), {
    statusCode: 0, setHeader() {},
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; this.emit('finish'); return this; },
    end() { this.emit('finish'); return this; },
  });
}

// Only the database transport is substituted. The authentication verifier and
// resource handlers are the production exports; keys and tokens stay in memory.
function memoryDatabase(initialRows) {
  const rows = structuredClone(initialRows);
  let reads = 0;
  return { rows, get reads() { return reads; }, from(table) {
    assert.equal(table, 'notes');
    reads += 1;
    const filters = [];
    let patch;
    return {
      select() { return this; },
      eq(field, value) { filters.push([field, value]); return this; },
      update(value) { patch = value; return this; },
      async maybeSingle() {
        const row = rows.find(candidate => filters.every(([field, value]) => candidate[field] === value));
        if (row && patch) Object.assign(row, patch);
        return { data: row ? structuredClone(row) : null, error: null };
      },
      async order() {
        return { data: structuredClone(rows.filter(candidate => filters.every(([field, value]) => candidate[field] === value))), error: null };
      },
    };
  } };
}

async function fixture() {
  const pair = await generateKeyPair('ES256');
  const publicKey = await exportJWK(pair.publicKey);
  const judgeKeySet = createLocalJWKSet({ keys: [{ ...publicKey, kid: 'ephemeral', alg: 'ES256', use: 'sig' }] });
  const verify = createLoginVerifier({ config, judgeKeySet,
    supabaseClient: { auth: { getClaims: async () => ({ error: new Error('student_auth_not_used') }) } } });
  const a = randomUUID(), b = randomUUID(), run = randomUUID(), id = randomUUID();
  const db = memoryDatabase([{ note_id: id, owner_id: a, title: 'Synthetic note', content: 'Synthetic content' },
    { note_id: randomUUID(), owner_id: null, title: 'Legacy synthetic note', content: 'Legacy synthetic content' }]);
  const diagnostics = [];
  const services = () => ({ verify, db });
  const handler = createNotesHandler(services, line => diagnostics.push(JSON.parse(line)));
  const announcements = createAnnouncementHandler(services, line => diagnostics.push(JSON.parse(line)));
  async function authorization(identity, key = pair.privateKey) {
    const now = Math.floor(Date.now() / 1000);
    return `Bearer ${await new SignJWT({ iss: config.judgeIssuer, aud: 'student-defense.vercel.app',
      sub: identity === 'a' ? a : b, aleph_role: 'judge', aleph_identity: identity,
      aleph_run: run, iat: now, exp: now + 300 })
      .setProtectedHeader({ alg: 'ES256', kid: 'ephemeral' }).sign(key)}`;
  }
  const headers = { a: await authorization('a'), b: await authorization('b') };
  async function request(identity, method, body, token = headers[identity], path = `/api/notes/${id}`) {
    const res = response();
    await handler({ method, url: path, body, headers: { authorization: token } }, res,
      path === '/api/notes' ? undefined : id);
    return res;
  }
  return { a, b, id, db, diagnostics, verify, request, authorization, announcements, headers };
}

test('signed A/B identities remain distinct through verifier and API ownership checks', async () => {
  const f = await fixture();
  const a = await f.verify(f.headers.a), b = await f.verify(f.headers.b);
  assert.equal(a.kind, 'judge'); assert.equal(b.kind, 'judge');
  assert.equal(a.identity, 'a'); assert.equal(b.identity, 'b');
  assert.equal(a.userId, f.a); assert.equal(b.userId, f.b);
  assert.notEqual(a.userId, b.userId);
  assert.equal(a.runId, b.runId);
  assert.ok(Object.isFrozen(a)); assert.ok(Object.isFrozen(b));
  assert.equal((await f.request('a', 'GET')).statusCode, 200);
  assert.equal((await f.request('b', 'GET')).statusCode, 404);
  assert.equal((await f.request('a', 'PUT', { title: 'Updated synthetic note', body: 'Updated synthetic content', owner_id: f.b })).statusCode, 200);
  const beforeDeniedWrite = structuredClone(f.db.rows);
  assert.equal((await f.request('b', 'PUT', { title: 'Unauthorized synthetic write', body: 'Unauthorized synthetic content' })).statusCode, 404);
  assert.deepEqual(f.db.rows, beforeDeniedWrite);
  assert.equal(f.db.rows[0].owner_id, f.a);
  assert.equal(f.db.rows[1].owner_id, null);
  assert.equal((await f.request('a', 'GET')).body.title, 'Updated synthetic note');
});

test('forged judge signature is denied before any database query or mutation', async () => {
  const f = await fixture();
  const forgedPair = await generateKeyPair('ES256');
  const forged = await f.authorization('a', forgedPair.privateKey);
  const before = structuredClone(f.db.rows);
  assert.equal(await f.verify(forged), null);
  for (const method of ['GET', 'PUT']) {
    const res = await f.request('a', method, { title: 'Forged synthetic write', body: 'Forged synthetic content' }, forged);
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.error, 'AUTH_REQUIRED');
  }
  assert.equal(f.db.reads, 0);
  assert.deepEqual(f.db.rows, before);
  assert.ok(f.diagnostics.every(entry => entry.verifiedKind === 'none'));
});

test('signed identities see only owned collection records and cannot gain announcement authority', async () => {
  const f = await fixture();
  const a = await f.request('a', 'GET', undefined, undefined, '/api/notes');
  const b = await f.request('b', 'GET', undefined, undefined, '/api/notes');
  assert.equal(a.statusCode, 200); assert.equal(b.statusCode, 200);
  assert.deepEqual(a.body.notes.map(row => row.id), [f.id]);
  assert.deepEqual(b.body.notes, []);
  const before = structuredClone(f.db.rows);
  for (const identity of ['a', 'b']) {
    const res = response();
    await f.announcements({ method: 'PUT', url: `/api/announcements/${f.id}`,
      headers: { authorization: f.headers[identity] }, body: { role: 'instructor', title: 'Synthetic', body: 'Synthetic' } }, res);
    assert.equal(res.statusCode, 403);
    assert.equal(res.body.error, 'INSTRUCTOR_AUTHORITY_REQUIRED');
  }
  assert.deepEqual(f.db.rows, before);
  const diagnosticText = JSON.stringify(f.diagnostics);
  for (const privateValue of [f.a, f.b, f.id, f.headers.a, f.headers.b]) assert.equal(diagnosticText.includes(privateValue), false);
});
