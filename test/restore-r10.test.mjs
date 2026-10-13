import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { createNotesHandler } from '../src/notes-api.mjs';
import { createRestoreHandler } from '../src/restore-api.mjs';

const config = { judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  publicAppUrl: 'https://student-defense.vercel.app',
  identityProvider: { issuer: 'https://student-project.supabase.co/auth/v1', audience: 'authenticated',
    jwksUrl: 'https://student-project.supabase.co/auth/v1/.well-known/jwks.json' } };
const res = () => ({ setHeader() {}, status(code) { this.statusCode = code; return this; },
  json(body) { this.body = body; return this; } });

async function fixture() {
  const pair = await generateKeyPair('ES256'), other = await generateKeyPair('ES256');
  const publicKey = await exportJWK(pair.publicKey);
  const a = randomUUID(), b = randomUUID(), run = randomUUID(), id = randomUUID();
  const verify = createLoginVerifier({ config,
    judgeKeySet: createLocalJWKSet({ keys: [{ ...publicKey, kid: 'ephemeral', use: 'sig', alg: 'ES256' }] }),
    supabaseClient: { auth: { getClaims: async () => ({ error: new Error('student_auth_unused') }) } } });
  async function token(identity, key = pair.privateKey) {
    const now = Math.floor(Date.now() / 1000);
    return `Bearer ${await new SignJWT({ iss: config.judgeIssuer, aud: 'student-defense.vercel.app',
      sub: identity === 'a' ? a : b, aleph_identity: identity, aleph_run: run,
      aleph_role: 'judge', iat: now, exp: now + 300 }).setProtectedHeader({ alg: 'ES256', kid: 'ephemeral' }).sign(key)}`;
  }
  const calls = [], direct = [];
  let rpcResult;
  const db = {
    async rpc(name, args) { calls.push({ name, args }); return rpcResult ?? { data: { id: args.p_note_id, restored: true }, error: null }; },
    from(name) { assert.equal(name, 'notes'); return { async insert(row) { direct.push(row); return { error: null }; } }; },
  };
  const services = () => ({ db, verify });
  const notes = createNotesHandler(services, () => {}), restore = createRestoreHandler(services);
  const tokens = { a: await token('a'), b: await token('b'), forged: await token('b', other.privateKey) };
  async function request(handler, identity, body, method = 'POST', url = '/api/restore') {
    const result = res();
    await handler({ method, url, body, headers: { authorization: tokens[identity] } }, result);
    return result;
  }
  return { a, b, run, id, calls, direct, notes, restore, request, setResult(value) { rpcResult = value; } };
}

test('only signature-verified judge B creation uses atomic snapshot RPC', async () => {
  const f = await fixture();
  const body = { id: f.id, title: ' Synthetic ', body: 'Synthetic content', owner_id: f.a, runId: randomUUID() };
  assert.equal((await f.request(f.notes, 'b', body, 'POST', '/api/notes')).statusCode, 201);
  assert.deepEqual(f.calls, [{ name: 'stage10_create_judge_b_note', args: {
    p_run_id: f.run, p_owner_id: f.b, p_note_id: f.id, p_title: 'Synthetic', p_content: 'Synthetic content',
  } }]);
  assert.equal(f.direct.length, 0);
  assert.equal((await f.request(f.notes, 'a', body, 'POST', '/api/notes')).statusCode, 201);
  assert.equal(f.calls.length, 1);
  assert.equal(f.direct.length, 1); assert.equal(f.direct[0].owner_id, f.a);
  f.setResult({ error: { code: 'XX000' } });
  assert.equal((await f.request(f.notes, 'b', body, 'POST', '/api/notes')).statusCode, 500);
  assert.equal(f.direct.length, 1, 'snapshot failure must not fall back to unprotected direct insert');
});

test('restore derives owner/run only from signed B and rejects A, forged signature, invalid route/body', async () => {
  const f = await fixture();
  assert.equal((await f.request(f.restore, 'b', { id: f.id })).statusCode, 200);
  assert.deepEqual(f.calls, [{ name: 'stage10_restore_judge_b_note', args: {
    p_run_id: f.run, p_owner_id: f.b, p_note_id: f.id,
  } }]);
  for (const [identity, body, method, path, status] of [
    ['a', { id: f.id }, 'POST', '/api/restore', 403],
    ['forged', { id: f.id }, 'POST', '/api/restore', 401],
    ['b', { id: f.id, owner_id: f.a }, 'POST', '/api/restore', 400],
    ['b', { id: f.id, runId: randomUUID() }, 'POST', '/api/restore', 400],
    ['b', { id: '../notes' }, 'POST', '/api/restore', 400],
    ['b', [f.id], 'POST', '/api/restore', 400],
    ['b', { id: f.id }, 'GET', '/api/restore', 405],
    ['b', { id: f.id }, 'POST', '/api/restore?owner=forged', 403],
    ['b', { id: f.id }, 'POST', '/api/notes', 403],
  ]) assert.equal((await f.request(f.restore, identity, body, method, path)).statusCode, status);
  assert.equal(f.calls.length, 1);
});

test('restore exposes only fixed failure codes and requires an exact successful RPC result', async () => {
  const f = await fixture();
  for (const [code, status, error] of [['P0002', 404, 'BACKUP_NOT_FOUND'], ['23505', 409, 'RESTORE_CONFLICT'],
    ['22000', 503, 'RESTORE_UNAVAILABLE'], ['XX000', 503, 'RESTORE_UNAVAILABLE']]) {
    f.setResult({ error: { code, message: 'private database detail' } });
    const result = await f.request(f.restore, 'b', { id: f.id });
    assert.equal(result.statusCode, status); assert.deepEqual(result.body, { error });
  }
  for (const data of [null, { id: randomUUID(), restored: true }, { id: f.id, restored: false }]) {
    f.setResult({ data });
    assert.equal((await f.request(f.restore, 'b', { id: f.id })).statusCode, 503);
  }
});

test('student POST keeps original insertion path and student restore is denied', async () => {
  const owner = randomUUID(), id = randomUUID(), inserted = [];
  const services = () => ({ verify: async () => ({ kind: 'student', userId: owner }), db: {
    rpc() { throw new Error('student_must_not_call_recovery_rpc'); },
    from() { return { async insert(row) { inserted.push(row); return { error: null }; } }; },
  } });
  const created = res();
  await createNotesHandler(services, () => {})({ method: 'POST', url: '/api/notes',
    headers: {}, body: { id, title: 'Synthetic student note', body: 'Synthetic student content' } }, created);
  assert.equal(created.statusCode, 201); assert.equal(inserted.length, 1); assert.equal(inserted[0].owner_id, owner);
  const denied = res();
  await createRestoreHandler(services)({ method: 'POST', url: '/api/restore', headers: {}, body: { id } }, denied);
  assert.equal(denied.statusCode, 403);
});
