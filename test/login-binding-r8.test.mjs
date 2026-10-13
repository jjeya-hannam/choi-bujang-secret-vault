import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { createLoginVerifier } from '../src/verify-login.mjs';

const config = {
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  publicAppUrl: 'https://student-defense.vercel.app',
  identityProvider: { issuer: 'https://student-project.supabase.co/auth/v1',
    audience: 'authenticated',
    jwksUrl: 'https://student-project.supabase.co/auth/v1/.well-known/jwks.json' },
};
const deploymentHostname = 'student-defense-current.vercel.app';
const pair = await generateKeyPair('ES256');
const publicKey = await exportJWK(pair.publicKey);
const judgeKeySet = createLocalJWKSet({ keys: [{ ...publicKey, kid: 'fixture', alg: 'ES256', use: 'sig' }] });
const supabaseClient = { auth: { getClaims: async () => ({ error: new Error('not_a_student_token') }) } };

async function authorization(audience, overrides = {}, signingKey = pair.privateKey) {
  // Ephemeral keys and tokens stay in memory and are never printed or saved.
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ iss: config.judgeIssuer, aud: audience,
    sub: randomUUID(), iat: now, exp: now + 300,
    aleph_role: 'judge', aleph_identity: 'a', aleph_run: randomUUID(), ...overrides })
    .setProtectedHeader({ alg: 'ES256', kid: 'fixture' }).sign(signingKey);
  return `Bearer ${token}`;
}

test('설정 별칭과 서버가 확인한 현재 배포 대상만 허용한다', async () => {
  const verify = createLoginVerifier({ config, deploymentHostname, judgeKeySet, supabaseClient });
  for (const host of ['student-defense.vercel.app', deploymentHostname]) {
    assert.equal((await verify(await authorization(host))).kind, 'judge');
  }
  for (const host of ['student-defense-old.vercel.app', 'another-project.vercel.app', 'external.example',
    [deploymentHostname], `https://${deploymentHostname}`]) {
    assert.equal(await verify(await authorization(host)), null);
  }
});

test('대상 주소 추가가 서명·발급자·역할·만료 검사를 우회하지 않는다', async () => {
  const verify = createLoginVerifier({ config, deploymentHostname, judgeKeySet, supabaseClient });
  const other = await generateKeyPair('ES256');
  assert.equal(await verify(await authorization(deploymentHostname, {}, other.privateKey)), null);
  for (const overrides of [
    { iss: 'https://another-issuer.example/defense/judge' },
    { aleph_role: 'student' }, { aleph_identity: 'instructor' }, { aleph_run: 'invalid' },
    { exp: Math.floor(Date.now() / 1000) - 60 },
  ]) assert.equal(await verify(await authorization(deploymentHostname, overrides)), null);
});

test('서버 배포 정보가 없으면 별칭만 허용하고 잘못된 서버 호스트는 설정 오류다', async () => {
  const verify = createLoginVerifier({ config, judgeKeySet, supabaseClient });
  assert.equal(await verify(await authorization(deploymentHostname)), null);
  for (const host of ['https://student-defense.vercel.app', 'evil.example', 'student-defense.vercel.app/other', '']) {
    assert.throws(() => createLoginVerifier({ config, deploymentHostname: host, judgeKeySet, supabaseClient }));
  }
});

test('인증 실패 진단에는 고정 사유 코드만 전달한다', async () => {
  const messages = [];
  const verify = createLoginVerifier({ config, judgeKeySet, supabaseClient, onReject: code => messages.push(code) });
  assert.equal(await verify(await authorization(deploymentHostname)), null);
  assert.deepEqual(messages, ['judge_audience_rejected']);
});
