import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

const productionEnv = {
  ...env, VERCEL_ENV: 'production',
  VERCEL_PROJECT_PRODUCTION_URL: 'student-defense.vercel.app',
};

test('production uses only its system hostname matched by the configured HTTPS root', () => {
  for (const publicAppUrl of [config.publicAppUrl, `${config.publicAppUrl}/`]) {
    const manifest = deploymentIdentity(productionEnv, { ...config, publicAppUrl });
    assert.equal(manifest.publicAppUrl, config.publicAppUrl);
    assert.equal(manifest.commit, env.VERCEL_GIT_COMMIT_SHA);
    assert.equal(manifest.repoUrl, 'https://github.com/student-a/aleph-defense');
  }
});

test('preview retains its unique deployment even when production information exists', () => {
  for (const VERCEL_ENV of ['preview', 'development', undefined]) {
    const manifest = deploymentIdentity({ ...productionEnv, VERCEL_ENV }, config);
    assert.equal(manifest.publicAppUrl, `https://${env.VERCEL_URL}`);
  }
});

test('legacy production without a system production hostname keeps its unique URL', () => {
  assert.equal(deploymentIdentity({ ...env, VERCEL_ENV: 'production' }, config).publicAppUrl,
    `https://${env.VERCEL_URL}`);
});

test('production rejects malformed system hosts and mismatched or decorated configured URLs', () => {
  for (const VERCEL_PROJECT_PRODUCTION_URL of [
    '', null, 'https://student-defense.vercel.app', 'student-defense.vercel.app/path',
    'student-defense.vercel.app:443', 'student-defense.vercel.app?x=1',
    'student-defense.vercel.app#fragment', 'user:password@student-defense.vercel.app',
    'external.example', 'student-defense.vercel.app.evil.example',
    ' student-defense.vercel.app', 'student-defense.vercel.app\n',
  ]) assert.throws(() => deploymentIdentity({ ...productionEnv, VERCEL_PROJECT_PRODUCTION_URL }, config));
  for (const publicAppUrl of [
    undefined, 'https://another-project.vercel.app', 'http://student-defense.vercel.app',
    'https://student-defense.vercel.app:443', 'https://student-defense.vercel.app/path',
    'https://student-defense.vercel.app?x=1', 'https://student-defense.vercel.app/#fragment',
    'https://user:password@student-defense.vercel.app', ' https://student-defense.vercel.app',
  ]) assert.throws(() => deploymentIdentity(productionEnv, { ...config, publicAppUrl }));
});

test('canonical production does not bypass Git or unique deployment validation', () => {
  for (const override of [
    { VERCEL_GIT_PROVIDER: undefined }, { VERCEL_GIT_REPO_OWNER: 'invalid/owner' },
    { VERCEL_GIT_REPO_SLUG: '..' }, { VERCEL_GIT_COMMIT_SHA: 'short' },
    { VERCEL_URL: undefined }, { VERCEL_URL: 'external.example' },
  ]) assert.throws(() => deploymentIdentity({ ...productionEnv, ...override }, config));
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
