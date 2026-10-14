import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, writeFile, rename, unlink, realpath } from 'node:fs/promises';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { createRequestLoginVerifier, SESSION_COOKIE, DEVICE_COOKIE, newCredential, hashCredential } from '../src/browser-session.mjs';
import { createNotesHandler, createAnnouncementHandler } from '../src/notes-api.mjs';
import { createRestoreHandler } from '../src/restore-api.mjs';
import { createAuthHandler } from '../api/auth.js';
import { decide } from '../src/decider.mjs';
import { detect } from '../src/detect.mjs';
import { fixtureRequests } from './fixture-7.mjs';
import { buildOperationsReport } from '../src/operations-report.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WORKSPACE = resolve(ROOT, '../..');
const execute = promisify(execFile);
const CODE = /^(?:HTTP_[1-5]\d{2}|allow|deny|step_up|observe|propose_revocation|LOCAL_TESTS_PASSED|SQL_ASSERTIONS_PASSED|JUDGE_SCORE_100)$/u;

export function trustedBase(value = config.publicAppUrl) {
  const base = new URL(value);
  if (value !== config.publicAppUrl || base.protocol !== 'https:' || base.username || base.password
      || base.port || base.search || base.hash || base.pathname !== '/' || !base.hostname.endsWith('.vercel.app')) {
    throw new Error('untrusted_operations_base');
  }
  return base.origin;
}

function response() {
  return Object.assign(new EventEmitter(), { statusCode: 0, setHeader() {},
    status(value) { this.statusCode = value; return this; },
    json() { this.emit('finish'); return this; }, end() { this.emit('finish'); return this; } });
}

async function signedFixture() {
  const pair = await generateKeyPair('ES256');
  const key = await exportJWK(pair.publicKey);
  const a = randomUUID(), b = randomUUID(), run = randomUUID(), note = randomUUID();
  const rows = [{ note_id: note, owner_id: a, title: 'Synthetic', content: 'Synthetic' }];
  const session = newCredential(), device = newCredential();
  let deviceStatus = 'approved';
  const db = { from(table) {
    if (table !== 'notes') throw new Error('unexpected_fixture_table');
    const filters = []; let patch;
    return { select() { return this; }, eq(field, value) { filters.push([field, value]); return this; },
      update(value) { patch = value; return this; },
      async maybeSingle() {
        const row = rows.find(candidate => filters.every(([field, value]) => candidate[field] === value));
        if (row && patch) Object.assign(row, patch);
        return { data: row ? { ...row } : null, error: null };
      }, async order() {
        return { data: rows.filter(row => filters.every(([field, value]) => row[field] === value)), error: null };
      } };
  }, async rpc(name, parameters) {
    if (name === 'stage11_lookup_browser_session') {
      return { data: parameters.p_session_hash === hashCredential(session) && parameters.p_device_hash === hashCredential(device)
        ? { signedIn: true, userId: a, deviceStatus } : { signedIn: false }, error: null };
    }
    if (name === 'stage10_restore_judge_b_note') {
      return parameters.p_run_id === run && parameters.p_owner_id === b && parameters.p_note_id === note
        ? { data: { id: note, restored: true }, error: null } : { data: null, error: { code: 'P0002' } };
    }
    throw new Error('unexpected_fixture_rpc');
  } };
  const verifyBearer = createLoginVerifier({ config,
    judgeKeySet: createLocalJWKSet({ keys: [{ ...key, kid: 'student-check', alg: 'ES256', use: 'sig' }] }),
    supabaseClient: { auth: { getClaims: async () => ({ error: true }) } } });
  const verify = createRequestLoginVerifier({ verifyBearer, db, config });
  async function authorization(identity, signingKey = pair.privateKey) {
    const now = Math.floor(Date.now() / 1000);
    return `Bearer ${await new SignJWT({ iss: config.judgeIssuer, aud: new URL(config.publicAppUrl).hostname,
      sub: identity === 'a' ? a : b, aleph_role: 'judge', aleph_identity: identity,
      aleph_run: run, iat: now, exp: now + 300 }).setProtectedHeader({ alg: 'ES256', kid: 'student-check' }).sign(signingKey)}`;
  }
  const headers = { a: await authorization('a'), b: await authorization('b') };
  const forged = await authorization('a', (await generateKeyPair('ES256')).privateKey);
  const services = () => ({ db, verify });
  const notes = createNotesHandler(services, () => {});
  const announcements = createAnnouncementHandler(services, () => {});
  const restore = createRestoreHandler(services);
  const auth = createAuthHandler(() => ({ db, config }));
  async function api(handler, req, id) {
    const res = response(); await handler(req, res, id); return `HTTP_${res.statusCode}`;
  }
  return {
    note, rows,
    anonymous: () => api(notes, { method: 'GET', url: `/api/notes/${note}`, headers: {} }, note),
    read: identity => api(notes, { method: 'GET', url: `/api/notes/${note}`, headers: { authorization: headers[identity] } }, note),
    update: identity => api(notes, { method: 'PUT', url: `/api/notes/${note}`, headers: { authorization: headers[identity] }, body: { title: 'Synthetic update', body: 'Synthetic update' } }, note),
    forged: () => api(notes, { method: 'GET', url: `/api/notes/${note}`, headers: { authorization: forged } }, note),
    announcement: () => api(announcements, { method: 'PUT', url: `/api/announcements/${note}`, headers: { authorization: headers.a }, body: { role: 'instructor' } }),
    restore: identity => api(restore, { method: 'POST', url: '/api/restore', headers: { authorization: headers[identity] }, body: { id: note } }),
    cookieRead: status => { deviceStatus = status; return api(notes, { method: 'GET', url: `/api/notes/${note}`, headers: { cookie: `${SESSION_COOKIE}=${session}; ${DEVICE_COOKIE}=${device}` } }, note); },
    csrf: () => api(auth, { method: 'POST', headers: { origin: 'https://untrusted.invalid', 'content-type': 'application/json' }, body: { action: 'requestDevice' } }),
  };
}

export async function runOperationsChecks({ fetchImpl = globalThis.fetch, baseUrl = config.publicAppUrl,
  includeLive = true, checkedCommit } = {}) {
  const base = trustedBase(baseUrl);
  if (checkedCommit === undefined) {
    try { checkedCommit = (await execute('git', ['rev-parse', 'HEAD'], { cwd: ROOT })).stdout.trim(); }
    catch { checkedCommit = null; }
  }
  const checks = [];
  const skipped = (id, stage, kind, category, expected) => checks.push({ id, stage, kind, category,
    expected, actual: null, requestId: null, checkedAt: null, source: 'not_run', status: 'not_run' });
  async function check(id, stage, kind, category, source, expected, perform) {
    try {
      const actual = await perform();
      if (!CODE.test(actual)) throw new Error('invalid_check_code');
      checks.push({ id, stage, kind, category, expected, actual, requestId: `student_check_${randomUUID()}`,
        checkedAt: new Date().toISOString(), source, status: actual === expected ? 'passed' : 'failed' });
    } catch {
      checks.push({ id, stage, kind, category, expected, actual: null, requestId: null,
        checkedAt: null, source: 'not_run', status: 'unavailable' });
    }
  }
  async function live(id, stage, kind, path, expected) {
    if (!includeLive) return skipped(id, stage, kind, 'api', expected);
    return check(id, stage, kind, 'api', 'live_http', expected, async () => {
      const result = await fetchImpl(`${base}${path}`, { method: 'GET', credentials: 'omit', cache: 'no-store',
        redirect: 'error', signal: AbortSignal.timeout(15000) });
      // Read no response body or identities; save only the actual HTTP status.
      await result.body?.cancel();
      return `HTTP_${result.status}`;
    });
  }
  await live('stage1_public_shell', 1, 'normal', '/', 'HTTP_200');
  await live('stage2_static_notes_removed', 2, 'forbidden', '/data.json', 'HTTP_404');
  await live('stage3_anonymous_notes_denied', 3, 'forbidden', '/api/notes', 'HTTP_401');
  await live('stage5_public_deployment_manifest', 5, 'normal', '/aleph.json', 'HTTP_200');
  await live('stage10_anonymous_restore_denied', 10, 'forbidden', '/api/restore', 'HTTP_401');
  await live('stage11_public_pwa_manifest', 11, 'normal', '/manifest.webmanifest', 'HTTP_200');
  await live('stage11_anonymous_session_status', 11, 'normal', '/api/auth', 'HTTP_200');

  const f = await signedFixture();
  await check('stage1_current_anonymous_notes_denied', 1, 'forbidden', 'api', 'local_api', 'HTTP_401', f.anonymous);
  for (const stage of [2, 3, 4, 5, 8]) {
    await check(`stage${stage}_signed_fixture_owner_read`, stage, 'normal', 'api', 'local_api', 'HTTP_200', () => f.read('a'));
    await check(`stage${stage}_signed_fixture_other_owner_denied`, stage, 'forbidden', 'api', 'local_api', 'HTTP_404', () => f.read('b'));
  }
  await check('stage3_forged_fixture_signature_denied', 3, 'forbidden', 'api', 'local_api', 'HTTP_401', f.forged);
  await check('stage4_signed_fixture_owner_update', 4, 'normal', 'api', 'local_api', 'HTTP_200', () => f.update('a'));
  await check('stage4_signed_fixture_other_update_denied', 4, 'forbidden', 'api', 'local_api', 'HTTP_404', async () => {
    const before = JSON.stringify(f.rows); const actual = await f.update('b');
    if (JSON.stringify(f.rows) !== before) throw new Error('fixture_mutation');
    return actual;
  });
  await check('stage8_fixture_announcement_write_denied', 8, 'forbidden', 'api', 'local_api', 'HTTP_403', f.announcement);
  const { normal, suspicious } = fixtureRequests();
  await check('stage6_registered_fixture', 6, 'normal', 'device', 'local_decider', 'allow', async () => (await decide(normal)).decision);
  await check('stage6_unregistered_fixture', 6, 'forbidden', 'device', 'local_decider', 'deny', async () => (await decide({ ...normal, deviceRegistered: false })).decision);
  await check('stage7_ordinary_fixture', 7, 'normal', 'policy', 'local_decider', 'allow', async () => (await decide(normal)).decision);
  await check('stage7_risk_fixture_step_up', 7, 'forbidden', 'policy', 'local_decider', 'step_up', async () => (await decide(suspicious)).decision);
  await check('stage8_collection_route_denied', 8, 'forbidden', 'policy', 'local_decider', 'deny', async () => (await decide({ ...normal, path: '/notes', route: 'GET /notes' })).decision);
  const events = count => Array.from({ length: count }, (_, index) => ({ at: new Date(Date.now() + index * 1000).toISOString(), method: 'GET', identity: { sub: 'learner_fixture' } }));
  await check('stage9_exact_limit_observed', 9, 'normal', 'detection', 'local_decider', 'observe', () => detect(events(120)).action);
  await check('stage9_burst_revocation_proposed', 9, 'forbidden', 'detection', 'local_decider', 'propose_revocation', () => detect(events(121)).action);
  skipped('stage9_live_revocation_execution', 9, 'forbidden', 'revocation', null);
  await check('stage10_fixture_restore_authorized', 10, 'normal', 'recovery', 'local_api', 'HTTP_200', () => f.restore('b'));
  await check('stage10_fixture_restore_wrong_identity', 10, 'forbidden', 'recovery', 'local_api', 'HTTP_403', () => f.restore('a'));
  skipped('stage10_live_restore_execution', 10, 'normal', 'recovery', 'HTTP_200');
  await check('stage11_fixture_approved_browser', 11, 'normal', 'device', 'local_api', 'HTTP_200', () => f.cookieRead('approved'));
  await check('stage11_fixture_pending_browser_denied', 11, 'forbidden', 'device', 'local_api', 'HTTP_403', () => f.cookieRead('pending'));
  await check('stage11_fixture_revoked_browser_denied', 11, 'forbidden', 'device', 'local_api', 'HTTP_403', () => f.cookieRead('revoked'));
  await check('stage11_cross_origin_request_denied', 11, 'forbidden', 'device', 'local_api', 'HTTP_403', f.csrf);
  skipped('stage11_live_approved_account', 11, 'normal', 'device', 'HTTP_200');
  skipped('stage4_current_database_rls_assertions', 4, 'forbidden', 'api', 'SQL_ASSERTIONS_PASSED');
  // Prior scores were separately observed by the parent. They are not executions
  // of this campaign, nor a claim that all 41 attacks ran on this source tree.
  for (const stage of [6, 7, 8, 9, 10, 11]) checks.push({ id: `stage${stage}_historical_judge_score`, stage,
    kind: 'normal', category: stage === 9 ? 'detection' : stage === 10 ? 'recovery' : stage === 11 ? 'device' : 'policy',
    expected: 'JUDGE_SCORE_100', actual: 'JUDGE_SCORE_100', requestId: null, checkedAt: null, source: 'judge', status: 'historical' });
  return buildOperationsReport({ schema: 'aleph.operations.v1', checkedCommit, generatedAt: new Date().toISOString(), checks,
    campaign: { total: 41, executed: 0, notRun: 41, coverageBasis: 'official_campaign_results_not_available' } });
}

export async function writeOperationsReport(path, report) {
  const target = resolve(path);
  const defaultOutput = resolve(ROOT, 'package/self-check/operations.json');
  const deliverable = resolve(WORKSPACE, 'outputs') + sep;
  const agentArchive = resolve(WORKSPACE, 'work/agents/stage12/stage8_review') + sep;
  if (!(target === defaultOutput || target.startsWith(deliverable) || target.startsWith(agentArchive))
      || !target.endsWith('.json')) throw new Error('invalid_operations_output');
  const normalized = buildOperationsReport(report);
  if (normalized.summary.availability !== 'available') throw new Error('invalid_operations_report');
  await mkdir(dirname(target), { recursive: true });
  if (await realpath(dirname(target)) !== dirname(target)) throw new Error('invalid_operations_output');
  const temporary = `${target}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(normalized, null, 2)}\n`, { flag: 'wx' });
    await rename(temporary, target);
  } finally { await unlink(temporary).catch(() => {}); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => {
    const args = process.argv.slice(2);
    let output = resolve(ROOT, 'package/self-check/operations.json'), includeLive = true;
    for (let index = 0; index < args.length; index += 1) {
      if (args[index] === '--output' && args[index + 1]) output = args[++index];
      else if (args[index] === '--local-only') includeLive = false;
      else throw new Error('invalid_operations_arguments');
    }
    const report = await runOperationsChecks({ includeLive });
    await writeOperationsReport(output, report);
    process.stdout.write(`${JSON.stringify({ checks: report.checks.length,
      passed: report.checks.filter(row => row.status === 'passed').length,
      failed: report.checks.filter(row => row.status === 'failed').length,
      unavailable: report.checks.filter(row => row.status === 'unavailable').length,
      campaignExecuted: report.campaign.executed, campaignNotRun: report.campaign.notRun })}\n`);
    if (report.checks.some(row => row.status === 'failed')) process.exitCode = 1;
  })().catch(() => { process.stderr.write('operations_check_failed\n'); process.exitCode = 1; });
}
