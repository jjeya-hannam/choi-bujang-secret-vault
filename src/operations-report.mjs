import { RULE_IDS } from './decider.mjs';

export const REPORT_SCHEMA = 'aleph.operations.v1';
export const REPORT_SOURCES = Object.freeze(['live_http', 'local_api', 'local_decider', 'local_sql', 'judge', 'not_run']);
export const REPORT_STATUSES = Object.freeze(['passed', 'failed', 'not_run', 'historical', 'unavailable']);
export const REPORT_CATEGORIES = Object.freeze(['api', 'policy', 'detection', 'revocation', 'recovery', 'device']);
const KINDS = ['normal', 'forbidden', 'attack'];
const CODES = new Set(['allow', 'deny', 'step_up', 'observe', 'propose_revocation',
  'LOCAL_TESTS_PASSED', 'SQL_ASSERTIONS_PASSED', 'JUDGE_SCORE_100']);
const ID = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/u;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$/u;
const CAMPAIGN_BASIS = 'official_campaign_results_not_available';
const TOP_KEYS = ['schema', 'checkedCommit', 'generatedAt', 'engineOrigin', 'rules', 'summary', 'checks', 'campaign'];
const CHECK_KEYS = ['id', 'stage', 'kind', 'category', 'expected', 'actual', 'requestId', 'checkedAt', 'source', 'status'];

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value, allowed) => Object.keys(value).every(key => allowed.includes(key));
const timestamp = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)
  && Number.isFinite(Date.parse(value))
  && new Date(value).toISOString().replace('.000Z', 'Z') === value.replace('.000Z', 'Z');
const code = value => value === null || (typeof value === 'string' && (CODES.has(value) || /^HTTP_[1-5]\d{2}$/u.test(value)));
const campaign = () => ({ total: 41, executed: 0, notRun: 41, coverageBasis: CAMPAIGN_BASIS });
const SNAPSHOT_PATHS = ['src/decider.mjs', 'src/detect.mjs', 'src/resource-policy.mjs', 'src/verify-login.mjs'];

// Public version metadata only. A valid manifest is not proof that its files were
// restored, their contents rehashed now, or any database note was recovered.
export function buildPolicySnapshot(manifest) {
  const unavailable = { availability: 'unavailable', scope: 'policy_code_snapshot',
    source: 'policy-backups/stage9/manifest.json', version: null, commit: null, fileCount: 0,
    verification: 'manifest_metadata_only' };
  if (!object(manifest) || !keys(manifest, ['schema', 'version', 'commit', 'files'])
      || manifest.schema !== 'aleph.policy.snapshot.v1' || typeof manifest.commit !== 'string'
      || !/^[0-9a-f]{40}$/u.test(manifest.commit) || manifest.version !== `stage9-${manifest.commit.slice(0, 7)}`
      || !Array.isArray(manifest.files) || manifest.files.length !== SNAPSHOT_PATHS.length) return unavailable;
  const seen = new Set();
  for (const file of manifest.files) {
    if (!object(file) || !keys(file, ['path', 'sha256']) || !SNAPSHOT_PATHS.includes(file.path)
        || seen.has(file.path) || typeof file.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(file.sha256)) return unavailable;
    seen.add(file.path);
  }
  return { ...unavailable, availability: 'available', version: manifest.version, commit: manifest.commit,
    fileCount: manifest.files.length };
}

export function unavailableOperationsReport(policyManifest = null) {
  return { schema: REPORT_SCHEMA, checkedCommit: null, generatedAt: null, engineOrigin: 'ALEPH SDP engine',
    rules: [...RULE_IDS], summary: { availability: 'unavailable', liveApi: 'not_run', detection: 'not_run',
      revocation: 'not_run', recovery: 'not_run' }, checks: [], campaign: campaign(), policySnapshot: buildPolicySnapshot(policyManifest) };
}

// Whitelist-only public projection. Do not import requests, sessions, DB rows or
// notes. Missing/invalid evidence cannot become a claimed successful execution.
export function buildOperationsReport(input, policyManifest = null) {
  if (!object(input) || !keys(input, TOP_KEYS) || input.schema !== REPORT_SCHEMA
      || !(input.checkedCommit === null || (typeof input.checkedCommit === 'string' && /^[0-9a-f]{40}$/u.test(input.checkedCommit)))
      || !(input.generatedAt === null || timestamp(input.generatedAt))
      || !Array.isArray(input.checks) || input.checks.length > 200) return unavailableOperationsReport(policyManifest);
  if (input.campaign !== undefined && (!object(input.campaign)
      || !keys(input.campaign, ['total', 'executed', 'notRun', 'coverageBasis'])
      || input.campaign.total !== 41 || input.campaign.executed !== 0 || input.campaign.notRun !== 41
      || input.campaign.coverageBasis !== CAMPAIGN_BASIS)) return unavailableOperationsReport(policyManifest);
  const checks = [], seen = new Set();
  for (const row of input.checks) {
    if (!object(row) || !keys(row, CHECK_KEYS) || typeof row.id !== 'string' || !ID.test(row.id) || seen.has(row.id)
        || !Number.isSafeInteger(row.stage) || row.stage < 1 || row.stage > 12
        || !KINDS.includes(row.kind) || !REPORT_CATEGORIES.includes(row.category ?? 'api')
        || !code(row.expected) || !code(row.actual)
        || !(row.requestId === null || (typeof row.requestId === 'string' && REQUEST_ID.test(row.requestId)))
        || !(row.checkedAt === null || timestamp(row.checkedAt))
        || !REPORT_SOURCES.includes(row.source) || !REPORT_STATUSES.includes(row.status)) return unavailableOperationsReport(policyManifest);
    if (['not_run', 'unavailable'].includes(row.status)) {
      if (row.source !== 'not_run' || row.actual !== null || row.requestId !== null || row.checkedAt !== null) return unavailableOperationsReport(policyManifest);
    } else if (row.status === 'historical') {
      if (row.source !== 'judge' || row.actual === null) return unavailableOperationsReport(policyManifest);
    } else if (row.source === 'not_run' || row.expected === null || row.actual === null || row.checkedAt === null) {
      return unavailableOperationsReport(policyManifest);
    }
    if ((row.status === 'passed' && row.expected !== row.actual)
        || (row.status === 'failed' && row.expected === row.actual)) return unavailableOperationsReport(policyManifest);
    seen.add(row.id);
    checks.push({ id: row.id, stage: row.stage, kind: row.kind, category: row.category ?? 'api', expected: row.expected,
      actual: row.actual, requestId: row.requestId, checkedAt: row.checkedAt, source: row.source, status: row.status });
  }
  const confirmed = category => checks.some(row => row.category === category && row.status === 'passed'
    && ['live_http', 'judge'].includes(row.source));
  return { schema: REPORT_SCHEMA, checkedCommit: input.checkedCommit, generatedAt: input.generatedAt,
    engineOrigin: 'ALEPH SDP engine', rules: [...RULE_IDS],
    summary: { availability: 'available', liveApi: confirmed('api') ? 'confirmed' : 'not_run',
      detection: confirmed('detection') ? 'confirmed' : 'not_run', revocation: confirmed('revocation') ? 'confirmed' : 'not_run',
      recovery: confirmed('recovery') ? 'confirmed' : 'not_run' }, checks, campaign: campaign(), policySnapshot: buildPolicySnapshot(policyManifest) };
}
