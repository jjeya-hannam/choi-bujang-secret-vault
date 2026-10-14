import { readFile, writeFile, rename, unlink, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

const MODULES = ['brute-force', 'web-injection', 'known-cve', 'persistence', 'privilege', 'exfiltration'];
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value, expected) => object(value) && Object.keys(value).length === expected.length
  && Object.keys(value).every(key => expected.includes(key));
const secret = /\bBearer\s+|sb_secret_|\bsk-[A-Za-z0-9_-]{8,}|\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|(?:password|token|api[_ -]?key)\s*[:=]|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu;
const identifier = value => typeof value === 'string' && /^[a-z0-9][a-z0-9_.-]{0,79}$/iu.test(value) && !secret.test(value);
const address = value => typeof value === 'string'
  && /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.(?:0|[1-9]\d{0,2})$/u.test(value)
  && Number(value.split('.').at(-1)) <= 255;
const iso = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)
  && Number.isFinite(Date.parse(value))
  && new Date(value).toISOString() === (value.includes('.') ? value : value.replace('Z', '.000Z'));
const fail = () => { throw new Error('INVALID_FIXTURE_RESPONSE'); };

async function existingFile(path) {
  try {
    const stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink()) fail();
    return await readFile(path, 'utf8');
  } catch (error) { if (error?.code === 'ENOENT') return null; fail(); }
}

// Local fixture response only. No SDP identity, live IP or client claim is trusted.
export async function respondFixture({ root, moduleKey: MODULE, reasons: REASONS, fixture, result, now = new Date() }) {
  if (!['persistence', 'privilege', 'exfiltration'].includes(MODULE) || !Array.isArray(REASONS)
      || !REASONS.length || !REASONS.every(identifier)) fail();
  const at = new Date(now).getTime();
  if (typeof root !== 'string' || !root || !Number.isFinite(at)
      || fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== MODULE || !Array.isArray(fixture.alerts)
      || result?.schema !== 'aleph.xdr.result.v1' || result.moduleKey !== MODULE || !Array.isArray(result.decisions)
      || fixture.alerts.length !== result.decisions.length) fail();
  const alerts = new Map(), decisions = new Map();
  for (const alert of fixture.alerts) {
    if (!identifier(alert?.id) || alerts.has(alert.id) || !address(alert?.data?.srcip)) fail();
    alerts.set(alert.id, alert);
  }
  for (const row of result.decisions) {
    if (!keys(row, ['alertId', 'action', 'confidence', 'reason']) || !identifier(row.alertId)
        || decisions.has(row.alertId) || !alerts.has(row.alertId) || !Number.isFinite(row.confidence)
        || row.confidence < 0 || row.confidence > 1
        || row.action !== (row.confidence >= 0.85 ? 'block' : row.confidence >= 0.5 ? 'alert' : 'record')
        || !(REASONS.includes(row.reason) || (row.action === 'record' && row.reason === 'no_matching_pattern'))) fail();
    decisions.set(row.alertId, row);
  }
  const counts = { block: 0, alert: 0, record: 0 };
  for (const row of decisions.values()) counts[row.action] += 1;
  if (!keys(result.counts, ['block', 'alert', 'record'])
      || !Object.keys(counts).every(key => result.counts[key] === counts[key])) fail();
  const nonblock = new Set(fixture.alerts.filter(alert => decisions.get(alert.id).action !== 'block'
    || (Array.isArray(alert.rule?.mitre) && alert.rule.mitre.length === 0
      && Number.isSafeInteger(alert.rule.level) && alert.rule.level >= 0 && alert.rule.level <= 3))
    .map(alert => alert.data.srcip));
  const grouped = new Map();
  for (const alert of fixture.alerts) {
    if (decisions.get(alert.id).action !== 'block' || nonblock.has(alert.data.srcip)) continue;
    if (!grouped.has(alert.data.srcip)) grouped.set(alert.data.srcip, []);
    grouped.get(alert.data.srcip).push(alert.id);
  }

  const directory = join(root, 'xdr');
  try { const stat = await lstat(directory); if (!stat.isDirectory() || stat.isSymbolicLink()) fail(); }
  catch { fail(); }
  const rulesPath = join(directory, 'deny-rules.json'), logPath = join(directory, 'alerts.log');
  const previousText = await existingFile(rulesPath), logText = await existingFile(logPath);
  let previous;
  try { previous = previousText === null ? { schema: 'aleph.xdr.deny-rules.v1', rules: [] } : JSON.parse(previousText); }
  catch { fail(); }
  if (!keys(previous, ['schema', 'rules']) || previous.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(previous.rules)) fail();
  for (const rule of previous.rules) {
    if (!keys(rule, ['moduleKey', 'action', 'sourceAddress', 'expiresAt', 'evidenceAlertIds'])
        || !MODULES.includes(rule.moduleKey) || rule.action !== 'deny' || !address(rule.sourceAddress)
        || !iso(rule.expiresAt) || !Array.isArray(rule.evidenceAlertIds) || !rule.evidenceAlertIds.length
        || !rule.evidenceAlertIds.every(identifier)) fail();
  }
  const lines = logText === null ? [] : logText.split(/\r?\n/u).filter(Boolean), seen = new Set();
  for (const line of lines) {
    let row; try { row = JSON.parse(line); } catch { fail(); }
    if (!keys(row, ['moduleKey', 'alertId', 'action', 'pattern', 'sourceAddress'])
        || !MODULES.includes(row.moduleKey) || !identifier(row.alertId) || !['block', 'alert'].includes(row.action)
        || !identifier(row.pattern) || !address(row.sourceAddress)) fail();
    seen.add(row.moduleKey + ':' + row.alertId);
  }
  const expiry = new Date(at + 60 * 60 * 1000).toISOString();
  const rules = previous.rules.filter(rule => rule.moduleKey !== MODULE);
  for (const [sourceAddress, ids] of grouped) {
    const evidenceAlertIds = [...ids].sort();
    const active = previous.rules.find(rule => rule.moduleKey === MODULE && rule.sourceAddress === sourceAddress
      && Date.parse(rule.expiresAt) > at && JSON.stringify([...rule.evidenceAlertIds].sort()) === JSON.stringify(evidenceAlertIds));
    rules.push({ moduleKey: MODULE, action: 'deny', sourceAddress,
      expiresAt: active?.expiresAt ?? expiry, evidenceAlertIds });
  }
  let addedLogs = 0;
  for (const alert of fixture.alerts) {
    const chosen = decisions.get(alert.id), key = MODULE + ':' + alert.id;
    if (chosen.action === 'record' || seen.has(key)) continue;
    lines.push(JSON.stringify({ moduleKey: MODULE, alertId: alert.id, action: chosen.action,
      pattern: chosen.reason, sourceAddress: alert.data.srcip }));
    seen.add(key); addedLogs += 1;
  }
  const rulesText = JSON.stringify({ schema: previous.schema, rules }, null, 2) + '\n';
  const nextLog = lines.length ? lines.join('\n') + '\n' : '';
  if (rulesText === previousText && nextLog === (logText ?? '')) return { denyRules: grouped.size, addedLogs: 0, logged: lines.length };
  const suffix = '.fixture-' + randomUUID() + '.tmp';
  const tempRules = rulesPath + suffix, tempLog = logPath + suffix;
  try {
    // Validate and prepare both before activation. Commit evidence before denial:
    // an interrupted second rename cannot introduce an unlogged denial rule.
    await writeFile(tempRules, rulesText, { flag: 'wx', mode: 0o600 });
    await writeFile(tempLog, nextLog, { flag: 'wx', mode: 0o600 });
    await rename(tempLog, logPath);
    await rename(tempRules, rulesPath);
  } catch { throw new Error('FIXTURE_RESPONSE_WRITE_FAILED'); }
  finally {
    await Promise.all([unlink(tempRules).catch(() => {}), unlink(tempLog).catch(() => {})]);
  }
  return { denyRules: grouped.size, addedLogs, logged: lines.length };
}
