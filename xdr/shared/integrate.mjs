import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

async function readJson(path, fallback) {
  try { return JSON.parse(await readFile(path, 'utf8')); }
  catch (error) { if (error?.code === 'ENOENT') return fallback; throw error; }
}

export async function integrateDecisions({ root, moduleKey, fixture, result, now = new Date() }) {
  const decisions = new Map(result.decisions.map(item => [item.alertId, item]));
  const normalAddresses = new Set(fixture.alerts.filter(item =>
    decisions.get(item.id)?.action !== 'block').map(item => item.data?.srcip));
  const grouped = new Map();
  for (const alert of fixture.alerts) {
    const chosen = decisions.get(alert.id);
    const address = alert.data?.srcip;
    if (chosen?.action !== 'block' || typeof address !== 'string'
      || normalAddresses.has(address)) continue;
    if (!grouped.has(address)) grouped.set(address, []);
    grouped.get(address).push(alert.id);
  }

  const rulesPath = join(root, 'xdr', 'deny-rules.json');
  const previous = await readJson(rulesPath, { schema: 'aleph.xdr.deny-rules.v1', rules: [] });
  if (previous.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(previous.rules)) {
    throw new Error('INVALID_XDR_RULES');
  }
  const expiresAt = new Date(new Date(now).getTime() + 60 * 60 * 1000).toISOString();
  const rules = [
    ...previous.rules.filter(rule => rule.moduleKey !== moduleKey
      && new Date(rule.expiresAt).getTime() > new Date(now).getTime()),
    ...[...grouped].map(([sourceAddress, evidenceAlertIds]) => ({
      moduleKey, action: 'deny', sourceAddress, expiresAt, evidenceAlertIds,
    })),
  ];
  await writeFile(rulesPath, `${JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules }, null, 2)}\n`, 'utf8');

  const logPath = join(root, 'xdr', 'alerts.log');
  let lines = [];
  try { lines = (await readFile(logPath, 'utf8')).split(/\r?\n/u).filter(Boolean); }
  catch (error) { if (error?.code !== 'ENOENT') throw error; }
  const seen = new Set(lines.map(line => {
    try { const item = JSON.parse(line); return `${item.moduleKey}:${item.alertId}`; }
    catch { throw new Error('INVALID_XDR_ALERT_LOG'); }
  }));
  for (const alert of fixture.alerts) {
    const chosen = decisions.get(alert.id);
    if (!chosen || chosen.action === 'record' || seen.has(`${moduleKey}:${alert.id}`)) continue;
    lines.push(JSON.stringify({ moduleKey, alertId: alert.id, action: chosen.action,
      pattern: chosen.reason.split(':')[0], sourceAddress: alert.data?.srcip ?? '' }));
  }
  await writeFile(logPath, `${lines.join('\n')}\n`, 'utf8');
  return { rules, logged: lines.length };
}
