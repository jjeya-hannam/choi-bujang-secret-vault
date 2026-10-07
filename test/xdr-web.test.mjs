import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { readAlerts } from '../xdr/web-injection/read-alerts.mjs';
import { decide } from '../xdr/web-injection/decide.mjs';
import { evaluateDenyRules } from '../xdr/ztna-overlay.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/web-injection.json', import.meta.url)));

test('web reader returns one five-field row per fixture alert', () => {
  const rows = readAlerts(fixture);
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]).sort(),
    ['timestamp', 'sourceAddress', 'account', 'ruleLevel', 'description'].sort());
});

test('repeated injection, single suspicious input, and routine requests stay separate', async () => {
  const result = await Promise.all(fixture.alerts.map(decide));
  assert.deepEqual(result.slice(0, 8).map(x => x.action), Array(8).fill('block'));
  assert.deepEqual(result.slice(8, 17).map(x => x.action), Array(9).fill('alert'));
  assert.deepEqual(result.slice(17).map(x => x.action), Array(9).fill('record'));
  assert.ok(result.every(x => x.confidence >= 0 && x.confidence <= 1 && !x.reason.includes('\n')));
});

test('Jev outage alerts on a borderline request', async () => {
  const result = await decide(fixture.alerts[8], { jev: async () => null });
  assert.equal(result.action, 'alert');
});

test('normal request address is not in the deny overlay', async () => {
  const candidate = { action: 'deny', sourceAddress: fixture.alerts[0].data.srcip,
    evidenceAlertIds: ['wi-01'], expiresAt: '2030-01-01T01:00:00.000Z' };
  const rules = [candidate];
  assert.equal(evaluateDenyRules(fixture.alerts[17].data.srcip, rules).blocked, false);
  assert.ok(candidate?.evidenceAlertIds.length);
  assert.equal(evaluateDenyRules(candidate.sourceAddress, rules, new Date(Date.parse(candidate.expiresAt) - 1000)).blocked, true);
});
