import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { readAlerts } from '../xdr/brute-force/read-alerts.mjs';
import { decide } from '../xdr/brute-force/decide.mjs';
import { evaluateDenyRules } from '../xdr/ztna-overlay.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url)));

test('reader retains one redacted five-field row per alert', () => {
  const rows = readAlerts(fixture);
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]).sort(),
    ['timestamp', 'sourceAddress', 'account', 'ruleLevel', 'description'].sort());
  const injected = structuredClone(fixture);
  injected.alerts[0].rule.description = 'token=private-value login failures';
  assert.doesNotMatch(readAlerts(injected)[0].description, /private-value/u);
});

test('clear, ambiguous, and routine authentication events stay separate', async () => {
  const result = await Promise.all(fixture.alerts.map(decide));
  assert.deepEqual(result.slice(0, 10).map(x => x.action), Array(10).fill('block'));
  assert.deepEqual(result.slice(10, 19).map(x => x.action), Array(9).fill('alert'));
  assert.deepEqual(result.slice(19).map(x => x.action), Array(9).fill('record'));
  assert.ok(result.every(x => x.confidence >= 0 && x.confidence <= 1 && !x.reason.includes('\n')));
});

test('unavailable Jev keeps a borderline alert out of automatic blocking', async () => {
  const result = await decide(fixture.alerts[10], { jev: async () => { throw Error('offline'); } });
  assert.equal(result.action, 'alert');
});

test('trusted source rule expires and never matches a normal event source', async () => {
  const rules = JSON.parse(await readFile(new URL('../xdr/deny-rules.json', import.meta.url))).rules;
  const rule = rules.find(x => x.moduleKey === 'brute-force');
  assert.ok(rule?.evidenceAlertIds.length);
  assert.equal(evaluateDenyRules(rule.sourceAddress, rules, new Date(Date.parse(rule.expiresAt) - 1000)).blocked, true);
  assert.equal(evaluateDenyRules(rule.sourceAddress, rules, new Date(Date.parse(rule.expiresAt) + 1000)).blocked, false);
  assert.equal(evaluateDenyRules(fixture.alerts[19].data.srcip, rules).blocked, false);
});
