import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { decide } from '../xdr/persistence/decide.mjs';
import { readAlerts } from '../xdr/persistence/read-alerts.mjs';

const fixtureUrl = new URL('../xdr/fixtures/persistence.json', import.meta.url);
const event = (description, data = {}, level = 12, mitre = ['T1543']) => ({
  id: 'synthetic-event', rule: { description, level, mitre }, data,
});
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };

test('fixture decisions preserve original content and classify strong/review/normal events', async () => {
  const input = JSON.parse(await readFile(fixtureUrl, 'utf8')), before = JSON.stringify(input);
  freeze(input);
  const outputs = input.alerts.map(decide);
  const counts = { block: 0, alert: 0, record: 0 };
  for (const out of outputs) {
    assert.deepEqual(Object.keys(out), ['action', 'confidence', 'reason']);
    assert.ok(Number.isFinite(out.confidence) && out.confidence >= 0 && out.confidence <= 1);
    assert.equal(out.action, out.confidence >= 0.85 ? 'block' : out.confidence >= 0.5 ? 'alert' : 'record');
    assert.match(out.reason, /^(?:unsigned_service_change|suspicious_scheduled_task|unexpected_startup_entry|persistence_review|no_matching_pattern)$/u);
    counts[out.action] += 1;
  }
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
  assert.ok(input.alerts.filter(a => a.rule.level <= 3).every(a => decide(a).action === 'record'));
  assert.equal(JSON.stringify(input), before);
});

test('service, scheduled task and startup patterns depend on behavior rather than IDs, paths or counts', () => {
  const scenarios = [
    event('서명 없는 새 서비스가 임시 폴더의 실행 파일을 가리킵니다.', { path: 'D:\\Temp\\synthetic.exe' }),
    event('처음 보는 예약 작업이 임시 폴더의 프로그램을 실행합니다.', { path: 'D:\\Temp\\synthetic.exe' }, 12, ['T1053']),
    event('시작 폴더에 평소 목록에 없는 프로그램이 추가됐습니다.', { path: 'D:\\Programs\\Startup\\synthetic.exe' }, 12, ['T1547.001']),
  ];
  for (const input of scenarios) {
    assert.equal(decide(input).action, 'block');
    for (const count of [0, 1, 999999]) assert.deepEqual(decide({ ...input, id: 'unrelated-id', data: { ...input.data, srcip: '192.0.2.200', count } }), decide(input));
    assert.equal(decide({ ...input, rule: { ...input.rule, level: 5 } }).action, 'alert');
  }
});

test('temporary files, unknown signature, technique labels and normal maintenance never independently block', () => {
  for (const input of [
    event('임시 폴더에 실행 파일이 생겼습니다. 서비스 등록은 없습니다.', { path: 'D:\\Temp\\draft.exe' }),
    event('시작 항목에 도구가 있습니다. 서명은 아직 모릅니다.'),
    event('service', {}, 16),
    event('ordinary event', {}, 16, ['T1543', 'T1053']),
    event('기존 서명된 서비스가 실행 중입니다.', { path: 'D:\\Apps\\signed.exe' }),
    event('운영체제 업데이트 예약이 평소 시각에 그대로입니다.', {}, 2, ['T1053']),
  ]) assert.notEqual(decide(input).action, 'block');
  assert.equal(decide(event('기존 서명된 서비스가 실행 중입니다.')).action, 'record');
  assert.equal(decide(event('서비스 실행 파일이 바뀌었고 서명이 없습니다.', { path: 'D:\\Temp\\synthetic.exe' })).action, 'block');
  assert.equal(decide(event('서명 없는 서비스의 임시 실행 파일을 관찰했습니다.', { path: 'D:\\Temp\\synthetic.exe' })).action, 'alert');
  assert.equal(decide(event('서명 없는 새 서비스 등록', {}, 16)).action, 'record');
  assert.equal(decide(event('승인된 정기 유지보수 예약 작업이 임시 폴더에서 수업 시간 밖에 실행합니다.', { path: 'D:/Temp/maintenance.cmd' }, 12, ['T1053'])).action, 'alert');
  assert.equal(decide(event('기존 signed service unapproved new registration with unsigned executable', { path: 'D:/Temp/service.exe' })).action, 'block');
  assert.equal(decide(event('기존 signed service with unapproved new registration', { path: 'D:/Temp/service.exe' })).action, 'alert');
  for (const description of ['서명 없는 새 서비스는 등록하지 않았습니다.', 'unsigned service added not', 'unsigned service no new service registration']) {
    assert.equal(decide(event(description)).action, 'alert');
  }
});

test('pure decision rejects invalid objects and cannot invoke callbacks or return private input', () => {
  for (const input of [null, [], {}, event('synthetic', {}, Infinity), event('synthetic', {}, '12')]) assert.equal(decide(input).action, 'record');
  let calls = 0;
  const input = freeze(event('서명 없는 새 서비스 등록', { token: 'private_synthetic_sentinel', srcuser: 'private_synthetic_sentinel' }));
  const output = decide(input, { jev() { calls++; throw new Error('must_not_call'); } });
  assert.equal(calls, 0); assert.equal(JSON.stringify(output).includes('private_synthetic_sentinel'), false);
});

test('standalone decision imports only its single file and embeds the exact public pattern definitions', async () => {
  const source = await readFile(new URL('../xdr/persistence/decide.mjs', import.meta.url), 'utf8');
  const patterns = JSON.parse(await readFile(new URL('../xdr/persistence/patterns.json', import.meta.url), 'utf8'));
  assert.deepEqual(JSON.parse(source.match(/^const PATTERNS = (\[[\s\S]*?\]);/u)[1]), patterns.patterns);
  assert.equal(/\bimport\s|\bfetch\s*\(|\beval\s*\(/u.test(source), false);
  const directory = await mkdtemp(join(tmpdir(), 'persistence-standalone-'));
  try {
    const entry = join(directory, 'decide.mjs');
    await copyFile(new URL('../xdr/persistence/decide.mjs', import.meta.url), entry);
    const module = await import(pathToFileURL(entry)); assert.deepEqual(Object.keys(module), ['decide']);
    assert.equal(module.decide(event('ordinary event')).action, 'record');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('reader emits exactly five redacted fields without private paths or malformed levels', async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const rows = readAlerts(fixture); assert.equal(rows.length, 24);
  for (const row of rows) assert.deepEqual(Object.keys(row), ['timestamp', 'sourceAddress', 'account', 'ruleLevel', 'description']);
  const safe = readAlerts({ schema: 'aleph.xdr.fixture.v1', alerts: [{ timestamp: 'token=synthetic',
    data: { srcip: 'password=synthetic', srcuser: 'Bearer synthetic', path: 'private_synthetic_sentinel' },
    rule: { level: 0, description: 'api_key=synthetic' } }, {}] });
  assert.deepEqual(safe[0], { timestamp: '[REDACTED]', sourceAddress: '[REDACTED]', account: '[REDACTED]', ruleLevel: 0, description: '[REDACTED]' });
  assert.deepEqual(safe[1], { timestamp: null, sourceAddress: null, account: null, ruleLevel: null, description: null });
  const cli = execFileSync(process.execPath, [new URL('../xdr/persistence/read-alerts.mjs', import.meta.url).pathname], { encoding: 'utf8' });
  assert.equal(cli.trimEnd().split('\n').length, 24);
});
