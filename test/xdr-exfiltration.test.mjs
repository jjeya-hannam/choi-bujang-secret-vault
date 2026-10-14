import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile, mkdtemp, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { readAlerts, readFixture } from '../xdr/exfiltration/read-alerts.mjs';

const event = (description, data = {}, level = 11, mitre = ['T1048']) => ({
  id: 'synthetic-case', timestamp: '2026-10-14T00:00:00Z',
  rule: { description, level, mitre },
  data: { srcip: '192.0.2.100', dstip: '198.51.100.100', ...data },
});
function valid(value) {
  assert.deepEqual(Object.keys(value).sort(), ['action','confidence','reason']);
  assert.ok(Number.isFinite(value.confidence) && value.confidence >= 0 && value.confidence <= 1);
  assert.equal(value.action, value.confidence >= 0.85 ? 'block' : value.confidence >= 0.5 ? 'alert' : 'record');
  assert.match(value.reason, /^[a-z_]+$/u);
}
test('meaning-based completed bulk/alternate-channel signals block without address or identity lookup', () => {
  const alert = event('처음 보는 목적지로 다수 자료가 나갔습니다.', {bytes:'96000000', files:'80'});
  assert.equal(decide(alert).action,'block');
  const changed = structuredClone(alert);changed.id='renamed';changed.data.srcuser='renamed';changed.data.srcip='203.0.113.101';changed.data.dstip='192.0.2.102';changed.timestamp='2026-10-14T18:00:00Z';
  assert.deepEqual(decide(changed),decide(alert));
  assert.equal(decide(event('평소에 쓰지 않던 포트로 자료 이름이 연속 전송됐습니다.',{bytes:80000000,files:90})).action,'block');
  assert.equal(decide(event('명령 통로로 큰 파일이 반복 전송됐습니다.',{bytes:90000000,count:7},11,['T1041'])).action,'block');
});
test('large bytes, high severity and ATT&CK tags alone do not block approved backup or business transfer', () => {
  for (const text of ['승인된 백업이 정기 목적지로 전송됐습니다.','정상 업무 전송이 완료됐습니다.','authorized business transfer sent to the scheduled backup destination']) {
    const out=decide(event(text,{bytes:900000000,files:900,count:50},12,['T1041','T1048']));valid(out);assert.equal(out.action,'record');
  }
  assert.notEqual(decide(event('자료 전송이 있습니다.',{bytes:900000000},12,['T1048'])).action,'block');
  assert.equal(decide(event('수업 자료 주소로 작은 동기화가 끝났습니다.',{bytes:'20000',files:'3'},3)).action,'record');
});
test('failed, missing, negative or nonnumeric transfer volume cannot establish a completed exfiltration', () => {
  const text='처음 보는 목적지로 다수 자료가 나갔습니다.';
  for(const bytes of [undefined,0,-1,'-1','not-a-number',Infinity,NaN,{},true])assert.notEqual(decide(event(text,{bytes,files:100})).action,'block');
  assert.equal(decide(event('전송이 실패 1건으로 끝났습니다. 목적지는 처음 봅니다.',{bytes:0,files:1},5)).action,'alert');
  assert.equal(decide(event('압축 파일 1건을 만들었습니다. 외부 전송은 아직 없습니다.',{bytes:2000000,files:1},5)).action,'alert');
  for(const description of ['Data was not transferred to a new destination.','Data has not been uploaded to a new destination.','Data was not sent to a new destination.']){
    const output=decide(event(description,{bytes:120000000,files:100},12));assert.equal(output.action,'alert');assert.equal(output.reason,'incomplete_transfer_review');
  }
});
test('single synchronous decision preserves ambiguity without invoking callbacks or returning promises', () => {
  const input=event('처음 보는 목적지로 작은 파일이 나갔습니다.',{bytes:400000,files:2},6);
  let calls=0;const value=decide(input,{jev(){calls++;throw new Error('must_not_call');}});
  valid(value);assert.equal(value.action,'alert');assert.equal(value.confidence,0.65);assert.equal(calls,0);assert.equal(typeof value.then,'undefined');
  for(const description of ['승인된 백업이 처음 보는 목적지로 나갔습니다.','승인된 업무 전송이 업무 시간 밖에 나갔습니다.']){
    const out=decide(event(description,{bytes:120000000,files:100,count:10},12));assert.notEqual(out.action,'record');assert.equal(out.action,'alert');
  }
});
test('fixture processing is immutable with exact three-field decisions and is invariant to fixture IDs/IPs', async () => {
  const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/exfiltration.json',import.meta.url),'utf8'));
  const patterns=JSON.parse(await readFile(new URL('../xdr/exfiltration/patterns.json',import.meta.url),'utf8'));const reasons=new Set(['no_matching_pattern',...patterns.patterns.map(pattern=>pattern.name)]);
  const before=JSON.stringify(fixture);
  for(const input of fixture.alerts){const output=decide(input);valid(output);assert.ok(reasons.has(output.reason));const clone=structuredClone(input);delete clone.id;clone.data.srcip='192.0.2.101';clone.data.dstip=input.data.dstip?'203.0.113.101':undefined;clone.data.srcuser='different';assert.deepEqual(decide(clone),output);}
  assert.equal(JSON.stringify(fixture),before);
});
test('isolated decide file imports and runs with no repository files, imports or I/O', async () => {
  const text=await readFile(new URL('../xdr/exfiltration/decide.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(text, /(?:^|\n)\s*import\b|\b(?:fetch|process|require|readFile|writeFile|console|Promise|jev)\b/u);
  const patterns=JSON.parse(await readFile(new URL('../xdr/exfiltration/patterns.json',import.meta.url),'utf8'));assert.deepEqual(JSON.parse(text.match(/^const PATTERNS = (\[[\s\S]*?\]);/u)[1]),patterns.patterns);
  const root=await mkdtemp(join(tmpdir(),'xdr-exfiltration-isolated-'));
  try{const target=join(root,'decide.mjs');await copyFile(new URL('../xdr/exfiltration/decide.mjs',import.meta.url),target);const loaded=await import(pathToFileURL(target));valid(loaded.decide(event('자료실 전체가 외부 주소로 복사됐습니다.',{bytes:300000000,files:350},12,['T1041'])));}
  finally{await rm(root,{recursive:true,force:true});}
});
test('safe reader exposes only five fields and redacts secrets from every free-text field', async () => {
  const rows=await readFixture();assert.ok(rows.length>0);
  for(const row of rows)assert.deepEqual(Object.keys(row).sort(),['account','description','ruleLevel','sourceAddress','timestamp']);
  const input=event('token=synthetic_test_only');input.data.srcuser='person@example.invalid';input.data.srcip='Bearer synthetic_placeholder';input.timestamp='password=synthetic_placeholder';input.data.hidden='excluded';
  const [row]=readAlerts({schema:'aleph.xdr.fixture.v1',moduleKey:'exfiltration',alerts:[input]});
  for(const key of ['timestamp','sourceAddress','account','description'])assert.equal(row[key],'[REDACTED]');
  assert.equal(Object.hasOwn(row,'hidden'),false);
  assert.throws(()=>readAlerts({schema:'aleph.xdr.fixture.v1',moduleKey:'different',alerts:[]}),/INVALID_WAZUH_FIXTURE/u);
});
test('malformed event inputs yield conservative exact responses without reflected free text', () => {
  for(const input of [null,[],{},event('x',{},-1),event('x',{},16),event('x',{},20),event('x',{},'11')]){const result=decide(input);valid(result);assert.equal(result.action,'record');assert.equal(result.reason,'no_matching_pattern');}
});
