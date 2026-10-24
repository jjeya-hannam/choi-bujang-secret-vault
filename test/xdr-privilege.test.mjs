// Synthetic redaction fixtures are assembled only during tests; no credential source is read.
const syntheticText = (...parts) => parts.join('');
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { decide } from '../xdr/privilege/decide.mjs';
import { readAlerts, readFixture } from '../xdr/privilege/read-alerts.mjs';
const fixtureURL = new URL('../xdr/fixtures/privilege.json', import.meta.url);
const digest = value => createHash('sha256').update(value).digest('hex');
const event = (description, level = 12, mitre = ['T1078'], group = 'administrators') => ({
  rule: { description, level, mitre }, data: { group },
});
function contract(value) {
  assert.deepEqual(Object.keys(value).sort(), ['action','confidence','reason']);
  assert.ok(Number.isFinite(value.confidence) && value.confidence >= 0 && value.confidence <= 1);
  assert.equal(value.action, value.confidence >= .85 ? 'block' : value.confidence >= .5 ? 'alert' : 'record');
  assert.ok(['privileged_group_change','new_privileged_session_execution','privilege_review_candidate','no_matching_pattern'].includes(value.reason));
}
test('판정 상수는 원본 패턴과 같고 단일 파일은 외부 import 없이 실행된다', async () => {
  const source = await readFile(new URL('../xdr/privilege/decide.mjs', import.meta.url),'utf8');
  const patterns = JSON.parse(await readFile(new URL('../xdr/privilege/patterns.json', import.meta.url),'utf8'));
  assert.doesNotMatch(source, /^\s*import\s|\bimport\s*\(|\bfetch\s*\(|\brequire\s*\(/mu);
  const loaded = await import(`data:text/javascript;base64,${Buffer.from(source+'\nexport { PATTERNS as reviewPatterns };').toString('base64')}`);
  assert.deepEqual(loaded.reviewPatterns,patterns.patterns);
  const out=loaded.decide(event('원격 주소에서 관리자 그룹에 추가됐습니다.'));contract(out);assert.equal(out.action,'block');
});
test('실제 가상 사건은 의미별로 분류하고 입력·원본을 보존한다', async () => {
  const bytes=await readFile(fixtureURL), f=JSON.parse(bytes), before=digest(JSON.stringify(f));
  const results=f.alerts.map(alert=>decide(alert));results.forEach(contract);
  const counts={block:0,alert:0,record:0};results.forEach(x=>counts[x.action]++);
  assert.deepEqual(counts,{block:9,alert:8,record:9});
  assert.equal(digest(JSON.stringify(f)),before);assert.equal(digest(await readFile(fixtureURL)),digest(bytes));
  assert.deepEqual([...f.alerts].reverse().map(a=>decide(a)).reverse(),results);
  assert.deepEqual(decide(f.alerts[0]),results[0]);
});
test('주소·계정·ID 변경은 결과를 바꾸지 않으며 위험 의미 변경은 결과를 바꾼다', () => {
  const strong=event('원격 주소에서 관리자 그룹에 추가됐습니다.');
  const before=decide(strong); assert.equal(before.action,'block');
  const changed={...structuredClone(strong),id:'unrelated-id',data:{...strong.data,srcip:'198.51.100.9',srcuser:'different_synthetic_user',count:'999999'}};
  assert.deepEqual(decide(changed),before);
  assert.equal(decide(event('평소 주소에서 관리자 명령이 한 번 실행됐습니다.',5,['T1068'])).action,'alert');
  assert.equal(decide(event('승인된 정기 관리로 관리자 그룹에 추가됐습니다.')).action,'record');
  assert.equal(decide(event('승인된 정기 관리라고 표시됐지만 처음 보는 주소에서 관리자 그룹에 추가됐습니다.')).action,'block');
  for (const description of ['관리자 그룹에 추가하지 않았다.', '관리자 그룹에 추가되지 않았습니다.', 'administrator group was not added', 'No users were added to administrators group.', 'None of the users were added to administrators group.']) {
    assert.equal(decide(event(description)).action,'alert');
  }
  for (const description of ['unauthorized routine administrator group added', 'unapproved routine administrator group added', 'not authorized routine administrator group added', '승인받지 않은 정기 관리로 관리자 그룹에 추가됐습니다.']) {
    assert.equal(decide(event(description)).action,'block');
  }
});
test('관리자 단어·MITRE·수준·반복 횟수만으로 block하지 않고 오류·비밀값을 반사하지 않는다', () => {
  for(const a of [event('정상 로그인',15,['T1068']),event('',15,['T1078']),event('관리자 명령 실행',15,[]),
    event('관리자 명령 실행 실패',12,['T1068']),event('그룹 소속 조회',12,['T1078']),null,undefined,[],{}]) {
    const out=decide(a);contract(out);assert.notEqual(out.action,'block');
  }
  let called=0;const a=event(syntheticText("원격 주소에서 ", "관리자 그룹에 ", "추가됐습니다. ", "token=PR", "IVATE_SE", "NTINEL"));
  Object.freeze(a.rule);Object.freeze(a.data);Object.freeze(a);
  const out=decide(a,{jev(){called++;}});contract(out);assert.equal(called,0);assert.equal(JSON.stringify(out).includes('PRIVATE_'),false);
});
test('안전 reader는 다섯 필드만 제공하고 모든 선택 문자열의 비밀값을 가린다', async () => {
  const rows=await readFixture();assert.equal(rows.length,26);
  assert.ok(rows.every(r=>Object.keys(r).sort().join(',')==='account,description,ruleLevel,sourceAddress,timestamp'));
  const input={schema:'aleph.xdr.fixture.v1',moduleKey:'privilege',alerts:[{timestamp:syntheticText("token=PR", "IVATE_TI", "ME"),data:{srcip:syntheticText("Bearer P", "RIVATE_S", "OURCE"),srcuser:syntheticText("password", "=PRIVATE", "_ACCOUNT"),extra:'PRIVATE_EXTRA'},rule:{level:0,description:syntheticText("api_key=", "PRIVATE_", "DESCRIPT", "ION")}}]};
  const out=readAlerts(input);assert.ok(['timestamp','sourceAddress','account','description'].every(k=>out[0][k]==='[REDACTED]'));
  assert.equal(JSON.stringify(out).includes('PRIVATE_'),false);assert.equal(out[0].ruleLevel,0);
  assert.throws(()=>readAlerts({schema:'wrong',moduleKey:'privilege',alerts:[]}),{name:'TypeError',message:'INVALID_WAZUH_FIXTURE'});
});
