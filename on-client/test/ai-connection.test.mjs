import test from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL, fileURLToPath } from 'node:url';
import path from 'node:path';
class MockElement {
  constructor(tag) { this.tagName=tag.toUpperCase();this.children=[];this.attributes={};this._text=''; }
  set textContent(value) { this._text=String(value??'');this.children=[]; }
  get textContent() { return this._text+this.children.map(n=>n.textContent).join(''); }
  set innerHTML(_) { throw Error('HTML sink'); }
  set outerHTML(_) { throw Error('HTML sink'); }
  insertAdjacentHTML() { throw Error('HTML sink'); }
  appendChild(node) { this.children.push(node);return node; }
  setAttribute(k,v) { this.attributes[k]=String(v); }
  getAttribute(k) { return this.attributes[k]??null; }
  addEventListener() { throw Error('No student controls'); }
}
globalThis.document={createElement:tag=>new MockElement(tag)};
const source=process.env.STUDENT_SOURCE?path.resolve(process.env.STUDENT_SOURCE):fileURLToPath(new URL('../student/extension.mjs',import.meta.url));
const {createStudentView}=await import(pathToFileURL(source));
const view=createStudentView();
const time='2026-10-24T13:00:00Z';
const ok=(audienceAuthorization='verified',modelCount=7)=>({status:'ok',mode:'connected',data:{transportChecked:true,audienceAuthorization,modelCount,help:{}},checkedAt:time,explanationAccepted:false});
const walk=node=>[node,...node.children.flatMap(walk)];
function render(input) { const before=structuredClone(input);const node=view.renderAiConnection(input);assert.deepEqual(input,before);assert.ok(node instanceof MockElement);assert.equal(walk(node).filter(n=>['BUTTON','INPUT','FORM','SCRIPT','IMG','IFRAME'].includes(n.tagName)).length,0);return node; }
test('verified and test distinguish transport from unrequested explanation',()=>{for(const authorization of ['verified','test']){const node=render(ok(authorization));for(const term of [authorization,'7',time,'transportChecked: true'])assert.ok(node.textContent.includes(term));assert.match(node.textContent,/사건 설명은 아직 실행하지 않았/);assert.match(node.textContent,/모델 호출.*별도/);if(authorization==='test')assert.match(node.textContent,/실제 게이트 수용 아님/);}});
test('fresh idle loading error trees discard previous model count and time',()=>{const first=render(ok());for(const value of [{status:'idle'},{status:'loading'},{status:'error',error:{code:'WB_CLCO_AUTH_REQUIRED',message:'계정 인증을 확인하세요.'}}]){const node=render(value);assert.notEqual(first,node);assert.ok(!node.textContent.includes('응답 모델 수: 7'));assert.ok(!node.textContent.includes(time));}});
test('error categories give safe code cause and manual next step',()=>{const cases={ON_AI_PROVISIONING_PENDING:/준비 중/,WB_CLCO_AUTH_REQUIRED:/인증/,WB_CLCO_ACCESS_BLOCKED:/제한/,WB_CLCO_COHORT_BUDGET_EXHAUSTED:/사용량/,WB_CLCO_LIMIT_REACHED:/한도/,WB_CLCO_SESSION_CLOSED:/이용 시간/,WB_CLCO_RATE_LIMITED:/요청.*제한/,TIMEOUT:/시간.*초과/,CANCELLED:/취소/,ON_AI_MODEL_LIST_EMPTY:/모델.*없/,AI_REQUEST_UNVERIFIED:/확인.*없/};for(const[code,pattern]of Object.entries(cases)){const node=render({status:'error',mode:'unknown',error:{code,message:'서버가 안전하게 정리한 안내입니다.'}});assert.ok(node.textContent.includes(code));assert.ok(node.textContent.includes('서버가 안전하게 정리한 안내입니다.'));assert.match(node.textContent,pattern);assert.match(node.textContent,/직접.*누르/);}});
test('unsafe messages and unknown codes never leak',()=>{for(const payload of ['Bearer synthetic-secret','sk-proj-syntheticexample000','api_key=synthetic-secret','person@example.test','eyJfake.payload.signature','앞\u0000뒤','x'.repeat(501)]){const node=render({status:'error',error:{code:payload,message:payload}});assert.ok(!node.textContent.includes(payload));assert.match(node.textContent,/AI_REQUEST_UNVERIFIED/);}});
test('safe error markup remains literal text',()=>{const payload='<img src=x onerror=alert(1)> 연결을 확인하세요.';const node=render({status:'error',error:{code:'AI_REQUEST_UNVERIFIED',message:payload}});assert.ok(node.textContent.includes(payload));assert.equal(walk(node).filter(n=>n.tagName==='IMG').length,0);});
test('all modes persist during idle loading error and success',()=>{for(const[mode,term]of Object.entries({demo:'예제 자료',disconnected:'연결 없음',unknown:'확인 불가'}))for(const value of [{status:'idle'},{status:'loading'},{status:'error',error:{}},ok()])assert.ok(render({...value,mode}).textContent.includes(term));});
test('invalid success data fails without model result',()=>{for(const value of [{...ok(),data:null},{...ok(),data:{...ok().data,transportChecked:false}},{...ok(),data:{...ok().data,audienceAuthorization:'unsafe'}},{...ok(),data:{...ok().data,modelCount:-1}},{...ok(),checkedAt:'not-time'}]){const node=render(value);assert.match(node.textContent,/확인할 수 없/);assert.ok(!node.textContent.includes('응답 모델 수:'));}});
test('manual recovery replaces auth cancel timeout errors',()=>{for(const code of ['WB_CLCO_AUTH_REQUIRED','CANCELLED','TIMEOUT']){render({status:'error',error:{code}});const node=render(ok());assert.ok(!node.textContent.includes(code));assert.ok(!node.textContent.includes('점검 실패'));assert.ok(node.textContent.includes('응답 모델 수: 7'));}});
test('zero count remains zero with no claim of explanation success',()=>{const node=render(ok('verified',0));assert.match(node.textContent,/응답 모델 수: 0/);assert.match(node.textContent,/모델.*없/);assert.match(node.textContent,/사건 설명은 아직 실행하지 않았/);});
