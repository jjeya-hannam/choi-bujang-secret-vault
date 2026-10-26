// Synthetic redaction fixtures are assembled only during tests; no credential source is read.
const syntheticText = (...parts) => parts.join('');
import test from 'node:test';
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
class Element {
  constructor(tag) { this.tagName=tag.toUpperCase();this.children=[];this.attributes={};this.listeners={};this._text='';this.value='';this.disabled=false;this.isConnected=true; }
  set textContent(v) {this._text=String(v??'');this.children=[];}
  get textContent() {return this._text+this.children.map(n=>n.textContent).join('');}
  set innerHTML(v){throw Error('HTML sink');}
  append(...nodes){this.children.push(...nodes);}
  appendChild(n){this.append(n);return n;}
  replaceChildren(...nodes){this._text='';this.children=nodes;}
  setAttribute(k,v){this.attributes[k]=String(v);}
  getAttribute(k){return this.attributes[k]??null;}
  addEventListener(k,fn){this.listeners[k]=fn;}
  async fire(k){if(!this.disabled)return this.listeners[k]?.({target:this});}
}
globalThis.Element=Element;globalThis.document={createElement:tag=>new Element(tag)};
const module=await import(process.env.STUDENT_SOURCE?pathToFileURL(process.env.STUDENT_SOURCE).href:new URL('../student/extension.mjs',import.meta.url).href);
const view=module.createStudentView();
const walk=n=>[n,...n.children.flatMap(walk)];
const button=(n,name)=>walk(n).find(e=>e.tagName==='BUTTON'&&e.textContent===name);
const marked=(n,name)=>walk(n).filter(e=>e.getAttribute(name)!==null);
const ok=data=>({status:'ok',mode:'demo',data});
const event={id:'event-old',kind:'access',at:'2026-10-23T00:00:00Z',appId:'app-one',summary:'<b>synthetic</b>',evidence:[{id:'proof-one',text:'synthetic proof'}],rules:[{id:'rule-one',text:'synthetic rule'}],state:{access:'unknown',session:'expired',device:'noncompliant'},supportedActions:['revoke_session']};
test('identity reads IDs labels and distinct status values from all resources',()=>{
 const node=view.renderIdentity({me:ok({user:{id:'u-one',label:'Synthetic person'},device:{id:'d-one',label:'Synthetic PC',status:'noncompliant'},session:{id:'s-one',status:'revoked'}}),devices:ok([{id:'d-two',label:'Other PC',status:'compliant'}]),sessions:ok([{id:'s-two',status:'expired'}])});
 for(const value of ['u-one','Synthetic person','d-one','s-one','d-two','s-two','보안 기준 미충족','보안 기준 충족','철회됨','만료','예제 자료'])assert.ok(node.textContent.includes(value),value);
 const next=view.renderIdentity({me:{status:'error',mode:'disconnected',error:{message:'synthetic unavailable'}}});assert.ok(!next.textContent.includes('Synthetic person'));assert.match(next.textContent,/연결 실패.*synthetic unavailable/);assert.match(next.textContent,/연결 없음/);
});
test('identity loading and error preserve mode independently',()=>{for(const mode of ['demo','disconnected','unknown'])for(const status of ['loading','error']){const n=view.renderIdentity({me:{status,mode,error:{message:'mock-error'}}});assert.match(n.textContent,new RegExp({demo:'예제 자료',disconnected:'연결 없음',unknown:'확인 불가'}[mode]));assert.match(n.textContent,status==='loading'?/불러오는 중/:/연결 실패/);}});
test('decision has four distinct values reason timestamp and failure semantics',()=>{for(const decision of ['allow','deny','challenge','unknown','unlisted']){const n=view.renderDecision({status:'ok',data:{appId:'app-one',decision,reason:'synthetic reason',checkedAt:'2026-10-23T00:00:00Z'}});assert.ok(n.textContent.includes(`(${decision==='unlisted'?'unknown':decision})`));assert.match(n.textContent,/synthetic reason/);assert.match(n.textContent,/2026-10-23/);}const n=view.renderDecision({status:'error',mode:'demo',error:{message:'mock-error'}});assert.match(n.textContent,/요청 실패/);assert.match(n.textContent,/거부 판정이 아닙니다/);assert.match(n.textContent,/예제 자료/);assert.ok(!n.textContent.includes('synthetic reason'));});
test('event order filters detail and disabled unsupported actions work locally',async()=>{
 const newer={...structuredClone(event),id:'event-new',kind:'xdr',at:'2026-10-24T00:00:00Z',appId:'app-two',state:{access:'denied',session:'unknown',device:'unknown'},supportedActions:[]};
 const input=ok([event,newer]),before=structuredClone(input),n=view.renderEvents(input);assert.deepEqual(input,before);
 assert.deepEqual(marked(n,'data-student-event-id').map(x=>x.getAttribute('data-student-event-id')),['event-new','event-old']);
 await button(n,'event-old 상세').fire('click');const detail=marked(n,'data-student-event-detail')[0];
 for(const s of ['proof-one','synthetic proof','rule-one','synthetic rule','확인 불가(unknown)','만료(expired)','보안 기준 미충족(noncompliant)'])assert.ok(detail.textContent.includes(s),s);
 assert.equal(button(detail,'revoke_session 미지원').disabled,true);
 const select=walk(n).find(x=>x.getAttribute('aria-label')==='기록 종류');select.value='xdr';await select.fire('change');assert.deepEqual(marked(n,'data-student-event-id').map(x=>x.getAttribute('data-student-event-id')),['event-new']);assert.equal(marked(n,'data-student-event-detail').length,0);
 await button(n,'event-new 상세').fire('click');assert.equal(walk(marked(n,'data-student-event-detail')[0]).filter(x=>x.tagName==='BUTTON').length,0);
 assert.ok(n.textContent.includes('<b>synthetic</b>'));assert.equal(walk(n).filter(x=>x.tagName==='B').length,0);
});
test('events empty error loading and replaced details are distinct',()=>{assert.match(view.renderEvents(ok([])).textContent,/표시할 기록이 없습니다/);const n=view.renderEvents({status:'error',mode:'unknown',error:{message:'mock-down'}});assert.match(n.textContent,/불러오지 못했습니다.*mock-down/);assert.ok(!n.textContent.includes('표시할 기록이 없습니다'));assert.equal(marked(n,'data-student-event-detail').length,0);assert.match(view.renderEvents({status:'loading',mode:'demo'}).textContent,/예제 자료.*불러오는 중/);});
test('status distinguishes empty timeout loading and fresh success',()=>{let n=view.renderStatus({devices:ok([]),sessions:ok([]),notifications:[]});assert.match(n.textContent,/등록된 기기가 없습니다/);assert.match(n.textContent,/현재 연결이 없습니다/);assert.match(n.textContent,/주의할 알림이 없습니다/);n=view.renderStatus({devices:{status:'error',mode:'demo',error:{code:'ENGINE_TIMEOUT',message:'synthetic timeout'}},sessions:{status:'loading',mode:'unknown'},notifications:[{resource:'devices',code:'ENGINE_TIMEOUT',message:'synthetic timeout'}]});for(const s of ['시간 초과','다시 불러오기','불러오는 중','devices','ENGINE_TIMEOUT','synthetic timeout'])assert.ok(n.textContent.includes(s));const next=view.renderStatus({devices:ok([{id:'d',label:'pc',status:'compliant'}]),sessions:ok([{id:'s',status:'active'}])});assert.ok(!next.textContent.includes('synthetic timeout'));assert.match(next.textContent,/보안 기준 충족\(compliant\)/);assert.match(next.textContent,/활성\(active\)/);});
test('diagnostics whitelist copies only after click and handles clipboard failure',async()=>{
 let copied=null;Object.defineProperty(globalThis,'navigator',{configurable:true,value:{clipboard:{writeText:async value=>{copied=value;}}}});
 const n=view.renderStatus({diagnostics:ok({requestId:'request-one',component:'on-client',version:'0.2.14',checkedAt:'2026-10-24T00:00:00Z',engine:{mode:'demo',code:'DEMO_ONLY'},token:'DO_NOT_COPY',nested:{secret:'HIDDEN'}})});
 assert.equal(copied,null);assert.ok(!n.textContent.includes('DO_NOT_COPY'));assert.ok(!n.textContent.includes('HIDDEN'));await button(n,'도움정보 복사').fire('click');assert.ok(copied.includes('request-one'));assert.ok(!copied.includes('DO_NOT_COPY'));assert.match(n.textContent,/도움정보를 복사했습니다/);
 Object.defineProperty(globalThis,'navigator',{configurable:true,value:{clipboard:{writeText:async()=>{throw Error('denied');}}}});await button(n,'도움정보 복사').fire('click');assert.match(n.textContent,/복사하지 못했습니다/);
 const bad=view.renderStatus({diagnostics:ok({requestId:syntheticText("Bearer s", "ynthetic", "-private"),component:'on-client',version:'0.2.14',checkedAt:'now',engine:{mode:'demo',code:'DEMO_ONLY'}})});assert.ok(!bad.textContent.includes('synthetic-private'));
});
