import test from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
class Element {
 constructor(tag){this.tagName=tag.toUpperCase();this.children=[];this.attributes={};this.value='';}
 set textContent(v){this.value=String(v??'');this.children=[];}
 get textContent(){return this.value+this.children.map(x=>x.textContent).join('');}
 set innerHTML(v){throw Error('HTML sink');}
 appendChild(x){this.children.push(x);return x;}
 setAttribute(k,v){this.attributes[k]=String(v);}
 getAttribute(k){return this.attributes[k]??null;}
}
globalThis.document={createElement:tag=>new Element(tag)};
globalThis.fetch=()=>{throw Error('network forbidden');};
const source=process.env.STUDENT_SOURCE??new URL('../student/extension.mjs',import.meta.url).pathname.replace(/^\/([A-Z]:)/,'$1');
const view=(await import(pathToFileURL(source))).createStudentView();
const event={id:'event-demo',evidence:[{id:'proof-demo'}],supportedActions:['revoke_session']};
const receipt={requestId:'request-demo',receiptId:'receipt-demo',version:2,status:'pending'};
const render=(fn,input)=>{const before=structuredClone(input);const result=view[fn](input);assert.deepEqual(input,before);assert.ok(result instanceof Element);return result;};
const walk=n=>[n,...n.children.flatMap(walk)];
test('action states and intent binding',()=>{
 for(const [status,phrase] of Object.entries({idle:'미실행',loading:'중',prepared:'미실행',executing:'아직',pending:'ACK',denied:'거절',failed:'실패',expired:'다시 준비',error:'처리 안 됨',unknown:'결과 불명'})){
 const root=render('renderAction',{status,event,actionId:'revoke_session',target:{id:'device:demo',generation:3},receipt,message:'연습 오류 사유',error:{code:'ACTION_DENIED',message:'연습 상세 사유'},confirmationExpiresAt:'2026-11-01T00:00:00Z'});
 for(const v of [phrase,status,'event-demo','proof-demo','revoke_session','device:demo','3','request-demo','receipt-demo','2'])assert.ok(root.textContent.includes(v),`${status}: ${v}`);
 assert.equal(root.getAttribute('data-student-action-event'),event.id);assert.equal(root.getAttribute('data-student-action-request'),receipt.requestId);
 assert.equal(walk(root).filter(n=>['BUTTON','INPUT','SCRIPT','FORM'].includes(n.tagName)).length,0);
 }
});
test('effect confirmation requires true; replay is not new execution',()=>{
 for(const effectApplied of [false,undefined,null,'true']){
 const t=render('renderAction',{status:'succeeded',event,receipt,observation:{effectApplied,observedAt:'2026-10-24T00:00:00Z'}}).textContent;
 assert.ok(t.includes('결과 불명'));assert.ok(!t.includes('효과 확인(succeeded)'));
 }
 const t=render('renderAction',{status:'succeeded',event,receipt:{...receipt,replayed:true},observation:{effectApplied:true,observedAt:'2026-10-24T00:00:00Z'}}).textContent;
 for(const v of ['효과 확인(succeeded)','2026-10-24T00:00:00Z','effectApplied: true','receipt-demo','새 실행으로 세지 않습니다'])assert.ok(t.includes(v));
});
test('new action drops previous intent and unsupported action explained',()=>{
 render('renderAction',{status:'pending',event,receipt});
 const root=render('renderAction',{status:'idle',event:{id:'new-event',evidence:[],supportedActions:[]}});
 for(const old of ['event-demo','proof-demo','request-demo','receipt-demo'])assert.ok(!root.textContent.includes(old));
 assert.match(root.textContent,/지원.*조치.*없/);assert.equal(root.getAttribute('data-student-action-request'),null);
});
const scan={status:'partial',lockfileVersion:3,lockfileHash:'a'.repeat(64),checkedAt:'2026-10-24T00:00:00Z',packages:[{name:'synthetic-package',version:'1.2.3',status:'unverifiable',source:'https://api.osv.dev/v1/querybatch',checkedAt:'2026-10-24T00:00:00Z',vulnerabilities:[{id:'CVE-2026-12345',modified:'2026-10-23T00:00:00Z'}]}]};
test('partial scan preserves ID provenance timestamps markers',()=>{
 const root=render('renderVulnerabilities',{status:'ok',mode:'demo',data:scan});
 for(const v of ['partial','3',scan.lockfileHash,scan.checkedAt,'synthetic-package','1.2.3','unverifiable','일부 확인·전체 조회 확인 불가','CVE-2026-12345','2026-10-23T00:00:00Z',scan.packages[0].source,'예제 자료'])assert.ok(root.textContent.includes(v),v);
 const row=walk(root).find(n=>n.getAttribute('data-student-package-name'));
 assert.equal(row.getAttribute('data-student-package-name'),'synthetic-package');assert.equal(row.getAttribute('data-student-package-version'),'1.2.3');
});
test('all scan states and replacements drop previous results',()=>{
 for(const status of ['complete','partial','not_checked','not_configured','unverifiable']){
 const root=render('renderVulnerabilities',{status:'ok',data:{...scan,status,packages:[]}});assert.ok(root.textContent.includes(status));assert.ok(!root.textContent.includes('synthetic-package'));
 }
 render('renderVulnerabilities',{status:'ok',data:scan});
 for(const [status,phrase] of [['idle','조회 전'],['loading','조회 중'],['error','조회 실패']]){
 const root=render('renderVulnerabilities',{status,mode:'disconnected',error:{message:'연습 연결 실패'}});
 for(const v of [phrase,'연결 없음'])assert.ok(root.textContent.includes(v));
 for(const old of ['synthetic-package','CVE-2026-12345',scan.lockfileHash])assert.ok(!root.textContent.includes(old));
 }
 const root=render('renderVulnerabilities',{status:'ok',data:{...scan,lockfileHash:'b'.repeat(64)}});assert.ok(root.textContent.includes('b'.repeat(64)));assert.ok(!root.textContent.includes(scan.lockfileHash));
});
test('markup is inert text and safe errors remain visible',()=>{
 const payload='<img src=x onerror=alert(1)>';
 for(const root of [render('renderAction',{status:'error',error:{code:'ACTION_DENIED',message:payload}}),render('renderVulnerabilities',{status:'error',error:{message:payload}})]){
 assert.ok(root.textContent.includes(payload));assert.equal(walk(root).filter(n=>n.tagName==='IMG').length,0);
 }
});


test('scan omits absent metadata and qualifies none_found by lookup scope',()=>{
 const empty=render('renderVulnerabilities',{status:'ok',data:{status:'not_configured',packages:[]}}).textContent;
 for(const absent of ['lockfileVersion:','lockfileHash:','조회 시각:'])assert.ok(!empty.includes(absent));
 const clean=render('renderVulnerabilities',{status:'ok',data:{...scan,status:'complete',packages:[{...scan.packages[0],status:'none_found',vulnerabilities:[]}]}}).textContent;
 assert.ok(clean.includes('조회 범위에서 알려진 항목 없음'));assert.ok(clean.includes('none_found'));
});
