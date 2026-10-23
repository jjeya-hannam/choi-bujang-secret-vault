import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL, fileURLToPath } from 'node:url';
import path from 'node:path';

class MockElement {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attributes = {}; this._text = ''; this.dataset = new Proxy({}, { set: (_, k, v) => { this.setAttribute('data-' + k.replace(/[A-Z]/g, x => '-' + x.toLowerCase()), v); return true; } }); this.style = {}; this.classList = { add: () => {} }; }
  set textContent(value) { this._text = String(value ?? ''); this.children = []; }
  get textContent() { return this._text + this.children.map(n => typeof n === 'string' ? n : n.textContent).join(''); }
  set innerHTML(_) { throw Error('HTML sink used'); }
  get innerHTML() { throw Error('HTML sink used'); }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k] ?? null; }
  removeAttribute(k) { delete this.attributes[k]; }
  append(...nodes) { this.children.push(...nodes); }
  appendChild(node) { this.append(node); return node; }
  replaceChildren(...nodes) { this._text = ''; this.children = [...nodes]; }
  addEventListener() { throw Error('Unexpected event handler'); }
}
globalThis.Element = MockElement;
globalThis.document = { createElement: tag => new MockElement(tag), createTextNode: text => String(text) };
const source = process.env.STUDENT_SOURCE ? path.resolve(process.env.STUDENT_SOURCE) : fileURLToPath(new URL('../student/extension.mjs', import.meta.url));
const module = await import(pathToFileURL(source));
const view = module.createStudentView();
const clone = structuredClone;
const event = { id: 'event-A', kind: 'xdr', at: '2026-10-23T00:00:00Z', appId: 'course-app', summary: 'event summary', evidence: [{ id: 'e-A', text: 'first evidence' }, { id: 'e-B', text: 'second evidence' }], rules: [{ id: 'rule-A', text: 'rule content' }], state: { access: 'unknown', session: 'unknown', device: 'unknown' }, supportedActions: [] };
const data = { summary: 'Synthetic AI summary', evidenceIds: ['e-A', 'e-B'], proposals: [], requiresHumanConfirmation: true, executed: false };
const input = (e = event, d = data) => ({ event: clone(e), explanation: { status: 'ok', data: clone(d) }, checkedAt: '2026-10-23T00:00:01Z' });
const text = node => typeof node === 'string' ? node : node.textContent;
const walk = node => node instanceof MockElement ? [node, ...node.children.flatMap(walk)] : [];
const marker = node => walk(node).filter(n => n.getAttribute('data-student-explanation-event'));
function render(value) { const before = clone(value); const node = view.renderExplanation(value); assert.deepEqual(value, before, 'input mutation'); assert.ok(node instanceof MockElement || typeof node === 'string'); assert.equal(walk(node).filter(n => ['BUTTON','SCRIPT','IFRAME','INPUT','FORM'].includes(n.tagName)).length, 0); return node; }

test('success binds current event, evidence, rules and three unknown states', () => { const node = render(input()); const t = text(node); for (const s of ['event-A','Synthetic AI summary','e-A','first evidence','e-B','second evidence','rule-A','rule content','접속','세션','기기','unknown','참고']) assert.ok(t.includes(s), s); assert.equal(marker(node).length, 1); assert.equal(marker(node)[0].getAttribute('data-student-explanation-event'), 'event-A'); assert.match(t, /지원.*조치.*없|조치.*지원.*없/); });
test('success data variations follow current evidence and rule text', () => { const e = clone(event); e.id = 'event-B'; e.evidence = [{ id: 'other-evidence', text: 'replacement proof' }]; e.rules = [{id:'other-rule', text:'replacement rule'}]; const d = {...clone(data), evidenceIds:['other-evidence'], summary:'new summary'}; const t = text(render(input(e,d))); for (const s of ['event-B','other-evidence','replacement proof','other-rule','replacement rule']) assert.ok(t.includes(s), s); for (const s of ['event-A','first evidence','rule content']) assert.ok(!t.includes(s), s); });
test('error has priority with no event and does not reflect sensitive message', () => { const node = render({ event:null, explanation:{status:'error',error:{code:'ON_AI_UNAUTHORIZED',message:'Bearer secret-example-token person@example.test'}} }); assert.match(text(node), /실패|오류|권한|인증/); assert.match(text(node), /기록.*그대로|기록.*유지/); assert.ok(!text(node).includes('secret-example-token')); assert.ok(!text(node).includes('person@example.test')); assert.equal(marker(node).length, 0); });
test('loading and no-event have distinct safe views', () => { const loading = render({event:clone(event), explanation:{status:'loading'}}); assert.match(text(loading), /요청.*중|불러.*중|설명.*중/); assert.equal(marker(loading).length, 0); const empty = render({event:null, explanation:{status:'idle'}}); assert.match(text(empty), /기록.*고르|사건.*선택|기록.*선택/); assert.equal(marker(empty).length, 0); });
test('unknown evidence rejected without success marker or summary', () => { const d = {...clone(data), evidenceIds:['absent-proof'], summary:'REJECTED_SUMMARY'}; const node = render(input(event,d)); assert.equal(marker(node).length, 0); assert.ok(!text(node).includes('REJECTED_SUMMARY')); assert.match(text(node), /근거.*맞|근거.*일치|근거.*없|근거.*확인/); });
test('empty/incomplete evidence and executed explanation rejected', () => { for (const d of [{...clone(data),evidenceIds:[]},{...clone(data),evidenceIds:['e-A']},{...clone(data),executed:true}]) assert.equal(marker(render(input(event,d))).length,0); });
test('proposal displays action reason human confirmation and no execution controls', () => { const e = {...clone(event),supportedActions:['revoke_session']}; const d = {...clone(data),proposals:[{action:'revoke_session',evidenceIds:['e-A'],reason:'Synthetic reason'}]}; const node = render(input(e,d)); for (const s of ['revoke_session','Synthetic reason']) assert.ok(text(node).includes(s)); assert.match(text(node), /사람.*확인/); assert.match(text(node), /실행되지|미실행|실행.*않/); });
test('no proposals with supported actions explains AI omitted proposals', () => { const node = render(input({...clone(event),supportedActions:['revoke_session']})); assert.match(text(node), /AI.*제안.*없|AI.*제안.*않/); });
test('text insertion treats markup as inert text', () => { const payload = '<img src=x onerror=alert(1)>'; const e = clone(event); e.evidence[0].text = payload; e.rules[0].text = payload; const d = {...clone(data),summary:payload}; const node = render(input(e,d)); assert.ok(text(node).includes(payload)); assert.equal(walk(node).filter(n => n.tagName === 'IMG').length, 0); });
test('new calls cannot carry previous event explanation or success marker', () => { render(input()); for(const value of [{event:null,explanation:{status:'idle'}},{event:clone(event),explanation:{status:'loading'}},{event:null,explanation:{status:'error',error:{code:'CANCELLED',message:'cancelled'}}}]) {const node=render(value); assert.equal(marker(node).length,0); assert.ok(!text(node).includes('Synthetic AI summary'));} });
test('other starter view functions remain unchanged', async () => { const src = await readFile(source,'utf8'); for (const name of ['renderIdentity','renderDecision','renderEvents','renderStatus','renderVulnerabilities','renderAiConnection','renderAction']) { assert.equal(typeof view[name], 'function'); assert.match(view[name](), /학생 구현 대기/); } assert.ok(!/\bfetch\s*\(/.test(src)); });
test('secret-shaped identifiers are rejected without reflection', () => { const fake = 'sk-proj-syntheticexample000'; const variants = []; const eventId = clone(event); eventId.id = fake; variants.push(input(eventId)); const evidenceId = clone(event); evidenceId.evidence[0].id = fake; variants.push(input(evidenceId,{...clone(data),evidenceIds:[fake,'e-B']})); const ruleId = clone(event); ruleId.rules[0].id=fake; variants.push(input(ruleId)); for(const value of variants) {const node=render(value);assert.equal(marker(node).length,0);assert.ok(!text(node).includes(fake));} });

test('safe insufficient-evidence error retains specific reason even without event', () => {
  const message = '이 기록에는 연결할 근거가 부족하여 설명을 만들 수 없습니다.';
  for (const currentEvent of [null, clone(event)]) {
    const node = render({ event: currentEvent, explanation: { status: 'error', error: { code: 'ON_AI_INVALID_OUTPUT', message } } });
    assert.ok(text(node).includes(message));
    assert.ok(text(node).includes('ON_AI_INVALID_OUTPUT'));
    assert.match(text(node), /기록.*그대로|기록.*유지/);
    assert.equal(marker(node).length, 0);
  }
});

test('unsafe missing control and excessive error messages use safe fallback', () => {
  const rejected = [undefined, null, '', '   ', 'Bearer synthetic-secret-value', 'api_key=synthetic-secret-value', 'sk-proj-syntheticexample000', '앞\u0000뒤', '앞\u001b뒤', '앞\n뒤', '앞\t뒤', '앞\u007f뒤', '초'.repeat(501)];
  for (const message of rejected) {
    const node = render({ event: null, explanation: { status: 'error', error: { code: 'ON_AI_INVALID_OUTPUT', message } } });
    assert.match(text(node), /근거·조치·응답 형식을 확인할 수 없습니다/);
    if (typeof message === 'string' && message.trim()) assert.ok(!text(node).includes(message));
    assert.equal(marker(node).length, 0);
  }
});

test('safe error markup remains literal text with no DOM execution', () => {
  const message = '<img src=x onerror=alert(1)> 근거가 부족합니다.';
  const node = render({ event: null, explanation: { status: 'error', error: { code: 'ON_AI_INVALID_OUTPUT', message } } });
  assert.ok(text(node).includes(message));
  assert.equal(walk(node).filter(n => n.tagName === 'IMG').length, 0);
  assert.equal(marker(node).length, 0);
});

test('duplicate evidence and unsupported or unconfirmed proposals cannot succeed', () => {
  const variants = [
    {...clone(data),evidenceIds:['e-A','e-A']},
    {...clone(data),requiresHumanConfirmation:false},
    {...clone(data),proposals:[{action:'revoke_session',evidenceIds:['e-A'],reason:'unsupported action'}]},
  ];
  for(const d of variants) assert.equal(marker(render(input(event,d))).length, 0);
});

test('credential-shaped JWT and personal-address errors are not reflected', () => {
  const rejected = ['인증 응답 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.syntheticSignature0123456789', '계정 synthetic.person@example.test 연결을 확인하세요.'];
  for (const message of rejected) {
    const node = render({event:null, explanation:{status:'error',error:{code:'ON_AI_INVALID_OUTPUT',message}}});
    assert.ok(!text(node).includes(message));
    assert.match(text(node), /근거·조치·응답 형식을 확인할 수 없습니다/);
    assert.equal(marker(node).length, 0);
  }
});
