const $ = id => document.getElementById(id);
const SOURCES = { live_http:'실제 HTTP', local_api:'로컬 API', local_decider:'로컬 판정기', local_sql:'로컬 SQL', judge:'심판', not_run:'미실행' };
const STATUSES = { passed:'통과 기록', failed:'실패', not_run:'미실행', historical:'과거 기록', unavailable:'확인 불가' };
const KINDS = { normal:'정상', forbidden:'거부', attack:'공격' };
const CATEGORIES = { api:'API', policy:'정책', detection:'탐지', revocation:'접속 회수', recovery:'복구', device:'기기' };
const CODES = new Set(['allow','deny','step_up','observe','propose_revocation','LOCAL_TESTS_PASSED','SQL_ASSERTIONS_PASSED','JUDGE_SCORE_100']);
const ID = /^[A-Za-z0-9_.:-]{1,100}$/;
const DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const iso = value => value === null || (typeof value === 'string' && DATE.test(value) && Number.isFinite(Date.parse(value)));
const code = value => value === null || (typeof value === 'string' && (CODES.has(value) || /^HTTP_[1-5]\d{2}$/.test(value)));
const commit = value => value === null || (typeof value === 'string' && /^[0-9a-f]{40}$/i.test(value));
const identifier = value => value === null || (typeof value === 'string' && ID.test(value));
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function validSnapshot(snapshot) {
  if(!object(snapshot) || !['available','unavailable'].includes(snapshot.availability)
      || snapshot.scope!=='policy_code_snapshot' || snapshot.source!=='policy-backups/stage9/manifest.json'
      || snapshot.verification!=='manifest_metadata_only' || !commit(snapshot.commit)
      || !Number.isInteger(snapshot.fileCount) || snapshot.fileCount<0 || snapshot.fileCount>4) return false;
  if(snapshot.availability==='unavailable')return snapshot.version===null && snapshot.commit===null && snapshot.fileCount===0;
  return typeof snapshot.version==='string' && /^[A-Za-z0-9_.-]{1,80}$/.test(snapshot.version) && snapshot.commit!==null && snapshot.fileCount>0;
}
let report = null;
let generation = 0;

// Accept only the redacted API contract. No arbitrary server text enters the page.
function validReport(data) {
  if (!object(data) || data.schema !== 'aleph.operations.v1' || data.engineOrigin !== 'ALEPH SDP engine') return false;
  if (!validSnapshot(data.policySnapshot)) return false;
  if (!commit(data.checkedCommit) || !commit(data.deployedCommit) || !iso(data.generatedAt)) return false;
  if (!Array.isArray(data.rules) || data.rules.length > 80 || data.rules.some(rule => typeof rule !== 'string' || !/^[a-z][a-z0-9_.-]{0,79}$/i.test(rule))) return false;
  if (!object(data.summary) || !['available','unavailable'].includes(data.summary.availability)) return false;
  if (['liveApi','detection','revocation','recovery'].some(key => !['confirmed','not_run'].includes(data.summary[key]))) return false;
  if (!Array.isArray(data.checks) || data.checks.length > 500 || data.checks.some(check => !object(check)
      || !identifier(check.id) || check.id === null || !Number.isInteger(check.stage) || check.stage < 1 || check.stage > 12
      || (check.category !== undefined && !Object.hasOwn(CATEGORIES,check.category))
      || !Object.hasOwn(KINDS,check.kind) || !code(check.expected) || !code(check.actual) || !identifier(check.requestId)
      || !iso(check.checkedAt) || !Object.hasOwn(SOURCES,check.source) || !Object.hasOwn(STATUSES,check.status))) return false;
  const campaign = data.campaign;
  return object(campaign) && campaign.total === 41 && campaign.coverageBasis === 'official_campaign_results_not_available'
    && campaign.executed === 0 && campaign.notRun === 41;
}
function time(value) {
  return value === null ? '미기록' : new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(new Date(value));
}
function element(tag,text,className) {
  const node=document.createElement(tag); if (text !== undefined) node.textContent=text; if (className) node.className=className; return node;
}
function setStatus(text,state='ready') { $('load-status').textContent=text; $('load-status').dataset.state=state; }
function emptyRow(text) { const row=element('tr'); const cell=element('td',text);cell.colSpan=9;row.append(cell);$('checks').replaceChildren(row); }
function result(value) {
  if(value===null)return '미기록';
  const labels={200:'정상 응답',201:'생성됨',204:'처리 완료',401:'로그인 필요',403:'권한 거부',404:'자료 접근 불가',429:'호출 상한',allow:'허용',deny:'거부',step_up:'추가 확인',observe:'관찰',propose_revocation:'회수 제안',LOCAL_TESTS_PASSED:'로컬 검사 통과',SQL_ASSERTIONS_PASSED:'SQL 검증 통과',JUDGE_SCORE_100:'심판 점수 100'};
  const key=value.replace(/^HTTP[:_/]?/i,'').split(/[/:]/)[0];
  return Object.hasOwn(labels,key)?`${labels[key]} · ${value}`:value;
}
function clearReport(text) {
  report=null; $('checked-commit').textContent='미확인';$('deployed-commit').textContent='미확인';$('generated-at').textContent='미확인';
  $('commit-alignment').textContent='현재 배포와 검증 대상의 일치 여부는 미확인입니다.';
  $('snapshot-version').textContent='미확인';$('snapshot-commit').textContent='미확인';$('snapshot-files').textContent='미확인';$('snapshot-status').textContent='사본 메타데이터를 확인할 수 없습니다. 실제 복구 완료 여부도 별도 확인이 필요합니다.';
  for(const key of ['liveApi','detection','revocation','recovery']){$(key).textContent='미확인';$(key).dataset.state='unavailable';}
  $('campaign-executed').textContent='미확인';$('campaign-not-run').textContent='미확인';$('campaign-basis').textContent='현재 기록의 실행 범위를 확인할 수 없습니다.';
  $('rules').replaceChildren(element('li','기록 미확인'));$('row-count').textContent='검증 기록 미확인';emptyRow(text);
}
function renderChecks() {
  if(!report) return;
  const visible=report.checks.filter(check => ($('stage-filter').value==='all' || String(check.stage)===$('stage-filter').value)
    && ($('source-filter').value==='all' || check.source===$('source-filter').value)
    && ($('status-filter').value==='all' || check.status===$('status-filter').value));
  const counts=Object.fromEntries(Object.keys(STATUSES).map(status=>[status,visible.filter(check=>check.status===status).length]));
  $('row-count').textContent=`전체 ${report.checks.length}건 중 ${visible.length}건 표시 · 통과 기록 ${counts.passed} · 실패 ${counts.failed} · 미실행 ${counts.not_run} · 과거 ${counts.historical} · 확인 불가 ${counts.unavailable}`;
  if(!visible.length){emptyRow(report.checks.length?'선택한 조건의 기록이 없습니다.':'실행 기록이 없습니다. 통과 여부는 미확인입니다.');return;}
  const rows=visible.map(check=>{
    const row=element('tr');const name=element('td',`${check.stage}단계`);name.append(element('span',check.id,'check-id'));row.append(name);
    for(const text of [CATEGORIES[check.category??'api'],KINDS[check.kind],result(check.expected),result(check.actual),check.requestId??'미기록',time(check.checkedAt),SOURCES[check.source]])row.append(element('td',text));
    const state=element('td');const badge=element('span',STATUSES[check.status],'status-badge');badge.dataset.state=check.status;state.append(badge);row.append(state);return row;
  });
  $('checks').replaceChildren(...rows);
}
function renderReport(data) {
  report=data;$('checked-commit').textContent=data.checkedCommit??'미확인';$('deployed-commit').textContent=data.deployedCommit??'미확인';$('generated-at').textContent=data.generatedAt===null?'미확인':time(data.generatedAt);
  $('commit-alignment').textContent=!data.checkedCommit||!data.deployedCommit?'현재 배포와 검증 대상의 일치 여부는 미확인입니다.':data.checkedCommit===data.deployedCommit?'검증 대상과 배포 커밋이 같습니다. 심판 통과 여부는 각 기록의 출처와 상태로 확인하세요.':'검증 대상과 현재 배포 커밋이 다릅니다. 이 기록은 현재 배포를 검증했다는 증거가 아닙니다.';
  const snapshot=data.policySnapshot, snapshotAvailable=snapshot.availability==='available';
  $('snapshot-version').textContent=snapshotAvailable?snapshot.version:'미확인';$('snapshot-commit').textContent=snapshotAvailable?snapshot.commit:'미확인';$('snapshot-files').textContent=snapshotAvailable?`${snapshot.fileCount}개`:'미확인';
  $('snapshot-status').textContent=snapshotAvailable?'manifest 메타데이터만 확인했습니다. 사본 파일 내용·해시를 현재 재검증한 기록과 실제 정책·메모 복구 완료 증거는 별도입니다.':'사본 메타데이터를 확인할 수 없습니다. 실제 복구 완료 여부도 별도 확인이 필요합니다.';
  const available=data.summary.availability==='available';
  for(const key of ['liveApi','detection','revocation','recovery']){
    const state=available?data.summary[key]:'unavailable';$(key).dataset.state=state;$(key).textContent=state==='confirmed'?'확인 기록 있음':state==='not_run'?'미실행 · 운영 확인 없음':'기록 확인 불가';
  }
  $('campaign-executed').textContent=available?`${data.campaign.executed} / 41`:'미확인';$('campaign-not-run').textContent=available?String(data.campaign.notRun):'미확인';
  $('campaign-basis').textContent=available?'공식 41개 공격의 개별 실행 결과가 제공되지 않았습니다. 아래 로컬·과거 기록과 별도로 표시합니다.':'검증 보고서가 없어 실행 범위는 미확인입니다.';
  $('rules').replaceChildren(...(data.rules.length?data.rules.map(rule=>element('li',rule)):[element('li','등록 규칙 기록 없음')]));
  renderChecks();setStatus(available?'서버의 검증 기록을 읽었습니다. 출처별 결과를 확인하세요.':'서버는 응답했지만 검증 보고서가 없습니다. 완료 여부는 미확인입니다.',available?'ready':'error');
}
async function loadReport() {
  const started=++generation;clearReport('기록을 읽는 중입니다.');$('retry').disabled=true;setStatus('서버에서 검증 기록을 읽는 중입니다.','loading');
  try {
    if(!navigator.onLine)throw new Error('offline');
    const response=await fetch('/api/operations',{method:'GET',credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
    if(!response.ok)throw new Error('unavailable');
    const data=await response.json();if(started!==generation)return;
    if(!validReport(data))throw new Error('invalid_report');renderReport(data);
  } catch {
    if(started!==generation)return;clearReport('검증 기록을 확인할 수 없습니다. 연결 후 다시 읽어 주세요.');
    setStatus(navigator.onLine?'기록을 확인하지 못했습니다. 통과 또는 완료로 표시하지 않습니다.':'오프라인입니다. 서버 기록을 확인할 수 없습니다.','error');
  } finally {if(started===generation)$('retry').disabled=false;}
}
$('filters').addEventListener('submit',event=>event.preventDefault());
for(let stage=1;stage<=12;stage++){const option=element('option',`${stage}단계`);option.value=String(stage);$('stage-filter').append(option);}
for(const id of ['stage-filter','source-filter','status-filter'])$(id).addEventListener('change',renderChecks);
$('retry').addEventListener('click',loadReport);
window.addEventListener('offline',()=>{generation++;clearReport('오프라인에서는 기록을 확인할 수 없습니다.');$('retry').disabled=false;setStatus('오프라인입니다. 연결 후 기록을 다시 읽어 주세요.','error');});
window.addEventListener('online',loadReport);
loadReport();
