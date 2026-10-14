// Self-contained HTTP checker for the operator's isolated bundle runner.
// No imports, local fixtures, credentials, note content or identity values.
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const allowedKeys = (value, keys) => object(value) && Object.keys(value).every(key => keys.includes(key));
const sha = value => typeof value === 'string' && /^[0-9a-f]{40}$/u.test(value);
const iso = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)
  && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().replace('.000Z', 'Z') === value.replace('.000Z', 'Z');
const fixedCode = value => value === null || (typeof value === 'string'
  && /^(?:HTTP_[1-5]\d{2}|allow|deny|step_up|observe|propose_revocation|LOCAL_TESTS_PASSED|SQL_ASSERTIONS_PASSED|JUDGE_SCORE_100)$/u.test(value));
const sources = ['live_http', 'local_api', 'local_decider', 'local_sql', 'judge', 'not_run'];
const statuses = ['passed', 'failed', 'not_run', 'historical', 'unavailable'];
const categories = ['api', 'policy', 'detection', 'revocation', 'recovery', 'device'];

function trustedBase(config) {
  if (!Number.isSafeInteger(config?.step) || config.step < 1 || config.step > 12
      || typeof config.publicAppUrl !== 'string' || config.publicAppUrl !== config.publicAppUrl.trim()) {
    throw new Error('invalid_check_configuration');
  }
  let url;
  try { url = new URL(config.publicAppUrl); } catch { throw new Error('invalid_check_configuration'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash || url.pathname !== '/'
      || ![url.origin, url.origin + '/'].includes(config.publicAppUrl)
      || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/u.test(url.hostname)) {
    throw new Error('invalid_check_configuration');
  }
  return url;
}

async function get(base, path) {
  try {
    const response = await fetch(new URL(path, base), {
      method: 'GET', cache: 'no-store', redirect: 'error', credentials: 'omit',
      headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10000),
    });
    const status = Number.isSafeInteger(response.status) && response.status >= 100 && response.status <= 599 ? response.status : 0;
    let data = null;
    if (/(?:application\/json|application\/manifest\+json)/iu.test(response.headers.get('content-type') ?? '')) {
      try { data = await response.json(); } catch { /* Malformed JSON is recorded as a failed check. */ }
    }
    return { status, data, unavailable: false };
  } catch { return { status: 0, data: null, unavailable: true }; }
}

function result(response, passed) {
  return response.unavailable ? '실제 HTTP 확인 불가; network_unavailable'
    : '실제 HTTP ' + response.status + '; result=' + (passed ? 'passed' : 'failed');
}

function operationsShape(data) {
  if (!allowedKeys(data, ['schema', 'checkedCommit', 'deployedCommit', 'generatedAt', 'engineOrigin', 'rules',
    'summary', 'checks', 'campaign', 'policySnapshot']) || data.schema !== 'aleph.operations.v1'
      || !(data.checkedCommit === null || sha(data.checkedCommit))
      || !(data.deployedCommit === null || sha(data.deployedCommit))
      || !(data.generatedAt === null || iso(data.generatedAt))
      || data.engineOrigin !== 'ALEPH SDP engine' || !Array.isArray(data.rules) || data.rules.length > 80
      || data.rules.some(rule => typeof rule !== 'string' || !/^[a-z][a-z0-9_.-]{0,79}$/u.test(rule))
      || new Set(data.rules).size !== data.rules.length
      || !allowedKeys(data.summary, ['availability', 'liveApi', 'detection', 'revocation', 'recovery'])
      || !['available', 'unavailable'].includes(data.summary.availability)
      || ['liveApi', 'detection', 'revocation', 'recovery'].some(key => !['confirmed', 'not_run'].includes(data.summary[key]))
      || !Array.isArray(data.checks) || data.checks.length > 200
      || !allowedKeys(data.campaign, ['total', 'executed', 'notRun', 'coverageBasis'])
      || data.campaign.total !== 41 || data.campaign.executed !== 0 || data.campaign.notRun !== 41
      || data.campaign.coverageBasis !== 'official_campaign_results_not_available'
      || !allowedKeys(data.policySnapshot, ['availability', 'scope', 'source', 'version', 'commit', 'fileCount', 'verification'])
      || !['available', 'unavailable'].includes(data.policySnapshot.availability)
      || data.policySnapshot.scope !== 'policy_code_snapshot' || data.policySnapshot.source !== 'policy-backups/stage9/manifest.json'
      || data.policySnapshot.verification !== 'manifest_metadata_only') return false;
  const snapshot = data.policySnapshot;
  if (snapshot.availability === 'available') {
    if (!sha(snapshot.commit) || snapshot.version !== 'stage9-' + snapshot.commit.slice(0, 7) || snapshot.fileCount !== 4) return false;
  } else if (snapshot.commit !== null || snapshot.version !== null || snapshot.fileCount !== 0) return false;
  const ids = new Set();
  for (const row of data.checks) {
    if (!allowedKeys(row, ['id', 'stage', 'kind', 'category', 'expected', 'actual', 'requestId', 'checkedAt', 'source', 'status'])
        || typeof row.id !== 'string' || !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/u.test(row.id) || ids.has(row.id)
        || !Number.isSafeInteger(row.stage) || row.stage < 1 || row.stage > 12
        || !['normal', 'forbidden', 'attack'].includes(row.kind) || !categories.includes(row.category)
        || !fixedCode(row.expected) || !fixedCode(row.actual)
        || !(row.requestId === null || (typeof row.requestId === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$/u.test(row.requestId)))
        || !(row.checkedAt === null || iso(row.checkedAt)) || !sources.includes(row.source) || !statuses.includes(row.status)) return false;
    if (['not_run', 'unavailable'].includes(row.status)) {
      if (row.source !== 'not_run' || row.actual !== null || row.requestId !== null || row.checkedAt !== null) return false;
    } else if (row.status === 'historical') {
      if (row.source !== 'judge' || row.actual === null) return false;
    } else if (row.source === 'not_run' || row.expected === null || row.actual === null || row.checkedAt === null
        || (row.status === 'passed' && row.expected !== row.actual) || (row.status === 'failed' && row.expected === row.actual)) return false;
    ids.add(row.id);
  }
  for (const [field, category] of [['liveApi', 'api'], ['detection', 'detection'], ['revocation', 'revocation'], ['recovery', 'recovery']]) {
    const confirmed = data.checks.some(row => row.category === category && row.status === 'passed' && ['live_http', 'judge'].includes(row.source));
    if (data.summary[field] !== (confirmed ? 'confirmed' : 'not_run')) return false;
  }
  return true;
}

export async function runAttackChecks(config) {
  const base = trustedBase(config);
  if (config.step === 1) {
    if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('invalid_check_configuration');
    const response = await get(base, '/data.json');
    const visible = response.status === 200 && response.data?.sampleMarker === config.sampleMarker
      && Array.isArray(response.data.notes) && response.data.notes.length > 0;
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: response.unavailable ? '비로그인 요청 확인 불가; network_unavailable'
        : visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임'
          : '비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ' + response.status + ')' }];
  }
  if (config.step === 2) {
    const response = await get(base, '/data.json');
    return [{ attackId: 'anonymous_static_notes_removed', expected: '공개 data.json 경로 404',
      observed: result(response, response.status === 404) }];
  }
  const attempts = [];
  const response = await get(base, '/api/notes');
  const error = allowedKeys(response.data, ['error']) && ['AUTH_REQUIRED', 'DEVICE_NOT_REGISTERED', 'RESOURCE_FORBIDDEN'].includes(response.data.error)
    ? response.data.error : 'unexpected_response';
  attempts.push({ attackId: 'anonymous_note_read', expected: '비로그인 API 401 또는 403 JSON 거부',
    observed: result(response, [401, 403].includes(response.status) && error !== 'unexpected_response') + '; code=' + error });
  if (config.step >= 7) attempts.push({ attackId: 'live_step_up_verification', expected: '정상 재확인 요청과 서버 판정 검증',
    observed: '미실행; not_run. 실제 재로그인 계정 요청을 보내지 않음' });
  if (config.step >= 8) attempts.push({ attackId: 'live_resource_accounts', expected: '실제 A 본인 메모 허용·B 타인 메모 거부',
    observed: '미실행; not_run. 인증된 계정의 실제 요청을 보내지 않음; 로컬 회귀는 별도 명령' });
  if (config.step >= 9) attempts.push({ attackId: 'live_detection_revocation', expected: '운영 탐지·단일 기기 회수·경과 시간 확인',
    observed: '미실행; not_run. 운영 엔진 탐지·회수 기록과 측정 시간을 확인하지 않음' });
  if (config.step >= 10) attempts.push({ attackId: 'live_restore', expected: '실제 합성 B 사전 백업과 자기 메모 복구',
    observed: '미실행; not_run. 실제 HTTP 복구 요청과 DB 변경을 수행하지 않음' });
  if (config.step >= 11) {
    const manifest = await get(base, '/manifest.webmanifest');
    const installable = manifest.status === 200 && manifest.data?.display === 'standalone'
      && typeof manifest.data.name === 'string' && manifest.data.name.length > 0
      && Array.isArray(manifest.data.icons) && manifest.data.icons.length >= 2;
    attempts.push({ attackId: 'live_pwa_manifest', expected: '공개 설치형 manifest 이름·아이콘·standalone 확인',
      observed: result(manifest, installable) });
    const auth = await get(base, '/api/auth');
    const signedOut = auth.status === 200 && allowedKeys(auth.data, ['signedIn', 'deviceStatus'])
      && auth.data.signedIn === false && auth.data.deviceStatus === 'unrequested';
    attempts.push({ attackId: 'live_unsigned_device_status', expected: '익명은 미로그인·미승인 상태',
      observed: result(auth, signedOut) });
    attempts.push({ attackId: 'live_approved_student_browser', expected: '실제 승인 전 차단·승인 후 본인 자료 허용',
      observed: '미실행; not_run. 실제 학생 계정 생성·기기 승인을 수행하지 않음' });
  }
  if (config.step >= 12) {
    const operations = await get(base, '/api/operations');
    const valid = operationsShape(operations.data);
    let observed = result(operations, operations.status === 200 && valid && operations.data.summary.availability === 'available');
    if (valid) {
      const report = operations.data;
      const basis = report.checkedCommit === null || report.deployedCommit === null ? 'unknown'
        : report.checkedCommit === report.deployedCommit ? 'matched' : 'different';
      observed += '; schema=aleph.operations.v1; basis=' + basis + '; rows=' + report.checks.length
        + '; passed=' + report.checks.filter(row => row.status === 'passed').length
        + '; failed=' + report.checks.filter(row => row.status === 'failed').length
        + '; historical=' + report.checks.filter(row => row.status === 'historical').length
        + '; not_run=' + report.checks.filter(row => row.status === 'not_run').length
        + '; availability=' + report.summary.availability;
    } else observed += '; schema=unavailable';
    attempts.push({ attackId: 'live_operations_summary', expected: '공개 서버 요약 스키마·실측 기록 수·검사 기준/배포 커밋 구분',
      observed });
    attempts.push({ attackId: 'official_campaign_41', expected: '공식 41종 각각의 실제 공격 결과',
      observed: '미실행; not_run. 항목별 공식 캠페인 결과 없음; 과거 점수·로컬 결과를 실행 수로 합산하지 않음' });
  }
  return attempts;
}
