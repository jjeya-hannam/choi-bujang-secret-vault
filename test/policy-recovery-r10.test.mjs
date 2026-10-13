import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, cp, readFile, writeFile, rm, symlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createRecoveryPlan, applyRecovery, loadVerifiedSnapshot, TRIAL_ROOT, SNAPSHOT_DIR } from '../scripts/policy-recovery.mjs';

const execute = promisify(execFile);
const script = new URL('../scripts/policy-recovery.mjs', import.meta.url).pathname;
const paths = ['src/decider.mjs', 'src/detect.mjs', 'src/resource-policy.mjs', 'src/verify-login.mjs'];
async function trial(t) {
  await mkdir(TRIAL_ROOT, { recursive: true });
  const target = await mkdtemp(join(TRIAL_ROOT, 'test-'));
  t.after(() => rm(target, { recursive: true, force: true }));
  await cp(join(SNAPSHOT_DIR, 'src'), join(target, 'src'), { recursive: true });
  return target;
}

test('고정 trusted commit snapshot과 네 공개 소스 SHA256를 확인한다', async () => {
  const snapshot = await loadVerifiedSnapshot();
  assert.equal(snapshot.commit, '225e242573807cb7b225a7f8b5135983e9086720');
  assert.deepEqual(snapshot.files.map(row => row.path), paths);
});

test('기본 CLI는 hash 계획만 출력하고 시험 정책이나 감사 기록을 바꾸지 않는다', async t => {
  const target = await trial(t);
  const changed = '// trial policy only\n';
  await writeFile(join(target, paths[0]), changed);
  await writeFile(join(target, 'audit.log'), 'preserve trial audit\n');
  const { stdout } = await execute(process.execPath, [script, '--target', target]);
  const plan = JSON.parse(stdout);
  assert.equal(plan.version, 'stage9-225e242');
  assert.equal(plan.changes.filter(row => row.change === 'replace').length, 1);
  assert.match(plan.digest, /^[a-f0-9]{64}$/u);
  assert.equal(stdout.includes(changed.trim()), false);
  assert.equal(await readFile(join(target, paths[0]), 'utf8'), changed);
  assert.equal(await readFile(join(target, 'audit.log'), 'utf8'), 'preserve trial audit\n');
});

test('명시 확인 후 지정 네 정책만 복원하고 다른 서비스와 audit를 보존한다', async t => {
  const target = await trial(t);
  for (const path of paths) await writeFile(join(target, path), '// altered trial\n');
  await mkdir(join(target, 'other-service'));
  await writeFile(join(target, 'other-service', 'policy.json'), '{"retain":true}\n');
  await writeFile(join(target, 'audit.log'), 'audit before recovery\n');
  const plan = await createRecoveryPlan(target);
  const result = await applyRecovery(target, plan.digest);
  assert.equal(result.applied, true);
  for (const path of paths) assert.deepEqual(await readFile(join(target, path)), await readFile(join(SNAPSHOT_DIR, path)));
  assert.equal(await readFile(join(target, 'audit.log'), 'utf8'), 'audit before recovery\n');
  assert.equal(await readFile(join(target, 'other-service', 'policy.json'), 'utf8'), '{"retain":true}\n');
});

test('검토 뒤 정책이 바뀌면 오래된 확인 digest로 덮어쓰지 않는다', async t => {
  const target = await trial(t);
  await writeFile(join(target, paths[0]), '// first trial\n');
  const plan = await createRecoveryPlan(target);
  await writeFile(join(target, paths[0]), '// newer trial\n');
  await assert.rejects(applyRecovery(target, plan.digest), /review_plan_conflict/u);
  assert.equal(await readFile(join(target, paths[0]), 'utf8'), '// newer trial\n');
});

test('명시 --confirm 없거나 틀린 확인이면 쓰지 않는다', async t => {
  const target = await trial(t);
  await assert.rejects(applyRecovery(target), /review_confirmation_required/u);
  await assert.rejects(applyRecovery(target, '0'.repeat(64)), /review_plan_conflict/u);
});

test('CLI --apply도 사전 검토 digest를 요구하고 정상 확인 때만 복원한다', async t => {
  const target = await trial(t);
  await writeFile(join(target, paths[0]), '// trial CLI\n');
  await assert.rejects(execute(process.execPath, [script, '--target', target, '--apply']),
    error => error.code === 1 && error.stderr.trim() === 'review_confirmation_required');
  const plan = await createRecoveryPlan(target);
  const { stdout } = await execute(process.execPath,
    [script, '--target', target, '--apply', '--confirm', plan.digest]);
  assert.equal(JSON.parse(stdout).applied, true);
  assert.deepEqual(await readFile(join(target, paths[0])), await readFile(join(SNAPSHOT_DIR, paths[0])));
});

test('시험 대상이 없거나 managed 파일이 없으면 복원 대신 중단한다', async t => {
  const target = await trial(t);
  await assert.rejects(createRecoveryPlan(join(target, 'missing')), /trial_target_missing_or_invalid/u);
  await rm(join(target, paths[0]));
  await assert.rejects(createRecoveryPlan(target), /trial_policy_file_missing_or_invalid/u);
});

test('snapshot 변조나 누락은 dry run에서도 중단한다', async t => {
  const target = await trial(t);
  const backup = join(target, 'backup');
  await cp(SNAPSHOT_DIR, backup, { recursive: true });
  await writeFile(join(backup, paths[0]), '// tampered snapshot\n');
  await assert.rejects(createRecoveryPlan(target, { backupDir: backup }), /snapshot_hash_invalid/u);
  await rm(join(backup, paths[0]));
  await assert.rejects(createRecoveryPlan(target, { backupDir: backup }), /snapshot_file_missing/u);
});

test('manifest의 hash 자체도 고정 trusted 값과 달라지면 거부한다', async t => {
  const target = await trial(t);
  const backup = join(target, 'backup');
  await cp(SNAPSHOT_DIR, backup, { recursive: true });
  const manifest = JSON.parse(await readFile(join(backup, 'manifest.json'), 'utf8'));
  manifest.files[0].sha256 = '0'.repeat(64);
  await writeFile(join(backup, 'manifest.json'), JSON.stringify(manifest));
  await assert.rejects(createRecoveryPlan(target, { backupDir: backup }), /snapshot_manifest_invalid/u);
});

test('실제 저장소·허용 root 자체·root 밖·symlink 대상은 거부한다', async t => {
  const target = await trial(t);
  for (const outside of [resolve(SNAPSHOT_DIR, '../..'), TRIAL_ROOT, resolve(TRIAL_ROOT, '..')]) {
    await assert.rejects(createRecoveryPlan(outside), /trial_target_outside_safe_root/u);
  }
  const link = join(target, 'linked');
  await symlink(target, link);
  await assert.rejects(createRecoveryPlan(link), /trial_target_missing_or_invalid/u);
  await rm(join(target, paths[0]));
  await symlink(join(SNAPSHOT_DIR, paths[0]), join(target, paths[0]));
  await assert.rejects(createRecoveryPlan(target), /trial_policy_file_missing_or_invalid/u);
});
