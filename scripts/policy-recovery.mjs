import { createHash, randomUUID } from 'node:crypto';
import { readFile, writeFile, lstat, realpath, rename, unlink } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const TRIAL_ROOT = resolve(REPO_ROOT, '..', 'trial-policy');
export const SNAPSHOT_DIR = join(REPO_ROOT, 'policy-backups', 'stage9');
const VERSION = 'stage9-225e242';
const COMMIT = '225e242573807cb7b225a7f8b5135983e9086720';
const HASHES = Object.freeze({
  'src/decider.mjs': 'bebe31d08205a7908e5001499cf799ac7757d515efd512859e3b9744ac54a2e1',
  'src/detect.mjs': 'ca101bbcc6beff2a79c2391f0c930cd6199ec68151a980c65c735b8abfe98609',
  'src/resource-policy.mjs': 'ff7dd8bd8c76bbba9512cac0a0cf811b8d9f12e43e223464405d0c269dd5d1a8',
  'src/verify-login.mjs': '30c14808756937abb49bb0afb68c4862700c173739dfc6e64b2a54978f14cfb0',
});
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw new Error(code); };

async function regularFile(path, code) {
  let stat;
  try { stat = await lstat(path); } catch { fail(code); }
  if (!stat.isFile() || stat.isSymbolicLink()) fail(code);
  return stat;
}

export async function loadVerifiedSnapshot(backupDir = SNAPSHOT_DIR) {
  let manifest;
  try {
    await regularFile(join(backupDir, 'manifest.json'), 'snapshot_missing');
    manifest = JSON.parse(await readFile(join(backupDir, 'manifest.json'), 'utf8'));
  } catch { fail('snapshot_manifest_invalid'); }
  const expected = Object.entries(HASHES).map(([path, sha256]) => ({ path, sha256 }));
  if (manifest.schema !== 'aleph.policy.snapshot.v1' || manifest.version !== VERSION
      || manifest.commit !== COMMIT || JSON.stringify(manifest.files) !== JSON.stringify(expected)) {
    fail('snapshot_manifest_invalid');
  }
  const files = [];
  for (const { path, sha256 } of expected) {
    const fullPath = join(backupDir, path);
    await regularFile(fullPath, 'snapshot_file_missing');
    if (await realpath(fullPath) !== resolve(fullPath)) fail('snapshot_path_invalid');
    const bytes = await readFile(fullPath);
    if (hash(bytes) !== sha256) fail('snapshot_hash_invalid');
    files.push({ path, sha256, bytes });
  }
  return { version: VERSION, commit: COMMIT, files };
}

async function validateTarget(target) {
  if (typeof target !== 'string' || !target) fail('explicit_trial_target_required');
  const fullPath = resolve(target);
  if (!fullPath.startsWith(TRIAL_ROOT + sep)) fail('trial_target_outside_safe_root');
  try {
    if (await realpath(TRIAL_ROOT) !== TRIAL_ROOT || await realpath(fullPath) !== fullPath) {
      fail('trial_target_symlink_forbidden');
    }
    const stat = await lstat(fullPath);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail('trial_target_invalid');
  } catch { fail('trial_target_missing_or_invalid'); }
  return fullPath;
}

export async function createRecoveryPlan(target, { backupDir = SNAPSHOT_DIR } = {}) {
  const targetPath = await validateTarget(target);
  const snapshot = await loadVerifiedSnapshot(backupDir);
  const changes = [];
  for (const file of snapshot.files) {
    const path = join(targetPath, file.path);
    await regularFile(path, 'trial_policy_file_missing_or_invalid');
    if (await realpath(path) !== path) fail('trial_policy_symlink_forbidden');
    const currentHash = hash(await readFile(path));
    changes.push({ path: file.path, beforeSha256: currentHash,
      afterSha256: file.sha256, change: currentHash === file.sha256 ? 'unchanged' : 'replace' });
  }
  const review = { schema: 'aleph.policy.recovery.plan.v1', version: snapshot.version,
    commit: snapshot.commit, target: targetPath, changes };
  return { ...review, digest: hash(JSON.stringify(review)) };
}

export async function applyRecovery(target, confirmation, { backupDir = SNAPSHOT_DIR } = {}) {
  if (typeof confirmation !== 'string' || !/^[a-f0-9]{64}$/u.test(confirmation)) fail('review_confirmation_required');
  const plan = await createRecoveryPlan(target, { backupDir });
  if (confirmation !== plan.digest) fail('review_plan_conflict');
  const snapshot = await loadVerifiedSnapshot(backupDir);
  const staged = [];
  try {
    for (const file of snapshot.files) {
      const change = plan.changes.find(item => item.path === file.path);
      if (change.change === 'unchanged') continue;
      const finalPath = join(plan.target, file.path);
      const stat = await regularFile(finalPath, 'trial_policy_file_missing_or_invalid');
      const tempPath = join(dirname(finalPath), `.policy-recovery-${randomUUID()}.tmp`);
      await writeFile(tempPath, file.bytes, { flag: 'wx', mode: stat.mode & 0o777 });
      staged.push({ tempPath, finalPath });
    }
    // Recheck every planned file before replacing any of them. A stale reviewed
    // digest cannot authorize overwriting newer trial-policy work.
    const rechecked = await createRecoveryPlan(target, { backupDir });
    if (rechecked.digest !== confirmation) fail('review_plan_conflict');
    for (const { tempPath, finalPath } of staged) await rename(tempPath, finalPath);
  } finally {
    for (const { tempPath } of staged) await unlink(tempPath).catch(() => {});
  }
  return { ...plan, applied: true };
}

async function main(args) {
  let target, confirmation, apply = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--target' && target === undefined) target = args[++index];
    else if (arg === '--confirm' && confirmation === undefined) confirmation = args[++index];
    else if (arg === '--apply' && !apply) apply = true;
    else fail('invalid_recovery_arguments');
  }
  if (!apply && confirmation !== undefined) fail('confirmation_requires_apply');
  const result = apply ? await applyRecovery(target, confirmation) : await createRecoveryPlan(target);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    // Fixed error codes only: no source content, tokens, policies or stack traces.
    const allowed = new Set(['snapshot_missing', 'snapshot_manifest_invalid', 'snapshot_file_missing',
      'snapshot_path_invalid', 'snapshot_hash_invalid', 'explicit_trial_target_required',
      'trial_target_outside_safe_root', 'trial_target_symlink_forbidden', 'trial_target_invalid',
      'trial_target_missing_or_invalid', 'trial_policy_file_missing_or_invalid', 'trial_policy_symlink_forbidden',
      'review_confirmation_required', 'review_plan_conflict', 'confirmation_requires_apply', 'invalid_recovery_arguments']);
    process.stderr.write(`${allowed.has(error.message) ? error.message : 'trial_policy_recovery_failed'}\n`);
    process.exitCode = 1;
  });
}
