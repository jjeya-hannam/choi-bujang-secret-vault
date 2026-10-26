// Read-only diagnostics. Never prints environment values, user paths or credentials.
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import * as fs from 'node:fs/promises';

export function assessRuntime(version, features = {}) {
  const parts = typeof version === 'string' ? /^v?(\d+)\.(\d+)\.(\d+)$/.exec(version) : null;
  const supported = Boolean(parts && Number(parts[1]) === 24 && Number(parts[2]) >= 19);
  return { supported, code: !supported ? 'NODE_24_19_OR_NEWER_24_REQUIRED' : features.sqlite !== true || features.statfs !== true ? 'NODE_FEATURE_UNAVAILABLE' : 'OK' };
}
export async function inspectEnvironment() {
  let sqlite = null;
  if (assessRuntime(process.versions.node).supported) {
    try { const mod = await import('node:sqlite'); sqlite = typeof mod.DatabaseSync === 'function'; } catch { /* fixed diagnostic only */ }
  }
  const features = { sqlite, statfs: typeof fs.statfs === 'function' };
  const runtime = assessRuntime(process.versions.node, features);
  const platform = ['win32','darwin','linux'].includes(process.platform) ? process.platform : 'other';
  let windowsReader = 'NOT_APPLICABLE';
  if (platform === 'win32') {
    try { await fs.access('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'); windowsReader = 'SUPPORTED_PATH_PRESENT_NOT_EXECUTED'; }
    catch { windowsReader = 'SUPPORTED_PATH_UNAVAILABLE'; }
  }
  return { schema:'student.environment.v1', node:process.versions.node, runtime, platform, features, windowsReader,
    inAppDirectory:resolve(process.cwd()) === resolve(fileURLToPath(new URL('../',import.meta.url))),
    inheritedPortSetting:Boolean(process.env.ON_PORT), portAvailability:'NOT_CHECKED',
    notes:['Run from on-client; root project is the separate Vercel web application.', 'Portable launchers use port 5189 in this process only.', 'Windows readers and shortcuts require a real Windows test; unsupported fields stay unknown.', 'No account credentials or other-PC configuration are copied.'] };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { const result=await inspectEnvironment(); console.log(JSON.stringify(result,null,2)); if(result.runtime.code!=='OK')process.exitCode=1; }
  catch { console.error('ENVIRONMENT_CHECK_UNAVAILABLE');process.exitCode=1; }
}
