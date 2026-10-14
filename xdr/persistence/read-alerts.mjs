import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFixture as readSafeFixture } from '../known-cve/read-alerts.mjs';

export { readAlerts } from '../known-cve/read-alerts.mjs';
export function readFixture(path = new URL('../fixtures/persistence.json', import.meta.url)) {
  return readSafeFixture(path);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try { for (const row of await readFixture()) process.stdout.write(JSON.stringify(row) + '\n'); }
  catch { process.stderr.write('persistence_read_failed\n'); process.exitCode = 1; }
}
