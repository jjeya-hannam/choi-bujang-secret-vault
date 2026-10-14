import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readAlerts as projectAlerts } from '../known-cve/read-alerts.mjs';

export function readAlerts(fixture) {
  if (fixture?.moduleKey !== 'privilege') throw new TypeError('INVALID_WAZUH_FIXTURE');
  return projectAlerts(fixture);
}
export async function readFixture(path = new URL('../fixtures/privilege.json', import.meta.url)) {
  try { return readAlerts(JSON.parse(await readFile(path, 'utf8'))); }
  catch { throw new TypeError('INVALID_WAZUH_FIXTURE'); }
}
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try { for (const row of await readFixture()) process.stdout.write(JSON.stringify(row) + '\n'); }
  catch { process.stderr.write('privilege_read_failed\n'); process.exitCode = 1; }
}
