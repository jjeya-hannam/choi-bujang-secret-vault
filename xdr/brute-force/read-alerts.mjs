import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { readFixture } from '../shared/read-alerts.mjs';

export { readAlerts } from '../shared/read-alerts.mjs';

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const rows = await readFixture(new URL('../fixtures/brute-force.json', import.meta.url));
  for (const row of rows) console.log(JSON.stringify(row));
}
