import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Confirmation-only reader: never imported into decide.mjs or a live response.
const SECRET = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+\S+|\b(?:sb_secret_|sk-)[A-Za-z0-9._~+/-]{8,}|\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|\b(?:password|passwd|secret|access[_ -]?token|refresh[_ -]?token|token|api[_ -]?key|authorization)\b\s*["']?\s*[:=]\s*["']?\S+|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu;

function text(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  return SECRET.test(value) ? '[REDACTED]' : value;
}

export function readAlerts(fixture) {
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || !Array.isArray(fixture.alerts)) {
    throw new TypeError('INVALID_WAZUH_FIXTURE');
  }
  return fixture.alerts.map(alert => ({
    timestamp: text(alert?.timestamp),
    sourceAddress: text(alert?.data?.srcip),
    account: text(alert?.data?.srcuser),
    ruleLevel: Number.isSafeInteger(alert?.rule?.level) ? alert.rule.level : null,
    description: text(alert?.rule?.description),
  }));
}

export async function readFixture(path = new URL('../fixtures/known-cve.json', import.meta.url)) {
  try { return readAlerts(JSON.parse(await readFile(path, 'utf8'))); }
  catch { throw new TypeError('INVALID_WAZUH_FIXTURE'); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const rows = await readFixture();
    for (const row of rows) process.stdout.write(JSON.stringify(row) + '\n');
  } catch {
    process.stderr.write('known_cve_read_failed\n');
    process.exitCode = 1;
  }
}
