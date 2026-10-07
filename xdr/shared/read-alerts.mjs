import { readFile } from 'node:fs/promises';

const SECRET = /(?:Bearer\s+|sb_secret_|sk-)[A-Za-z0-9._~+/-]{8,}|(?:password|token|api[_ -]?key)\s*[:=]\s*\S+/giu;

export function readAlerts(fixture) {
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || !Array.isArray(fixture.alerts)) {
    throw new TypeError('INVALID_WAZUH_FIXTURE');
  }
  return fixture.alerts.map(alert => ({
    timestamp: typeof alert?.timestamp === 'string' ? alert.timestamp : '',
    sourceAddress: typeof alert?.data?.srcip === 'string' ? alert.data.srcip : '',
    account: typeof alert?.data?.srcuser === 'string' ? alert.data.srcuser : '',
    ruleLevel: Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0,
    description: typeof alert?.rule?.description === 'string'
      ? alert.rule.description.replace(SECRET, '[REDACTED]') : '',
  }));
}

export async function readFixture(path) {
  return readAlerts(JSON.parse(await readFile(path, 'utf8')));
}
