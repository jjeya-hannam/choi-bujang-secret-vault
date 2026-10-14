import { readFile } from 'node:fs/promises';
import { respondFixture } from '../shared/respond-fixture.mjs';

// Fixture-only response; the isolated judge imports decide.mjs alone.
export async function respondPrivilege(options) {
  let patterns;
  try { patterns = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url), 'utf8')); }
  catch { throw new Error('INVALID_RESPONSE_PATTERNS'); }
  if (patterns?.schema !== 'aleph.xdr.patterns.v1' || patterns.moduleKey !== 'privilege'
      || !Array.isArray(patterns.patterns)) throw new Error('INVALID_RESPONSE_PATTERNS');
  return respondFixture({ ...options, moduleKey: 'privilege', reasons: patterns.patterns.map(row => row?.name) });
}
