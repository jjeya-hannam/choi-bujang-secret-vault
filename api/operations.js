import evidence from '../package/self-check/operations.json' with { type: 'json' };
import policyManifest from '../policy-backups/stage9/manifest.json' with { type: 'json' };
import { buildOperationsReport, unavailableOperationsReport } from '../src/operations-report.mjs';

export function createOperationsHandler(readEvidence = () => evidence, runtimeCommit = process.env.VERCEL_GIT_COMMIT_SHA,
  readPolicyManifest = () => policyManifest) {
  // Deployment provenance comes from the trusted runtime, never request headers.
  const deployedCommit = typeof runtimeCommit === 'string' && /^[0-9a-f]{40}$/iu.test(runtimeCommit)
    ? runtimeCommit.toLowerCase() : null;
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    let snapshot = null;
    try { snapshot = await readPolicyManifest(); } catch { /* Missing metadata claims no snapshot version. */ }
    try { return res.status(200).json({ ...buildOperationsReport(await readEvidence(), snapshot), deployedCommit }); }
    catch { return res.status(200).json({ ...unavailableOperationsReport(snapshot), deployedCommit }); }
  };
}
export default createOperationsHandler();
