// Trusted gateway boundary: pass an IP supplied by the gateway, never a
// client-controlled request field. This module cannot change the SDP contract.
export function evaluateDenyRules(trustedSourceAddress, rules, at = new Date()) {
  if (typeof trustedSourceAddress !== 'string' || !Array.isArray(rules)) {
    return { blocked: false, rule: null };
  }
  const now = new Date(at).getTime();
  if (!Number.isFinite(now)) return { blocked: false, rule: null };
  const rule = rules.find(candidate => candidate?.action === 'deny'
    && candidate.sourceAddress === trustedSourceAddress
    && Array.isArray(candidate.evidenceAlertIds)
    && candidate.evidenceAlertIds.length > 0
    && new Date(candidate.expiresAt).getTime() > now);
  return { blocked: Boolean(rule), rule: rule ?? null };
}
