export function decision(action, confidence, pattern) {
  return { action, confidence, reason: pattern };
}

// A configured Jev adapter may review ambiguous alerts. The fixture runner has
// no Jev service or credentials, so absence/error means alert, never a block.
export async function reviewAmbiguous(alert, pattern, jev) {
  if (typeof jev === 'function') {
    try {
      const confidence = await jev(alert);
      if (typeof confidence === 'number' && Number.isFinite(confidence)
        && confidence >= 0 && confidence <= 1) {
        if (confidence >= 0.85) return decision('block', confidence, pattern);
        if (confidence >= 0.5) return decision('alert', confidence, pattern);
        return decision('record', confidence, pattern);
      }
    } catch { /* explicit safe fallback */ }
  }
  return decision('alert', 0.65, `${pattern}:jev_unavailable`);
}

export function validAlert(alert, technique) {
  return alert && typeof alert === 'object'
    && Array.isArray(alert.rule?.mitre)
    && alert.rule.mitre.includes(technique)
    && typeof alert.rule.description === 'string'
    && typeof alert.data?.srcip === 'string'
    && Number.isInteger(alert.rule.level);
}
