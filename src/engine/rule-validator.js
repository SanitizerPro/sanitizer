export function validateRules(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw new Error('Rules payload must be a non-empty array.');
  }

  const seenIds = new Set();

  for (const rule of rules) {
    if (!rule || typeof rule !== 'object') {
      throw new Error('Rule item must be a valid object.');
    }

    if (typeof rule.id !== 'string' || rule.id.trim() === '') {
      throw new Error("Rule missing required string 'id'.");
    }

    if (seenIds.has(rule.id)) {
      throw new Error(`Duplicate rule ID detected: '${rule.id}'. Rule IDs must be unique.`);
    }
    seenIds.add(rule.id);

    if (typeof rule.tokenType !== 'string' || rule.tokenType.trim() === '') {
      throw new Error(`Rule '${rule.id}' missing required string 'tokenType'.`);
    }

    const scope = rule.scope ?? 'line';
    if (scope !== 'line' && scope !== 'block') {
      throw new Error(`Rule '${rule.id}' has invalid scope '${scope}'. Must be 'line' or 'block'.`);
    }

    if (scope === 'line') {
      if (!(rule.regex instanceof RegExp)) {
        throw new Error(`Line rule '${rule.id}' must provide a valid RegExp instance.`);
      }
    } else if (scope === 'block') {
      if (!(rule.startRegex instanceof RegExp) || !(rule.endRegex instanceof RegExp)) {
        throw new Error(`Block rule '${rule.id}' requires valid 'startRegex' and 'endRegex' RegExp instances.`);
      }
    }

    if (rule.replacementGroup !== undefined) {
      const rg = rule.replacementGroup;
      if (!Number.isInteger(rg) || rg < 1) {
        throw new Error(`Rule '${rule.id}' has invalid replacementGroup '${rg}'. Must be a positive integer.`);
      }
    }

    if (rule.maxBytes !== undefined) {
      const mb = rule.maxBytes;
      if (!Number.isInteger(mb) || mb <= 0 || !Number.isSafeInteger(mb)) {
        throw new Error(`Rule '${rule.id}' has invalid maxBytes '${mb}'. It must be a positive safe integer.`);
      }
    }

    if (rule.priority !== undefined) {
      const p = rule.priority;
      if (typeof p !== 'number' || !Number.isInteger(p) || !Number.isFinite(p)) {
        throw new Error(`Rule '${rule.id}' has invalid priority '${p}'. Priority must be an integer.`);
      }
    }
  }

  return true;
}
