export function applyReplacement(rule, match, captureGroups, tokenMap, stats) {
  if (!rule || typeof rule !== 'object') {
    throw new TypeError('Invalid rule object passed to applyReplacement');
  }

  const tokenType = rule.tokenType || 'GENERIC';
  const ruleId = rule.id || 'unknown';

  if (stats && stats.matches) {
    stats.matches[ruleId] = (stats.matches[ruleId] || 0) + 1;
  }

  if (rule.replacementGroup === undefined || rule.replacementGroup === null) {
    return tokenMap.getOrSet(match, tokenType);
  }

  const groupIdx = Number(rule.replacementGroup);
  if (!Number.isInteger(groupIdx) || groupIdx < 1) {
    return match;
  }

  const targetValue = captureGroups[groupIdx - 1];
  if (targetValue === undefined || targetValue === null || targetValue === '') {
    return match;
  }

  const token = tokenMap.getOrSet(targetValue, tokenType);
  const targetIndex = match.indexOf(targetValue);

  if (targetIndex !== -1) {
    return (
      match.slice(0, targetIndex) +
      token +
      match.slice(targetIndex + targetValue.length)
    );
  }

  return match;
}
