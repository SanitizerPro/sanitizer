/**
 * SanitizerPro
 * Local detection matcher engine.
 *
 * Responsibilities:
 * - Execute deterministic local detection rules.
 * - Match against normalized and compact text views.
 * - Support regular expressions, literal strings, and custom matchers.
 * - Convert matched ranges back to original-text offsets.
 * - Calculate deterministic confidence values.
 * - Deduplicate overlapping findings.
 * - Enforce scan and per-rule limits.
 * - Reject obviously unsafe regular expressions.
 * - Never log, persist, transmit, or expose matched secret values.
 *
 * This module does NOT:
 * - make policy decisions
 * - block page actions
 * - modify user content
 * - access Chrome APIs
 * - access the DOM
 * - access the clipboard
 * - perform network requests
 */

import {
  SCAN_LIMITS,
  DATA_CATEGORIES,
  SEVERITY,
} from "../config/defaults.js";

import {
  normalizeText,
  isNormalizationResult,
  getOriginalRange,
  getOriginalRangeFromCompact,
  getOriginalText,
} from "./normalizer.js";

const MATCHER_VERSION = 1;

const DEFAULT_MAX_FINDINGS =
  Number.isInteger(SCAN_LIMITS?.maxFindingsPerScan) &&
  SCAN_LIMITS.maxFindingsPerScan > 0
    ? SCAN_LIMITS.maxFindingsPerScan
    : 100;

const DEFAULT_MAX_RULE_MATCHES =
  Number.isInteger(SCAN_LIMITS?.maxRuleMatchesPerFinding) &&
  SCAN_LIMITS.maxRuleMatchesPerFinding > 0
    ? SCAN_LIMITS.maxRuleMatchesPerFinding
    : 10;

const DEFAULT_MAX_PATTERN_LENGTH = 4096;

const DEFAULT_MAX_RULES = 1000;

const DEFAULT_CONFIDENCE = 0.75;

const MATCH_VIEWS = Object.freeze({
  NORMALIZED: "normalized",
  COMPACT: "compact",
});

const RULE_TYPES = Object.freeze({
  REGEX: "regex",
  LITERAL: "literal",
  CUSTOM: "custom",
});

const VALID_RULE_TYPES = new Set(
  Object.values(RULE_TYPES)
);

const VALID_MATCH_VIEWS = new Set(
  Object.values(MATCH_VIEWS)
);

const DEFAULT_RULE = Object.freeze({
  enabled: true,
  type: RULE_TYPES.REGEX,
  view: MATCH_VIEWS.NORMALIZED,
  flags: "giu",
  confidence: DEFAULT_CONFIDENCE,
  severity: SEVERITY?.MEDIUM ?? "medium",
  category: DATA_CATEGORIES?.UNKNOWN ?? "unknown",
});

const INTERNAL_RULE_KEYS = new Set([
  "id",
  "name",
  "description",
  "enabled",
  "type",
  "view",
  "pattern",
  "flags",
  "confidence",
  "severity",
  "category",
  "subCategory",
  "tags",
  "source",
  "priority",
  "maxMatches",
  "validator",
  "validate",
  "matcher",
  "normalize",
  "transform",
  "metadata",
]);

const REGEX_FLAG_PATTERN = /^[dgimsuvy]*$/u;

const UNSAFE_REGEX_PATTERNS = [
  /\(\?:[^)]*\+[^)]*\)\+/u,
  /\(\?:[^)]*\*[^)]*\)\+/u,
  /\([^)]*\+[^)]*\)\+/u,
  /\([^)]*\*[^)]*\)\*/u,
  /\([^)]*\+[^)]*\)\*/u,
  /\([^)]*\*[^)]*\)\+/u,
  /\(\.\*\)\+/u,
  /\(\.\+\)\+/u,
];

const SECRET_LIKE_CATEGORY_NAMES = new Set([
  "secret",
  "credential",
  "private_key",
  "token",
  "api_key",
  "password",
  "database",
]);

const HIGH_RISK_SEVERITIES = new Set([
  "high",
  "critical",
]);

function isObject(value) {
  return value !== null && typeof value === "object";
}

function isFunction(value) {
  return typeof value === "function";
}

function isString(value) {
  return typeof value === "string";
}

function isPositiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

function clampNumber(value, minimum, maximum, fallback) {
  if (!Number.isFinite(value)) {
    return fallback;
  }

  return Math.min(
    maximum,
    Math.max(minimum, value)
  );
}

function safeString(value, fallback = "") {
  return typeof value === "string"
    ? value
    : fallback;
}

function safeArray(value) {
  return Array.isArray(value)
    ? value
    : [];
}

function getRuleId(rule, index = 0) {
  if (isString(rule?.id) && rule.id.trim()) {
    return rule.id.trim();
  }

  return `anonymous-rule-${index + 1}`;
}

function getRuleName(rule, index = 0) {
  if (isString(rule?.name) && rule.name.trim()) {
    return rule.name.trim();
  }

  return getRuleId(rule, index);
}

function getRuleCategory(rule) {
  if (
    isString(rule?.category) &&
    rule.category.trim()
  ) {
    return rule.category.trim();
  }

  return DATA_CATEGORIES?.UNKNOWN ?? "unknown";
}

function getRuleSeverity(rule) {
  if (
    isString(rule?.severity) &&
    rule.severity.trim()
  ) {
    return rule.severity.trim();
  }

  return SEVERITY?.MEDIUM ?? "medium";
}

function normalizeConfidence(value) {
  return clampNumber(
    value,
    0,
    1,
    DEFAULT_CONFIDENCE
  );
}

function normalizePriority(value) {
  if (!Number.isFinite(value)) {
    return 0;
  }

  return Math.floor(value);
}

function normalizeMaxMatches(value) {
  if (!isPositiveInteger(value)) {
    return DEFAULT_MAX_RULE_MATCHES;
  }

  return Math.min(
    value,
    DEFAULT_MAX_RULE_MATCHES
  );
}

function normalizeRuleType(value) {
  if (VALID_RULE_TYPES.has(value)) {
    return value;
  }

  return RULE_TYPES.REGEX;
}

function normalizeMatchView(value) {
  if (VALID_MATCH_VIEWS.has(value)) {
    return value;
  }

  return MATCH_VIEWS.NORMALIZED;
}

function normalizeRegexFlags(flags, view) {
  let value = isString(flags)
    ? flags
    : DEFAULT_RULE.flags;

  value = value.replace(/[^dgimsuvy]/gu, "");

  const characters = new Set(
    Array.from(value)
  );

  characters.add("g");

  if (view === MATCH_VIEWS.NORMALIZED) {
    characters.add("u");
  }

  return Array.from(characters).join("");
}

function hasDuplicateCharacters(value) {
  const seen = new Set();

  for (const character of value) {
    if (seen.has(character)) {
      return true;
    }

    seen.add(character);
  }

  return false;
}

function isRegexPatternObviouslyUnsafe(pattern) {
  if (!isString(pattern)) {
    return true;
  }

  if (pattern.length === 0) {
    return true;
  }

  if (pattern.length > DEFAULT_MAX_PATTERN_LENGTH) {
    return true;
  }

  for (const unsafePattern of UNSAFE_REGEX_PATTERNS) {
    if (unsafePattern.test(pattern)) {
      return true;
    }
  }

  return false;
}

function compileRegex(pattern, flags) {
  if (pattern instanceof RegExp) {
    const safeFlags = normalizeRegexFlags(
      pattern.flags,
      MATCH_VIEWS.NORMALIZED
    );

    try {
      return new RegExp(
        pattern.source,
        safeFlags
      );
    } catch {
      return null;
    }
  }

  if (!isString(pattern)) {
    return null;
  }

  if (isRegexPatternObviouslyUnsafe(pattern)) {
    return null;
  }

  const safeFlags = normalizeRegexFlags(
    flags,
    MATCH_VIEWS.NORMALIZED
  );

  try {
    return new RegExp(
      pattern,
      safeFlags
    );
  } catch {
    return null;
  }
}

function escapeRegExp(value) {
  return value.replace(
    /[.*+?^${}()|[\]\\]/gu,
    "\\$&"
  );
}

function compileLiteral(
  pattern,
  flags,
  view
) {
  if (!isString(pattern)) {
    return null;
  }

  if (
    pattern.length === 0 ||
    pattern.length > DEFAULT_MAX_PATTERN_LENGTH
  ) {
    return null;
  }

  const escaped = escapeRegExp(pattern);

  const safeFlags = normalizeRegexFlags(
    flags,
    view
  );

  try {
    return new RegExp(
      escaped,
      safeFlags
    );
  } catch {
    return null;
  }
}

function resetRegex(regex) {
  if (regex && typeof regex.lastIndex === "number") {
    regex.lastIndex = 0;
  }
}

function getViewText(
  normalizationResult,
  view
) {
  if (!isNormalizationResult(normalizationResult)) {
    return "";
  }

  if (view === MATCH_VIEWS.COMPACT) {
    return normalizationResult.compactText;
  }

  return normalizationResult.normalizedText;
}

function mapViewRangeToOriginal(
  normalizationResult,
  view,
  start,
  end
) {
  if (
    !isNormalizationResult(normalizationResult)
  ) {
    return null;
  }

  if (view === MATCH_VIEWS.COMPACT) {
    return getOriginalRangeFromCompact(
      normalizationResult,
      start,
      end
    );
  }

  return getOriginalRange(
    normalizationResult,
    start,
    end
  );
}

function isValidRange(start, end, textLength) {
  return (
    Number.isInteger(start) &&
    Number.isInteger(end) &&
    start >= 0 &&
    end > start &&
    end <= textLength
  );
}

function normalizeRange(
  start,
  end,
  textLength
) {
  const safeStart = Math.max(
    0,
    Math.min(
      textLength,
      Math.floor(Number(start) || 0)
    )
  );

  const safeEnd = Math.max(
    safeStart,
    Math.min(
      textLength,
      Math.floor(Number(end) || 0)
    )
  );

  return {
    start: safeStart,
    end: safeEnd,
  };
}

function createEmptyMatchResult(
  rule,
  reason = null
) {
  return {
    matched: false,
    ruleId: getRuleId(rule),
    matches: [],
    matchCount: 0,
    truncated: false,
    error: reason,
  };
}

function createMatchRecord({
  rule,
  view,
  viewStart,
  viewEnd,
  normalizationResult,
  ruleIndex,
  matchIndex,
  groups = null,
  scoreOverride = null,
}) {
  const originalRange = mapViewRangeToOriginal(
    normalizationResult,
    view,
    viewStart,
    viewEnd
  );

  if (!originalRange) {
    return null;
  }

  const originalText =
    normalizationResult.originalText;

  if (
    !isValidRange(
      originalRange.start,
      originalRange.end,
      originalText.length
    )
  ) {
    return null;
  }

  const matchedText = getOriginalText(
    normalizationResult,
    view === MATCH_VIEWS.COMPACT
      ? mapViewRangeToNormalizedRange(
          normalizationResult,
          view,
          viewStart,
          viewEnd
        )?.start ?? 0
      : viewStart,
    view === MATCH_VIEWS.COMPACT
      ? mapViewRangeToNormalizedRange(
          normalizationResult,
          view,
          viewStart,
          viewEnd
        )?.end ?? 0
      : viewEnd
  );

  const confidence = normalizeConfidence(
    scoreOverride ??
      rule.confidence ??
      DEFAULT_CONFIDENCE
  );

  return {
    ruleId: getRuleId(rule, ruleIndex),
    ruleName: getRuleName(rule, ruleIndex),

    category: getRuleCategory(rule),
    subCategory:
      isString(rule.subCategory)
        ? rule.subCategory
        : null,

    severity: getRuleSeverity(rule),

    confidence,

    priority: normalizePriority(
      rule.priority
    ),

    view,

    match: {
      start: originalRange.start,
      end: originalRange.end,
      length:
        originalRange.end -
        originalRange.start,
    },

    normalizedMatch: {
      start: viewStart,
      end: viewEnd,
      length: viewEnd - viewStart,
    },

    matchedText,

    groups: sanitizeGroups(groups),

    ruleIndex,
    matchIndex,
  };
}

function mapViewRangeToNormalizedRange(
  normalizationResult,
  view,
  start,
  end
) {
  if (
    view !== MATCH_VIEWS.COMPACT
  ) {
    return {
      start,
      end,
    };
  }

  if (
    !isNormalizationResult(normalizationResult)
  ) {
    return null;
  }

  const mappings =
    normalizationResult.compactMappings;

  if (
    !Array.isArray(mappings) ||
    mappings.length === 0
  ) {
    return null;
  }

  const originalRange =
    mapViewRangeToOriginal(
      normalizationResult,
      view,
      start,
      end
    );

  if (!originalRange) {
    return null;
  }

  let normalizedStart = null;
  let normalizedEnd = null;

  for (const segment of normalizationResult.mappings) {
    if (
      segment.originalEnd <=
      originalRange.start
    ) {
      continue;
    }

    if (
      segment.originalStart >=
      originalRange.end
    ) {
      break;
    }

    if (normalizedStart === null) {
      normalizedStart =
        segment.normalizedStart;
    }

    normalizedEnd =
      segment.normalizedEnd;
  }

  if (
    normalizedStart === null ||
    normalizedEnd === null
  ) {
    return null;
  }

  return {
    start: normalizedStart,
    end: normalizedEnd,
  };
}

function sanitizeGroups(groups) {
  if (!groups) {
    return null;
  }

  if (Array.isArray(groups)) {
    return groups.map((value) =>
      typeof value === "string"
        ? value.length
        : value
    );
  }

  if (isObject(groups)) {
    const result = {};

    for (const [key, value] of Object.entries(
      groups
    )) {
      if (typeof value === "string") {
        result[key] = value.length;
      } else if (
        value === null ||
        typeof value === "number" ||
        typeof value === "boolean"
      ) {
        result[key] = value;
      }
    }

    return result;
  }

  return null;
}

function getRegexGroups(match) {
  if (!match) {
    return null;
  }

  if (
    match.groups &&
    isObject(match.groups)
  ) {
    return {
      named: Object.fromEntries(
        Object.entries(match.groups).map(
          ([key, value]) => [
            key,
            typeof value === "string"
              ? value.length
              : value,
          ]
        )
      ),
    };
  }

  if (match.length > 1) {
    return match
      .slice(1)
      .map((value) =>
        typeof value === "string"
          ? value.length
          : value
      );
  }

  return null;
}

function collectRegexMatches(
  regex,
  text,
  maxMatches
) {
  const matches = [];

  if (!regex || !text) {
    return {
      matches,
      truncated: false,
    };
  }

  resetRegex(regex);

  let match;

  while (
    (match = regex.exec(text)) !== null
  ) {
    const start = match.index;

    const matchedValue =
      typeof match[0] === "string"
        ? match[0]
        : "";

    const end =
      start + matchedValue.length;

    if (end > start) {
      matches.push({
        start,
        end,
        groups: getRegexGroups(match),
      });
    }

    if (
      matches.length >= maxMatches
    ) {
      return {
        matches,
        truncated:
          regex.lastIndex < text.length,
      };
    }

    if (match[0] === "") {
      regex.lastIndex += 1;
    }
  }

  return {
    matches,
    truncated: false,
  };
}

function collectLiteralMatches(
  regex,
  text,
  maxMatches
) {
  return collectRegexMatches(
    regex,
    text,
    maxMatches
  );
}

function validateCustomMatch(match, textLength) {
  if (!isObject(match)) {
    return null;
  }

  const start = Number(match.start);
  const end = Number(match.end);

  if (
    !Number.isInteger(start) ||
    !Number.isInteger(end)
  ) {
    return null;
  }

  const range = normalizeRange(
    start,
    end,
    textLength
  );

  if (
    !isValidRange(
      range.start,
      range.end,
      textLength
    )
  ) {
    return null;
  }

  return {
    start: range.start,
    end: range.end,
    score:
      Number.isFinite(match.score)
        ? match.score
        : null,
    confidence:
      Number.isFinite(match.confidence)
        ? match.confidence
        : null,
    groups:
      match.groups ?? null,
  };
}

function executeCustomMatcher(
  rule,
  text,
  normalizationResult,
  maxMatches
) {
  if (!isFunction(rule.matcher)) {
    return {
      matches: [],
      truncated: false,
      error: "Custom matcher is missing.",
    };
  }

  let result;

  try {
    result = rule.matcher(
      text,
      normalizationResult
    );
  } catch {
    return {
      matches: [],
      truncated: false,
      error: "Custom matcher failed.",
    };
  }

  const candidateMatches =
    Array.isArray(result)
      ? result
      : Array.isArray(result?.matches)
        ? result.matches
        : [];

  const matches = [];

  for (
    let index = 0;
    index < candidateMatches.length;
    index += 1
  ) {
    const normalized =
      validateCustomMatch(
        candidateMatches[index],
        text.length
      );

    if (!normalized) {
      continue;
    }

    matches.push(normalized);

    if (matches.length >= maxMatches) {
      return {
        matches,
        truncated:
          candidateMatches.length >
          matches.length,
        error: null,
      };
    }
  }

  return {
    matches,
    truncated: false,
    error: null,
  };
}

function executeRuleMatcher(
  rule,
  text,
  normalizationResult,
  maxMatches
) {
  const type = normalizeRuleType(
    rule.type
  );

  if (type === RULE_TYPES.CUSTOM) {
    return executeCustomMatcher(
      rule,
      text,
      normalizationResult,
      maxMatches
    );
  }

  if (type === RULE_TYPES.LITERAL) {
    const regex = compileLiteral(
      rule.pattern,
      normalizeRegexFlags(
        rule.flags,
        normalizeMatchView(rule.view)
      ),
      normalizeMatchView(rule.view)
    );

    if (!regex) {
      return {
        matches: [],
        truncated: false,
        error: "Invalid literal rule.",
      };
    }

    return collectLiteralMatches(
      regex,
      text,
      maxMatches
    );
  }

  const regex = compileRegex(
    rule.pattern,
    normalizeRegexFlags(
      rule.flags,
      normalizeMatchView(rule.view)
    )
  );

  if (!regex) {
    return {
      matches: [],
      truncated: false,
      error: "Invalid regular expression rule.",
    };
  }

  return collectRegexMatches(
    regex,
    text,
    maxMatches
  );
}

function applyRuleValidator(
  rule,
  match,
  text,
  normalizationResult
) {
  const validator =
    isFunction(rule.validator)
      ? rule.validator
      : isFunction(rule.validate)
        ? rule.validate
        : null;

  if (!validator) {
    return {
      accepted: true,
      confidence: null,
    };
  }

  try {
    const result = validator({
      match,
      text,
      normalizationResult,
    });

    if (typeof result === "boolean") {
      return {
        accepted: result,
        confidence: null,
      };
    }

    if (isObject(result)) {
      return {
        accepted:
          result.accepted !== false,
        confidence:
          Number.isFinite(result.confidence)
            ? result.confidence
            : null,
      };
    }

    return {
      accepted: Boolean(result),
      confidence: null,
    };
  } catch {
    return {
      accepted: false,
      confidence: null,
    };
  }
}

function normalizeRule(rule, index = 0) {
  if (!isObject(rule)) {
    return null;
  }

  const normalized = {
    ...rule,

    id: getRuleId(rule, index),

    name: getRuleName(rule, index),

    enabled:
      rule.enabled !== false,

    type: normalizeRuleType(
      rule.type
    ),

    view: normalizeMatchView(
      rule.view
    ),

    category: getRuleCategory(rule),

    severity: getRuleSeverity(rule),

    confidence:
      normalizeConfidence(
        rule.confidence
      ),

    priority:
      normalizePriority(
        rule.priority
      ),

    maxMatches:
      normalizeMaxMatches(
        rule.maxMatches
      ),
  };

  if (
    normalized.type === RULE_TYPES.REGEX ||
    normalized.type === RULE_TYPES.LITERAL
  ) {
    if (
      typeof normalized.pattern !==
      "string" &&
      !(normalized.pattern instanceof RegExp)
    ) {
      return null;
    }
  }

  if (
    normalized.type === RULE_TYPES.CUSTOM &&
    !isFunction(normalized.matcher)
  ) {
    return null;
  }

  return normalized;
}

function normalizeRuleList(rules) {
  if (!Array.isArray(rules)) {
    return [];
  }

  const normalized = [];
  const seenIds = new Set();

  for (
    let index = 0;
    index < rules.length &&
    normalized.length < DEFAULT_MAX_RULES;
    index += 1
  ) {
    const rule = normalizeRule(
      rules[index],
      index
    );

    if (!rule || !rule.enabled) {
      continue;
    }

    if (seenIds.has(rule.id)) {
      continue;
    }

    seenIds.add(rule.id);
    normalized.push(rule);
  }

  return normalized;
}

function getFindingKey(finding) {
  return [
    finding.ruleId,
    finding.match.start,
    finding.match.end,
    finding.category,
  ].join(":");
}

function compareFindings(a, b) {
  if (
    a.match.start !==
    b.match.start
  ) {
    return (
      a.match.start -
      b.match.start
    );
  }

  if (
    a.match.end !==
    b.match.end
  ) {
    return (
      b.match.end -
      a.match.end
    );
  }

  if (
    a.priority !==
    b.priority
  ) {
    return (
      b.priority -
      a.priority
    );
  }

  if (
    a.confidence !==
    b.confidence
  ) {
    return (
      b.confidence -
      a.confidence
    );
  }

  if (
    a.severity !==
    b.severity
  ) {
    return compareSeverity(
      a.severity,
      b.severity
    );
  }

  return a.ruleId.localeCompare(
    b.ruleId
  );
}

function severityRank(severity) {
  switch (severity) {
    case "critical":
      return 4;

    case "high":
      return 3;

    case "medium":
      return 2;

    case "low":
      return 1;

    default:
      return 0;
  }
}

function compareSeverity(a, b) {
  return (
    severityRank(b) -
    severityRank(a)
  );
}

function rangesOverlap(a, b) {
  return (
    a.start < b.end &&
    b.start < a.end
  );
}

function containsRange(container, value) {
  return (
    container.start <= value.start &&
    container.end >= value.end
  );
}

function mergeEquivalentFindings(
  findings
) {
  const result = [];
  const seen = new Set();

  for (const finding of findings) {
    const key = getFindingKey(finding);

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    result.push(finding);
  }

  return result;
}

function selectHigherPriorityFinding(
  first,
  second
) {
  if (
    first.priority !==
    second.priority
  ) {
    return first.priority >
      second.priority
      ? first
      : second;
  }

  if (
    first.confidence !==
    second.confidence
  ) {
    return first.confidence >
      second.confidence
      ? first
      : second;
  }

  if (
    severityRank(first.severity) !==
    severityRank(second.severity)
  ) {
    return severityRank(first.severity) >
      severityRank(second.severity)
      ? first
      : second;
  }

  const firstSensitive =
    SECRET_LIKE_CATEGORY_NAMES.has(
      first.category
    );

  const secondSensitive =
    SECRET_LIKE_CATEGORY_NAMES.has(
      second.category
    );

  if (
    firstSensitive !==
    secondSensitive
  ) {
    return firstSensitive
      ? first
      : second;
  }

  return first;
}

function deduplicateOverlappingFindings(
  findings
) {
  if (findings.length <= 1) {
    return findings.slice();
  }

  const sorted = findings
    .slice()
    .sort(compareFindings);

  const result = [];

  for (const finding of sorted) {
    let discarded = false;

    for (
      let index = result.length - 1;
      index >= 0;
      index -= 1
    ) {
      const existing =
        result[index];

      if (
        existing.match.end <=
        finding.match.start
      ) {
        break;
      }

      if (
        !rangesOverlap(
          existing.match,
          finding.match
        )
      ) {
        continue;
      }

      if (
        containsRange(
          existing.match,
          finding.match
        )
      ) {
        const selected =
          selectHigherPriorityFinding(
            existing,
            finding
          );

        if (selected === finding) {
          result[index] = finding;
        }

        discarded = true;
        break;
      }

      if (
        containsRange(
          finding.match,
          existing.match
        )
      ) {
        const selected =
          selectHigherPriorityFinding(
            existing,
            finding
          );

        if (selected === finding) {
          result[index] = finding;
        }

        discarded = true;
        break;
      }

      const selected =
        selectHigherPriorityFinding(
          existing,
          finding
        );

      if (selected === existing) {
        discarded = true;
        break;
      }

      result[index] = finding;
      discarded = true;
      break;
    }

    if (!discarded) {
      result.push(finding);
    }
  }

  return result.sort(
    compareFindings
  );
}

function enforceFindingLimit(
  findings,
  maximum
) {
  if (
    findings.length <= maximum
  ) {
    return {
      findings,
      truncated: false,
    };
  }

  const prioritized = findings
    .slice()
    .sort((a, b) => {
      if (
        a.priority !==
        b.priority
      ) {
        return (
          b.priority -
          a.priority
        );
      }

      if (
        a.confidence !==
        b.confidence
      ) {
        return (
          b.confidence -
          a.confidence
        );
      }

      return (
        severityRank(b.severity) -
        severityRank(a.severity)
      );
    })
    .slice(0, maximum)
    .sort(compareFindings);

  return {
    findings: prioritized,
    truncated: true,
  };
}

function createFindingSummary(
  findings
) {
  const categories = {};
  const severities = {};

  for (const finding of findings) {
    categories[finding.category] =
      (categories[finding.category] ?? 0) + 1;

    severities[finding.severity] =
      (severities[finding.severity] ?? 0) + 1;
  }

  return {
    total: findings.length,
    categories,
    severities,
  };
}

function createSafeRuleError(
  rule,
  reason
) {
  return {
    ruleId: getRuleId(rule),
    ruleName: getRuleName(rule),
    reason,
  };
}

function createMatcherResult({
  findings,
  ruleCount,
  rulesMatched,
  ruleErrors,
  truncated,
  durationMs,
  normalization,
}) {
  return {
    version: MATCHER_VERSION,

    matched:
      findings.length > 0,

    findings,

    findingCount:
      findings.length,

    summary:
      createFindingSummary(findings),

    ruleCount,

    rulesMatched,

    ruleErrors,

    truncated,

    durationMs:

      Number.isFinite(durationMs)
        ? Math.max(0, durationMs)
        : 0,

    normalization: {
      version:
        normalization?.version ?? null,

      truncated:
        normalization?.truncated ?? false,

      originalLength:
        normalization?.originalText?.length ?? 0,

      normalizedLength:
        normalization?.normalizedText?.length ?? 0,

      compactLength:
        normalization?.compactText?.length ?? 0,
    },
  };
}

function now() {
  if (
    typeof performance !==
      "undefined" &&
    typeof performance.now ===
      "function"
  ) {
    return performance.now();
  }

  return Date.now();
}

/**
 * Match a single rule against normalized text.
 *
 * @param {object} rule
 * @param {object} normalizationResult
 * @param {number} ruleIndex
 * @returns {object}
 */
export function matchRule(
  rule,
  normalizationResult,
  ruleIndex = 0
) {
  const normalizedRule =
    normalizeRule(
      rule,
      ruleIndex
    );

  if (!normalizedRule) {
    return createEmptyMatchResult(
      rule,
      "Invalid rule."
    );
  }

  if (
    !isNormalizationResult(
      normalizationResult
    )
  ) {
    return createEmptyMatchResult(
      normalizedRule,
      "Invalid normalization result."
    );
  }

  const view =
    normalizedRule.view;

  const text = getViewText(
    normalizationResult,
    view
  );

  if (!text) {
    return createEmptyMatchResult(
      normalizedRule
    );
  }

  const maxMatches =
    normalizedRule.maxMatches;

  const execution =
    executeRuleMatcher(
      normalizedRule,
      text,
      normalizationResult,
      maxMatches
    );

  if (
    execution.error
  ) {
    return {
      matched: false,
      ruleId:
        normalizedRule.id,
      matches: [],
      matchCount: 0,
      truncated: false,
      error: execution.error,
    };
  }

  const matches = [];

  for (
    let index = 0;
    index <
      execution.matches.length;
    index += 1
  ) {
    const candidate =
      execution.matches[index];

    const validation =
      applyRuleValidator(
        normalizedRule,
        candidate,
        text,
        normalizationResult
      );

    if (!validation.accepted) {
      continue;
    }

    const finding =
      createMatchRecord({
        rule: normalizedRule,
        view,
        viewStart:
          candidate.start,
        viewEnd:
          candidate.end,
        normalizationResult,
        ruleIndex,
        matchIndex: index,
        groups:
          candidate.groups,
        scoreOverride:
          validation.confidence ??
          candidate.confidence ??
          candidate.score ??
          null,
      });

    if (!finding) {
      continue;
    }

    matches.push(finding);

    if (
      matches.length >=
      maxMatches
    ) {
      break;
    }
  }

  return {
    matched:
      matches.length > 0,

    ruleId:
      normalizedRule.id,

    matches,

    matchCount:
      matches.length,

    truncated:
      execution.truncated,

    error: null,
  };
}

/**
 * Match all supplied rules against normalized text.
 *
 * @param {object} normalizationResult
 * @param {Array<object>} rules
 * @param {object} options
 * @returns {object}
 */
export function matchNormalizedText(
  normalizationResult,
  rules,
  options = {}
) {
  const startedAt = now();

  if (
    !isNormalizationResult(
      normalizationResult
    )
  ) {
    return createMatcherResult({
      findings: [],
      ruleCount: 0,
      rulesMatched: 0,
      ruleErrors: [
        {
          ruleId: null,
          ruleName: null,
          reason:
            "Invalid normalization result.",
        },
      ],
      truncated: false,
      durationMs:
        now() - startedAt,
      normalization: null,
    });
  }

  const normalizedRules =
    normalizeRuleList(rules);

  const maximumFindings =
    isPositiveInteger(
      options.maxFindings
    )
      ? Math.min(
          options.maxFindings,
          DEFAULT_MAX_FINDINGS
        )
      : DEFAULT_MAX_FINDINGS;

  const findings = [];
  const ruleErrors = [];

  let rulesMatched = 0;
  let globallyTruncated = false;

  for (
    let ruleIndex = 0;
    ruleIndex <
      normalizedRules.length;
    ruleIndex += 1
  ) {
    if (
      findings.length >=
      maximumFindings
    ) {
      globallyTruncated = true;
      break;
    }

    const rule =
      normalizedRules[ruleIndex];

    const result =
      matchRule(
        rule,
        normalizationResult,
        ruleIndex
      );

    if (result.error) {
      ruleErrors.push(
        createSafeRuleError(
          rule,
          result.error
        )
      );

      continue;
    }

    if (result.matched) {
      rulesMatched += 1;
    }

    if (result.truncated) {
      globallyTruncated = true;
    }

    for (const finding of result.matches) {
      findings.push(finding);

      if (
        findings.length >=
        maximumFindings
      ) {
        globallyTruncated = true;
        break;
      }
    }
  }

  const uniqueFindings =
    mergeEquivalentFindings(
      findings
    );

  const deduplicated =
    deduplicateOverlappingFindings(
      uniqueFindings
    );

  const limited =
    enforceFindingLimit(
      deduplicated,
      maximumFindings
    );

  return createMatcherResult({
    findings:
      limited.findings,

    ruleCount:
      normalizedRules.length,

    rulesMatched,

    ruleErrors,

    truncated:
      globallyTruncated ||
      limited.truncated,

    durationMs:
      now() - startedAt,

    normalization:
      normalizationResult,
  });
}

/**
 * Normalize and match text in one operation.
 *
 * This is the primary convenience API used by scanner.js.
 *
 * @param {string} text
 * @param {Array<object>} rules
 * @param {object} options
 * @returns {object}
 */
export function matchText(
  text,
  rules,
  options = {}
) {
  const normalization =
    normalizeText(
      typeof text === "string"
        ? text
        : "",
      options.normalization ?? {}
    );

  return matchNormalizedText(
    normalization,
    rules,
    options
  );
}

/**
 * Create a reusable matcher function.
 *
 * @param {Array<object>} rules
 * @param {object} options
 * @returns {Function}
 */
export function createMatcher(
  rules = [],
  options = {}
) {
  const normalizedRules =
    normalizeRuleList(rules);

  const matcherOptions = {
    ...options,
  };

  return function matcher(text) {
    return matchText(
      text,
      normalizedRules,
      matcherOptions
    );
  };
}

/**
 * Create a standard regex detection rule.
 *
 * @param {object} definition
 * @returns {object|null}
 */
export function createRegexRule(
  definition
) {
  if (!isObject(definition)) {
    return null;
  }

  const rule = normalizeRule(
    {
      ...definition,
      type: RULE_TYPES.REGEX,
    },
    0
  );

  if (!rule) {
    return null;
  }

  if (
    typeof rule.pattern !==
    "string" &&
    !(rule.pattern instanceof RegExp)
  ) {
    return null;
  }

  return rule;
}

/**
 * Create a standard literal detection rule.
 *
 * @param {object} definition
 * @returns {object|null}
 */
export function createLiteralRule(
  definition
) {
  if (!isObject(definition)) {
    return null;
  }

  const rule = normalizeRule(
    {
      ...definition,
      type: RULE_TYPES.LITERAL,
    },
    0
  );

  if (!rule) {
    return null;
  }

  if (
    typeof rule.pattern !==
    "string"
  ) {
    return null;
  }

  return rule;
}

/**
 * Create a custom detection rule.
 *
 * @param {object} definition
 * @returns {object|null}
 */
export function createCustomRule(
  definition
) {
  if (!isObject(definition)) {
    return null;
  }

  const rule = normalizeRule(
    {
      ...definition,
      type: RULE_TYPES.CUSTOM,
    },
    0
  );

  if (!rule) {
    return null;
  }

  if (
    typeof rule.matcher !==
    "function"
  ) {
    return null;
  }

  return rule;
}

/**
 * Validate a detection rule without executing it.
 *
 * @param {object} rule
 * @returns {{valid:boolean,errors:string[]}}
 */
export function validateRule(
  rule
) {
  const errors = [];

  if (!isObject(rule)) {
    return {
      valid: false,
      errors: [
        "Rule must be an object.",
      ],
    };
  }

  if (
    !isString(rule.id) ||
    !rule.id.trim()
  ) {
    errors.push(
      "Rule id is required."
    );
  }

  if (
    rule.name !== undefined &&
    !isString(rule.name)
  ) {
    errors.push(
      "Rule name must be a string."
    );
  }

  const type =
    normalizeRuleType(
      rule.type
    );

  if (
    rule.type !== undefined &&
    !VALID_RULE_TYPES.has(
      rule.type
    )
  ) {
    errors.push(
      "Rule type is invalid."
    );
  }

  const view =
    normalizeMatchView(
      rule.view
    );

  if (
    rule.view !== undefined &&
    !VALID_MATCH_VIEWS.has(
      rule.view
    )
  ) {
    errors.push(
      "Rule view is invalid."
    );
  }

  if (
    !isString(rule.category) ||
    !rule.category.trim()
  ) {
    errors.push(
      "Rule category is required."
    );
  }

  if (
    rule.confidence !== undefined &&
    (
      !Number.isFinite(
        rule.confidence
      ) ||
      rule.confidence < 0 ||
      rule.confidence > 1
    )
  ) {
    errors.push(
      "Rule confidence must be between 0 and 1."
    );
  }

  if (
    rule.maxMatches !== undefined &&
    !isPositiveInteger(
      rule.maxMatches
    )
  ) {
    errors.push(
      "Rule maxMatches must be a positive integer."
    );
  }

  if (
    type === RULE_TYPES.REGEX
  ) {
    if (
      typeof rule.pattern !==
        "string" &&
      !(rule.pattern instanceof RegExp)
    ) {
      errors.push(
        "Regex rule requires a pattern."
      );
    } else if (
      typeof rule.pattern ===
        "string" &&
      isRegexPatternObviouslyUnsafe(
        rule.pattern
      )
    ) {
      errors.push(
        "Regex pattern is invalid or potentially unsafe."
      );
    }
  }

  if (
    type === RULE_TYPES.LITERAL
  ) {
    if (
      !isString(rule.pattern) ||
      rule.pattern.length === 0
    ) {
      errors.push(
        "Literal rule requires a non-empty string pattern."
      );
    }
  }

  if (
    type === RULE_TYPES.CUSTOM
  ) {
    if (
      !isFunction(rule.matcher)
    ) {
      errors.push(
        "Custom rule requires a matcher function."
      );
    }
  }

  if (
    rule.flags !== undefined &&
    (
      !isString(rule.flags) ||
      !REGEX_FLAG_PATTERN.test(
        rule.flags
      ) ||
      hasDuplicateCharacters(
        rule.flags
      )
    )
  ) {
    errors.push(
      "Rule flags are invalid."
    );
  }

  if (
    view === MATCH_VIEWS.COMPACT &&
    type === RULE_TYPES.CUSTOM &&
    !isFunction(rule.matcher)
  ) {
    errors.push(
      "Compact custom rules require a matcher function."
    );
  }

  return {
    valid:
      errors.length === 0,
    errors,
  };
}

/**
 * Validate an entire rule set.
 *
 * @param {Array<object>} rules
 * @returns {{valid:boolean,errors:Array}}
 */
export function validateRuleSet(
  rules
) {
  if (!Array.isArray(rules)) {
    return {
      valid: false,
      errors: [
        {
          index: -1,
          errors: [
            "Rule set must be an array.",
          ],
        },
      ],
    };
  }

  const errors = [];
  const ids = new Set();

  for (
    let index = 0;
    index < rules.length;
    index += 1
  ) {
    const rule =
      rules[index];

    const validation =
      validateRule(rule);

    if (!validation.valid) {
      errors.push({
        index,
        id:
          isString(rule?.id)
            ? rule.id
            : null,
        errors:
          validation.errors,
      });
    }

    if (
      isString(rule?.id) &&
      rule.id.trim()
    ) {
      if (ids.has(rule.id)) {
        errors.push({
          index,
          id: rule.id,
          errors: [
            "Duplicate rule id.",
          ],
        });
      }

      ids.add(rule.id);
    }
  }

  if (
    rules.length >
    DEFAULT_MAX_RULES
  ) {
    errors.push({
      index: -1,
      id: null,
      errors: [
        `Rule set exceeds maximum of ${DEFAULT_MAX_RULES} rules.`,
      ],
    });
  }

  return {
    valid:
      errors.length === 0,
    errors,
  };
}

/**
 * Return a safe representation of a rule.
 *
 * This intentionally excludes the pattern because patterns themselves
 * may contain sensitive or proprietary matching material.
 *
 * @param {object} rule
 * @returns {object}
 */
export function getRuleMetadata(
  rule
) {
  if (!isObject(rule)) {
    return null;
  }

  const metadata = {
    id: getRuleId(rule),
    name: getRuleName(rule),
    enabled:
      rule.enabled !== false,
    type:
      normalizeRuleType(rule.type),
    view:
      normalizeMatchView(rule.view),
    category:
      getRuleCategory(rule),
    subCategory:
      isString(rule.subCategory)
        ? rule.subCategory
        : null,
    severity:
      getRuleSeverity(rule),
    confidence:
      normalizeConfidence(
        rule.confidence
      ),
    priority:
      normalizePriority(
        rule.priority
      ),
    maxMatches:
      normalizeMaxMatches(
        rule.maxMatches
      ),
    tags:
      Array.isArray(rule.tags)
        ? rule.tags.filter(
            (tag) =>
              typeof tag ===
              "string"
          )
        : [],
  };

  return metadata;
}

/**
 * Return metadata for a complete rule set.
 *
 * @param {Array<object>} rules
 * @returns {object}
 */
export function getRuleSetMetadata(
  rules
) {
  const normalized =
    normalizeRuleList(rules);

  const categories = {};
  const severities = {};
  const types = {};
  const views = {};

  for (const rule of normalized) {
    categories[rule.category] =
      (categories[rule.category] ?? 0) + 1;

    severities[rule.severity] =
      (severities[rule.severity] ?? 0) + 1;

    types[rule.type] =
      (types[rule.type] ?? 0) + 1;

    views[rule.view] =
      (views[rule.view] ?? 0) + 1;
  }

  return {
    version: MATCHER_VERSION,
    ruleCount: normalized.length,
    categories,
    severities,
    types,
    views,
  };
}

/**
 * Return matcher engine diagnostics.
 *
 * Does not include sensitive text or rule patterns.
 *
 * @returns {object}
 */
export function getMatcherDiagnostics() {
  return {
    version: MATCHER_VERSION,
    ruleTypes: {
      ...RULE_TYPES,
    },
    matchViews: {
      ...MATCH_VIEWS,
    },
    maximumFindings:
      DEFAULT_MAX_FINDINGS,
    maximumRuleMatches:
      DEFAULT_MAX_RULE_MATCHES,
    maximumRules:
      DEFAULT_MAX_RULES,
    maximumPatternLength:
      DEFAULT_MAX_PATTERN_LENGTH,
  };
}

/**
 * Return whether a finding represents a high-risk category.
 *
 * This is informational only. Policy decisions belong to policy-engine.js.
 *
 * @param {object} finding
 * @returns {boolean}
 */
export function isHighRiskFinding(
  finding
) {
  if (!isObject(finding)) {
    return false;
  }

  if (
    HIGH_RISK_SEVERITIES.has(
      finding.severity
    )
  ) {
    return true;
  }

  return SECRET_LIKE_CATEGORY_NAMES.has(
    finding.category
  );
}

/**
 * Return the highest severity among findings.
 *
 * @param {Array<object>} findings
 * @returns {string}
 */
export function getHighestSeverity(
  findings
) {
  if (!Array.isArray(findings)) {
    return SEVERITY?.LOW ?? "low";
  }

  let highest =
    SEVERITY?.LOW ?? "low";

  for (const finding of findings) {
    if (
      severityRank(
        finding?.severity
      ) >
      severityRank(highest)
    ) {
      highest =
        finding.severity;
    }
  }

  return highest;
}

/**
 * Return the highest confidence among findings.
 *
 * @param {Array<object>} findings
 * @returns {number}
 */
export function getHighestConfidence(
  findings
) {
  if (!Array.isArray(findings)) {
    return 0;
  }

  let highest = 0;

  for (const finding of findings) {
    if (
      Number.isFinite(
        finding?.confidence
      )
    ) {
      highest = Math.max(
        highest,
        finding.confidence
      );
    }
  }

  return highest;
}

/**
 * Return true when two findings overlap.
 *
 * @param {object} first
 * @param {object} second
 * @returns {boolean}
 */
export function findingsOverlap(
  first,
  second
) {
  if (
    !isObject(first) ||
    !isObject(second)
  ) {
    return false;
  }

  if (
    !isObject(first.match) ||
    !isObject(second.match)
  ) {
    return false;
  }

  return rangesOverlap(
    first.match,
    second.match
  );
}

/**
 * Deduplicate a finding list without executing rules.
 *
 * @param {Array<object>} findings
 * @param {object} options
 * @returns {Array<object>}
 */
export function deduplicateFindings(
  findings,
  options = {}
) {
  if (!Array.isArray(findings)) {
    return [];
  }

  const maximum =
    isPositiveInteger(
      options.maxFindings
    )
      ? Math.min(
          options.maxFindings,
          DEFAULT_MAX_FINDINGS
        )
      : DEFAULT_MAX_FINDINGS;

  const equivalent =
    mergeEquivalentFindings(
      findings
    );

  const deduplicated =
    deduplicateOverlappingFindings(
      equivalent
    );

  return enforceFindingLimit(
    deduplicated,
    maximum
  ).findings;
}

/**
 * Get only safe finding metadata.
 *
 * The returned objects intentionally do not contain matchedText,
 * normalizedMatch data, or any other content-bearing fields.
 *
 * @param {Array<object>} findings
 * @returns {Array<object>}
 */
export function stripFindingContent(
  findings
) {
  if (!Array.isArray(findings)) {
    return [];
  }

  return findings.map(
    (finding) => ({
      ruleId:
        finding?.ruleId ?? null,

      ruleName:
        finding?.ruleName ?? null,

      category:
        finding?.category ?? null,

      subCategory:
        finding?.subCategory ?? null,

      severity:
        finding?.severity ?? null,

      confidence:
        Number.isFinite(
          finding?.confidence
        )
          ? finding.confidence
          : 0,

      priority:
        Number.isFinite(
          finding?.priority
        )
          ? finding.priority
          : 0,

      matchStart:
        Number.isInteger(
          finding?.match?.start
        )
          ? finding.match.start
          : null,

      matchEnd:
        Number.isInteger(
          finding?.match?.end
        )
          ? finding.match.end
          : null,
    })
  );
}

/**
 * Export constants for scanner and tests.
 */
export {
  MATCHER_VERSION,
  MATCH_VIEWS,
  RULE_TYPES,
  DEFAULT_MAX_FINDINGS,
  DEFAULT_MAX_RULE_MATCHES,
  DEFAULT_MAX_PATTERN_LENGTH,
  DEFAULT_MAX_RULES,
};
