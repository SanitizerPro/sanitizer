/**
 * SanitizerPro
 * src/policy/mask.js
 *
 * Local masking policy action.
 *
 * Responsibilities:
 * - Replace sensitive portions of text locally.
 * - Prefer exact finding offsets from the scanner.
 * - Safely handle overlapping findings.
 * - Never expose original sensitive values in diagnostics/results.
 * - Preserve non-sensitive content exactly where possible.
 * - Provide deterministic masking behavior.
 *
 * Privacy:
 * - No Chrome APIs.
 * - No network requests.
 * - No storage.
 * - No telemetry.
 * - No raw content logging.
 * - No sensitive values returned in diagnostics.
 *
 * Important:
 * - This module performs masking only.
 * - It does not decide whether masking is allowed.
 * - Policy decisions are made by policy-engine.js.
 */

import {
  ACTIONS,
  MASK_DEFAULTS,
  SCAN_LIMITS,
} from "../config/defaults.js";

import {
  MESSAGE_STATUS,
  SOURCE_TYPES,
} from "../config/constants.js";

const ACTION_VERSION = "1.0.0";
const ACTION_NAME = ACTIONS.MASK;

const DEFAULT_REPLACEMENT = "[REDACTED]";

const MASK_STRATEGIES = Object.freeze({
  REPLACEMENT: "replacement",
  PRESERVE_LENGTH: "preserve-length",
  PRESERVE_TYPE: "preserve-type",
});

const DEFAULT_STRATEGY = MASK_STRATEGIES.REPLACEMENT;

const MAX_REPLACEMENT_LENGTH = 100;
const MAX_FINDINGS = 100;
const MAX_MASKED_RANGES = 100;
const MAX_CATEGORY_LENGTH = 100;
const MAX_RULE_ID_LENGTH = 150;

const SENSITIVE_CATEGORIES = new Set([
  "secret",
  "credential",
  "private_key",
  "token",
  "api_key",
  "password",
  "pii",
  "email",
  "phone",
  "address",
  "person_name",
  "financial",
  "credit_card",
  "bank_account",
  "iban",
  "health",
  "internal",
  "confidential",
  "source_code",
  "database",
  "infrastructure",
]);

const CATEGORY_REPLACEMENTS = Object.freeze({
  email: "[EMAIL]",
  phone: "[PHONE]",
  address: "[ADDRESS]",
  person_name: "[NAME]",
  credit_card: "[CARD]",
  bank_account: "[BANK_ACCOUNT]",
  iban: "[IBAN]",
  api_key: "[API_KEY]",
  token: "[TOKEN]",
  password: "[PASSWORD]",
  private_key: "[PRIVATE_KEY]",
  credential: "[CREDENTIAL]",
  secret: "[SECRET]",
  health: "[HEALTH_DATA]",
  source_code: "[SOURCE_CODE]",
  database: "[DATABASE]",
  infrastructure: "[INFRASTRUCTURE]",
  internal: "[INTERNAL_DATA]",
  confidential: "[CONFIDENTIAL_DATA]",
});

const SECRET_LIKE_CATEGORIES = new Set([
  "secret",
  "credential",
  "private_key",
  "token",
  "api_key",
  "password",
]);

const NUMBER_LIKE_CATEGORIES = new Set([
  "credit_card",
  "bank_account",
  "iban",
]);

function normalizeString(value, maxLength = MAX_REPLACEMENT_LENGTH) {
  if (typeof value !== "string") {
    return "";
  }

  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .slice(0, maxLength);
}

function normalizeCategory(value) {
  return normalizeString(value, MAX_CATEGORY_LENGTH)
    .trim()
    .toLowerCase();
}

function normalizeRuleId(value) {
  return normalizeString(
    value,
    MAX_RULE_ID_LENGTH,
  ).trim();
}

function normalizeSourceType(value) {
  if (
    typeof value === "string" &&
    Object.values(SOURCE_TYPES).includes(value)
  ) {
    return value;
  }

  return SOURCE_TYPES.UNKNOWN;
}

function normalizeReplacement(value) {
  const replacement = normalizeString(
    value,
    MAX_REPLACEMENT_LENGTH,
  );

  return replacement || DEFAULT_REPLACEMENT;
}

function normalizeStrategy(value) {
  if (
    Object.values(MASK_STRATEGIES).includes(value)
  ) {
    return value;
  }

  return DEFAULT_STRATEGY;
}

function clampTextLength(text) {
  if (typeof text !== "string") {
    return "";
  }

  const maxLength =
    Number.isInteger(SCAN_LIMITS?.maxTextCharacters)
      ? SCAN_LIMITS.maxTextCharacters
      : 250000;

  return text.slice(0, Math.max(0, maxLength));
}

function isFiniteInteger(value) {
  return Number.isInteger(value) && Number.isFinite(value);
}

function isValidRange(start, end, textLength) {
  return (
    isFiniteInteger(start) &&
    isFiniteInteger(end) &&
    start >= 0 &&
    end > start &&
    end <= textLength
  );
}

function normalizeRange(finding, textLength) {
  if (!finding || typeof finding !== "object") {
    return null;
  }

  const start = Number.isInteger(finding.start)
    ? finding.start
    : Number.isInteger(finding.startIndex)
      ? finding.startIndex
      : Number.isInteger(finding.offset)
        ? finding.offset
        : null;

  const end = Number.isInteger(finding.end)
    ? finding.end
    : Number.isInteger(finding.endIndex)
      ? finding.endIndex
      : start !== null &&
          Number.isInteger(finding.length)
        ? start + finding.length
        : null;

  if (
    start === null ||
    end === null ||
    !isValidRange(start, end, textLength)
  ) {
    return null;
  }

  return {
    start,
    end,
  };
}

function getFindingCategory(finding) {
  return normalizeCategory(
    finding?.category,
  );
}

function getFindingRuleId(finding) {
  return normalizeRuleId(
    finding?.ruleId,
  );
}

function isSensitiveCategory(category) {
  return SENSITIVE_CATEGORIES.has(
    normalizeCategory(category),
  );
}

function getCategoryReplacement(category) {
  const normalizedCategory =
    normalizeCategory(category);

  return (
    CATEGORY_REPLACEMENTS[normalizedCategory] ||
    DEFAULT_REPLACEMENT
  );
}

function getReplacementForFinding(
  finding,
  options = {},
) {
  const strategy = normalizeStrategy(
    options.strategy,
  );

  const configuredReplacement =
    normalizeReplacement(
      options.replacement ??
      MASK_DEFAULTS?.replacement ??
      DEFAULT_REPLACEMENT,
    );

  const category =
    getFindingCategory(finding);

  if (
    strategy === MASK_STRATEGIES.PRESERVE_TYPE ||
    (
      strategy === MASK_STRATEGIES.REPLACEMENT &&
      options.preserveType === true
    )
  ) {
    return getCategoryReplacement(category);
  }

  if (
    strategy === MASK_STRATEGIES.PRESERVE_LENGTH
  ) {
    return configuredReplacement;
  }

  return configuredReplacement;
}

function createLengthPreservingMask(
  original,
  options = {},
) {
  if (typeof original !== "string") {
    return DEFAULT_REPLACEMENT;
  }

  if (original.length === 0) {
    return "";
  }

  const replacement =
    normalizeReplacement(
      options.replacement ??
      MASK_DEFAULTS?.replacement ??
      DEFAULT_REPLACEMENT,
    );

  /*
   * For very short values, asterisks are less likely to
   * accidentally disclose type information than a fixed
   * replacement string.
   */
  if (original.length <= 2) {
    return "*".repeat(original.length);
  }

  if (replacement.length === 1) {
    return replacement.repeat(
      original.length,
    );
  }

  return "*".repeat(original.length);
}

function createTypePreservingMask(
  original,
  finding,
  options = {},
) {
  const category =
    getFindingCategory(finding);

  if (
    SECRET_LIKE_CATEGORIES.has(category)
  ) {
    return "[REDACTED]";
  }

  if (
    NUMBER_LIKE_CATEGORIES.has(category)
  ) {
    return createNumericMask(original);
  }

  if (category === "email") {
    return "[EMAIL]";
  }

  if (category === "phone") {
    return "[PHONE]";
  }

  if (category === "person_name") {
    return "[NAME]";
  }

  return getReplacementForFinding(
    finding,
    {
      ...options,
      preserveType: true,
    },
  );
}

function createNumericMask(value) {
  if (typeof value !== "string") {
    return "[REDACTED]";
  }

  const digits = value.replace(
    /\D/g,
    "",
  );

  if (digits.length === 0) {
    return "[REDACTED]";
  }

  return "[NUMBER]";
}

function createMaskForRange(
  text,
  range,
  finding,
  options,
) {
  const original =
    text.slice(
      range.start,
      range.end,
    );

  const strategy = normalizeStrategy(
    options.strategy,
  );

  if (
    strategy === MASK_STRATEGIES.PRESERVE_LENGTH ||
    options.preserveLength === true
  ) {
    return createLengthPreservingMask(
      original,
      options,
    );
  }

  if (
    strategy === MASK_STRATEGIES.PRESERVE_TYPE ||
    options.preserveType === true
  ) {
    return createTypePreservingMask(
      original,
      finding,
      options,
    );
  }

  return getReplacementForFinding(
    finding,
    options,
  );
}

function normalizeFindings(
  findings,
  textLength,
) {
  if (!Array.isArray(findings)) {
    return [];
  }

  const normalized = [];
  const limit = Math.min(
    findings.length,
    MAX_FINDINGS,
  );

  for (let index = 0; index < limit; index += 1) {
    const finding = findings[index];

    const range = normalizeRange(
      finding,
      textLength,
    );

    if (!range) {
      continue;
    }

    const category =
      getFindingCategory(finding);

    /*
     * Do not blindly mask arbitrary categories.
     * Unknown categories require explicit sensitive
     * classification or a caller-provided override.
     */
    if (
      category &&
      !isSensitiveCategory(category) &&
      finding.maskable !== true
    ) {
      continue;
    }

    normalized.push({
      start: range.start,
      end: range.end,
      category,
      ruleId:
        getFindingRuleId(finding),
      severity:
        normalizeString(
          finding.severity,
          30,
        ).toLowerCase() || null,
      confidence:
        Number.isFinite(finding.confidence)
          ? Math.max(
              0,
              Math.min(1, finding.confidence),
            )
          : null,
      sourceIndex: index,
    });
  }

  return normalized;
}

function sortRanges(ranges) {
  return [...ranges].sort(
    (left, right) => {
      if (left.start !== right.start) {
        return left.start - right.start;
      }

      if (left.end !== right.end) {
        return right.end - left.end;
      }

      return (
        left.sourceIndex -
        right.sourceIndex
      );
    },
  );
}

function mergeOverlappingRanges(ranges) {
  if (ranges.length === 0) {
    return [];
  }

  const sorted = sortRanges(ranges);
  const merged = [];

  let current = {
    ...sorted[0],
    findings: [sorted[0]],
  };

  for (let index = 1; index < sorted.length; index += 1) {
    const next = sorted[index];

    if (next.start <= current.end) {
      current.end = Math.max(
        current.end,
        next.end,
      );

      current.findings.push(next);
      continue;
    }

    merged.push(current);

    current = {
      ...next,
      findings: [next],
    };
  }

  merged.push(current);

  return merged.slice(
    0,
    MAX_MASKED_RANGES,
  );
}

function selectPrimaryFinding(
  mergedRange,
) {
  if (
    !mergedRange ||
    !Array.isArray(mergedRange.findings) ||
    mergedRange.findings.length === 0
  ) {
    return null;
  }

  return [...mergedRange.findings].sort(
    (left, right) => {
      const severityRank = {
        low: 1,
        medium: 2,
        high: 3,
        critical: 4,
      };

      const leftSeverity =
        severityRank[left.severity] || 0;

      const rightSeverity =
        severityRank[right.severity] || 0;

      if (
        leftSeverity !== rightSeverity
      ) {
        return (
          rightSeverity -
          leftSeverity
        );
      }

      const leftConfidence =
        left.confidence ?? 0;

      const rightConfidence =
        right.confidence ?? 0;

      return (
        rightConfidence -
        leftConfidence
      );
    },
  )[0];
}

function buildMaskRanges(
  text,
  findings,
  options,
) {
  const normalizedFindings =
    normalizeFindings(
      findings,
      text.length,
    );

  const merged =
    mergeOverlappingRanges(
      normalizedFindings,
    );

  return merged.map(
    (mergedRange) => {
      const primaryFinding =
        selectPrimaryFinding(
          mergedRange,
        );

      return {
        start: mergedRange.start,
        end: mergedRange.end,

        replacement:
          createMaskForRange(
            text,
            mergedRange,
            primaryFinding,
            options,
          ),

        findingCount:
          mergedRange.findings.length,

        categories: [
          ...new Set(
            mergedRange.findings
              .map(
                (finding) =>
                  finding.category,
              )
              .filter(Boolean),
          ),
        ],

        ruleIds: [
          ...new Set(
            mergedRange.findings
              .map(
                (finding) =>
                  finding.ruleId,
              )
              .filter(Boolean),
          ),
        ],
      };
    },
  );
}

function applyRanges(
  text,
  ranges,
) {
  if (!Array.isArray(ranges)) {
    return text;
  }

  let output = text;

  /*
   * Apply from right to left so replacing an earlier
   * range never changes the offsets of later ranges.
   */
  for (
    let index = ranges.length - 1;
    index >= 0;
    index -= 1
  ) {
    const range = ranges[index];

    output =
      output.slice(0, range.start) +
      range.replacement +
      output.slice(range.end);
  }

  return output;
}

function createSafeRangeMetadata(ranges) {
  return ranges.map(
    (range) => ({
      start: range.start,
      end: range.end,
      replacementLength:
        typeof range.replacement === "string"
          ? range.replacement.length
          : 0,
      findingCount:
        Number.isInteger(
          range.findingCount,
        )
          ? range.findingCount
          : 0,
      categories: Array.isArray(
        range.categories,
      )
        ? range.categories.slice(
            0,
            20,
          )
        : [],
      ruleIds: Array.isArray(
        range.ruleIds,
      )
        ? range.ruleIds.slice(
            0,
            20,
          )
        : [],
    }),
  );
}

function countMaskedCharacters(ranges) {
  let total = 0;

  for (const range of ranges) {
    if (
      Number.isInteger(range.start) &&
      Number.isInteger(range.end)
    ) {
      total += Math.max(
        0,
        range.end - range.start,
      );
    }
  }

  return total;
}

function getSafeCategorySummary(ranges) {
  const counts = Object.create(null);

  for (const range of ranges) {
    if (!Array.isArray(range.categories)) {
      continue;
    }

    for (const category of range.categories) {
      if (!category) {
        continue;
      }

      counts[category] =
        (counts[category] || 0) + 1;
    }
  }

  return counts;
}

function getSafeRuleSummary(ranges) {
  const counts = Object.create(null);

  for (const range of ranges) {
    if (!Array.isArray(range.ruleIds)) {
      continue;
    }

    for (const ruleId of range.ruleIds) {
      if (!ruleId) {
        continue;
      }

      counts[ruleId] =
        (counts[ruleId] || 0) + 1;
    }
  }

  return counts;
}

/**
 * Mask text using scanner findings.
 *
 * Returns the sanitized content because the content
 * context must replace the original DOM value with it.
 *
 * The original input is never included in the result.
 */
export function maskText(
  text,
  findings = [],
  options = {},
) {
  if (typeof text !== "string") {
    return createMaskResult({
      originalLength: 0,
      maskedText: "",
      ranges: [],
      options,
      sourceType:
        options.sourceType,
      error: "INVALID_TEXT",
    });
  }

  const boundedText =
    clampTextLength(text);

  const normalizedOptions = {
    replacement:
      normalizeReplacement(
        options.replacement ??
        MASK_DEFAULTS?.replacement ??
        DEFAULT_REPLACEMENT,
      ),

    strategy:
      normalizeStrategy(
        options.strategy,
      ),

    preserveLength:
      options.preserveLength === true ||
      MASK_DEFAULTS?.preserveLength === true,

    preserveType:
      options.preserveType === true ||
      MASK_DEFAULTS?.preserveType === true,
  };

  const ranges =
    buildMaskRanges(
      boundedText,
      findings,
      normalizedOptions,
    );

  const maskedText =
    applyRanges(
      boundedText,
      ranges,
    );

  return createMaskResult({
    originalLength:
      boundedText.length,

    maskedText,

    ranges,

    options:
      normalizedOptions,

    sourceType:
      options.sourceType,

    truncated:
      boundedText.length !==
      text.length,

    error: null,
  });
}

/**
 * Create a privacy-safe mask result.
 *
 * maskedText is intentionally included because the caller
 * needs the sanitized content to replace the original.
 *
 * original content is never returned.
 */
function createMaskResult({
  originalLength,
  maskedText,
  ranges,
  options = {},
  sourceType,
  truncated = false,
  error = null,
}) {
  const safeRanges =
    createSafeRangeMetadata(
      ranges,
    );

  return {
    action: ACTION_NAME,
    status:
      error === null
        ? MESSAGE_STATUS.MASKED
        : MESSAGE_STATUS.ERROR,

    allowed: error === null,
    blocked: false,

    pending: false,
    requiresConfirmation: false,
    shouldContinue: error === null,

    contentModified:
      error === null &&
      safeRanges.length > 0,

    maskedText:
      typeof maskedText === "string"
        ? maskedText
        : "",

    originalLength:
      Number.isInteger(originalLength)
        ? originalLength
        : 0,

    maskedLength:
      typeof maskedText === "string"
        ? maskedText.length
        : 0,

    maskedRangeCount:
      safeRanges.length,

    maskedCharacterCount:
      countMaskedCharacters(
        safeRanges,
      ),

    categories:
      Object.keys(
        getSafeCategorySummary(
          ranges,
        ),
      ),

    ruleIds:
      Object.keys(
        getSafeRuleSummary(
          ranges,
        ),
      ),

    rangeMetadata:
      safeRanges,

    sourceType:
      normalizeSourceType(
        sourceType,
      ),

    strategy:
      normalizeStrategy(
        options.strategy,
      ),

    preserveLength:
      options.preserveLength === true,

    preserveType:
      options.preserveType === true,

    truncated: Boolean(truncated),

    error,

    version:
      ACTION_VERSION,
  };
}

/**
 * Apply the MASK policy action.
 *
 * This is the policy-facing wrapper around maskText().
 */
export function applyMask(
  content,
  findings = [],
  options = {},
) {
  const result =
    maskText(
      content,
      findings,
      options,
    );

  return result;
}

/**
 * Check whether an action is MASK.
 */
export function isMaskAction(action) {
  return action === ACTIONS.MASK;
}

/**
 * Check whether a result represents a successful
 * masking operation.
 */
export function isMaskedResult(result) {
  return Boolean(
    result &&
    result.action === ACTIONS.MASK &&
    result.status === MESSAGE_STATUS.MASKED &&
    result.allowed === true &&
    result.shouldContinue === true &&
    result.error === null,
  );
}

/**
 * Check whether masking actually changed content.
 */
export function contentWasMasked(result) {
  return Boolean(
    result &&
    result.contentModified === true &&
    result.maskedRangeCount > 0,
  );
}

/**
 * Check whether the operation should continue.
 */
export function shouldContinue(result) {
  return Boolean(
    result &&
    result.shouldContinue === true &&
    result.blocked !== true &&
    result.error === null,
  );
}

/**
 * Check whether masking modified content.
 */
export function modifiesContent(result) {
  return Boolean(
    result &&
    result.contentModified === true,
  );
}

/**
 * Get the configured default replacement.
 */
export function getDefaultReplacement() {
  return normalizeReplacement(
    MASK_DEFAULTS?.replacement ??
    DEFAULT_REPLACEMENT,
  );
}

/**
 * Get supported masking strategies.
 */
export function getMaskStrategies() {
  return Object.values(
    MASK_STRATEGIES,
  );
}

/**
 * Get a privacy-safe mask summary.
 *
 * This intentionally excludes:
 * - original text
 * - matched values
 * - masked text
 * - clipboard contents
 * - uploaded file contents
 */
export function getSafeMaskResult(result) {
  if (!result || typeof result !== "object") {
    return null;
  }

  return {
    action:
      result.action,

    status:
      result.status,

    allowed:
      Boolean(result.allowed),

    blocked:
      Boolean(result.blocked),

    pending:
      Boolean(result.pending),

    requiresConfirmation:
      Boolean(
        result.requiresConfirmation,
      ),

    shouldContinue:
      Boolean(result.shouldContinue),

    contentModified:
      Boolean(result.contentModified),

    originalLength:
      Number.isInteger(
        result.originalLength,
      )
        ? result.originalLength
        : 0,

    maskedLength:
      Number.isInteger(
        result.maskedLength,
      )
        ? result.maskedLength
        : 0,

    maskedRangeCount:
      Number.isInteger(
        result.maskedRangeCount,
      )
        ? result.maskedRangeCount
        : 0,

    maskedCharacterCount:
      Number.isInteger(
        result.maskedCharacterCount,
      )
        ? result.maskedCharacterCount
        : 0,

    categories:
      Array.isArray(result.categories)
        ? result.categories.slice(
            0,
            50,
          )
        : [],

    ruleIds:
      Array.isArray(result.ruleIds)
        ? result.ruleIds.slice(
            0,
            100,
          )
        : [],

    sourceType:
      normalizeSourceType(
        result.sourceType,
      ),

    strategy:
      normalizeStrategy(
        result.strategy,
      ),

    preserveLength:
      Boolean(result.preserveLength),

    preserveType:
      Boolean(result.preserveType),

    truncated:
      Boolean(result.truncated),

    error:
      normalizeString(
        result.error,
        200,
      ) || null,

    version:
      ACTION_VERSION,
  };
}

/**
 * Validate a mask result.
 */
export function validateMaskResult(result) {
  const errors = [];

  if (!result || typeof result !== "object") {
    return {
      valid: false,
      errors: [
        "Result must be an object.",
      ],
    };
  }

  if (result.action !== ACTIONS.MASK) {
    errors.push(
      "Result action must be MASK.",
    );
  }

  if (
    result.error === null &&
    result.status !== MESSAGE_STATUS.MASKED
  ) {
    errors.push(
      "Successful mask result must have MASKED status.",
    );
  }

  if (
    result.error === null &&
    result.shouldContinue !== true
  ) {
    errors.push(
      "Successful mask result must allow continuation.",
    );
  }

  if (
    result.contentModified === true &&
    result.maskedRangeCount <= 0
  ) {
    errors.push(
      "Modified content must contain at least one masked range.",
    );
  }

  if (
    !Number.isInteger(
      result.originalLength,
    ) ||
    result.originalLength < 0
  ) {
    errors.push(
      "Invalid originalLength.",
    );
  }

  if (
    !Number.isInteger(
      result.maskedLength,
    ) ||
    result.maskedLength < 0
  ) {
    errors.push(
      "Invalid maskedLength.",
    );
  }

  if (
    !Number.isInteger(
      result.maskedRangeCount,
    ) ||
    result.maskedRangeCount < 0 ||
    result.maskedRangeCount > MAX_MASKED_RANGES
  ) {
    errors.push(
      "Invalid maskedRangeCount.",
    );
  }

  if (
    !Number.isInteger(
      result.maskedCharacterCount,
    ) ||
    result.maskedCharacterCount < 0
  ) {
    errors.push(
      "Invalid maskedCharacterCount.",
    );
  }

  if (
    result.strategy !== undefined &&
    !getMaskStrategies().includes(
      result.strategy,
    )
  ) {
    errors.push(
      "Invalid masking strategy.",
    );
  }

  if (
    result.sourceType !== undefined &&
    !Object.values(
      SOURCE_TYPES,
    ).includes(
      result.sourceType,
    )
  ) {
    errors.push(
      "Invalid source type.",
    );
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Get static action information.
 */
export function getMaskActionInfo() {
  return {
    action: ACTIONS.MASK,
    status: MESSAGE_STATUS.MASKED,

    requiresConfirmation: false,
    automaticallyContinues: true,
    modifiesContent: true,
    blocksByDefault: false,

    strategies:
      getMaskStrategies(),

    defaultStrategy:
      DEFAULT_STRATEGY,

    defaultReplacement:
      getDefaultReplacement(),

    privacy: {
      localOnly: true,
      storesContent: false,
      storesMatchedValues: false,
      sendsRawContentToBackground: false,
      sendsRawContentToNetwork: false,
    },

    version:
      ACTION_VERSION,
  };
}

/**
 * Static diagnostics only.
 */
export function getMaskDiagnostics() {
  return {
    module: "mask",
    action: ACTIONS.MASK,
    version: ACTION_VERSION,

    strategies:
      getMaskStrategies(),

    defaultStrategy:
      DEFAULT_STRATEGY,

    defaultReplacement:
      getDefaultReplacement(),

    limits: {
      maxFindings:
        MAX_FINDINGS,

      maxMaskedRanges:
        MAX_MASKED_RANGES,

      maxReplacementLength:
        MAX_REPLACEMENT_LENGTH,
    },

    privacy: {
      rawContentStored: false,
      rawContentReturned: false,
      matchedValuesStored: false,
      matchedValuesReturned: false,
      networkAccess: false,
      chromeApiAccess: false,
    },
  };
}

/**
 * Default export for consumers that prefer
 * a single policy-action object.
 */
export default Object.freeze({
  maskText,
  applyMask,

  isMaskAction,
  isMaskedResult,
  contentWasMasked,
  shouldContinue,
  modifiesContent,

  getDefaultReplacement,
  getMaskStrategies,

  getSafeMaskResult,
  validateMaskResult,

  getMaskActionInfo,
  getMaskDiagnostics,

  MASK_STRATEGIES,
});
