/**
 * SanitizerPro
 * src/policy/warn.js
 *
 * WARN policy action.
 *
 * Responsibilities:
 * - Represent a policy decision that requires user confirmation.
 * - Never automatically allow a warned operation.
 * - Never automatically modify the protected content.
 * - Keep sensitive finding values out of the warning result.
 * - Allow the content layer to resolve the warning as:
 *     ALLOW
 *     MASK
 *     BLOCK
 *
 * Privacy:
 * - No Chrome APIs.
 * - No network requests.
 * - No storage.
 * - No raw prompt contents.
 * - No clipboard contents.
 * - No uploaded file contents.
 * - No matched sensitive values in returned metadata.
 */

import {
  ACTIONS,
} from "./../config/defaults.js";

import {
  MESSAGE_STATUS,
  SOURCE_TYPES,
} from "./../config/constants.js";

const ACTION_VERSION = "1.0.0";
const ACTION_NAME = ACTIONS.WARN;

const RESOLUTION_ACTIONS = Object.freeze([
  ACTIONS.ALLOW,
  ACTIONS.MASK,
  ACTIONS.BLOCK,
]);

const WARNING_REASON_CODES = Object.freeze({
  SENSITIVE_DATA_DETECTED: "SENSITIVE_DATA_DETECTED",
  HIGH_RISK_DATA_DETECTED: "HIGH_RISK_DATA_DETECTED",
  CRITICAL_DATA_DETECTED: "CRITICAL_DATA_DETECTED",
  POLICY_REQUIRES_CONFIRMATION: "POLICY_REQUIRES_CONFIRMATION",
});

const DEFAULT_WARNING_REASON =
  WARNING_REASON_CODES.POLICY_REQUIRES_CONFIRMATION;

const DEFAULT_WARNING_MESSAGE =
  "Sensitive information was detected. Review the detected categories before continuing.";

const MAX_REASON_LENGTH = 500;
const MAX_CATEGORY_COUNT = 50;
const MAX_RULE_COUNT = 100;

function createRequestId() {
  const randomPart = Math.random()
    .toString(36)
    .slice(2, 12);

  return `warn_${Date.now().toString(36)}_${randomPart}`;
}

function normalizeString(value, maxLength = MAX_REASON_LENGTH) {
  if (typeof value !== "string") {
    return "";
  }

  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
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

function normalizeCategories(categories) {
  if (!Array.isArray(categories)) {
    return [];
  }

  const result = [];
  const seen = new Set();

  for (const category of categories) {
    const normalized = normalizeString(category, 100);

    if (!normalized || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    result.push(normalized);

    if (result.length >= MAX_CATEGORY_COUNT) {
      break;
    }
  }

  return result;
}

function normalizeRuleIds(ruleIds) {
  if (!Array.isArray(ruleIds)) {
    return [];
  }

  const result = [];
  const seen = new Set();

  for (const ruleId of ruleIds) {
    const normalized = normalizeString(ruleId, 150);

    if (!normalized || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    result.push(normalized);

    if (result.length >= MAX_RULE_COUNT) {
      break;
    }
  }

  return result;
}

function normalizeSeverity(value) {
  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.trim().toLowerCase();

  if (
    normalized === "low" ||
    normalized === "medium" ||
    normalized === "high" ||
    normalized === "critical"
  ) {
    return normalized;
  }

  return null;
}

function normalizeRiskLevel(value) {
  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.trim().toLowerCase();

  if (
    normalized === "low" ||
    normalized === "medium" ||
    normalized === "high" ||
    normalized === "critical"
  ) {
    return normalized;
  }

  return null;
}

function sanitizeContext(context = {}) {
  if (!context || typeof context !== "object") {
    return {};
  }

  return {
    platformId: normalizeString(context.platformId, 150) || null,
    platformName: normalizeString(context.platformName, 150) || null,
    hostname: normalizeString(context.hostname, 253) || null,
    sourceType: normalizeSourceType(context.sourceType),
    fieldType: normalizeString(context.fieldType, 100) || null,
    operation: normalizeString(context.operation, 100) || null,
  };
}

function getWarningReason(scanResult = {}) {
  if (
    scanResult?.risk?.level === "critical" ||
    scanResult?.riskLevel === "critical"
  ) {
    return WARNING_REASON_CODES.CRITICAL_DATA_DETECTED;
  }

  if (
    scanResult?.risk?.level === "high" ||
    scanResult?.riskLevel === "high"
  ) {
    return WARNING_REASON_CODES.HIGH_RISK_DATA_DETECTED;
  }

  if (
    Array.isArray(scanResult?.findings) &&
    scanResult.findings.length > 0
  ) {
    return WARNING_REASON_CODES.SENSITIVE_DATA_DETECTED;
  }

  return DEFAULT_WARNING_REASON;
}

function extractSafeScanMetadata(scanResult = {}) {
  if (!scanResult || typeof scanResult !== "object") {
    return {
      findingCount: 0,
      categories: [],
      ruleIds: [],
      highestSeverity: null,
      riskScore: null,
      riskLevel: null,
    };
  }

  const findings = Array.isArray(scanResult.findings)
    ? scanResult.findings
    : [];

  const categories = [];
  const ruleIds = [];
  const categorySet = new Set();
  const ruleSet = new Set();

  let highestSeverity = null;

  const severityRank = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };

  for (const finding of findings) {
    if (!finding || typeof finding !== "object") {
      continue;
    }

    const category = normalizeString(
      finding.category,
      100,
    );

    if (category && !categorySet.has(category)) {
      categorySet.add(category);
      categories.push(category);
    }

    const ruleId = normalizeString(
      finding.ruleId,
      150,
    );

    if (ruleId && !ruleSet.has(ruleId)) {
      ruleSet.add(ruleId);
      ruleIds.push(ruleId);
    }

    const severity = normalizeSeverity(finding.severity);

    if (
      severity &&
      (
        highestSeverity === null ||
        severityRank[severity] > severityRank[highestSeverity]
      )
    ) {
      highestSeverity = severity;
    }

    if (categories.length >= MAX_CATEGORY_COUNT) {
      break;
    }

    if (ruleIds.length >= MAX_RULE_COUNT) {
      break;
    }
  }

  const riskScore =
    Number.isFinite(scanResult?.risk?.score)
      ? Math.max(0, Math.min(100, scanResult.risk.score))
      : Number.isFinite(scanResult?.riskScore)
        ? Math.max(0, Math.min(100, scanResult.riskScore))
        : null;

  const riskLevel =
    normalizeRiskLevel(scanResult?.risk?.level) ||
    normalizeRiskLevel(scanResult?.riskLevel);

  return {
    findingCount: Math.max(0, Math.min(100, findings.length)),
    categories: normalizeCategories(categories),
    ruleIds: normalizeRuleIds(ruleIds),
    highestSeverity,
    riskScore,
    riskLevel,
  };
}

/**
 * Create a warning decision.
 *
 * A warning is intentionally NOT an allow decision.
 * The operation remains pending until resolveWarning() is called.
 */
export function createWarnResult(options = {}) {
  const scanMetadata = extractSafeScanMetadata(
    options.scanResult,
  );

  const reason =
    normalizeString(options.reason, MAX_REASON_LENGTH) ||
    getWarningReason(options.scanResult);

  const message =
    normalizeString(options.message, MAX_REASON_LENGTH) ||
    DEFAULT_WARNING_MESSAGE;

  const sourceType = normalizeSourceType(
    options.sourceType ??
    options.context?.sourceType,
  );

  const context = sanitizeContext({
    ...options.context,
    sourceType,
  });

  return {
    action: ACTION_NAME,

    status: MESSAGE_STATUS.WARNING,

    allowed: false,
    blocked: false,

    pending: true,
    requiresConfirmation: true,

    shouldContinue: false,
    contentModified: false,

    requestId:
      normalizeString(options.requestId, 150) ||
      createRequestId(),

    reason,
    reasonCode:
      normalizeString(options.reasonCode, 150) ||
      reason,

    message,

    sourceType,

    context,

    findingCount: scanMetadata.findingCount,
    categories: scanMetadata.categories,
    ruleIds: scanMetadata.ruleIds,

    highestSeverity: scanMetadata.highestSeverity,
    riskScore: scanMetadata.riskScore,
    riskLevel: scanMetadata.riskLevel,

    resolved: false,
    resolution: null,

    createdAt: Date.now(),

    version: ACTION_VERSION,
  };
}

/**
 * Check whether an action is WARN.
 */
export function isWarnAction(action) {
  return action === ACTIONS.WARN;
}

/**
 * Check whether a result represents an unresolved warning.
 */
export function isWarningResult(result) {
  return Boolean(
    result &&
    result.action === ACTIONS.WARN &&
    result.pending === true &&
    result.requiresConfirmation === true &&
    result.resolved === false,
  );
}

/**
 * Check whether a warning can be resolved.
 */
export function canResolveWarning(result) {
  return isWarningResult(result);
}

/**
 * Validate a requested warning resolution.
 */
export function isValidWarningResolution(action) {
  return RESOLUTION_ACTIONS.includes(action);
}

/**
 * Apply the WARN action.
 *
 * This function deliberately does not modify content.
 * The operation remains blocked/pending until the warning is resolved.
 */
export function applyWarn(content, options = {}) {
  const result = createWarnResult(options);

  return {
    ...result,
    content,
    contentModified: false,
  };
}

/**
 * Resolve a pending warning.
 *
 * ALLOW:
 *   Continues the original operation without changing content.
 *
 * MASK:
 *   Permits the caller to perform masking. This module does not perform
 *   masking because masking belongs to mask.js.
 *
 * BLOCK:
 *   Stops the operation.
 *
 * The original warning result is never mutated.
 */
export function resolveWarning(
  warningResult,
  resolution,
  options = {},
) {
  if (!isWarningResult(warningResult)) {
    return createInvalidResolutionResult(
      warningResult,
      "INVALID_WARNING_RESULT",
    );
  }

  if (!isValidWarningResolution(resolution)) {
    return createInvalidResolutionResult(
      warningResult,
      "INVALID_WARNING_RESOLUTION",
    );
  }

  const normalizedReason =
    normalizeString(options.reason, MAX_REASON_LENGTH);

  const resolvedAt = Date.now();

  if (resolution === ACTIONS.ALLOW) {
    return {
      ...warningResult,

      action: ACTIONS.ALLOW,
      status: MESSAGE_STATUS.ALLOWED,

      allowed: true,
      blocked: false,

      pending: false,
      requiresConfirmation: false,
      shouldContinue: true,

      contentModified: false,

      resolved: true,
      resolution: ACTIONS.ALLOW,

      resolutionReason:
        normalizedReason ||
        "User confirmed that the operation should continue.",

      resolvedAt,

      version: ACTION_VERSION,
    };
  }

  if (resolution === ACTIONS.MASK) {
    return {
      ...warningResult,

      action: ACTIONS.MASK,
      status: MESSAGE_STATUS.MASKED,

      allowed: true,
      blocked: false,

      pending: false,
      requiresConfirmation: false,
      shouldContinue: true,

      /*
       * The mask policy is responsible for actually producing the
       * sanitized content. This module only records the resolution.
       */
      contentModified: true,

      resolved: true,
      resolution: ACTIONS.MASK,

      resolutionReason:
        normalizedReason ||
        "User confirmed that sensitive content should be masked.",

      resolvedAt,

      version: ACTION_VERSION,
    };
  }

  return {
    ...warningResult,

    action: ACTIONS.BLOCK,
    status: MESSAGE_STATUS.BLOCKED,

    allowed: false,
    blocked: true,

    pending: false,
    requiresConfirmation: false,
    shouldContinue: false,

    contentModified: false,

    resolved: true,
    resolution: ACTIONS.BLOCK,

    resolutionReason:
      normalizedReason ||
      "User chose to block the operation.",

    resolvedAt,

    version: ACTION_VERSION,
  };
}

function createInvalidResolutionResult(
  warningResult,
  reason,
) {
  const base = (
    warningResult &&
    typeof warningResult === "object"
  )
    ? warningResult
    : createWarnResult();

  return {
    ...base,

    action: ACTIONS.BLOCK,
    status: MESSAGE_STATUS.BLOCKED,

    allowed: false,
    blocked: true,

    pending: false,
    requiresConfirmation: false,
    shouldContinue: false,

    contentModified: false,

    resolved: true,
    resolution: ACTIONS.BLOCK,

    resolutionReason:
      normalizeString(reason, MAX_REASON_LENGTH) ||
      "Warning resolution failed safely.",

    resolvedAt: Date.now(),

    version: ACTION_VERSION,
  };
}

/**
 * Convenience helpers for consumers.
 */
export function shouldContinue(result) {
  return Boolean(
    result &&
    result.shouldContinue === true &&
    result.blocked !== true,
  );
}

export function requiresConfirmation(result) {
  return Boolean(
    result &&
    result.requiresConfirmation === true &&
    result.pending === true,
  );
}

export function isResolved(result) {
  return Boolean(
    result &&
    result.resolved === true,
  );
}

export function isWarningPending(result) {
  return Boolean(
    result &&
    result.action === ACTIONS.WARN &&
    result.pending === true &&
    result.resolved === false,
  );
}

export function getWarningResolutionOptions() {
  return [...RESOLUTION_ACTIONS];
}

/**
 * Return a privacy-safe copy suitable for UI rendering/logging.
 *
 * Never includes raw matched text or original content.
 */
export function getSafeWarnResult(result) {
  if (!result || typeof result !== "object") {
    return null;
  }

  return {
    action:
      result.action === ACTIONS.WARN
        ? ACTIONS.WARN
        : result.action,

    status: result.status,

    allowed: Boolean(result.allowed),
    blocked: Boolean(result.blocked),

    pending: Boolean(result.pending),
    requiresConfirmation: Boolean(
      result.requiresConfirmation,
    ),

    shouldContinue: Boolean(result.shouldContinue),
    contentModified: Boolean(result.contentModified),

    requestId:
      normalizeString(result.requestId, 150) || null,

    reason:
      normalizeString(result.reason, MAX_REASON_LENGTH) ||
      null,

    reasonCode:
      normalizeString(result.reasonCode, 150) ||
      null,

    message:
      normalizeString(result.message, MAX_REASON_LENGTH) ||
      null,

    sourceType:
      normalizeSourceType(result.sourceType),

    context: sanitizeContext(result.context),

    findingCount:
      Number.isFinite(result.findingCount)
        ? Math.max(0, Math.min(100, result.findingCount))
        : 0,

    categories:
      normalizeCategories(result.categories),

    ruleIds:
      normalizeRuleIds(result.ruleIds),

    highestSeverity:
      normalizeSeverity(result.highestSeverity),

    riskScore:
      Number.isFinite(result.riskScore)
        ? Math.max(0, Math.min(100, result.riskScore))
        : null,

    riskLevel:
      normalizeRiskLevel(result.riskLevel),

    resolved:
      Boolean(result.resolved),

    resolution:
      isValidWarningResolution(result.resolution)
        ? result.resolution
        : null,

    createdAt:
      Number.isFinite(result.createdAt)
        ? result.createdAt
        : null,

    resolvedAt:
      Number.isFinite(result.resolvedAt)
        ? result.resolvedAt
        : null,

    version: ACTION_VERSION,
  };
}

/**
 * Validate the structural integrity of a warning result.
 */
export function validateWarnResult(result) {
  const errors = [];

  if (!result || typeof result !== "object") {
    return {
      valid: false,
      errors: ["Result must be an object."],
    };
  }

  if (
    result.action !== ACTIONS.WARN &&
    !RESOLUTION_ACTIONS.includes(result.action)
  ) {
    errors.push("Invalid action.");
  }

  if (
    result.action === ACTIONS.WARN &&
    result.pending !== true
  ) {
    errors.push(
      "An unresolved warning must have pending=true.",
    );
  }

  if (
    result.action === ACTIONS.WARN &&
    result.requiresConfirmation !== true
  ) {
    errors.push(
      "An unresolved warning must require confirmation.",
    );
  }

  if (
    result.action === ACTIONS.WARN &&
    result.shouldContinue !== false
  ) {
    errors.push(
      "An unresolved warning cannot continue automatically.",
    );
  }

  if (
    result.action === ACTIONS.WARN &&
    result.resolved !== false
  ) {
    errors.push(
      "An unresolved warning must have resolved=false.",
    );
  }

  if (
    result.action !== ACTIONS.WARN &&
    result.pending === true
  ) {
    errors.push(
      "A resolved action cannot remain pending.",
    );
  }

  if (
    result.resolution !== null &&
    result.resolution !== undefined &&
    !isValidWarningResolution(result.resolution)
  ) {
    errors.push("Invalid resolution action.");
  }

  if (
    result.findingCount !== undefined &&
    (
      !Number.isInteger(result.findingCount) ||
      result.findingCount < 0 ||
      result.findingCount > 100
    )
  ) {
    errors.push("Invalid findingCount.");
  }

  if (
    result.riskScore !== null &&
    result.riskScore !== undefined &&
    (
      !Number.isFinite(result.riskScore) ||
      result.riskScore < 0 ||
      result.riskScore > 100
    )
  ) {
    errors.push("Invalid riskScore.");
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Get static action information.
 */
export function getWarnActionInfo() {
  return {
    action: ACTIONS.WARN,
    status: MESSAGE_STATUS.WARNING,

    requiresConfirmation: true,
    automaticallyContinues: false,
    modifiesContent: false,
    blocksByDefault: true,

    resolutionActions: [
      ...RESOLUTION_ACTIONS,
    ],

    privacy: {
      localOnly: true,
      storesContent: false,
      storesMatchedValues: false,
      sendsRawContentToBackground: false,
      sendsRawContentToNetwork: false,
    },

    version: ACTION_VERSION,
  };
}

/**
 * Diagnostics contain only static/non-sensitive information.
 */
export function getWarnDiagnostics() {
  return {
    module: "warn",
    action: ACTIONS.WARN,
    version: ACTION_VERSION,

    resolutionActions: [
      ...RESOLUTION_ACTIONS,
    ],

    defaults: {
      pending: true,
      requiresConfirmation: true,
      shouldContinue: false,
      contentModified: false,
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

export default Object.freeze({
  createWarnResult,
  isWarnAction,
  isWarningResult,
  canResolveWarning,
  isValidWarningResolution,
  applyWarn,
  resolveWarning,
  shouldContinue,
  requiresConfirmation,
  isResolved,
  isWarningPending,
  getWarningResolutionOptions,
  getSafeWarnResult,
  validateWarnResult,
  getWarnActionInfo,
  getWarnDiagnostics,
});
