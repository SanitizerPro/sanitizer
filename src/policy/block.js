/**
 * SanitizerPro
 * src/policy/block.js
 *
 * Local BLOCK policy action.
 *
 * Responsibilities:
 * - Represent a policy decision that must stop an operation.
 * - Prevent the protected operation from continuing.
 * - Never modify the original content.
 * - Provide privacy-safe metadata for UI and diagnostics.
 * - Provide helpers for consumers to determine block state.
 *
 * Privacy:
 * - No Chrome APIs.
 * - No network requests.
 * - No storage.
 * - No telemetry.
 * - No raw prompt contents.
 * - No clipboard contents.
 * - No uploaded file contents.
 * - No matched sensitive values in returned metadata.
 *
 * Security model:
 * - BLOCK is fail-closed.
 * - Invalid block results are treated as blocked.
 * - A block result never grants continuation.
 */

import {
  ACTIONS,
} from "../config/defaults.js";

import {
  MESSAGE_STATUS,
  SOURCE_TYPES,
} from "../config/constants.js";

const ACTION_VERSION = "1.0.0";
const ACTION_NAME = ACTIONS.BLOCK;

const MAX_REASON_LENGTH = 500;
const MAX_CATEGORY_COUNT = 50;
const MAX_RULE_COUNT = 100;

const BLOCK_REASON_CODES = Object.freeze({
  SENSITIVE_DATA_DETECTED: "SENSITIVE_DATA_DETECTED",
  CRITICAL_DATA_DETECTED: "CRITICAL_DATA_DETECTED",
  HIGH_RISK_DATA_DETECTED: "HIGH_RISK_DATA_DETECTED",
  POLICY_BLOCK: "POLICY_BLOCK",
  LOW_CONFIDENCE_BLOCK: "LOW_CONFIDENCE_BLOCK",
  INVALID_OPERATION: "INVALID_OPERATION",
  SCAN_FAILED: "SCAN_FAILED",
  POLICY_FAILED: "POLICY_FAILED",
  SECURITY_FAILURE: "SECURITY_FAILURE",
});

const DEFAULT_BLOCK_REASON =
  BLOCK_REASON_CODES.POLICY_BLOCK;

const DEFAULT_BLOCK_MESSAGE =
  "This operation was blocked because sensitive information was detected.";

function createRequestId() {
  const randomPart = Math.random()
    .toString(36)
    .slice(2, 12);

  return `block_${Date.now().toString(36)}_${randomPart}`;
}

function normalizeString(
  value,
  maxLength = MAX_REASON_LENGTH,
) {
  if (typeof value !== "string") {
    return "";
  }

  return value
    .replace(
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g,
      "",
    )
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
    const normalized = normalizeString(
      category,
      100,
    );

    if (
      !normalized ||
      seen.has(normalized)
    ) {
      continue;
    }

    seen.add(normalized);
    result.push(normalized);

    if (
      result.length >=
      MAX_CATEGORY_COUNT
    ) {
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
    const normalized = normalizeString(
      ruleId,
      150,
    );

    if (
      !normalized ||
      seen.has(normalized)
    ) {
      continue;
    }

    seen.add(normalized);
    result.push(normalized);

    if (
      result.length >=
      MAX_RULE_COUNT
    ) {
      break;
    }
  }

  return result;
}

function normalizeSeverity(value) {
  if (typeof value !== "string") {
    return null;
  }

  const normalized =
    value.trim().toLowerCase();

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

  const normalized =
    value.trim().toLowerCase();

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
  if (
    !context ||
    typeof context !== "object"
  ) {
    return {};
  }

  return {
    platformId:
      normalizeString(
        context.platformId,
        150,
      ) || null,

    platformName:
      normalizeString(
        context.platformName,
        150,
      ) || null,

    hostname:
      normalizeString(
        context.hostname,
        253,
      ) || null,

    sourceType:
      normalizeSourceType(
        context.sourceType,
      ),

    fieldType:
      normalizeString(
        context.fieldType,
        100,
      ) || null,

    operation:
      normalizeString(
        context.operation,
        100,
      ) || null,
  };
}

function getDefaultBlockReason(
  scanResult = {},
) {
  const riskLevel =
    normalizeRiskLevel(
      scanResult?.risk?.level,
    ) ||
    normalizeRiskLevel(
      scanResult?.riskLevel,
    );

  if (riskLevel === "critical") {
    return (
      BLOCK_REASON_CODES.CRITICAL_DATA_DETECTED
    );
  }

  if (riskLevel === "high") {
    return (
      BLOCK_REASON_CODES.HIGH_RISK_DATA_DETECTED
    );
  }

  if (
    Array.isArray(
      scanResult?.findings,
    ) &&
    scanResult.findings.length > 0
  ) {
    return (
      BLOCK_REASON_CODES.SENSITIVE_DATA_DETECTED
    );
  }

  return DEFAULT_BLOCK_REASON;
}

function extractSafeScanMetadata(
  scanResult = {},
) {
  if (
    !scanResult ||
    typeof scanResult !== "object"
  ) {
    return {
      findingCount: 0,
      categories: [],
      ruleIds: [],
      highestSeverity: null,
      riskScore: null,
      riskLevel: null,
    };
  }

  const findings =
    Array.isArray(
      scanResult.findings,
    )
      ? scanResult.findings
      : [];

  const categories = [];
  const ruleIds = [];

  const categorySet = new Set();
  const ruleSet = new Set();

  const severityRank = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };

  let highestSeverity = null;

  for (
    const finding of findings.slice(
      0,
      100,
    )
  ) {
    if (
      !finding ||
      typeof finding !== "object"
    ) {
      continue;
    }

    const category =
      normalizeString(
        finding.category,
        100,
      );

    if (
      category &&
      !categorySet.has(category)
    ) {
      categorySet.add(category);
      categories.push(category);
    }

    const ruleId =
      normalizeString(
        finding.ruleId,
        150,
      );

    if (
      ruleId &&
      !ruleSet.has(ruleId)
    ) {
      ruleSet.add(ruleId);
      ruleIds.push(ruleId);
    }

    const severity =
      normalizeSeverity(
        finding.severity,
      );

    if (
      severity &&
      (
        highestSeverity === null ||
        severityRank[severity] >
          severityRank[
            highestSeverity
          ]
      )
    ) {
      highestSeverity = severity;
    }
  }

  let riskScore = null;

  if (
    Number.isFinite(
      scanResult?.risk?.score,
    )
  ) {
    riskScore = Math.max(
      0,
      Math.min(
        100,
        scanResult.risk.score,
      ),
    );
  } else if (
    Number.isFinite(
      scanResult?.riskScore,
    )
  ) {
    riskScore = Math.max(
      0,
      Math.min(
        100,
        scanResult.riskScore,
      ),
    );
  }

  const riskLevel =
    normalizeRiskLevel(
      scanResult?.risk?.level,
    ) ||
    normalizeRiskLevel(
      scanResult?.riskLevel,
    );

  return {
    findingCount: Math.max(
      0,
      Math.min(
        100,
        findings.length,
      ),
    ),

    categories:
      normalizeCategories(
        categories,
      ),

    ruleIds:
      normalizeRuleIds(
        ruleIds,
      ),

    highestSeverity,

    riskScore,

    riskLevel,
  };
}

/**
 * Create a BLOCK decision.
 *
 * The result is always non-continuable.
 */
export function createBlockResult(
  options = {},
) {
  const scanMetadata =
    extractSafeScanMetadata(
      options.scanResult,
    );

  const reason =
    normalizeString(
      options.reason,
      MAX_REASON_LENGTH,
    ) ||
    getDefaultBlockReason(
      options.scanResult,
    );

  const message =
    normalizeString(
      options.message,
      MAX_REASON_LENGTH,
    ) ||
    DEFAULT_BLOCK_MESSAGE;

  const sourceType =
    normalizeSourceType(
      options.sourceType ??
      options.context?.sourceType,
    );

  const context =
    sanitizeContext({
      ...options.context,
      sourceType,
    });

  return {
    action: ACTION_NAME,

    status:
      MESSAGE_STATUS.BLOCKED,

    allowed: false,
    blocked: true,

    pending: false,
    requiresConfirmation: false,

    shouldContinue: false,
    contentModified: false,

    requestId:
      normalizeString(
        options.requestId,
        150,
      ) ||
      createRequestId(),

    reason,

    reasonCode:
      normalizeString(
        options.reasonCode,
        150,
      ) ||
      reason,

    message,

    sourceType,

    context,

    findingCount:
      scanMetadata.findingCount,

    categories:
      scanMetadata.categories,

    ruleIds:
      scanMetadata.ruleIds,

    highestSeverity:
      scanMetadata.highestSeverity,

    riskScore:
      scanMetadata.riskScore,

    riskLevel:
      scanMetadata.riskLevel,

    resolved: true,

    resolution:
      ACTIONS.BLOCK,

    createdAt: Date.now(),
    resolvedAt: Date.now(),

    version:
      ACTION_VERSION,
  };
}

/**
 * Apply the BLOCK action.
 *
 * Content is deliberately not modified.
 * The caller must prevent the original operation.
 */
export function applyBlock(
  content,
  options = {},
) {
  const result =
    createBlockResult(
      options,
    );

  return {
    ...result,

    /*
     * The original content is not returned.
     *
     * A caller that still holds the original content
     * in local scope can discard it after receiving
     * the block decision.
     */
    content: undefined,

    contentModified: false,

    shouldContinue: false,

    blocked: true,
    allowed: false,
  };
}

/**
 * Check whether an action is BLOCK.
 */
export function isBlockAction(action) {
  return action === ACTIONS.BLOCK;
}

/**
 * Check whether a result is a valid block result.
 */
export function isBlockedResult(result) {
  return Boolean(
    result &&
    result.action === ACTIONS.BLOCK &&
    result.status === MESSAGE_STATUS.BLOCKED &&
    result.blocked === true &&
    result.allowed === false &&
    result.shouldContinue === false,
  );
}

/**
 * Check whether the operation must stop.
 */
export function shouldBlock(result) {
  if (!result) {
    return true;
  }

  if (
    result.blocked === true
  ) {
    return true;
  }

  if (
    result.action === ACTIONS.BLOCK
  ) {
    return true;
  }

  if (
    result.status ===
    MESSAGE_STATUS.BLOCKED
  ) {
    return true;
  }

  /*
   * Fail closed if a supposedly final result
   * explicitly says it cannot continue.
   */
  if (
    result.shouldContinue === false &&
    result.resolved === true
  ) {
    return true;
  }

  return false;
}

/**
 * A BLOCK result can never continue.
 */
export function shouldContinue() {
  return false;
}

/**
 * BLOCK never modifies content.
 */
export function modifiesContent() {
  return false;
}

/**
 * BLOCK never requires a confirmation step.
 *
 * If the policy is BLOCK, the operation is already denied.
 */
export function requiresConfirmation() {
  return false;
}

/**
 * Get the default block reason.
 */
export function getDefaultBlockReasonCode() {
  return DEFAULT_BLOCK_REASON;
}

/**
 * Get all supported block reason codes.
 */
export function getBlockReasonCodes() {
  return {
    ...BLOCK_REASON_CODES,
  };
}

/**
 * Check whether a block reason code is recognized.
 */
export function isValidBlockReasonCode(
  reasonCode,
) {
  return Object.values(
    BLOCK_REASON_CODES,
  ).includes(reasonCode);
}

/**
 * Create a safe UI/logging representation.
 *
 * Never includes:
 * - original content
 * - matched values
 * - clipboard data
 * - file contents
 * - prompt contents
 */
export function getSafeBlockResult(
  result,
) {
  if (
    !result ||
    typeof result !== "object"
  ) {
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

    requestId:
      normalizeString(
        result.requestId,
        150,
      ) || null,

    reason:
      normalizeString(
        result.reason,
        MAX_REASON_LENGTH,
      ) || null,

    reasonCode:
      normalizeString(
        result.reasonCode,
        150,
      ) || null,

    message:
      normalizeString(
        result.message,
        MAX_REASON_LENGTH,
      ) || null,

    sourceType:
      normalizeSourceType(
        result.sourceType,
      ),

    context:
      sanitizeContext(
        result.context,
      ),

    findingCount:
      Number.isFinite(
        result.findingCount,
      )
        ? Math.max(
            0,
            Math.min(
              100,
              result.findingCount,
            ),
          )
        : 0,

    categories:
      normalizeCategories(
        result.categories,
      ),

    ruleIds:
      normalizeRuleIds(
        result.ruleIds,
      ),

    highestSeverity:
      normalizeSeverity(
        result.highestSeverity,
      ),

    riskScore:
      Number.isFinite(
        result.riskScore,
      )
        ? Math.max(
            0,
            Math.min(
              100,
              result.riskScore,
            ),
          )
        : null,

    riskLevel:
      normalizeRiskLevel(
        result.riskLevel,
      ),

    resolved:
      Boolean(result.resolved),

    resolution:
      result.resolution ===
      ACTIONS.BLOCK
        ? ACTIONS.BLOCK
        : null,

    createdAt:
      Number.isFinite(
        result.createdAt,
      )
        ? result.createdAt
        : null,

    resolvedAt:
      Number.isFinite(
        result.resolvedAt,
      )
        ? result.resolvedAt
        : null,

    version:
      ACTION_VERSION,
  };
}

/**
 * Validate a block result.
 *
 * Invalid BLOCK results should themselves be treated
 * as blocked by the caller.
 */
export function validateBlockResult(
  result,
) {
  const errors = [];

  if (
    !result ||
    typeof result !== "object"
  ) {
    return {
      valid: false,
      errors: [
        "Result must be an object.",
      ],
    };
  }

  if (
    result.action !== ACTIONS.BLOCK
  ) {
    errors.push(
      "Result action must be BLOCK.",
    );
  }

  if (
    result.status !==
    MESSAGE_STATUS.BLOCKED
  ) {
    errors.push(
      "Block result must have BLOCKED status.",
    );
  }

  if (
    result.allowed !== false
  ) {
    errors.push(
      "Block result must have allowed=false.",
    );
  }

  if (
    result.blocked !== true
  ) {
    errors.push(
      "Block result must have blocked=true.",
    );
  }

  if (
    result.shouldContinue !== false
  ) {
    errors.push(
      "Block result must have shouldContinue=false.",
    );
  }

  if (
    result.contentModified !== false
  ) {
    errors.push(
      "Block result must not modify content.",
    );
  }

  if (
    result.pending !== false
  ) {
    errors.push(
      "Block result cannot remain pending.",
    );
  }

  if (
    result.requiresConfirmation !== false
  ) {
    errors.push(
      "Block result does not require confirmation.",
    );
  }

  if (
    result.resolution !==
    ACTIONS.BLOCK
  ) {
    errors.push(
      "Block result must resolve to BLOCK.",
    );
  }

  if (
    result.findingCount !== undefined &&
    (
      !Number.isInteger(
        result.findingCount,
      ) ||
      result.findingCount < 0 ||
      result.findingCount > 100
    )
  ) {
    errors.push(
      "Invalid findingCount.",
    );
  }

  if (
    result.riskScore !== null &&
    result.riskScore !== undefined &&
    (
      !Number.isFinite(
        result.riskScore,
      ) ||
      result.riskScore < 0 ||
      result.riskScore > 100
    )
  ) {
    errors.push(
      "Invalid riskScore.",
    );
  }

  if (
    result.reasonCode !== undefined &&
    !isValidBlockReasonCode(
      result.reasonCode,
    ) &&
    normalizeString(
      result.reasonCode,
      150,
    ) !== result.reasonCode
  ) {
    errors.push(
      "Invalid reasonCode.",
    );
  }

  return {
    valid:
      errors.length === 0,
    errors,
  };
}

/**
 * Create a fail-closed block result for internal errors.
 *
 * This should be used when a security-sensitive
 * operation cannot be evaluated safely.
 */
export function createSecurityBlockResult(
  options = {},
) {
  return createBlockResult({
    ...options,

    reason:
      options.reason ||
      BLOCK_REASON_CODES.SECURITY_FAILURE,

    reasonCode:
      options.reasonCode ||
      BLOCK_REASON_CODES.SECURITY_FAILURE,

    message:
      options.message ||
      "The operation was blocked because SanitizerPro could not safely evaluate it.",
  });
}

/**
 * Create a block result when scanning fails.
 */
export function createScanFailureBlockResult(
  options = {},
) {
  return createBlockResult({
    ...options,

    reason:
      options.reason ||
      BLOCK_REASON_CODES.SCAN_FAILED,

    reasonCode:
      options.reasonCode ||
      BLOCK_REASON_CODES.SCAN_FAILED,

    message:
      options.message ||
      "The operation was blocked because the security scan could not be completed safely.",
  });
}

/**
 * Create a block result when policy evaluation fails.
 */
export function createPolicyFailureBlockResult(
  options = {},
) {
  return createBlockResult({
    ...options,

    reason:
      options.reason ||
      BLOCK_REASON_CODES.POLICY_FAILED,

    reasonCode:
      options.reasonCode ||
      BLOCK_REASON_CODES.POLICY_FAILED,

    message:
      options.message ||
      "The operation was blocked because the security policy could not be evaluated safely.",
  });
}

/**
 * Static information about the BLOCK action.
 */
export function getBlockActionInfo() {
  return {
    action:
      ACTIONS.BLOCK,

    status:
      MESSAGE_STATUS.BLOCKED,

    requiresConfirmation:
      false,

    automaticallyContinues:
      false,

    modifiesContent:
      false,

    blocksByDefault:
      true,

    failClosed:
      true,

    reasonCodes:
      getBlockReasonCodes(),

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
export function getBlockDiagnostics() {
  return {
    module: "block",

    action:
      ACTIONS.BLOCK,

    version:
      ACTION_VERSION,

    behavior: {
      allowed: false,
      blocked: true,
      pending: false,
      requiresConfirmation: false,
      shouldContinue: false,
      contentModified: false,
      failClosed: true,
    },

    reasonCodes:
      getBlockReasonCodes(),

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
  createBlockResult,
  applyBlock,

  isBlockAction,
  isBlockedResult,
  shouldBlock,
  shouldContinue,
  modifiesContent,
  requiresConfirmation,

  getDefaultBlockReasonCode,
  getBlockReasonCodes,
  isValidBlockReasonCode,

  getSafeBlockResult,
  validateBlockResult,

  createSecurityBlockResult,
  createScanFailureBlockResult,
  createPolicyFailureBlockResult,

  getBlockActionInfo,
  getBlockDiagnostics,
});
