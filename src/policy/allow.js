/**
 * SanitizerPro
 * Allow Policy Action
 *
 * Responsibilities:
 * - Represent an explicit ALLOW decision.
 * - Provide helpers for checking and creating allow results.
 * - Never modify user content.
 * - Never access Chrome APIs.
 * - Never access the network.
 * - Never persist sensitive data.
 *
 * This module is intentionally small and deterministic.
 */

import {
  ACTIONS,
} from "../config/defaults.js";

import {
  MESSAGE_STATUS,
} from "../config/constants.js";

/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

const ACTION_VERSION = "1.0.0";

const ACTION_NAME = ACTIONS.ALLOW;

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                           */
/* -------------------------------------------------------------------------- */

function safeString(value) {
  return typeof value === "string"
    ? value
    : "";
}

function normalizeAction(value) {
  return safeString(value)
    .trim()
    .toLowerCase();
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function clone(value) {
  if (
    value === null ||
    typeof value !== "object"
  ) {
    return value;
  }

  if (
    typeof structuredClone === "function"
  ) {
    try {
      return structuredClone(value);
    } catch {
      // Fall through to manual cloning.
    }
  }

  if (Array.isArray(value)) {
    return value.map(clone);
  }

  const result = {};

  for (
    const [key, item]
    of Object.entries(value)
  ) {
    result[key] = clone(item);
  }

  return result;
}

function normalizeSourceType(value) {
  return safeString(value)
    .trim()
    .toLowerCase();
}

function sanitizeContext(context) {
  if (
    !isPlainObject(context)
  ) {
    return {};
  }

  /*
   * Only metadata is copied.
   *
   * Raw prompt text, clipboard data,
   * uploaded file contents and matched
   * sensitive values must never be copied
   * into this action result.
   */
  return {
    platformId:
      normalizeSourceType(
        context.platformId,
      ),

    platformCategory:
      normalizeSourceType(
        context.platformCategory,
      ),

    hostname:
      normalizeSourceType(
        context.hostname,
      ),

    sourceType:
      normalizeSourceType(
        context.sourceType,
      ),

    inputType:
      normalizeSourceType(
        context.inputType,
      ),
  };
}

/* -------------------------------------------------------------------------- */
/* Allow result                                                               */
/* -------------------------------------------------------------------------- */

export function createAllowResult(
  options = {},
) {
  const source =
    isPlainObject(options)
      ? options
      : {};

  return {
    action: ACTION_NAME,

    status:
      MESSAGE_STATUS.ALLOWED,

    allowed: true,

    blocked: false,

    requiresUserConfirmation:
      false,

    contentModified:
      false,

    shouldContinue:
      true,

    reason:
      safeString(
        source.reason,
      ) ||
      "content-allowed",

    sourceType:
      normalizeSourceType(
        source.sourceType,
      ),

    context:
      sanitizeContext(
        source.context,
      ),

    timestamp:
      Date.now(),

    actionVersion:
      ACTION_VERSION,
  };
}

/* -------------------------------------------------------------------------- */
/* Action checks                                                              */
/* -------------------------------------------------------------------------- */

export function isAllowAction(
  action,
) {
  return (
    normalizeAction(action) ===
    ACTION_NAME
  );
}

export function isAllowedResult(
  result,
) {
  if (
    !result ||
    typeof result !== "object"
  ) {
    return false;
  }

  return (
    result.action ===
      ACTION_NAME &&
    result.allowed === true &&
    result.blocked !== true
  );
}

/* -------------------------------------------------------------------------- */
/* Apply allow action                                                         */
/* -------------------------------------------------------------------------- */

/**
 * ALLOW never changes the supplied content.
 *
 * The original value is returned by reference intentionally.
 * This avoids unnecessary copies of potentially sensitive
 * prompt data.
 */
export function applyAllow(
  content,
  options = {},
) {
  return {
    ...createAllowResult(options),

    content,

    contentModified:
      false,

    originalContentAvailable:
      true,
  };
}

/**
 * Explicitly named helper for code paths where the caller
 * wants a continuation decision rather than a content result.
 */
export function allow(
  options = {},
) {
  return createAllowResult(
    options,
  );
}

/* -------------------------------------------------------------------------- */
/* Allow continuation                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Returns whether execution should continue.
 *
 * This function deliberately does not inspect or modify
 * the content itself.
 */
export function shouldContinue(
  result,
) {
  return isAllowedResult(
    result,
  );
}

/**
 * ALLOW is always a non-mutating action.
 */
export function modifiesContent() {
  return false;
}

/**
 * ALLOW never requires a confirmation dialog.
 */
export function requiresConfirmation() {
  return false;
}

/**
 * ALLOW never blocks the originating browser operation.
 */
export function blocksOperation() {
  return false;
}

/* -------------------------------------------------------------------------- */
/* Result normalization                                                       */
/* -------------------------------------------------------------------------- */

export function normalizeAllowResult(
  result,
) {
  if (
    !result ||
    typeof result !== "object"
  ) {
    return createAllowResult({
      reason:
        "invalid-allow-result",
    });
  }

  return {
    action: ACTION_NAME,

    status:
      MESSAGE_STATUS.ALLOWED,

    allowed: true,

    blocked: false,

    requiresUserConfirmation:
      false,

    contentModified:
      false,

    shouldContinue:
      true,

    reason:
      safeString(
        result.reason,
      ) ||
      "content-allowed",

    sourceType:
      normalizeSourceType(
        result.sourceType,
      ),

    context:
      sanitizeContext(
        result.context,
      ),

    timestamp:
      Number.isFinite(
        result.timestamp,
      )
        ? result.timestamp
        : Date.now(),

    actionVersion:
      ACTION_VERSION,
  };
}

/* -------------------------------------------------------------------------- */
/* Safe diagnostic representation                                             */
/* -------------------------------------------------------------------------- */

/**
 * Produces a diagnostic object that contains no content.
 */
export function getSafeAllowResult(
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
      ACTION_NAME,

    status:
      MESSAGE_STATUS.ALLOWED,

    allowed:
      result.allowed === true,

    blocked:
      result.blocked === true,

    requiresUserConfirmation:
      result.requiresUserConfirmation === true,

    contentModified:
      result.contentModified === true,

    shouldContinue:
      result.shouldContinue === true,

    reason:
      safeString(
        result.reason,
      ),

    sourceType:
      normalizeSourceType(
        result.sourceType,
      ),

    context:
      sanitizeContext(
        result.context,
      ),

    timestamp:
      Number.isFinite(
        result.timestamp,
      )
        ? result.timestamp
        : null,

    actionVersion:
      ACTION_VERSION,
  };
}

/* -------------------------------------------------------------------------- */
/* Validation                                                                 */
/* -------------------------------------------------------------------------- */

export function validateAllowResult(
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
        "Allow result must be an object.",
      ],
    };
  }

  if (
    result.action !==
    ACTION_NAME
  ) {
    errors.push(
      "Allow result must contain the ALLOW action.",
    );
  }

  if (
    result.allowed !== true
  ) {
    errors.push(
      "Allow result must have allowed=true.",
    );
  }

  if (
    result.blocked === true
  ) {
    errors.push(
      "Allow result cannot have blocked=true.",
    );
  }

  if (
    result.requiresUserConfirmation === true
  ) {
    errors.push(
      "ALLOW cannot require user confirmation.",
    );
  }

  if (
    result.contentModified === true
  ) {
    errors.push(
      "ALLOW cannot modify content.",
    );
  }

  if (
    result.shouldContinue !== true
  ) {
    errors.push(
      "ALLOW must have shouldContinue=true.",
    );
  }

  return {
    valid:
      errors.length === 0,

    errors,
  };
}

/* -------------------------------------------------------------------------- */
/* Metadata                                                                    */
/* -------------------------------------------------------------------------- */

export function getAllowActionInfo() {
  return {
    action:
      ACTION_NAME,

    version:
      ACTION_VERSION,

    mutatesContent:
      false,

    blocksOperation:
      false,

    requiresConfirmation:
      false,

    localOnly:
      true,

    networkAccess:
      false,

    persistentData:
      false,
  };
}

/* -------------------------------------------------------------------------- */
/* Diagnostics                                                                 */
/* -------------------------------------------------------------------------- */

export function getAllowDiagnostics() {
  return {
    action:
      ACTION_NAME,

    version:
      ACTION_VERSION,

    behavior: {
      allowed:
        true,

      blocked:
        false,

      masks:
        false,

      modifiesContent:
        false,

      requiresConfirmation:
        false,

      continuesOperation:
        true,
    },

    security: {
      localOnly:
        true,

      networkAccess:
        false,

      chromeApiAccess:
        false,

      persistentSensitiveData:
        false,

      rawContentLogging:
        false,
    },
  };
}

/* -------------------------------------------------------------------------- */
/* Default export                                                             */
/* -------------------------------------------------------------------------- */

const allowAction = Object.freeze({
  action:
    ACTION_NAME,

  version:
    ACTION_VERSION,

  create:
    createAllowResult,

  apply:
    applyAllow,

  allow,

  isAction:
    isAllowAction,

  isResult:
    isAllowedResult,

  shouldContinue,

  modifiesContent,

  requiresConfirmation,

  blocksOperation,

  normalize:
    normalizeAllowResult,

  validate:
    validateAllowResult,

  getSafeResult:
    getSafeAllowResult,

  getInfo:
    getAllowActionInfo,

  getDiagnostics:
    getAllowDiagnostics,
});

export default allowAction;
