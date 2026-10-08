/**
 * SanitizerPro
 * Internal protocol and runtime constants.
 *
 * Security model:
 * - Raw user content should remain inside the content-script context.
 * - Messages should contain metadata, scan IDs, decisions, and findings.
 * - Do not send clipboard contents, prompt text, uploaded file contents,
 *   detected secret values, or other raw sensitive material to the service worker.
 * - The service worker coordinates configuration and extension state.
 *
 * Manifest V3 compatible.
 */

const freeze = (value) => Object.freeze(value);

/**
 * Protocol version.
 *
 * Increment this only when making a breaking change to the
 * internal message/event contract.
 */
export const PROTOCOL_VERSION = 1;

/**
 * Extension metadata used internally.
 */
export const EXTENSION = freeze({
  NAME: "SanitizerPro",
  ID: "sanitizerpro",
  VERSION: "1.0.0",
});

/**
 * Message types.
 *
 * Messages are request/response operations between extension contexts.
 */
export const MESSAGE_TYPES = freeze({
  PING: "ping",

  GET_CONFIG: "get_config",
  SET_CONFIG: "set_config",
  RESET_CONFIG: "reset_config",

  GET_STATUS: "get_status",
  SET_PROTECTION_MODE: "set_protection_mode",

  GET_PLATFORM: "get_platform",
  GET_PLATFORM_SUMMARY: "get_platform_summary",

  SCAN_TEXT: "scan_text",
  SCAN_FILE: "scan_file",

  EVALUATE_FINDINGS: "evaluate_findings",
  REQUEST_ACTION: "request_action",

  SHOW_WARNING: "show_warning",
  SHOW_BLOCK: "show_block",
  MASK_CONTENT: "mask_content",

  GET_STATS: "get_stats",
  RESET_STATS: "reset_stats",

  CONTENT_READY: "content_ready",
  PLATFORM_DETECTED: "platform_detected",

  REPORT_EVENT: "report_event",

  GET_EXTENSION_INFO: "get_extension_info",
});

/**
 * Runtime event types.
 *
 * Events describe things that happened during the protection workflow.
 */
export const EVENT_TYPES = freeze({
  INIT: "init",

  CONTENT_READY: "content_ready",
  PLATFORM_DETECTED: "platform_detected",

  INPUT_DETECTED: "input_detected",
  PASTE_DETECTED: "paste_detected",
  DROP_DETECTED: "drop_detected",
  UPLOAD_DETECTED: "upload_detected",

  SUBMIT_DETECTED: "submit_detected",
  SEND_DETECTED: "send_detected",
  SEARCH_DETECTED: "search_detected",

  SCAN_STARTED: "scan_started",
  SCAN_COMPLETED: "scan_completed",
  SCAN_FAILED: "scan_failed",

  POLICY_EVALUATED: "policy_evaluated",

  ACTION_ALLOWED: "action_allowed",
  ACTION_WARNED: "action_warned",
  ACTION_MASKED: "action_masked",
  ACTION_BLOCKED: "action_blocked",

  CONFIG_CHANGED: "config_changed",

  ERROR: "error",
});

/**
 * Input sources.
 *
 * These identify how content entered a protected destination.
 */
export const SOURCE_TYPES = freeze({
  TYPING: "typing",
  PASTE: "paste",
  DROP: "drop",
  UPLOAD: "upload",
  SUBMIT: "submit",
  SEND: "send",
  SEARCH: "search",
  UNKNOWN: "unknown",
});

/**
 * Runtime contexts.
 */
export const CONTEXT_TYPES = freeze({
  CONTENT: "content",
  BACKGROUND: "background",
  POPUP: "popup",
  OPTIONS: "options",
  UNKNOWN: "unknown",
});

/**
 * Message result status.
 */
export const MESSAGE_STATUS = freeze({
  OK: "ok",
  ERROR: "error",
  IGNORED: "ignored",
  ALLOWED: "allowed",
  WARNING: "warning",
  MASKED: "masked",
  BLOCKED: "blocked",
});

/**
 * Error codes.
 *
 * Error messages must never contain raw sensitive input.
 */
export const ERROR_CODES = freeze({
  INVALID_MESSAGE: "invalid_message",
  INVALID_PAYLOAD: "invalid_payload",
  UNSUPPORTED_MESSAGE: "unsupported_message",

  CONFIG_INVALID: "config_invalid",
  CONFIG_NOT_FOUND: "config_not_found",

  PLATFORM_UNKNOWN: "platform_unknown",
  PLATFORM_UNSUPPORTED: "platform_unsupported",

  SCAN_TIMEOUT: "scan_timeout",
  SCAN_LIMIT_EXCEEDED: "scan_limit_exceeded",
  SCAN_FAILED: "scan_failed",

  FILE_TOO_LARGE: "file_too_large",
  FILE_TYPE_UNSUPPORTED: "file_type_unsupported",
  FILE_READ_FAILED: "file_read_failed",

  POLICY_FAILED: "policy_failed",

  PERMISSION_DENIED: "permission_denied",

  RATE_LIMITED: "rate_limited",

  REQUEST_TIMEOUT: "request_timeout",

  INTERNAL_ERROR: "internal_error",
});

/**
 * Message categories.
 *
 * Used to distinguish configuration/control messages from
 * security-sensitive scanning operations.
 */
export const MESSAGE_CATEGORIES = freeze({
  SYSTEM: "system",
  CONFIG: "config",
  STATUS: "status",
  PLATFORM: "platform",
  SCAN: "scan",
  POLICY: "policy",
  UI: "ui",
  STATS: "stats",
  EVENT: "event",
});

/**
 * Message types that are expected to originate from content scripts.
 */
export const CONTENT_MESSAGE_TYPES = freeze([
  MESSAGE_TYPES.CONTENT_READY,
  MESSAGE_TYPES.PLATFORM_DETECTED,
  MESSAGE_TYPES.REPORT_EVENT,
]);

/**
 * Message types that are intended for configuration contexts.
 */
export const CONFIG_MESSAGE_TYPES = freeze([
  MESSAGE_TYPES.GET_CONFIG,
  MESSAGE_TYPES.SET_CONFIG,
  MESSAGE_TYPES.RESET_CONFIG,
]);

/**
 * Message types that are intended for status/control operations.
 */
export const STATUS_MESSAGE_TYPES = freeze([
  MESSAGE_TYPES.PING,
  MESSAGE_TYPES.GET_STATUS,
  MESSAGE_TYPES.SET_PROTECTION_MODE,
  MESSAGE_TYPES.GET_EXTENSION_INFO,
]);

/**
 * Message types related to platform discovery.
 */
export const PLATFORM_MESSAGE_TYPES = freeze([
  MESSAGE_TYPES.GET_PLATFORM,
  MESSAGE_TYPES.GET_PLATFORM_SUMMARY,
]);

/**
 * Message types related to scanning.
 *
 * Important:
 * Raw content should normally be scanned in the content context.
 * These message names exist for controlled future use and testing.
 */
export const SCAN_MESSAGE_TYPES = freeze([
  MESSAGE_TYPES.SCAN_TEXT,
  MESSAGE_TYPES.SCAN_FILE,
]);

/**
 * Message types related to policy decisions.
 */
export const POLICY_MESSAGE_TYPES = freeze([
  MESSAGE_TYPES.EVALUATE_FINDINGS,
  MESSAGE_TYPES.REQUEST_ACTION,
]);

/**
 * Message types related to UI actions.
 */
export const UI_MESSAGE_TYPES = freeze([
  MESSAGE_TYPES.SHOW_WARNING,
  MESSAGE_TYPES.SHOW_BLOCK,
  MESSAGE_TYPES.MASK_CONTENT,
]);

/**
 * Message types related to statistics.
 */
export const STATS_MESSAGE_TYPES = freeze([
  MESSAGE_TYPES.GET_STATS,
  MESSAGE_TYPES.RESET_STATS,
]);

/**
 * Messages that MUST NOT carry raw user content across extension contexts.
 *
 * The scanner and policy engine should preferably operate inside
 * the content-script context where the original content is available.
 *
 * Only sanitized metadata, findings, decisions, and identifiers should
 * be sent to the service worker.
 */
export const SENSITIVE_MESSAGE_TYPES = freeze([
  MESSAGE_TYPES.SCAN_TEXT,
  MESSAGE_TYPES.SCAN_FILE,
  MESSAGE_TYPES.EVALUATE_FINDINGS,
  MESSAGE_TYPES.REQUEST_ACTION,
  MESSAGE_TYPES.REPORT_EVENT,
]);

/**
 * Fields that must never be logged.
 *
 * This list is intentionally broader than the minimum required.
 */
export const SENSITIVE_FIELDS = freeze([
  "text",
  "content",
  "raw",
  "rawText",
  "rawContent",

  "clipboard",
  "clipboardText",
  "clipboardData",

  "fileContent",
  "fileContents",
  "fileData",
  "fileBytes",

  "prompt",
  "promptText",
  "query",
  "queryText",

  "secret",
  "secretValue",
  "detectedValue",
  "matchedValue",
  "value",

  "password",
  "passwordValue",

  "token",
  "tokenValue",

  "apiKey",
  "apiKeyValue",

  "privateKey",
  "privateKeyValue",

  "authorization",
  "authorizationHeader",

  "cookie",
  "cookies",

  "headers",
  "requestBody",
  "responseBody",
]);

/**
 * Maximum number of findings that may be transferred in a single
 * protocol message.
 *
 * The scanner has its own limits in defaults.js.
 */
export const MAX_FINDINGS_PER_MESSAGE = 100;

/**
 * Maximum number of rule matches attached to one finding.
 */
export const MAX_RULE_MATCHES_PER_MESSAGE = 10;

/**
 * Maximum number of platform IDs attached to one message.
 */
export const MAX_PLATFORM_IDS_PER_MESSAGE = 100;

/**
 * Maximum size for a non-content protocol string.
 *
 * This is intentionally smaller than the scan input limit.
 */
export const MAX_PROTOCOL_STRING_LENGTH = 2048;

/**
 * Maximum number of event details allowed in a protocol event.
 */
export const MAX_EVENT_DETAILS = 32;

/**
 * Request timeout used by extension context coordination.
 */
export const MESSAGE_TIMEOUT_MS = 5000;

/**
 * Maximum pending protocol requests.
 */
export const MAX_PENDING_MESSAGES = 100;

/**
 * Message envelope fields.
 */
export const MESSAGE_FIELDS = freeze({
  VERSION: "version",
  TYPE: "type",
  REQUEST_ID: "requestId",
  TIMESTAMP: "timestamp",
  SOURCE: "source",
  PAYLOAD: "payload",
});

/**
 * Creates a unique request identifier.
 *
 * crypto.randomUUID() is preferred when available.
 * The fallback is only for environments where randomUUID is unavailable.
 */
export function createRequestId() {
  if (
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.randomUUID === "function"
  ) {
    return globalThis.crypto.randomUUID();
  }

  const randomPart = Math.random().toString(36).slice(2);
  const timePart = Date.now().toString(36);

  return `req-${timePart}-${randomPart}`;
}

/**
 * Creates a protocol message.
 *
 * This function creates only the envelope. Callers are responsible for
 * ensuring that payload does not contain raw sensitive data unless the
 * message is intentionally handled entirely within the same trusted
 * execution context.
 */
export function createMessage(
  type,
  payload = {},
  {
    source = CONTEXT_TYPES.UNKNOWN,
    requestId = createRequestId(),
  } = {},
) {
  if (!isKnownMessageType(type)) {
    throw new Error(`Unsupported message type: ${String(type)}`);
  }

  return {
    [MESSAGE_FIELDS.VERSION]: PROTOCOL_VERSION,
    [MESSAGE_FIELDS.TYPE]: type,
    [MESSAGE_FIELDS.REQUEST_ID]: requestId,
    [MESSAGE_FIELDS.TIMESTAMP]: Date.now(),
    [MESSAGE_FIELDS.SOURCE]: source,
    [MESSAGE_FIELDS.PAYLOAD]: isPlainObject(payload) ? payload : {},
  };
}

/**
 * Creates a successful response.
 */
export function createSuccessResponse(
  requestId,
  payload = {},
  status = MESSAGE_STATUS.OK,
) {
  return {
    version: PROTOCOL_VERSION,
    status,
    requestId: requestId || null,
    payload: isPlainObject(payload) ? payload : {},
    error: null,
  };
}

/**
 * Creates an error response.
 *
 * The function intentionally accepts only an explicit safe error message.
 * Never pass raw user content into the error message.
 */
export function createErrorResponse(
  requestId,
  code = ERROR_CODES.INTERNAL_ERROR,
  message = "The requested operation could not be completed.",
  details = null,
) {
  return {
    version: PROTOCOL_VERSION,
    status: MESSAGE_STATUS.ERROR,
    requestId: requestId || null,
    payload: {},
    error: {
      code,
      message,
      details: sanitizeErrorDetails(details),
    },
  };
}

/**
 * Creates a runtime event object.
 *
 * Events are designed for metadata and state changes, not raw user content.
 */
export function createEvent(
  type,
  {
    source = CONTEXT_TYPES.UNKNOWN,
    requestId = null,
    details = {},
  } = {},
) {
  if (!isKnownEventType(type)) {
    throw new Error(`Unsupported event type: ${String(type)}`);
  }

  return {
    version: PROTOCOL_VERSION,
    type,
    timestamp: Date.now(),
    source,
    requestId,
    details: sanitizeEventDetails(details),
  };
}

/**
 * Checks whether an object is a plain object.
 */
export function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);

  return prototype === Object.prototype || prototype === null;
}

/**
 * Checks whether a value is a known message type.
 */
export function isKnownMessageType(type) {
  return (
    typeof type === "string" &&
    Object.values(MESSAGE_TYPES).includes(type)
  );
}

/**
 * Checks whether a value is a known event type.
 */
export function isKnownEventType(type) {
  return (
    typeof type === "string" &&
    Object.values(EVENT_TYPES).includes(type)
  );
}

/**
 * Checks whether a message has the expected protocol structure.
 *
 * This performs structural validation only.
 * Individual handlers must still validate their specific payload.
 */
export function isValidMessage(message) {
  if (!isPlainObject(message)) {
    return false;
  }

  if (message.version !== PROTOCOL_VERSION) {
    return false;
  }

  if (!isKnownMessageType(message.type)) {
    return false;
  }

  if (
    typeof message.requestId !== "string" ||
    message.requestId.length === 0 ||
    message.requestId.length > 128
  ) {
    return false;
  }

  if (
    typeof message.timestamp !== "number" ||
    !Number.isFinite(message.timestamp)
  ) {
    return false;
  }

  if (
    typeof message.source !== "string" ||
    !Object.values(CONTEXT_TYPES).includes(message.source)
  ) {
    return false;
  }

  if (!isPlainObject(message.payload)) {
    return false;
  }

  return true;
}

/**
 * Checks whether a message is a scan-related message.
 */
export function isScanMessage(type) {
  return SCAN_MESSAGE_TYPES.includes(type);
}

/**
 * Checks whether a message is policy-related.
 */
export function isPolicyMessage(type) {
  return POLICY_MESSAGE_TYPES.includes(type);
}

/**
 * Checks whether a message should be treated as sensitive.
 */
export function isSensitiveMessage(type) {
  return SENSITIVE_MESSAGE_TYPES.includes(type);
}

/**
 * Gets the logical category of a message.
 */
export function getMessageCategory(type) {
  if (STATUS_MESSAGE_TYPES.includes(type)) {
    return MESSAGE_CATEGORIES.SYSTEM;
  }

  if (CONFIG_MESSAGE_TYPES.includes(type)) {
    return MESSAGE_CATEGORIES.CONFIG;
  }

  if (PLATFORM_MESSAGE_TYPES.includes(type)) {
    return MESSAGE_CATEGORIES.PLATFORM;
  }

  if (SCAN_MESSAGE_TYPES.includes(type)) {
    return MESSAGE_CATEGORIES.SCAN;
  }

  if (POLICY_MESSAGE_TYPES.includes(type)) {
    return MESSAGE_CATEGORIES.POLICY;
  }

  if (UI_MESSAGE_TYPES.includes(type)) {
    return MESSAGE_CATEGORIES.UI;
  }

  if (STATS_MESSAGE_TYPES.includes(type)) {
    return MESSAGE_CATEGORIES.STATS;
  }

  if (type === MESSAGE_TYPES.CONTENT_READY) {
    return MESSAGE_CATEGORIES.SYSTEM;
  }

  if (type === MESSAGE_TYPES.PLATFORM_DETECTED) {
    return MESSAGE_CATEGORIES.PLATFORM;
  }

  if (type === MESSAGE_TYPES.REPORT_EVENT) {
    return MESSAGE_CATEGORIES.EVENT;
  }

  return MESSAGE_CATEGORIES.SYSTEM;
}

/**
 * Sanitizes an object before it can be written to logs or telemetry.
 *
 * Sanitization is defensive only. The preferred approach is still
 * not to log sensitive data in the first place.
 */
export function sanitizeForLog(value, depth = 0) {
  if (depth > 4) {
    return "[TRUNCATED]";
  }

  if (value === null) {
    return null;
  }

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (Array.isArray(value)) {
    return value
      .slice(0, 50)
      .map((item) => sanitizeForLog(item, depth + 1));
  }

  if (!isPlainObject(value)) {
    return "[UNSUPPORTED]";
  }

  const output = {};

  for (const [key, item] of Object.entries(value)) {
    if (isSensitiveField(key)) {
      output[key] = "[REDACTED]";
      continue;
    }

    output[key] = sanitizeForLog(item, depth + 1);
  }

  return output;
}

/**
 * Checks whether a field name is sensitive.
 */
export function isSensitiveField(fieldName) {
  if (typeof fieldName !== "string") {
    return false;
  }

  return SENSITIVE_FIELDS.includes(fieldName);
}

/**
 * Sanitizes event details.
 */
function sanitizeEventDetails(details) {
  if (!isPlainObject(details)) {
    return {};
  }

  const sanitized = sanitizeForLog(details);

  if (!isPlainObject(sanitized)) {
    return {};
  }

  const entries = Object.entries(sanitized).slice(0, MAX_EVENT_DETAILS);

  return Object.fromEntries(entries);
}

/**
 * Sanitizes error details.
 */
function sanitizeErrorDetails(details) {
  if (details === null || details === undefined) {
    return null;
  }

  if (!isPlainObject(details)) {
    return null;
  }

  return sanitizeForLog(details);
}

/**
 * Validates a request payload against a basic object requirement.
 *
 * Individual modules should implement stricter schema validation.
 */
export function isValidPayload(payload) {
  return isPlainObject(payload);
}

/**
 * Returns a safe summary of a message.
 *
 * Useful for debugging without exposing the original content.
 */
export function summarizeMessage(message) {
  if (!isValidMessage(message)) {
    return {
      valid: false,
      type: null,
      requestId: null,
      source: null,
    };
  }

  return {
    valid: true,
    version: message.version,
    type: message.type,
    requestId: message.requestId,
    source: message.source,
    category: getMessageCategory(message.type),
    sensitive: isSensitiveMessage(message.type),
  };
}

/**
 * Freezes the exported protocol structures.
 *
 * This prevents accidental mutation at runtime.
 */
Object.freeze(MESSAGE_TYPES);
Object.freeze(EVENT_TYPES);
Object.freeze(SOURCE_TYPES);
Object.freeze(CONTEXT_TYPES);
Object.freeze(MESSAGE_STATUS);
Object.freeze(ERROR_CODES);
Object.freeze(MESSAGE_CATEGORIES);
Object.freeze(MESSAGE_FIELDS);
Object.freeze(EXTENSION);
