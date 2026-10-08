/**
 * SanitizerPro
 * Local Sensitive Data Scanner
 *
 * Responsibilities:
 * - Normalize text locally.
 * - Run the local matching engine.
 * - Calculate deterministic risk.
 * - Enforce scan limits.
 * - Scan text files locally.
 * - Optionally scan filenames.
 * - Never persist raw content.
 * - Never send raw content to the service worker.
 *
 * This module is intentionally independent of Chrome APIs.
 */

import {
  SCAN_LIMITS,
  FILE_SCAN_DEFAULTS,
  TEXT_FILE_EXTENSIONS,
  TEXT_FILE_MIME_TYPES,
} from "../config/defaults.js";

import {
  SOURCE_TYPES,
  ERROR_CODES,
} from "../config/constants.js";

import { normalizeText } from "./normalizer.js";
import { matchText } from "./matcher.js";
import { calculateRiskScore } from "./risk-score.js";

/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

const SCANNER_VERSION = "1.0.0";

const DEFAULT_OPTIONS = Object.freeze({
  sourceType: SOURCE_TYPES.UNKNOWN,
  maxTextCharacters: SCAN_LIMITS.maxTextCharacters,
  maxNormalizedTextCharacters: SCAN_LIMITS.maxNormalizedTextCharacters,
  maxFindings: SCAN_LIMITS.maxFindingsPerScan,
  maxRuleMatchesPerFinding: SCAN_LIMITS.maxRuleMatchesPerFinding,
  maxScanTimeMs: SCAN_LIMITS.maxScanTimeMs,
  normalize: true,
  calculateRisk: true,
  includeMatchedText: true,
  includeSafeDiagnostics: false,
});

const FILE_TEXT_ENCODINGS = Object.freeze([
  "utf-8",
  "utf-16le",
]);

const SCAN_RESULT_STATUS = Object.freeze({
  COMPLETED: "completed",
  EMPTY: "empty",
  TRUNCATED: "truncated",
  REJECTED: "rejected",
  FAILED: "failed",
  TIMEOUT: "timeout",
});

const INPUT_TYPES = Object.freeze({
  TEXT: "text",
  FILE: "file",
  FILENAME: "filename",
});

const scannerState = {
  initialized: false,
  totalScans: 0,
  successfulScans: 0,
  failedScans: 0,
  rejectedScans: 0,
  timeoutScans: 0,
  textScans: 0,
  fileScans: 0,
  filenameScans: 0,
  totalCharactersScanned: 0,
  totalFindings: 0,
  lastScanAt: 0,
};

/* -------------------------------------------------------------------------- */
/* Utility helpers                                                            */
/* -------------------------------------------------------------------------- */

function now() {
  if (
    typeof globalThis !== "undefined" &&
    globalThis.performance &&
    typeof globalThis.performance.now === "function"
  ) {
    return globalThis.performance.now();
  }

  return Date.now();
}

function createScanId() {
  const timestamp = Date.now().toString(36);

  let randomPart;

  try {
    if (
      globalThis.crypto &&
      typeof globalThis.crypto.randomUUID === "function"
    ) {
      randomPart = globalThis.crypto.randomUUID().replace(/-/g, "");
    }
  } catch {
    randomPart = null;
  }

  if (!randomPart) {
    randomPart = Math.random().toString(36).slice(2, 14);
  }

  return `scan_${timestamp}_${randomPart}`;
}

function clampInteger(value, minimum, maximum, fallback) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return fallback;
  }

  const integer = Math.floor(number);

  return Math.min(
    maximum,
    Math.max(minimum, integer),
  );
}

function clampNumber(value, minimum, maximum, fallback) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return fallback;
  }

  return Math.min(
    maximum,
    Math.max(minimum, number),
  );
}

function safeString(value) {
  return typeof value === "string" ? value : "";
}

function normalizeSourceType(sourceType) {
  const value = safeString(sourceType).trim().toLowerCase();

  if (!value) {
    return SOURCE_TYPES.UNKNOWN;
  }

  const values = Object.values(SOURCE_TYPES);

  return values.includes(value)
    ? value
    : SOURCE_TYPES.UNKNOWN;
}

function sanitizeOptions(options = {}) {
  const input = options && typeof options === "object"
    ? options
    : {};

  return {
    ...DEFAULT_OPTIONS,

    sourceType: normalizeSourceType(
      input.sourceType ?? DEFAULT_OPTIONS.sourceType,
    ),

    maxTextCharacters: clampInteger(
      input.maxTextCharacters,
      1,
      SCAN_LIMITS.maxTextCharacters,
      SCAN_LIMITS.maxTextCharacters,
    ),

    maxNormalizedTextCharacters: clampInteger(
      input.maxNormalizedTextCharacters,
      1,
      SCAN_LIMITS.maxNormalizedTextCharacters,
      SCAN_LIMITS.maxNormalizedTextCharacters,
    ),

    maxFindings: clampInteger(
      input.maxFindings,
      1,
      SCAN_LIMITS.maxFindingsPerScan,
      SCAN_LIMITS.maxFindingsPerScan,
    ),

    maxRuleMatchesPerFinding: clampInteger(
      input.maxRuleMatchesPerFinding,
      1,
      SCAN_LIMITS.maxRuleMatchesPerFinding,
      SCAN_LIMITS.maxRuleMatchesPerFinding,
    ),

    maxScanTimeMs: clampNumber(
      input.maxScanTimeMs,
      1,
      SCAN_LIMITS.maxScanTimeMs,
      SCAN_LIMITS.maxScanTimeMs,
    ),

    normalize: input.normalize !== false,
    calculateRisk: input.calculateRisk !== false,
    includeMatchedText: input.includeMatchedText !== false,
    includeSafeDiagnostics: input.includeSafeDiagnostics === true,
  };
}

function createBaseResult({
  scanId,
  sourceType,
  inputType,
  startedAt,
}) {
  return {
    scanId,
    scannerVersion: SCANNER_VERSION,
    status: SCAN_RESULT_STATUS.COMPLETED,
    sourceType,
    inputType,
    startedAt,
    completedAt: null,
    durationMs: 0,

    limited: false,
    truncated: false,
    rejected: false,
    timedOut: false,

    findings: [],
    risk: null,

    statistics: {
      inputCharacters: 0,
      normalizedCharacters: 0,
      findings: 0,
      criticalFindings: 0,
      highFindings: 0,
      mediumFindings: 0,
      lowFindings: 0,
      ruleMatches: 0,
    },

    error: null,
  };
}

function finalizeResult(result, startedAt) {
  const completedAt = now();

  result.completedAt = completedAt;
  result.durationMs = Math.max(
    0,
    Math.round((completedAt - startedAt) * 100) / 100,
  );

  return result;
}

function createError(code, message) {
  return {
    code,
    message,
  };
}

function isDeadlineExceeded(startedAt, maxScanTimeMs) {
  return now() - startedAt >= maxScanTimeMs;
}

function truncateText(text, maximumCharacters) {
  if (text.length <= maximumCharacters) {
    return {
      text,
      truncated: false,
    };
  }

  return {
    text: text.slice(0, maximumCharacters),
    truncated: true,
  };
}

function countFindingsBySeverity(findings) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  for (const finding of findings) {
    const severity = safeString(finding?.severity)
      .trim()
      .toLowerCase();

    if (Object.prototype.hasOwnProperty.call(counts, severity)) {
      counts[severity] += 1;
    }
  }

  return counts;
}

function countRuleMatches(findings) {
  let total = 0;

  for (const finding of findings) {
    if (Array.isArray(finding?.matches)) {
      total += finding.matches.length;
      continue;
    }

    if (Number.isFinite(finding?.matchCount)) {
      total += Math.max(0, Number(finding.matchCount));
      continue;
    }

    total += 1;
  }

  return total;
}

/* -------------------------------------------------------------------------- */
/* Finding sanitization                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Findings can contain sensitive matched values because the policy engine
 * may need them to mask content. They must remain inside the content-script
 * execution context.
 *
 * This function is only used when a caller explicitly requests a safe
 * diagnostic representation.
 */
function createSafeFinding(finding) {
  if (!finding || typeof finding !== "object") {
    return null;
  }

  const safe = {
    ruleId: safeString(finding.ruleId),
    category: safeString(finding.category),
    severity: safeString(finding.severity),
    confidence: Number.isFinite(finding.confidence)
      ? finding.confidence
      : null,
    start: Number.isFinite(finding.start)
      ? finding.start
      : null,
    end: Number.isFinite(finding.end)
      ? finding.end
      : null,
    source: safeString(finding.source),
    location: safeString(finding.location),
  };

  if (Number.isFinite(finding.matchCount)) {
    safe.matchCount = finding.matchCount;
  }

  if (Array.isArray(finding.matches)) {
    safe.matchCount = finding.matches.length;
  }

  return safe;
}

function createSafeResult(result) {
  return {
    scanId: result.scanId,
    scannerVersion: result.scannerVersion,
    status: result.status,
    sourceType: result.sourceType,
    inputType: result.inputType,
    startedAt: result.startedAt,
    completedAt: result.completedAt,
    durationMs: result.durationMs,
    limited: result.limited,
    truncated: result.truncated,
    rejected: result.rejected,
    timedOut: result.timedOut,
    findings: result.findings
      .map(createSafeFinding)
      .filter(Boolean),
    risk: result.risk
      ? {
          score: result.risk.score,
          level: result.risk.level,
          label: result.risk.label,
          description: result.risk.description,
          findingCount: result.risk.findingCount,
        }
      : null,
    statistics: {
      ...result.statistics,
    },
    error: result.error
      ? {
          code: result.error.code,
          message: result.error.message,
        }
      : null,
  };
}

/* -------------------------------------------------------------------------- */
/* Matcher compatibility                                                       */
/* -------------------------------------------------------------------------- */

function normalizeMatcherResult(result) {
  if (!result) {
    return {
      findings: [],
      matches: 0,
    };
  }

  if (Array.isArray(result)) {
    return {
      findings: result,
      matches: result.length,
    };
  }

  if (typeof result !== "object") {
    return {
      findings: [],
      matches: 0,
    };
  }

  const findings = Array.isArray(result.findings)
    ? result.findings
    : Array.isArray(result.matches)
      ? result.matches
      : [];

  return {
    findings,
    matches: Number.isFinite(result.matchCount)
      ? result.matchCount
      : findings.length,
  };
}

/**
 * The matcher is expected to be local and synchronous.
 *
 * The options object deliberately contains no Chrome runtime object and no
 * external service information.
 */
function executeMatcher(text, options) {
  const matcherOptions = {
    maxFindings: options.maxFindings,
    maxRuleMatchesPerFinding: options.maxRuleMatchesPerFinding,
    includeMatchedText: options.includeMatchedText,
  };

  const result = matchText(text, matcherOptions);

  return normalizeMatcherResult(result);
}

/* -------------------------------------------------------------------------- */
/* Normalization compatibility                                                 */
/* -------------------------------------------------------------------------- */

function normalizeInputText(text, options) {
  if (!options.normalize) {
    return {
      text,
      truncated: false,
      mapping: null,
    };
  }

  const result = normalizeText(text, {
    maxCharacters: options.maxNormalizedTextCharacters,
  });

  if (typeof result === "string") {
    return {
      text: result,
      truncated: false,
      mapping: null,
    };
  }

  if (!result || typeof result !== "object") {
    return {
      text,
      truncated: false,
      mapping: null,
    };
  }

  return {
    text: typeof result.text === "string"
      ? result.text
      : text,

    truncated: result.truncated === true,

    mapping:
      result.mapping ??
      result.offsetMap ??
      result.indexMap ??
      null,
  };
}

/* -------------------------------------------------------------------------- */
/* Offset mapping                                                              */
/* -------------------------------------------------------------------------- */

function mapOffset(mapping, offset, fallback) {
  if (!mapping) {
    return fallback;
  }

  if (typeof mapping === "function") {
    try {
      const mapped = mapping(offset);

      if (Number.isFinite(mapped)) {
        return mapped;
      }
    } catch {
      return fallback;
    }

    return fallback;
  }

  if (Array.isArray(mapping)) {
    const value = mapping[offset];

    return Number.isFinite(value)
      ? value
      : fallback;
  }

  if (
    mapping &&
    typeof mapping === "object" &&
    typeof mapping.normalizedToOriginal === "function"
  ) {
    try {
      const value = mapping.normalizedToOriginal(offset);

      return Number.isFinite(value)
        ? value
        : fallback;
    } catch {
      return fallback;
    }
  }

  return fallback;
}

function mapFindingOffsets(finding, mapping, originalLength) {
  if (!finding || typeof finding !== "object") {
    return finding;
  }

  if (!mapping) {
    return finding;
  }

  const start = Number.isFinite(finding.start)
    ? finding.start
    : null;

  const end = Number.isFinite(finding.end)
    ? finding.end
    : null;

  if (start === null || end === null) {
    return finding;
  }

  const mappedStart = mapOffset(
    mapping,
    start,
    start,
  );

  const mappedEnd = mapOffset(
    mapping,
    Math.max(start, end - 1),
    Math.max(start, end - 1),
  );

  return {
    ...finding,
    start: Math.max(
      0,
      Math.min(originalLength, mappedStart),
    ),
    end: Math.max(
      0,
      Math.min(
        originalLength,
        mappedEnd + 1,
      ),
    ),
  };
}

/* -------------------------------------------------------------------------- */
/* Finding normalization                                                       */
/* -------------------------------------------------------------------------- */

function normalizeFinding(finding, source, inputType) {
  if (!finding || typeof finding !== "object") {
    return null;
  }

  const normalized = {
    ...finding,

    ruleId: safeString(
      finding.ruleId ??
      finding.id ??
      "unknown-rule",
    ),

    category: safeString(
      finding.category ??
      "unknown",
    ),

    severity: safeString(
      finding.severity ??
      "low",
    ),

    confidence: Number.isFinite(finding.confidence)
      ? Math.max(0, Math.min(1, finding.confidence))
      : 0,

    source,
    location: safeString(
      finding.location ??
      inputType,
    ),
  };

  if (Number.isFinite(finding.start)) {
    normalized.start = Math.max(
      0,
      Math.floor(finding.start),
    );
  }

  if (Number.isFinite(finding.end)) {
    normalized.end = Math.max(
      normalized.start ?? 0,
      Math.floor(finding.end),
    );
  }

  return normalized;
}

function limitFindings(findings, maximum) {
  if (!Array.isArray(findings)) {
    return {
      findings: [],
      truncated: false,
    };
  }

  if (findings.length <= maximum) {
    return {
      findings,
      truncated: false,
    };
  }

  return {
    findings: findings.slice(0, maximum),
    truncated: true,
  };
}

/* -------------------------------------------------------------------------- */
/* Risk calculation                                                            */
/* -------------------------------------------------------------------------- */

function calculateRisk(findings, options) {
  if (!options.calculateRisk) {
    return null;
  }

  try {
    return calculateRiskScore(findings);
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Text scanning                                                               */
/* -------------------------------------------------------------------------- */

export function scanText(text, options = {}) {
  const startedAt = now();
  const scanId = createScanId();

  const scanOptions = sanitizeOptions(options);

  const result = createBaseResult({
    scanId,
    sourceType: scanOptions.sourceType,
    inputType: INPUT_TYPES.TEXT,
    startedAt,
  });

  scannerState.totalScans += 1;
  scannerState.textScans += 1;
  scannerState.lastScanAt = Date.now();

  if (typeof text !== "string") {
    result.status = SCAN_RESULT_STATUS.REJECTED;
    result.rejected = true;
    result.error = createError(
      ERROR_CODES.INVALID_PAYLOAD,
      "Text input must be a string.",
    );

    scannerState.rejectedScans += 1;

    return finalizeResult(result, startedAt);
  }

  if (text.length === 0) {
    result.status = SCAN_RESULT_STATUS.EMPTY;
    scannerState.successfulScans += 1;

    return finalizeResult(result, startedAt);
  }

  if (isDeadlineExceeded(
    startedAt,
    scanOptions.maxScanTimeMs,
  )) {
    result.status = SCAN_RESULT_STATUS.TIMEOUT;
    result.timedOut = true;
    result.error = createError(
      ERROR_CODES.SCAN_TIMEOUT,
      "Scan time limit reached.",
    );

    scannerState.timeoutScans += 1;

    return finalizeResult(result, startedAt);
  }

  result.statistics.inputCharacters = text.length;

  const limitedInput = truncateText(
    text,
    scanOptions.maxTextCharacters,
  );

  const inputText = limitedInput.text;

  result.truncated = limitedInput.truncated;
  result.limited = limitedInput.truncated;

  if (limitedInput.truncated) {
    result.status = SCAN_RESULT_STATUS.TRUNCATED;
  }

  scannerState.totalCharactersScanned += inputText.length;

  let normalized;

  try {
    normalized = normalizeInputText(
      inputText,
      scanOptions,
    );
  } catch {
    result.status = SCAN_RESULT_STATUS.FAILED;
    result.error = createError(
      ERROR_CODES.SCAN_FAILED,
      "Text normalization failed.",
    );

    scannerState.failedScans += 1;

    return finalizeResult(result, startedAt);
  }

  if (normalized.truncated) {
    result.truncated = true;
    result.limited = true;

    if (result.status === SCAN_RESULT_STATUS.COMPLETED) {
      result.status = SCAN_RESULT_STATUS.TRUNCATED;
    }
  }

  const normalizedText = truncateText(
    normalized.text,
    scanOptions.maxNormalizedTextCharacters,
  );

  result.statistics.normalizedCharacters =
    normalizedText.text.length;

  if (normalizedText.truncated) {
    result.truncated = true;
    result.limited = true;

    if (result.status === SCAN_RESULT_STATUS.COMPLETED) {
      result.status = SCAN_RESULT_STATUS.TRUNCATED;
    }
  }

  if (normalizedText.text.length === 0) {
    scannerState.successfulScans += 1;

    return finalizeResult(result, startedAt);
  }

  if (isDeadlineExceeded(
    startedAt,
    scanOptions.maxScanTimeMs,
  )) {
    result.status = SCAN_RESULT_STATUS.TIMEOUT;
    result.timedOut = true;
    result.error = createError(
      ERROR_CODES.SCAN_TIMEOUT,
      "Scan time limit reached.",
    );

    scannerState.timeoutScans += 1;

    return finalizeResult(result, startedAt);
  }

  let matcherResult;

  try {
    matcherResult = executeMatcher(
      normalizedText.text,
      scanOptions,
    );
  } catch {
    result.status = SCAN_RESULT_STATUS.FAILED;
    result.error = createError(
      ERROR_CODES.SCAN_FAILED,
      "Local matching failed.",
    );

    scannerState.failedScans += 1;

    return finalizeResult(result, startedAt);
  }

  if (isDeadlineExceeded(
    startedAt,
    scanOptions.maxScanTimeMs,
  )) {
    result.status = SCAN_RESULT_STATUS.TIMEOUT;
    result.timedOut = true;
    result.error = createError(
      ERROR_CODES.SCAN_TIMEOUT,
      "Scan time limit reached.",
    );

    scannerState.timeoutScans += 1;

    return finalizeResult(result, startedAt);
  }

  const normalizedFindings = matcherResult.findings
    .map((finding) =>
      normalizeFinding(
        finding,
        scanOptions.sourceType,
        INPUT_TYPES.TEXT,
      ),
    )
    .filter(Boolean)
    .map((finding) =>
      mapFindingOffsets(
        finding,
        normalized.mapping,
        inputText.length,
      ),
    );

  const limitedFindings = limitFindings(
    normalizedFindings,
    scanOptions.maxFindings,
  );

  result.findings = limitedFindings.findings;

  if (limitedFindings.truncated) {
    result.truncated = true;
    result.limited = true;

    if (result.status === SCAN_RESULT_STATUS.COMPLETED) {
      result.status = SCAN_RESULT_STATUS.TRUNCATED;
    }
  }

  const severityCounts = countFindingsBySeverity(
    result.findings,
  );

  result.statistics.findings = result.findings.length;
  result.statistics.criticalFindings =
    severityCounts.critical;
  result.statistics.highFindings =
    severityCounts.high;
  result.statistics.mediumFindings =
    severityCounts.medium;
  result.statistics.lowFindings =
    severityCounts.low;
  result.statistics.ruleMatches =
    countRuleMatches(result.findings);

  scannerState.totalFindings +=
    result.findings.length;

  if (isDeadlineExceeded(
    startedAt,
    scanOptions.maxScanTimeMs,
  )) {
    result.status = SCAN_RESULT_STATUS.TIMEOUT;
    result.timedOut = true;
    result.error = createError(
      ERROR_CODES.SCAN_TIMEOUT,
      "Scan time limit reached.",
    );

    scannerState.timeoutScans += 1;

    return finalizeResult(result, startedAt);
  }

  result.risk = calculateRisk(
    result.findings,
    scanOptions,
  );

  scannerState.successfulScans += 1;

  return finalizeResult(result, startedAt);
}

/* -------------------------------------------------------------------------- */
/* File helpers                                                                */
/* -------------------------------------------------------------------------- */

function getFileExtension(fileName) {
  const name = safeString(fileName)
    .trim()
    .toLowerCase();

  const lastDot = name.lastIndexOf(".");

  if (lastDot === -1 || lastDot === name.length - 1) {
    return "";
  }

  return name.slice(lastDot + 1);
}

function normalizeExtension(extension) {
  return safeString(extension)
    .trim()
    .toLowerCase()
    .replace(/^\./, "");
}

function isExtensionTextFile(extension) {
  const normalized = normalizeExtension(extension);

  if (!normalized) {
    return false;
  }

  if (Array.isArray(TEXT_FILE_EXTENSIONS)) {
    return TEXT_FILE_EXTENSIONS.some(
      (item) =>
        normalizeExtension(item) === normalized,
    );
  }

  if (
    TEXT_FILE_EXTENSIONS &&
    typeof TEXT_FILE_EXTENSIONS === "object"
  ) {
    return Object.keys(TEXT_FILE_EXTENSIONS)
      .some(
        (item) =>
          normalizeExtension(item) === normalized,
      );
  }

  return false;
}

function normalizeMimeType(mimeType) {
  return safeString(mimeType)
    .trim()
    .toLowerCase()
    .split(";")[0]
    .trim();
}

function isMimeTextFile(mimeType) {
  const normalized = normalizeMimeType(mimeType);

  if (!normalized) {
    return false;
  }

  if (Array.isArray(TEXT_FILE_MIME_TYPES)) {
    return TEXT_FILE_MIME_TYPES.includes(normalized);
  }

  if (
    TEXT_FILE_MIME_TYPES &&
    typeof TEXT_FILE_MIME_TYPES === "object"
  ) {
    return Object.prototype.hasOwnProperty.call(
      TEXT_FILE_MIME_TYPES,
      normalized,
    );
  }

  return (
    normalized.startsWith("text/") ||
    normalized === "application/json" ||
    normalized === "application/javascript" ||
    normalized === "application/x-javascript"
  );
}

function isTextFile(file) {
  if (!file || typeof file !== "object") {
    return false;
  }

  const extension = getFileExtension(file.name);
  const mimeType = normalizeMimeType(file.type);

  if (isExtensionTextFile(extension)) {
    return true;
  }

  if (isMimeTextFile(mimeType)) {
    return true;
  }

  return false;
}

function getFileSize(file) {
  if (
    file &&
    Number.isFinite(file.size) &&
    file.size >= 0
  ) {
    return file.size;
  }

  return null;
}

async function decodeFileText(file) {
  if (!file) {
    throw new TypeError("File is required.");
  }

  if (
    typeof file.text === "function"
  ) {
    return file.text();
  }

  if (
    typeof file.arrayBuffer === "function"
  ) {
    const buffer = await file.arrayBuffer();

    for (const encoding of FILE_TEXT_ENCODINGS) {
      try {
        const decoder = new TextDecoder(
          encoding,
          {
            fatal: false,
          },
        );

        return decoder.decode(buffer);
      } catch {
        continue;
      }
    }

    throw new Error("Unable to decode file.");
  }

  throw new TypeError(
    "The supplied object is not a readable File.",
  );
}

function createFileResultBase({
  scanId,
  sourceType,
  startedAt,
  file,
}) {
  const result = createBaseResult({
    scanId,
    sourceType,
    inputType: INPUT_TYPES.FILE,
    startedAt,
  });

  result.file = {
    name: safeString(file?.name).slice(
      0,
      SCAN_LIMITS.maxFileNameCharacters,
    ),
    size: getFileSize(file),
    type: normalizeMimeType(file?.type),
    extension: getFileExtension(file?.name),
    textScanned: false,
    filenameScanned: false,
  };

  return result;
}

/* -------------------------------------------------------------------------- */
/* Filename scanning                                                           */
/* -------------------------------------------------------------------------- */

export function scanFilename(fileName, options = {}) {
  const startedAt = now();
  const scanId = createScanId();

  const scanOptions = sanitizeOptions({
    ...options,
    sourceType:
      options.sourceType ??
      SOURCE_TYPES.UPLOAD,
  });

  const result = createBaseResult({
    scanId,
    sourceType: scanOptions.sourceType,
    inputType: INPUT_TYPES.FILENAME,
    startedAt,
  });

  scannerState.totalScans += 1;
  scannerState.filenameScans += 1;
  scannerState.lastScanAt = Date.now();

  const filename = safeString(fileName);

  if (!filename) {
    result.status = SCAN_RESULT_STATUS.EMPTY;
    scannerState.successfulScans += 1;

    return finalizeResult(result, startedAt);
  }

  const limitedFilename = truncateText(
    filename,
    SCAN_LIMITS.maxFileNameCharacters,
  );

  result.statistics.inputCharacters =
    limitedFilename.text.length;

  result.truncated = limitedFilename.truncated;
  result.limited = limitedFilename.truncated;

  if (limitedFilename.truncated) {
    result.status = SCAN_RESULT_STATUS.TRUNCATED;
  }

  if (isDeadlineExceeded(
    startedAt,
    scanOptions.maxScanTimeMs,
  )) {
    result.status = SCAN_RESULT_STATUS.TIMEOUT;
    result.timedOut = true;
    result.error = createError(
      ERROR_CODES.SCAN_TIMEOUT,
      "Filename scan time limit reached.",
    );

    scannerState.timeoutScans += 1;

    return finalizeResult(result, startedAt);
  }

  let matcherResult;

  try {
    matcherResult = executeMatcher(
      limitedFilename.text,
      scanOptions,
    );
  } catch {
    result.status = SCAN_RESULT_STATUS.FAILED;
    result.error = createError(
      ERROR_CODES.SCAN_FAILED,
      "Filename matching failed.",
    );

    scannerState.failedScans += 1;

    return finalizeResult(result, startedAt);
  }

  const findings = matcherResult.findings
    .map((finding) =>
      normalizeFinding(
        finding,
        scanOptions.sourceType,
        INPUT_TYPES.FILENAME,
      ),
    )
    .filter(Boolean)
    .map((finding) => ({
      ...finding,
      location: INPUT_TYPES.FILENAME,
    }));

  const limitedFindings = limitFindings(
    findings,
    scanOptions.maxFindings,
  );

  result.findings = limitedFindings.findings;

  if (limitedFindings.truncated) {
    result.truncated = true;
    result.limited = true;
  }

  const severityCounts = countFindingsBySeverity(
    result.findings,
  );

  result.statistics.findings =
    result.findings.length;

  result.statistics.criticalFindings =
    severityCounts.critical;

  result.statistics.highFindings =
    severityCounts.high;

  result.statistics.mediumFindings =
    severityCounts.medium;

  result.statistics.lowFindings =
    severityCounts.low;

  result.statistics.ruleMatches =
    countRuleMatches(result.findings);

  result.risk = calculateRisk(
    result.findings,
    scanOptions,
  );

  scannerState.totalFindings +=
    result.findings.length;

  scannerState.successfulScans += 1;

  return finalizeResult(result, startedAt);
}

/* -------------------------------------------------------------------------- */
/* File scanning                                                               */
/* -------------------------------------------------------------------------- */

export async function scanFile(file, options = {}) {
  const startedAt = now();
  const scanId = createScanId();

  const scanOptions = sanitizeOptions({
    ...options,
    sourceType:
      options.sourceType ??
      SOURCE_TYPES.UPLOAD,
  });

  const result = createFileResultBase({
    scanId,
    sourceType: scanOptions.sourceType,
    startedAt,
    file,
  });

  scannerState.totalScans += 1;
  scannerState.fileScans += 1;
  scannerState.lastScanAt = Date.now();

  if (!file || typeof file !== "object") {
    result.status = SCAN_RESULT_STATUS.REJECTED;
    result.rejected = true;
    result.error = createError(
      ERROR_CODES.INVALID_PAYLOAD,
      "A readable file object is required.",
    );

    scannerState.rejectedScans += 1;

    return finalizeResult(result, startedAt);
  }

  const fileSize = getFileSize(file);

  if (
    fileSize !== null &&
    fileSize > SCAN_LIMITS.maxFileBytes
  ) {
    result.status = SCAN_RESULT_STATUS.REJECTED;
    result.rejected = true;
    result.limited = true;

    result.error = createError(
      ERROR_CODES.FILE_TOO_LARGE,
      "File exceeds the configured scan size limit.",
    );

    scannerState.rejectedScans += 1;

    if (FILE_SCAN_DEFAULTS.rejectOversizedFiles) {
      return finalizeResult(result, startedAt);
    }

    return finalizeResult(result, startedAt);
  }

  const filename = safeString(file.name);

  if (
    FILE_SCAN_DEFAULTS.scanFileNames &&
    filename
  ) {
    const filenameResult = scanFilename(
      filename,
      scanOptions,
    );

    result.file.filenameScanned = true;

    for (const finding of filenameResult.findings) {
      result.findings.push(finding);
    }

    result.statistics.findings =
      result.findings.length;

    if (filenameResult.truncated) {
      result.truncated = true;
      result.limited = true;
    }

    if (filenameResult.timedOut) {
      result.status = SCAN_RESULT_STATUS.TIMEOUT;
      result.timedOut = true;
      result.error = filenameResult.error;

      scannerState.timeoutScans += 1;

      return finalizeResult(result, startedAt);
    }
  }

  if (isDeadlineExceeded(
    startedAt,
    scanOptions.maxScanTimeMs,
  )) {
    result.status = SCAN_RESULT_STATUS.TIMEOUT;
    result.timedOut = true;
    result.error = createError(
      ERROR_CODES.SCAN_TIMEOUT,
      "File scan time limit reached.",
    );

    scannerState.timeoutScans += 1;

    return finalizeResult(result, startedAt);
  }

  const shouldScanText =
    FILE_SCAN_DEFAULTS.scanTextFiles !== false;

  if (
    shouldScanText &&
    !isTextFile(file)
  ) {
    result.status = result.findings.length > 0
      ? SCAN_RESULT_STATUS.COMPLETED
      : SCAN_RESULT_STATUS.REJECTED;

    result.rejected =
      result.findings.length === 0;

    result.error = result.findings.length === 0
      ? createError(
          ERROR_CODES.FILE_TYPE_UNSUPPORTED,
          "The file type is not supported for local text scanning.",
        )
      : null;

    const severityCounts =
      countFindingsBySeverity(
        result.findings,
      );

    result.statistics.findings =
      result.findings.length;

    result.statistics.criticalFindings =
      severityCounts.critical;

    result.statistics.highFindings =
      severityCounts.high;

    result.statistics.mediumFindings =
      severityCounts.medium;

    result.statistics.lowFindings =
      severityCounts.low;

    result.statistics.ruleMatches =
      countRuleMatches(result.findings);

    result.risk = calculateRisk(
      result.findings,
      scanOptions,
    );

    if (result.rejected) {
      scannerState.rejectedScans += 1;
    } else {
      scannerState.successfulScans += 1;
    }

    return finalizeResult(result, startedAt);
  }

  let fileText;

  try {
    fileText = await decodeFileText(file);
  } catch {
    result.status = SCAN_RESULT_STATUS.FAILED;
    result.error = createError(
      ERROR_CODES.FILE_READ_FAILED,
      "Unable to read the local file.",
    );

    scannerState.failedScans += 1;

    return finalizeResult(result, startedAt);
  }

  if (typeof fileText !== "string") {
    result.status = SCAN_RESULT_STATUS.FAILED;
    result.error = createError(
      ERROR_CODES.FILE_READ_FAILED,
      "The file did not produce readable text.",
    );

    scannerState.failedScans += 1;

    return finalizeResult(result, startedAt);
  }

  result.file.textScanned = true;

  const textResult = scanText(
    fileText,
    {
      ...scanOptions,
      sourceType: scanOptions.sourceType,
    },
  );

  for (const finding of textResult.findings) {
    result.findings.push({
      ...finding,
      location: INPUT_TYPES.FILE,
    });
  }

  result.statistics.inputCharacters =
    textResult.statistics.inputCharacters;

  result.statistics.normalizedCharacters =
    textResult.statistics.normalizedCharacters;

  result.statistics.findings =
    result.findings.length;

  result.statistics.criticalFindings =
    textResult.statistics.criticalFindings;

  result.statistics.highFindings =
    textResult.statistics.highFindings;

  result.statistics.mediumFindings =
    textResult.statistics.mediumFindings;

  result.statistics.lowFindings =
    textResult.statistics.lowFindings;

  result.statistics.ruleMatches =
    countRuleMatches(result.findings);

  result.truncated =
    result.truncated ||
    textResult.truncated;

  result.limited =
    result.limited ||
    textResult.limited;

  if (textResult.timedOut) {
    result.status = SCAN_RESULT_STATUS.TIMEOUT;
    result.timedOut = true;
    result.error = textResult.error;

    scannerState.timeoutScans += 1;

    return finalizeResult(result, startedAt);
  }

  if (textResult.status === SCAN_RESULT_STATUS.FAILED) {
    result.status = SCAN_RESULT_STATUS.FAILED;
    result.error = textResult.error;

    scannerState.failedScans += 1;

    return finalizeResult(result, startedAt);
  }

  if (textResult.status === SCAN_RESULT_STATUS.TRUNCATED) {
    result.status = SCAN_RESULT_STATUS.TRUNCATED;
  }

  const limitedFindings = limitFindings(
    result.findings,
    scanOptions.maxFindings,
  );

  result.findings =
    limitedFindings.findings;

  if (limitedFindings.truncated) {
    result.truncated = true;
    result.limited = true;
    result.status = SCAN_RESULT_STATUS.TRUNCATED;
  }

  const severityCounts =
    countFindingsBySeverity(
      result.findings,
    );

  result.statistics.findings =
    result.findings.length;

  result.statistics.criticalFindings =
    severityCounts.critical;

  result.statistics.highFindings =
    severityCounts.high;

  result.statistics.mediumFindings =
    severityCounts.medium;

  result.statistics.lowFindings =
    severityCounts.low;

  result.statistics.ruleMatches =
    countRuleMatches(result.findings);

  result.risk = calculateRisk(
    result.findings,
    scanOptions,
  );

  scannerState.totalFindings +=
    result.findings.length;

  scannerState.successfulScans += 1;

  return finalizeResult(result, startedAt);
}

/* -------------------------------------------------------------------------- */
/* Batch scanning                                                              */
/* -------------------------------------------------------------------------- */

export function scanTexts(items, options = {}) {
  if (!Array.isArray(items)) {
    return [];
  }

  const results = [];

  for (const item of items) {
    if (
      item &&
      typeof item === "object" &&
      typeof item.text === "string"
    ) {
      results.push(
        scanText(
          item.text,
          {
            ...options,
            sourceType:
              item.sourceType ??
              options.sourceType ??
              SOURCE_TYPES.UNKNOWN,
          },
        ),
      );

      continue;
    }

    if (typeof item === "string") {
      results.push(
        scanText(
          item,
          options,
        ),
      );
    }
  }

  return results;
}

/* -------------------------------------------------------------------------- */
/* Result aggregation                                                          */
/* -------------------------------------------------------------------------- */

export function mergeScanResults(results, options = {}) {
  const validResults = Array.isArray(results)
    ? results.filter(
        (result) =>
          result &&
          typeof result === "object",
      )
    : [];

  const scanId = createScanId();

  const merged = {
    scanId,
    scannerVersion: SCANNER_VERSION,
    status: SCAN_RESULT_STATUS.COMPLETED,
    sourceType: normalizeSourceType(
      options.sourceType ??
      SOURCE_TYPES.UNKNOWN,
    ),
    inputType: "aggregate",

    startedAt: null,
    completedAt: Date.now(),
    durationMs: 0,

    limited: false,
    truncated: false,
    rejected: false,
    timedOut: false,

    findings: [],
    risk: null,

    statistics: {
      inputCharacters: 0,
      normalizedCharacters: 0,
      findings: 0,
      criticalFindings: 0,
      highFindings: 0,
      mediumFindings: 0,
      lowFindings: 0,
      ruleMatches: 0,
    },

    error: null,
  };

  if (validResults.length === 0) {
    merged.status = SCAN_RESULT_STATUS.EMPTY;
    return merged;
  }

  for (const result of validResults) {
    if (
      merged.startedAt === null ||
      (
        Number.isFinite(result.startedAt) &&
        result.startedAt < merged.startedAt
      )
    ) {
      merged.startedAt = result.startedAt;
    }

    merged.findings.push(
      ...(Array.isArray(result.findings)
        ? result.findings
        : []),
    );

    merged.statistics.inputCharacters +=
      Number(result.statistics?.inputCharacters) || 0;

    merged.statistics.normalizedCharacters +=
      Number(result.statistics?.normalizedCharacters) || 0;

    merged.limited =
      merged.limited ||
      result.limited === true;

    merged.truncated =
      merged.truncated ||
      result.truncated === true;

    merged.rejected =
      merged.rejected ||
      result.rejected === true;

    merged.timedOut =
      merged.timedOut ||
      result.timedOut === true;
  }

  const maximumFindings = clampInteger(
    options.maxFindings,
    1,
    SCAN_LIMITS.maxFindingsPerScan,
    SCAN_LIMITS.maxFindingsPerScan,
  );

  if (merged.findings.length > maximumFindings) {
    merged.findings =
      merged.findings.slice(
        0,
        maximumFindings,
      );

    merged.limited = true;
    merged.truncated = true;
    merged.status = SCAN_RESULT_STATUS.TRUNCATED;
  }

  const severityCounts =
    countFindingsBySeverity(
      merged.findings,
    );

  merged.statistics.findings =
    merged.findings.length;

  merged.statistics.criticalFindings =
    severityCounts.critical;

  merged.statistics.highFindings =
    severityCounts.high;

  merged.statistics.mediumFindings =
    severityCounts.medium;

  merged.statistics.lowFindings =
    severityCounts.low;

  merged.statistics.ruleMatches =
    countRuleMatches(
      merged.findings,
    );

  merged.risk = calculateRisk(
    merged.findings,
    sanitizeOptions(options),
  );

  if (
    merged.startedAt !== null &&
    Number.isFinite(merged.startedAt)
  ) {
    merged.durationMs = Math.max(
      0,
      merged.completedAt -
        merged.startedAt,
    );
  }

  return merged;
}

/* -------------------------------------------------------------------------- */
/* Scanner state                                                               */
/* -------------------------------------------------------------------------- */

export function getScannerStats() {
  return {
    scannerVersion: SCANNER_VERSION,
    initialized: scannerState.initialized,

    totalScans: scannerState.totalScans,
    successfulScans: scannerState.successfulScans,
    failedScans: scannerState.failedScans,
    rejectedScans: scannerState.rejectedScans,
    timeoutScans: scannerState.timeoutScans,

    textScans: scannerState.textScans,
    fileScans: scannerState.fileScans,
    filenameScans: scannerState.filenameScans,

    totalCharactersScanned:
      scannerState.totalCharactersScanned,

    totalFindings:
      scannerState.totalFindings,

    lastScanAt:
      scannerState.lastScanAt,
  };
}

export function resetScannerStats() {
  scannerState.totalScans = 0;
  scannerState.successfulScans = 0;
  scannerState.failedScans = 0;
  scannerState.rejectedScans = 0;
  scannerState.timeoutScans = 0;

  scannerState.textScans = 0;
  scannerState.fileScans = 0;
  scannerState.filenameScans = 0;

  scannerState.totalCharactersScanned = 0;
  scannerState.totalFindings = 0;
  scannerState.lastScanAt = 0;
}

export function initializeScanner() {
  scannerState.initialized = true;

  return {
    initialized: true,
    scannerVersion: SCANNER_VERSION,
  };
}

export function destroyScanner() {
  scannerState.initialized = false;
}

/* -------------------------------------------------------------------------- */
/* Diagnostics                                                                 */
/* -------------------------------------------------------------------------- */

export function getScannerDiagnostics() {
  return {
    scannerVersion: SCANNER_VERSION,
    initialized: scannerState.initialized,

    localOnly: true,
    networkAccess: false,
    persistentRawContent: false,
    serviceWorkerRawContentTransfer: false,

    limits: {
      maxTextCharacters:
        SCAN_LIMITS.maxTextCharacters,

      maxNormalizedTextCharacters:
        SCAN_LIMITS.maxNormalizedTextCharacters,

      maxFileBytes:
        SCAN_LIMITS.maxFileBytes,

      maxFileNameCharacters:
        SCAN_LIMITS.maxFileNameCharacters,

      maxFindingsPerScan:
        SCAN_LIMITS.maxFindingsPerScan,

      maxRuleMatchesPerFinding:
        SCAN_LIMITS.maxRuleMatchesPerFinding,

      maxScanTimeMs:
        SCAN_LIMITS.maxScanTimeMs,
    },

    fileScanning: {
      enabled:
        FILE_SCAN_DEFAULTS.enabled === true,

      scanTextFiles:
        FILE_SCAN_DEFAULTS.scanTextFiles === true,

      scanFileNames:
        FILE_SCAN_DEFAULTS.scanFileNames === true,

      scanMetadata:
        FILE_SCAN_DEFAULTS.scanMetadata === true,

      rejectOversizedFiles:
        FILE_SCAN_DEFAULTS.rejectOversizedFiles === true,
    },

    stats: getScannerStats(),
  };
}

export function validateScannerConfiguration() {
  const errors = [];

  if (
    !Number.isFinite(
      SCAN_LIMITS.maxTextCharacters,
    ) ||
    SCAN_LIMITS.maxTextCharacters <= 0
  ) {
    errors.push(
      "SCAN_LIMITS.maxTextCharacters must be greater than zero.",
    );
  }

  if (
    !Number.isFinite(
      SCAN_LIMITS.maxNormalizedTextCharacters,
    ) ||
    SCAN_LIMITS.maxNormalizedTextCharacters <= 0
  ) {
    errors.push(
      "SCAN_LIMITS.maxNormalizedTextCharacters must be greater than zero.",
    );
  }

  if (
    !Number.isFinite(
      SCAN_LIMITS.maxFileBytes,
    ) ||
    SCAN_LIMITS.maxFileBytes <= 0
  ) {
    errors.push(
      "SCAN_LIMITS.maxFileBytes must be greater than zero.",
    );
  }

  if (
    !Number.isFinite(
      SCAN_LIMITS.maxFindingsPerScan,
    ) ||
    SCAN_LIMITS.maxFindingsPerScan <= 0
  ) {
    errors.push(
      "SCAN_LIMITS.maxFindingsPerScan must be greater than zero.",
    );
  }

  if (
    !Number.isFinite(
      SCAN_LIMITS.maxScanTimeMs,
    ) ||
    SCAN_LIMITS.maxScanTimeMs <= 0
  ) {
    errors.push(
      "SCAN_LIMITS.maxScanTimeMs must be greater than zero.",
    );
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/* -------------------------------------------------------------------------- */
/* Public helpers                                                              */
/* -------------------------------------------------------------------------- */

export function getScanStatus() {
  return {
    initialized: scannerState.initialized,
    scannerVersion: SCANNER_VERSION,
  };
}

export function getScanResultForDiagnostics(result) {
  return createSafeResult(result);
}

export function isTextFileForScanning(file) {
  return isTextFile(file);
}

export function getSupportedFileExtension(fileName) {
  return getFileExtension(fileName);
}

export function getScannerVersion() {
  return SCANNER_VERSION;
}

/* -------------------------------------------------------------------------- */
/* Automatic initialization                                                    */
/* -------------------------------------------------------------------------- */

initializeScanner();
