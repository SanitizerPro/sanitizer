/**
 * SanitizerPro
 * Content Script Orchestrator
 *
 * Responsibilities:
 * - Initialize and coordinate content-side protection components.
 * - Detect the current AI/search platform.
 * - Scan sensitive content locally.
 * - Evaluate local policy.
 * - Apply ALLOW, WARN, MASK, or BLOCK.
 * - Keep raw prompt, clipboard, file, and form data inside the content context.
 * - Send only non-sensitive metadata to the service worker.
 *
 * Security boundary:
 * - No raw prompt content is sent to chrome.runtime.
 * - No clipboard content is sent to chrome.runtime.
 * - No uploaded file content is sent to chrome.runtime.
 * - No matched sensitive values are sent to chrome.runtime.
 * - No remote scanning is performed.
 *
 * Manifest V3:
 * - This module runs as an isolated-world content script.
 * - The service worker is used only for configuration and safe telemetry/events.
 */

import {
  initializePlatformDetector,
  destroyPlatformDetector,
  detectCurrentPlatform,
  getDetectionResult,
  isCurrentAIPlatform,
  isCurrentSearchPlatform,
  reportPlatformToBackground,
  reportContentReady,
  getDetectorDiagnostics,
} from "./platform-detector.js";

import {
  initializeInputMonitor,
  destroyInputMonitor,
  getInputMonitorDiagnostics,
  getCurrentInputContext,
} from "./input-monitor.js";

import {
  initializePasteMonitor,
  destroyPasteMonitor,
  getPasteMonitorDiagnostics,
} from "./paste-monitor.js";

import {
  initializeDropMonitor,
  destroyDropMonitor,
  getDropMonitorDiagnostics,
} from "./drop-monitor.js";

import {
  initializeUploadMonitor,
  destroyUploadMonitor,
  getUploadMonitorDiagnostics,
} from "./upload-monitor.js";

import {
  initializeSubmitMonitor,
  destroySubmitMonitor,
  getSubmitMonitorDiagnostics,
} from "./submit-monitor.js";

import {
  scanText,
  scanFile,
  getScannerDiagnostics,
  initializeScanner,
  destroyScanner,
} from "../engine/scanner.js";

import {
  evaluatePolicy,
  getPolicySummary,
  initializePolicyEngine,
  destroyPolicyEngine,
} from "../policy/policy-engine.js";

import {
  applyAllow,
} from "../policy/allow.js";

import {
  createWarnResult,
  resolveWarning,
} from "../policy/warn.js";

import {
  applyMask,
} from "../policy/mask.js";

import {
  applyBlock,
  createSecurityBlockResult,
  createScanFailureBlockResult,
  createPolicyFailureBlockResult,
} from "../policy/block.js";

import {
  ACTIONS,
  DEFAULT_CONFIG,
  PROTECTION_MODES,
  SOURCE_TYPES,
  DATA_CATEGORIES,
} from "../config/defaults.js";

import {
  MESSAGE_TYPES,
  EVENT_TYPES,
  MESSAGE_STATUS,
  ERROR_CODES,
  createMessage,
  createEvent,
} from "../config/constants.js";

const CONTENT_VERSION = "1.0.0";

const DEFAULT_CONTEXT = Object.freeze({
  extension: "SanitizerPro",
  component: "content",
  version: CONTENT_VERSION,
});

const OPERATION_TIMEOUT_MS = 5000;
const WARNING_TIMEOUT_MS = 30000;
const PLATFORM_REFRESH_DELAY_MS = 300;

const state = {
  initialized: false,
  initializing: false,
  destroyed: false,

  config: cloneConfig(DEFAULT_CONFIG),

  platform: null,
  detection: null,

  protectionMode:
    DEFAULT_CONFIG?.protection?.mode ??
    DEFAULT_CONFIG?.protectionMode ??
    PROTECTION_MODES.ACTIVE,

  monitorsInitialized: false,

  warningDialog: null,
  warningResolver: null,

  lastOperation: null,
  operationCounter: 0,

  routeRefreshTimer: null,

  stats: {
    scans: 0,
    allowed: 0,
    warned: 0,
    masked: 0,
    blocked: 0,
    failed: 0,
    pasteEvents: 0,
    dropEvents: 0,
    uploadEvents: 0,
    submitEvents: 0,
  },

  eventQueue: [],
  eventFlushTimer: null,

  bound: {
    pageShow: null,
    visibilityChange: null,
  },
};

/* -------------------------------------------------------------------------- */
/* Initialization                                                            */
/* -------------------------------------------------------------------------- */

async function initialize() {
  if (state.initialized || state.initializing || state.destroyed) {
    return getContentStatus();
  }

  state.initializing = true;

  try {
    await loadConfiguration();

    initializeScanner(state.config);
    initializePolicyEngine(state.config);

    initializePlatformDetector({
      onPlatformChanged: handlePlatformChanged,
      onError: handleDetectorError,
    });

    const detection = detectCurrentPlatform();

    state.detection = detection;
    state.platform = detection?.platform ?? null;

    initializeMonitors();

    bindLifecycleEvents();

    state.initialized = true;

    queueSafeEvent(
      EVENT_TYPES.INIT,
      createSafeContext({
        sourceType: SOURCE_TYPES.UNKNOWN,
      }),
    );

    queueSafeEvent(
      EVENT_TYPES.CONTENT_READY,
      createSafeContext({
        sourceType: SOURCE_TYPES.UNKNOWN,
      }),
    );

    safeReportContentReady();

    safeReportPlatform();

    return getContentStatus();
  } catch (error) {
    state.stats.failed += 1;

    safeLog("error", "Content initialization failed.", error);

    queueSafeEvent(
      EVENT_TYPES.ERROR,
      createSafeContext({
        sourceType: SOURCE_TYPES.UNKNOWN,
        errorCode: ERROR_CODES.INTERNAL_ERROR,
      }),
    );

    /*
     * Security-sensitive monitors must not remain partially initialized.
     * Destroy any components that may have been initialized before failure.
     */
    destroyMonitors();

    throw error;
  } finally {
    state.initializing = false;
  }
}

function initializeMonitors() {
  if (state.monitorsInitialized || state.destroyed) {
    return;
  }

  /*
   * Input monitoring is deliberately observation-only.
   *
   * We do not scan every keystroke by default because:
   * - it creates unnecessary CPU overhead;
   * - it increases privacy exposure inside the extension;
   * - send/submit/paste/drop/upload are the actual data-transfer boundaries.
   */
  initializeInputMonitor({
    onInputActivity: handleInputActivity,
    onActionDetected: handleActionDetected,
    onError: handleMonitorError,
  });

  initializePasteMonitor({
    onPaste: handlePaste,
    onWarning: handleWarning,
    onError: handleMonitorError,
  });

  initializeDropMonitor({
    onDrop: handleDrop,
    onWarning: handleWarning,
    onError: handleMonitorError,
  });

  initializeUploadMonitor({
    onUpload: handleUpload,
    onWarning: handleWarning,
    onError: handleMonitorError,
  });

  initializeSubmitMonitor({
    onSubmit: handleSubmit,
    onWarning: handleWarning,
    onError: handleMonitorError,
  });

  state.monitorsInitialized = true;
}

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

async function loadConfiguration() {
  const defaults = cloneConfig(DEFAULT_CONFIG);

  state.config = defaults;

  try {
    if (
      typeof chrome === "undefined" ||
      !chrome.runtime ||
      typeof chrome.runtime.sendMessage !== "function"
    ) {
      applyConfigurationDefaults();
      return;
    }

    const response = await sendRuntimeRequest(
      MESSAGE_TYPES.GET_CONFIG,
      {},
      {
        timeoutMs: OPERATION_TIMEOUT_MS,
        allowFailure: true,
      },
    );

    if (
      response &&
      response.status === MESSAGE_STATUS.OK &&
      response.config &&
      typeof response.config === "object"
    ) {
      state.config = mergeConfig(defaults, response.config);
    }
  } catch (error) {
    /*
     * Local defaults remain authoritative if the service worker is unavailable.
     * Content protection must not depend on service-worker availability.
     */
    safeLog("warn", "Using local default configuration.", error);
    state.config = defaults;
  }

  applyConfigurationDefaults();
}

function applyConfigurationDefaults() {
  state.protectionMode =
    getConfiguredProtectionMode(state.config);

  if (!Object.values(PROTECTION_MODES).includes(state.protectionMode)) {
    state.protectionMode = PROTECTION_MODES.ACTIVE;
  }
}

function getConfiguredProtectionMode(config) {
  return (
    config?.protection?.mode ??
    config?.protectionMode ??
    config?.mode ??
    PROTECTION_MODES.ACTIVE
  );
}

function mergeConfig(base, override) {
  if (!isPlainObject(base)) {
    return cloneConfig(override);
  }

  if (!isPlainObject(override)) {
    return cloneConfig(base);
  }

  const result = cloneConfig(base);

  for (const [key, value] of Object.entries(override)) {
    if (
      isPlainObject(value) &&
      isPlainObject(result[key])
    ) {
      result[key] = mergeConfig(result[key], value);
    } else {
      result[key] = cloneValue(value);
    }
  }

  return result;
}

function cloneConfig(value) {
  return cloneValue(value);
}

function cloneValue(value) {
  if (value === undefined || value === null) {
    return value;
  }

  try {
    return structuredClone(value);
  } catch {
    try {
      return JSON.parse(JSON.stringify(value));
    } catch {
      return value;
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Platform handling                                                          */
/* -------------------------------------------------------------------------- */

function handlePlatformChanged(detection) {
  if (state.destroyed) {
    return;
  }

  state.detection = detection ?? null;
  state.platform = detection?.platform ?? null;

  queueSafeEvent(
    EVENT_TYPES.PLATFORM_DETECTED,
    createSafeContext({
      sourceType: SOURCE_TYPES.UNKNOWN,
    }),
  );

  safeReportPlatform();

  /*
   * Some AI applications are SPAs and replace their composer without
   * navigating the document. Refresh monitors after platform transitions.
   */
  schedulePlatformRefresh();
}

function schedulePlatformRefresh() {
  if (state.routeRefreshTimer !== null) {
    clearTimeout(state.routeRefreshTimer);
  }

  state.routeRefreshTimer = setTimeout(() => {
    state.routeRefreshTimer = null;

    if (state.destroyed) {
      return;
    }

    try {
      detectCurrentPlatform();

      /*
       * Most monitors use delegated listeners and MutationObservers.
       * Refreshing them is therefore safe and keeps them aligned with
       * dynamically replaced application DOM.
       */
      refreshMonitors();
    } catch (error) {
      safeLog("warn", "Platform refresh failed.", error);
    }
  }, PLATFORM_REFRESH_DELAY_MS);
}

function refreshMonitors() {
  if (!state.monitorsInitialized || state.destroyed) {
    return;
  }

  /*
   * Prefer optional refresh APIs if available. The monitor modules are
   * intentionally designed so initialization is generally sufficient,
   * but this defensive path allows SPA DOM replacement to be handled.
   */
  tryOptionalRefresh("input");
  tryOptionalRefresh("paste");
  tryOptionalRefresh("drop");
  tryOptionalRefresh("upload");
  tryOptionalRefresh("submit");
}

function tryOptionalRefresh(type) {
  /*
   * No hard dependency on refresh functions is created here because
   * monitor implementations may use MutationObservers internally.
   *
   * This function intentionally remains a no-op for monitors without
   * an exported refresh API.
   */
  void type;
}

function safeReportPlatform() {
  try {
    if (!state.detection) {
      return;
    }

    reportPlatformToBackground();
  } catch (error) {
    safeLog("debug", "Platform reporting unavailable.", error);
  }
}

function safeReportContentReady() {
  try {
    reportContentReady();
  } catch (error) {
    safeLog("debug", "Content-ready reporting unavailable.", error);
  }
}

/* -------------------------------------------------------------------------- */
/* Input monitoring                                                           */
/* -------------------------------------------------------------------------- */

function handleInputActivity(context) {
  if (state.destroyed) {
    return;
  }

  /*
   * Intentionally do not scan raw input activity.
   *
   * We retain only local, non-persistent state describing that activity
   * occurred. Actual scanning happens at transfer boundaries.
   */
  state.lastOperation = {
    type: "input",
    timestamp: Date.now(),
  };

  void context;
}

function handleActionDetected(actionContext) {
  if (state.destroyed) {
    return;
  }

  /*
   * A button click alone does not contain trustworthy content.
   * Submit/send/search monitors are responsible for obtaining the relevant
   * data and invoking their local callbacks.
   */
  queueSafeEvent(
    EVENT_TYPES.SEND_DETECTED,
    createSafeContext({
      sourceType:
        actionContext?.sourceType ??
        SOURCE_TYPES.SEND,
    }),
  );
}

/* -------------------------------------------------------------------------- */
/* Paste                                                                     */
/* -------------------------------------------------------------------------- */

async function handlePaste(pastePayload) {
  if (state.destroyed) {
    return createBlockResultForOperation(
      SOURCE_TYPES.PASTE,
      "Extension is shutting down.",
    );
  }

  state.stats.pasteEvents += 1;

  const text = extractTextPayload(pastePayload);

  if (!text) {
    return createAllowResultForOperation(
      SOURCE_TYPES.PASTE,
      "No text content available for scanning.",
    );
  }

  const context = buildOperationContext(
    SOURCE_TYPES.PASTE,
    pastePayload,
  );

  return executeTextProtection(text, context);
}

/* -------------------------------------------------------------------------- */
/* Drop                                                                      */
/* -------------------------------------------------------------------------- */

async function handleDrop(dropPayload) {
  if (state.destroyed) {
    return createBlockResultForOperation(
      SOURCE_TYPES.DROP,
      "Extension is shutting down.",
    );
  }

  state.stats.dropEvents += 1;

  const context = buildOperationContext(
    SOURCE_TYPES.DROP,
    dropPayload,
  );

  /*
   * Drop monitors may provide text directly or one or more File objects.
   * Files are scanned locally. No File object is forwarded to the service
   * worker.
   */
  if (typeof dropPayload === "string") {
    return executeTextProtection(
      dropPayload,
      context,
    );
  }

  const text = extractTextPayload(dropPayload);

  if (text) {
    return executeTextProtection(text, context);
  }

  const file = extractFilePayload(dropPayload);

  if (file) {
    return executeFileProtection(file, context);
  }

  return createAllowResultForOperation(
    SOURCE_TYPES.DROP,
    "No supported text or file content was available.",
  );
}

/* -------------------------------------------------------------------------- */
/* Upload                                                                     */
/* -------------------------------------------------------------------------- */

async function handleUpload(uploadPayload) {
  if (state.destroyed) {
    return createBlockResultForOperation(
      SOURCE_TYPES.UPLOAD,
      "Extension is shutting down.",
    );
  }

  state.stats.uploadEvents += 1;

  const context = buildOperationContext(
    SOURCE_TYPES.UPLOAD,
    uploadPayload,
  );

  const file = extractFilePayload(uploadPayload);

  if (!file) {
    const text = extractTextPayload(uploadPayload);

    if (text) {
      return executeTextProtection(text, context);
    }

    /*
     * Unsupported upload content should not be silently treated as
     * sensitive content. The upload monitor remains responsible for
     * file-type filtering and size limits.
     */
    return createAllowResultForOperation(
      SOURCE_TYPES.UPLOAD,
      "No supported local file or text payload was available.",
    );
  }

  return executeFileProtection(file, context);
}

/* -------------------------------------------------------------------------- */
/* Submit                                                                     */
/* -------------------------------------------------------------------------- */

async function handleSubmit(submitSnapshot) {
  if (state.destroyed) {
    return createBlockResultForOperation(
      SOURCE_TYPES.SUBMIT,
      "Extension is shutting down.",
    );
  }

  state.stats.submitEvents += 1;

  const context = buildOperationContext(
    SOURCE_TYPES.SUBMIT,
    submitSnapshot,
  );

  const text = extractSubmitText(submitSnapshot);

  if (!text) {
    /*
     * Empty forms do not contain data that needs scanning.
     */
    return createAllowResultForOperation(
      SOURCE_TYPES.SUBMIT,
      "No text content available for scanning.",
    );
  }

  return executeTextProtection(
    text,
    context,
    {
      submitSnapshot,
    },
  );
}

/* -------------------------------------------------------------------------- */
/* Core protection pipeline                                                   */
/* -------------------------------------------------------------------------- */

async function executeTextProtection(
  text,
  context,
  options = {},
) {
  if (state.destroyed) {
    return createBlockResultForOperation(
      context.sourceType,
      "Extension is shutting down.",
    );
  }

  if (typeof text !== "string") {
    return createBlockResultForOperation(
      context.sourceType,
      "Invalid text payload.",
    );
  }

  if (text.length === 0) {
    return createAllowResultForOperation(
      context.sourceType,
      "Empty text.",
    );
  }

  const operationId = createOperationId();

  state.lastOperation = {
    id: operationId,
    sourceType: context.sourceType,
    startedAt: Date.now(),
  };

  queueSafeEvent(
    EVENT_TYPES.SCAN_STARTED,
    createSafeContext(context),
  );

  state.stats.scans += 1;

  let scanResult;

  try {
    scanResult = await runWithTimeout(
      Promise.resolve(
        scanText(text, {
          sourceType: context.sourceType,
          platform: state.platform,
          config: state.config,
        }),
      ),
      OPERATION_TIMEOUT_MS,
      ERROR_CODES.SCAN_TIMEOUT,
    );
  } catch (error) {
    state.stats.failed += 1;

    queueSafeEvent(
      EVENT_TYPES.SCAN_FAILED,
      createSafeContext({
        ...context,
        errorCode:
          error?.code ??
          ERROR_CODES.SCAN_FAILED,
      }),
    );

    return createScanFailureBlockResult({
      sourceType: context.sourceType,
      reason:
        "SanitizerPro could not safely complete the local scan.",
      reasonCode:
        error?.code ??
        ERROR_CODES.SCAN_FAILED,
    });
  }

  queueSafeEvent(
    EVENT_TYPES.SCAN_COMPLETED,
    createSafeScanContext(
      context,
      scanResult,
    ),
  );

  let policyResult;

  try {
    policyResult = evaluatePolicy(
      scanResult,
      {
        sourceType: context.sourceType,
        platform: state.platform,
        platformId: state.platform?.id,
        url: safePageUrl(),
        operationId,
      },
      {
        config: state.config,
      },
    );
  } catch (error) {
    state.stats.failed += 1;

    queueSafeEvent(
      EVENT_TYPES.ERROR,
      createSafeContext({
        ...context,
        errorCode: ERROR_CODES.POLICY_FAILED,
      }),
    );

    return createPolicyFailureBlockResult({
      sourceType: context.sourceType,
      reason:
        "SanitizerPro could not safely evaluate the protection policy.",
    });
  }

  queueSafeEvent(
    EVENT_TYPES.POLICY_EVALUATED,
    createSafePolicyContext(
      context,
      policyResult,
    ),
  );

  return resolvePolicyAction(
    text,
    scanResult,
    policyResult,
    context,
    options,
  );
}

/* -------------------------------------------------------------------------- */
/* File protection                                                            */
/* -------------------------------------------------------------------------- */

async function executeFileProtection(file, context) {
  if (!file || typeof file !== "object") {
    return createAllowResultForOperation(
      context.sourceType,
      "No file available for scanning.",
    );
  }

  let scanResult;

  queueSafeEvent(
    EVENT_TYPES.SCAN_STARTED,
    createSafeContext(context),
  );

  state.stats.scans += 1;

  try {
    scanResult = await runWithTimeout(
      Promise.resolve(
        scanFile(file, {
          sourceType: context.sourceType,
          platform: state.platform,
          config: state.config,
        }),
      ),
      OPERATION_TIMEOUT_MS,
      ERROR_CODES.SCAN_TIMEOUT,
    );
  } catch (error) {
    state.stats.failed += 1;

    queueSafeEvent(
      EVENT_TYPES.SCAN_FAILED,
      createSafeContext({
        ...context,
        errorCode:
          error?.code ??
          ERROR_CODES.SCAN_FAILED,
      }),
    );

    /*
     * For a security-sensitive file upload, failure to inspect the file
     * must not silently permit potentially sensitive content.
     */
    return createScanFailureBlockResult({
      sourceType: context.sourceType,
      reason:
        "SanitizerPro could not safely inspect the uploaded file.",
      reasonCode:
        error?.code ??
        ERROR_CODES.SCAN_FAILED,
    });
  }

  queueSafeEvent(
    EVENT_TYPES.SCAN_COMPLETED,
    createSafeScanContext(
      context,
      scanResult,
    ),
  );

  let policyResult;

  try {
    policyResult = evaluatePolicy(
      scanResult,
      {
        sourceType: context.sourceType,
        platform: state.platform,
        platformId: state.platform?.id,
        url: safePageUrl(),
      },
      {
        config: state.config,
      },
    );
  } catch {
    state.stats.failed += 1;

    return createPolicyFailureBlockResult({
      sourceType: context.sourceType,
      reason:
        "SanitizerPro could not safely evaluate the file protection policy.",
    });
  }

  return resolvePolicyAction(
    null,
    scanResult,
    policyResult,
    context,
    {
      file,
    },
  );
}

/* -------------------------------------------------------------------------- */
/* Policy resolution                                                          */
/* -------------------------------------------------------------------------- */

async function resolvePolicyAction(
  originalText,
  scanResult,
  policyResult,
  context,
  options = {},
) {
  const action = normalizeAction(
    policyResult?.action,
  );

  if (state.protectionMode === PROTECTION_MODES.DISABLED) {
    return createAllowResultForOperation(
      context.sourceType,
      "Protection is disabled.",
    );
  }

  if (
    state.protectionMode === PROTECTION_MODES.MONITOR
  ) {
    const result = applyAllow(
      originalText,
      {
        sourceType: context.sourceType,
        reason:
          "Monitor mode records the decision without enforcing it.",
      },
    );

    state.stats.allowed += 1;

    queueSafeEvent(
      EVENT_TYPES.ACTION_ALLOWED,
      createSafeActionContext(
        context,
        scanResult,
        policyResult,
        ACTIONS.ALLOW,
      ),
    );

    return result;
  }

  switch (action) {
    case ACTIONS.ALLOW:
      return handleAllowAction(
        originalText,
        context,
        scanResult,
        policyResult,
      );

    case ACTIONS.WARN:
      return handleWarnAction(
        originalText,
        context,
        scanResult,
        policyResult,
        options,
      );

    case ACTIONS.MASK:
      return handleMaskAction(
        originalText,
        context,
        scanResult,
        policyResult,
        options,
      );

    case ACTIONS.BLOCK:
      return handleBlockAction(
        context,
        scanResult,
        policyResult,
      );

    default:
      /*
       * Unknown actions are treated as BLOCK.
       * This is intentionally fail-closed.
       */
      return handleBlockAction(
        context,
        scanResult,
        {
          ...policyResult,
          action: ACTIONS.BLOCK,
          reason:
            "Unknown policy action. Operation blocked for safety.",
        },
      );
  }
}

function handleAllowAction(
  text,
  context,
  scanResult,
  policyResult,
) {
  const result = applyAllow(
    text,
    {
      sourceType: context.sourceType,
      reason:
        policyResult?.reason ??
        "Content allowed by policy.",
    },
  );

  state.stats.allowed += 1;

  queueSafeEvent(
    EVENT_TYPES.ACTION_ALLOWED,
    createSafeActionContext(
      context,
      scanResult,
      policyResult,
      ACTIONS.ALLOW,
    ),
  );

  return result;
}

async function handleWarnAction(
  text,
  context,
  scanResult,
  policyResult,
  options,
) {
  state.stats.warned += 1;

  const warning = createWarnResult({
    sourceType: context.sourceType,
    reason:
      policyResult?.reason ??
      "Potentially sensitive information detected.",
    risk:
      policyResult?.risk ??
      scanResult?.risk,
    findingCount:
      getFindingCount(scanResult),
    operationId:
      options?.operationId,
  });

  queueSafeEvent(
    EVENT_TYPES.ACTION_WARNED,
    createSafeActionContext(
      context,
      scanResult,
      policyResult,
      ACTIONS.WARN,
    ),
  );

  const resolution = await showWarning(
    warning,
    scanResult,
    context,
  );

  const normalizedResolution = normalizeAction(
    resolution?.action ??
    resolution ??
    ACTIONS.BLOCK,
  );

  if (
    normalizedResolution === ACTIONS.ALLOW
  ) {
    const result = resolveWarning(
      warning,
      ACTIONS.ALLOW,
    );

    state.stats.allowed += 1;

    queueSafeEvent(
      EVENT_TYPES.ACTION_ALLOWED,
      createSafeActionContext(
        context,
        scanResult,
        policyResult,
        ACTIONS.ALLOW,
      ),
    );

    return {
      ...result,
      content: text,
      contentModified: false,
    };
  }

  if (
    normalizedResolution === ACTIONS.MASK
  ) {
    return handleMaskAction(
      text,
      context,
      scanResult,
      policyResult,
      {
        ...options,
        warningResolution: true,
      },
    );
  }

  const blocked = resolveWarning(
    warning,
    ACTIONS.BLOCK,
  );

  state.stats.blocked += 1;

  queueSafeEvent(
    EVENT_TYPES.ACTION_BLOCKED,
    createSafeActionContext(
      context,
      scanResult,
      policyResult,
      ACTIONS.BLOCK,
    ),
  );

  return blocked;
}

function handleMaskAction(
  text,
  context,
  scanResult,
  policyResult,
  options,
) {
  if (
    typeof text !== "string"
  ) {
    /*
     * File masking cannot safely be performed by the generic text masker.
     * Block rather than pretend that the file was sanitized.
     */
    return handleBlockAction(
      context,
      scanResult,
      {
        ...policyResult,
        action: ACTIONS.BLOCK,
        reason:
          "The detected file content cannot be safely masked.",
      },
    );
  }

  try {
    const result = applyMask(
      text,
      scanResult,
      {
        sourceType: context.sourceType,
        config: state.config,
        reason:
          policyResult?.reason ??
          "Sensitive content was masked before transmission.",
      },
    );

    if (
      !result ||
      typeof result.maskedText !== "string"
    ) {
      throw createNamedError(
        "Masking failed.",
        ERROR_CODES.POLICY_FAILED,
      );
    }

    state.stats.masked += 1;

    queueSafeEvent(
      EVENT_TYPES.ACTION_MASKED,
      createSafeActionContext(
        context,
        scanResult,
        policyResult,
        ACTIONS.MASK,
      ),
    );

    return result;
  } catch (error) {
    state.stats.failed += 1;

    /*
     * Never send the original content after a failed mask operation.
     */
    return createBlockResultForOperation(
      context.sourceType,
      "SanitizerPro could not safely mask the detected content.",
      error?.code ??
        ERROR_CODES.POLICY_FAILED,
    );
  }
}

function handleBlockAction(
  context,
  scanResult,
  policyResult,
) {
  state.stats.blocked += 1;

  const result = applyBlock({
    sourceType: context.sourceType,
    reason:
      policyResult?.reason ??
      "Sensitive information was blocked.",
    reasonCode:
      policyResult?.reasonCode ??
      "SENSITIVE_DATA_DETECTED",
    risk:
      policyResult?.risk ??
      scanResult?.risk,
  });

  queueSafeEvent(
    EVENT_TYPES.ACTION_BLOCKED,
    createSafeActionContext(
      context,
      scanResult,
      policyResult,
      ACTIONS.BLOCK,
    ),
  );

  return result;
}

/* -------------------------------------------------------------------------- */
/* Warning UI                                                                 */
/* -------------------------------------------------------------------------- */

function showWarning(
  warning,
  scanResult,
  context,
) {
  return new Promise((resolve) => {
    if (state.destroyed) {
      resolve(ACTIONS.BLOCK);
      return;
    }

    removeWarningDialog();

    const overlay = document.createElement("div");
    const dialog = document.createElement("div");

    overlay.setAttribute(
      "data-sanitizerpro-ui",
      "warning",
    );

    overlay.style.cssText = [
      "position:fixed",
      "inset:0",
      "z-index:2147483647",
      "display:flex",
      "align-items:center",
      "justify-content:center",
      "padding:20px",
      "background:rgba(0,0,0,.48)",
      "font-family:Arial,sans-serif",
      "box-sizing:border-box",
    ].join(";");

    dialog.setAttribute(
      "role",
      "dialog",
    );

    dialog.setAttribute(
      "aria-modal",
      "true",
    );

    dialog.setAttribute(
      "aria-labelledby",
      "sanitizerpro-warning-title",
    );

    dialog.style.cssText = [
      "width:min(520px,100%)",
      "max-height:calc(100vh - 40px)",
      "overflow:auto",
      "background:#fff",
      "color:#111827",
      "border-radius:12px",
      "box-shadow:0 20px 60px rgba(0,0,0,.3)",
      "padding:24px",
      "box-sizing:border-box",
    ].join(";");

    const title = document.createElement("h2");
    title.id = "sanitizerpro-warning-title";
    title.textContent = "SanitizerPro warning";
    title.style.cssText = [
      "margin:0 0 10px",
      "font-size:20px",
      "line-height:1.3",
    ].join(";");

    const message = document.createElement("p");
    message.textContent =
      "SanitizerPro detected potentially sensitive information before it can be sent.";
    message.style.cssText = [
      "margin:0 0 16px",
      "font-size:14px",
      "line-height:1.5",
    ].join(";");

    const summary = document.createElement("div");
    summary.style.cssText = [
      "padding:12px",
      "margin-bottom:18px",
      "background:#f3f4f6",
      "border-radius:8px",
      "font-size:13px",
      "line-height:1.5",
    ].join(";");

    const findingCount = getFindingCount(
      scanResult,
    );

    const riskLevel =
      scanResult?.risk?.level ??
      scanResult?.risk?.label ??
      "unknown";

    const platformName =
      state.platform?.name ??
      "this website";

    summary.textContent =
      `${findingCount} potential sensitive finding${findingCount === 1 ? "" : "s"} detected. ` +
      `Risk: ${String(riskLevel)}. ` +
      `Destination: ${platformName}.`;

    const buttonRow = document.createElement("div");

    buttonRow.style.cssText = [
      "display:flex",
      "flex-wrap:wrap",
      "gap:8px",
      "justify-content:flex-end",
    ].join(";");

    const maskButton = createUiButton(
      "Mask and continue",
      "primary",
    );

    const allowButton = createUiButton(
      "Allow once",
      "secondary",
    );

    const blockButton = createUiButton(
      "Block",
      "danger",
    );

    buttonRow.append(
      blockButton,
      allowButton,
      maskButton,
    );

    dialog.append(
      title,
      message,
      summary,
      buttonRow,
    );

    overlay.append(dialog);

    document.documentElement.append(
      overlay,
    );

    state.warningDialog = overlay;
    state.warningResolver = resolve;

    const cleanupAndResolve = (action) => {
      removeWarningDialog();
      resolve(action);
    };

    blockButton.addEventListener(
      "click",
      () => cleanupAndResolve(ACTIONS.BLOCK),
    );

    allowButton.addEventListener(
      "click",
      () => cleanupAndResolve(ACTIONS.ALLOW),
    );

    maskButton.addEventListener(
      "click",
      () => cleanupAndResolve(ACTIONS.MASK),
    );

    overlay.addEventListener(
      "click",
      (event) => {
        if (event.target === overlay) {
          cleanupAndResolve(ACTIONS.BLOCK);
        }
      },
    );

    const keyHandler = (event) => {
      if (event.key === "Escape") {
        cleanupAndResolve(ACTIONS.BLOCK);
      }
    };

    document.addEventListener(
      "keydown",
      keyHandler,
      true,
    );

    const originalResolver = state.warningResolver;

    state.warningResolver = (action) => {
      document.removeEventListener(
        "keydown",
        keyHandler,
        true,
      );

      originalResolver(action);
    };

    setTimeout(() => {
      if (
        state.warningDialog === overlay
      ) {
        document.removeEventListener(
          "keydown",
          keyHandler,
          true,
        );

        removeWarningDialog();
        resolve(ACTIONS.BLOCK);
      }
    }, WARNING_TIMEOUT_MS);

    void context;
  });
}

function createUiButton(
  label,
  type,
) {
  const button =
    document.createElement("button");

  button.type = "button";
  button.textContent = label;

  const baseStyle = [
    "border:0",
    "border-radius:7px",
    "padding:10px 14px",
    "font-size:13px",
    "font-weight:600",
    "cursor:pointer",
    "font-family:Arial,sans-serif",
  ];

  if (type === "danger") {
    baseStyle.push(
      "background:#b91c1c",
      "color:#fff",
    );
  } else if (type === "primary") {
    baseStyle.push(
      "background:#111827",
      "color:#fff",
    );
  } else {
    baseStyle.push(
      "background:#e5e7eb",
      "color:#111827",
    );
  }

  button.style.cssText =
    baseStyle.join(";");

  return button;
}

function removeWarningDialog() {
  const dialog = state.warningDialog;

  if (dialog?.parentNode) {
    dialog.parentNode.removeChild(
      dialog,
    );
  }

  state.warningDialog = null;

  if (state.warningResolver) {
    const resolver =
      state.warningResolver;

    state.warningResolver = null;

    try {
      resolver(ACTIONS.BLOCK);
    } catch {
      // Ignore resolver cleanup errors.
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Lifecycle                                                                  */
/* -------------------------------------------------------------------------- */

function bindLifecycleEvents() {
  if (state.bound.pageShow) {
    return;
  }

  state.bound.pageShow = () => {
    if (!state.destroyed) {
      schedulePlatformRefresh();
    }
  };

  state.bound.visibilityChange = () => {
    if (
      !state.destroyed &&
      document.visibilityState === "visible"
    ) {
      schedulePlatformRefresh();
    }
  };

  window.addEventListener(
    "pageshow",
    state.bound.pageShow,
    true,
  );

  document.addEventListener(
    "visibilitychange",
    state.bound.visibilityChange,
    true,
  );
}

function destroy() {
  if (state.destroyed) {
    return;
  }

  state.destroyed = true;
  state.initialized = false;

  if (state.routeRefreshTimer !== null) {
    clearTimeout(
      state.routeRefreshTimer,
    );

    state.routeRefreshTimer = null;
  }

  removeWarningDialog();

  if (state.bound.pageShow) {
    window.removeEventListener(
      "pageshow",
      state.bound.pageShow,
      true,
    );
  }

  if (state.bound.visibilityChange) {
    document.removeEventListener(
      "visibilitychange",
      state.bound.visibilityChange,
      true,
    );
  }

  state.bound.pageShow = null;
  state.bound.visibilityChange = null;

  destroyMonitors();

  try {
    destroyPlatformDetector();
  } catch (error) {
    safeLog(
      "debug",
      "Platform detector cleanup failed.",
      error,
    );
  }

  try {
    destroyScanner();
  } catch (error) {
    safeLog(
      "debug",
      "Scanner cleanup failed.",
      error,
    );
  }

  try {
    destroyPolicyEngine();
  } catch (error) {
    safeLog(
      "debug",
      "Policy engine cleanup failed.",
      error,
    );
  }

  flushSafeEvents();

  state.platform = null;
  state.detection = null;
}

function destroyMonitors() {
  try {
    destroyInputMonitor();
  } catch (error) {
    safeLog(
      "debug",
      "Input monitor cleanup failed.",
      error,
    );
  }

  try {
    destroyPasteMonitor();
  } catch (error) {
    safeLog(
      "debug",
      "Paste monitor cleanup failed.",
      error,
    );
  }

  try {
    destroyDropMonitor();
  } catch (error) {
    safeLog(
      "debug",
      "Drop monitor cleanup failed.",
      error,
    );
  }

  try {
    destroyUploadMonitor();
  } catch (error) {
    safeLog(
      "debug",
      "Upload monitor cleanup failed.",
      error,
    );
  }

  try {
    destroySubmitMonitor();
  } catch (error) {
    safeLog(
      "debug",
      "Submit monitor cleanup failed.",
      error,
    );
  }

  state.monitorsInitialized = false;
}

/* -------------------------------------------------------------------------- */
/* Safe runtime messaging                                                     */
/* -------------------------------------------------------------------------- */

async function sendRuntimeRequest(
  type,
  payload,
  options = {},
) {
  if (
    typeof chrome === "undefined" ||
    !chrome.runtime ||
    typeof chrome.runtime.sendMessage !== "function"
  ) {
    throw createNamedError(
      "Runtime messaging unavailable.",
      ERROR_CODES.INTERNAL_ERROR,
    );
  }

  const message = createMessage(
    type,
    payload ?? {},
  );

  const timeoutMs =
    Number.isFinite(options.timeoutMs)
      ? options.timeoutMs
      : OPERATION_TIMEOUT_MS;

  const request = Promise.resolve(
    chrome.runtime.sendMessage(
      message,
    ),
  );

  return runWithTimeout(
    request,
    timeoutMs,
    ERROR_CODES.REQUEST_TIMEOUT,
  );
}

function queueSafeEvent(
  eventType,
  context = {},
) {
  if (state.destroyed) {
    return;
  }

  const event = createSafeEvent(
    eventType,
    context,
  );

  if (!event) {
    return;
  }

  state.eventQueue.push(event);

  if (state.eventQueue.length > 50) {
    state.eventQueue.splice(
      0,
      state.eventQueue.length - 50,
    );
  }

  scheduleEventFlush();
}

function createSafeEvent(
  eventType,
  context,
) {
  try {
    return createEvent(
      eventType,
      sanitizeEventContext(context),
    );
  } catch (error) {
    safeLog(
      "debug",
      "Unable to create safe event.",
      error,
    );

    return null;
  }
}

function scheduleEventFlush() {
  if (state.eventFlushTimer !== null) {
    return;
  }

  state.eventFlushTimer = setTimeout(
    flushSafeEvents,
    250,
  );
}

async function flushSafeEvents() {
  if (state.eventFlushTimer !== null) {
    clearTimeout(
      state.eventFlushTimer,
    );

    state.eventFlushTimer = null;
  }

  if (
    state.eventQueue.length === 0 ||
    state.destroyed
  ) {
    return;
  }

  const events =
    state.eventQueue.splice(
      0,
      20,
    );

  /*
   * Only event metadata is sent.
   *
   * The sanitizer never puts:
   * - raw text
   * - matched values
   * - clipboard contents
   * - file contents
   * - form values
   * into these messages.
   */
  for (const event of events) {
    try {
      await sendRuntimeRequest(
        MESSAGE_TYPES.REPORT_EVENT,
        event,
        {
          timeoutMs: 1500,
          allowFailure: true,
        },
      );
    } catch {
      /*
       * Event reporting is non-critical.
       *
       * Protection must continue even if the service worker is asleep,
       * unavailable, restarted, or the extension context is being torn down.
       */
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Safe context generation                                                    */
/* -------------------------------------------------------------------------- */

function buildOperationContext(
  sourceType,
  payload,
) {
  return {
    ...DEFAULT_CONTEXT,
    sourceType,
    platformId:
      state.platform?.id ??
      null,
    platformCategory:
      state.platform?.category ??
      null,
    isAI:
      isCurrentAIPlatform(),
    isSearch:
      isCurrentSearchPlatform(),
    pageOrigin:
      safePageOrigin(),
    payloadType:
      detectPayloadType(payload),
  };
}

function createSafeContext(
  context = {},
) {
  return {
    sourceType:
      normalizeSourceType(
        context.sourceType,
      ),
    platformId:
      safeString(
        context.platformId,
        100,
      ),
    platformCategory:
      safeString(
        context.platformCategory,
        100,
      ),
    isAI:
      context.isAI === true,
    isSearch:
      context.isSearch === true,
  };
}

function createSafeScanContext(
  context,
  scanResult,
) {
  return {
    ...createSafeContext(context),
    findingCount:
      getFindingCount(scanResult),
    riskLevel:
      safeString(
        scanResult?.risk?.level ??
        scanResult?.risk?.label,
        50,
      ),
    riskScore:
      safeNumericScore(
        scanResult?.risk?.score,
      ),
    truncated:
      scanResult?.truncated === true,
  };
}

function createSafePolicyContext(
  context,
  policyResult,
) {
  return {
    ...createSafeContext(context),
    action:
      normalizeAction(
        policyResult?.action,
      ),
    riskLevel:
      safeString(
        policyResult?.risk?.level ??
        policyResult?.riskLevel,
        50,
      ),
  };
}

function createSafeActionContext(
  context,
  scanResult,
  policyResult,
  action,
) {
  return {
    ...createSafeContext(context),
    action,
    findingCount:
      getFindingCount(scanResult),
    riskLevel:
      safeString(
        scanResult?.risk?.level ??
        scanResult?.risk?.label ??
        policyResult?.risk?.level,
        50,
      ),
    riskScore:
      safeNumericScore(
        scanResult?.risk?.score ??
        policyResult?.risk?.score,
      ),
  };
}

function sanitizeEventContext(
  context,
) {
  const safe = {
    sourceType:
      normalizeSourceType(
        context?.sourceType,
      ),
  };

  const allowedKeys = [
    "platformId",
    "platformCategory",
    "isAI",
    "isSearch",
    "action",
    "findingCount",
    "riskLevel",
    "riskScore",
    "truncated",
    "errorCode",
  ];

  for (const key of allowedKeys) {
    if (!(key in context)) {
      continue;
    }

    const value = context[key];

    if (
      typeof value === "string"
    ) {
      safe[key] = safeString(
        value,
        150,
      );
    } else if (
      typeof value === "number" &&
      Number.isFinite(value)
    ) {
      safe[key] = value;
    } else if (
      typeof value === "boolean"
    ) {
      safe[key] = value;
    }
  }

  return safe;
}

/* -------------------------------------------------------------------------- */
/* Payload extraction                                                         */
/* -------------------------------------------------------------------------- */

function extractTextPayload(payload) {
  if (typeof payload === "string") {
    return payload;
  }

  if (!payload || typeof payload !== "object") {
    return "";
  }

  const candidates = [
    payload.text,
    payload.textContent,
    payload.content,
    payload.value,
    payload.plainText,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === "string") {
      return candidate;
    }
  }

  return "";
}

function extractFilePayload(payload) {
  if (!payload || typeof payload !== "object") {
    return null;
  }

  if (
    typeof File !== "undefined" &&
    payload instanceof File
  ) {
    return payload;
  }

  if (
    payload.file &&
    typeof File !== "undefined" &&
    payload.file instanceof File
  ) {
    return payload.file;
  }

  if (
    Array.isArray(payload.files) &&
    payload.files.length > 0
  ) {
    const file = payload.files[0];

    if (
      typeof File !== "undefined" &&
      file instanceof File
    ) {
      return file;
    }
  }

  return null;
}

function extractSubmitText(
  snapshot,
) {
  if (
    typeof snapshot === "string"
  ) {
    return snapshot;
  }

  if (!snapshot || typeof snapshot !== "object") {
    return "";
  }

  if (
    typeof snapshot.text === "string"
  ) {
    return snapshot.text;
  }

  if (
    typeof snapshot.combinedText === "string"
  ) {
    return snapshot.combinedText;
  }

  if (
    typeof snapshot.content === "string"
  ) {
    return snapshot.content;
  }

  if (
    Array.isArray(snapshot.fields)
  ) {
    return snapshot.fields
      .map((field) => {
        if (
          !field ||
          typeof field !== "object"
        ) {
          return "";
        }

        if (
          typeof field.value === "string"
        ) {
          return field.value;
        }

        if (
          typeof field.text === "string"
        ) {
          return field.text;
        }

        return "";
      })
      .filter(Boolean)
      .join("\n");
  }

  return "";
}

function detectPayloadType(payload) {
  if (typeof payload === "string") {
    return "text";
  }

  if (extractFilePayload(payload)) {
    return "file";
  }

  if (
    payload &&
    typeof payload === "object"
  ) {
    return "object";
  }

  return "unknown";
}

/* -------------------------------------------------------------------------- */
/* Operation result helpers                                                   */
/* -------------------------------------------------------------------------- */

function createAllowResultForOperation(
  sourceType,
  reason,
) {
  return applyAllow(
    undefined,
    {
      sourceType,
      reason,
    },
  );
}

function createBlockResultForOperation(
  sourceType,
  reason,
  reasonCode = "CONTENT_OPERATION_BLOCKED",
) {
  state.stats.blocked += 1;

  return applyBlock({
    sourceType,
    reason,
    reasonCode,
  });
}

function normalizeAction(
  action,
) {
  if (
    typeof action !== "string"
  ) {
    return ACTIONS.BLOCK;
  }

  const normalized =
    action.trim().toUpperCase();

  for (const value of Object.values(
    ACTIONS,
  )) {
    if (
      String(value).toUpperCase() ===
      normalized
    ) {
      return value;
    }
  }

  return ACTIONS.BLOCK;
}

function normalizeSourceType(
  sourceType,
) {
  if (
    typeof sourceType !== "string"
  ) {
    return SOURCE_TYPES.UNKNOWN;
  }

  const normalized =
    sourceType.trim().toLowerCase();

  for (const value of Object.values(
    SOURCE_TYPES,
  )) {
    if (
      String(value).toLowerCase() ===
      normalized
    ) {
      return value;
    }
  }

  return SOURCE_TYPES.UNKNOWN;
}

/* -------------------------------------------------------------------------- */
/* Diagnostics and status                                                     */
/* -------------------------------------------------------------------------- */

function getContentStatus() {
  return {
    initialized:
      state.initialized,
    initializing:
      state.initializing,
    destroyed:
      state.destroyed,
    version:
      CONTENT_VERSION,
    protectionMode:
      state.protectionMode,
    platform:
      sanitizePlatformForDiagnostics(
        state.platform,
      ),
    detection:
      sanitizeDetectionForDiagnostics(
        state.detection,
      ),
    monitorsInitialized:
      state.monitorsInitialized,
    stats: {
      ...state.stats,
    },
  };
}

function getContentDiagnostics() {
  return {
    ...getContentStatus(),

    detector:
      safeDiagnostics(
        getDetectorDiagnostics,
      ),

    input:
      safeDiagnostics(
        getInputMonitorDiagnostics,
      ),

    paste:
      safeDiagnostics(
        getPasteMonitorDiagnostics,
      ),

    drop:
      safeDiagnostics(
        getDropMonitorDiagnostics,
      ),

    upload:
      safeDiagnostics(
        getUploadMonitorDiagnostics,
      ),

    submit:
      safeDiagnostics(
        getSubmitMonitorDiagnostics,
      ),

    scanner:
      safeDiagnostics(
        getScannerDiagnostics,
      ),

    policy:
      safeDiagnostics(
        getPolicySummary,
      ),

    inputContext:
      safeInputContext(),

    page: {
      origin:
        safePageOrigin(),
      isAI:
        isCurrentAIPlatform(),
      isSearch:
        isCurrentSearchPlatform(),
    },
  };
}

function safeDiagnostics(
  getter,
) {
  try {
    if (
      typeof getter !== "function"
    ) {
      return null;
    }

    return sanitizeDiagnostics(
      getter(),
    );
  } catch {
    return null;
  }
}

function safeInputContext() {
  try {
    if (
      typeof getCurrentInputContext !==
      "function"
    ) {
      return null;
    }

    return sanitizeDiagnostics(
      getCurrentInputContext(),
    );
  } catch {
    return null;
  }
}

function sanitizePlatformForDiagnostics(
  platform,
) {
  if (!platform) {
    return null;
  }

  return {
    id:
      safeString(
        platform.id,
        100,
      ),
    name:
      safeString(
        platform.name,
        150,
      ),
    category:
      safeString(
        platform.category,
        100,
      ),
  };
}

function sanitizeDetectionForDiagnostics(
  detection,
) {
  if (!detection) {
    return null;
  }

  return {
    detected:
      detection.detected === true,
    platform:
      sanitizePlatformForDiagnostics(
        detection.platform,
      ),
    generic:
      detection.generic === true,
    confidence:
      safeNumericScore(
        detection.confidence,
      ),
  };
}

function sanitizeDiagnostics(
  value,
) {
  if (
    value === undefined ||
    value === null
  ) {
    return value;
  }

  if (
    typeof value !== "object"
  ) {
    return value;
  }

  const result = {};

  for (const [
    key,
    item,
  ] of Object.entries(value)) {
    /*
     * Never expose arbitrary text-bearing diagnostic fields.
     */
    if (
      /text|content|value|prompt|clipboard|secret|token|password|filedata|raw|match/i.test(
        key,
      )
    ) {
      continue;
    }

    if (
      typeof item === "string"
    ) {
      result[key] =
        safeString(item, 200);
    } else if (
      typeof item === "number" ||
      typeof item === "boolean"
    ) {
      result[key] = item;
    } else if (
      Array.isArray(item)
    ) {
      result[key] =
        item.slice(0, 20).map(
          (entry) =>
            sanitizeDiagnostics(
              entry,
            ),
        );
    } else if (
      item &&
      typeof item === "object"
    ) {
      result[key] =
        sanitizeDiagnostics(item);
    }
  }

  return result;
}

/* -------------------------------------------------------------------------- */
/* Utility functions                                                          */
/* -------------------------------------------------------------------------- */

function getFindingCount(
  scanResult,
) {
  if (
    !scanResult ||
    typeof scanResult !== "object"
  ) {
    return 0;
  }

  if (
    Number.isFinite(
      scanResult.findingCount,
    )
  ) {
    return Math.max(
      0,
      scanResult.findingCount,
    );
  }

  if (
    Array.isArray(
      scanResult.findings,
    )
  ) {
    return scanResult.findings.length;
  }

  return 0;
}

function safePageOrigin() {
  try {
    return window.location.origin;
  } catch {
    return null;
  }
}

function safePageUrl() {
  try {
    /*
     * Only the origin is used for policy context.
     * Query strings and fragments are intentionally excluded because they
     * may contain search queries or other sensitive user data.
     */
    return window.location.origin;
  } catch {
    return null;
  }
}

function safeNumericScore(
  value,
) {
  if (
    !Number.isFinite(value)
  ) {
    return null;
  }

  return Math.max(
    0,
    Math.min(
      100,
      Number(value),
    ),
  );
}

function safeString(
  value,
  maxLength = 200,
) {
  if (
    typeof value !== "string"
  ) {
    return "";
  }

  return value
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .slice(0, maxLength);
}

function isPlainObject(
  value,
) {
  if (
    value === null ||
    typeof value !== "object"
  ) {
    return false;
  }

  const prototype =
    Object.getPrototypeOf(value);

  return (
    prototype === Object.prototype ||
    prototype === null
  );
}

function createOperationId() {
  state.operationCounter += 1;

  return [
    "sp",
    Date.now().toString(36),
    state.operationCounter.toString(36),
    Math.random()
      .toString(36)
      .slice(2, 8),
  ].join("-");
}

function createNamedError(
  message,
  code,
) {
  const error =
    new Error(message);

  error.code = code;

  return error;
}

function runWithTimeout(
  promise,
  timeoutMs,
  errorCode,
) {
  let timeoutId;

  const timeoutPromise =
    new Promise((_, reject) => {
      timeoutId = setTimeout(() => {
        reject(
          createNamedError(
            "Operation timed out.",
            errorCode,
          ),
        );
      }, timeoutMs);
    });

  return Promise.race([
    Promise.resolve(promise).finally(
      () => {
        if (timeoutId) {
          clearTimeout(timeoutId);
        }
      },
    ),
    timeoutPromise,
  ]);
}

/* -------------------------------------------------------------------------- */
/* Error handlers                                                             */
/* -------------------------------------------------------------------------- */

function handleDetectorError(
  error,
) {
  safeLog(
    "warn",
    "Platform detector error.",
    error,
  );

  queueSafeEvent(
    EVENT_TYPES.ERROR,
    {
      sourceType:
        SOURCE_TYPES.UNKNOWN,
      errorCode:
        ERROR_CODES.INTERNAL_ERROR,
    },
  );
}

function handleMonitorError(
  error,
) {
  safeLog(
    "warn",
    "Content monitor error.",
    error,
  );

  queueSafeEvent(
    EVENT_TYPES.ERROR,
    {
      sourceType:
        SOURCE_TYPES.UNKNOWN,
      errorCode:
        ERROR_CODES.INTERNAL_ERROR,
    },
  );
}

function safeLog(
  level,
  message,
  error,
) {
  /*
   * Never log raw page content, matched values, clipboard contents,
   * uploaded files, passwords, or secrets.
   */
  if (
    typeof console === "undefined"
  ) {
    return;
  }

  const safeError =
    error instanceof Error
      ? {
          name: error.name,
          code: error.code,
          message: safeString(
            error.message,
            300,
          ),
        }
      : undefined;

  try {
    if (
      level === "error" &&
      typeof console.error ===
        "function"
    ) {
      console.error(
        "[SanitizerPro]",
        message,
        safeError,
      );
    } else if (
      level === "warn" &&
      typeof console.warn ===
        "function"
    ) {
      console.warn(
        "[SanitizerPro]",
        message,
        safeError,
      );
    } else if (
      typeof console.debug ===
      "function"
    ) {
      console.debug(
        "[SanitizerPro]",
        message,
        safeError,
      );
    }
  } catch {
    // Ignore logging failures.
  }
}

/* -------------------------------------------------------------------------- */
/* Automatic startup                                                          */
/* -------------------------------------------------------------------------- */

if (
  typeof window !== "undefined" &&
  typeof document !== "undefined"
) {
  void initialize().catch(
    (error) => {
      safeLog(
        "error",
        "SanitizerPro failed to initialize.",
        error,
      );
    },
  );
}

/* -------------------------------------------------------------------------- */
/* Public content-script API                                                  */
/* -------------------------------------------------------------------------- */

export {
  initialize,
  destroy,
  getContentStatus,
  getContentDiagnostics,
  loadConfiguration,
  executeTextProtection,
  executeFileProtection,
  detectCurrentPlatform,
  getDetectionResult,
};
