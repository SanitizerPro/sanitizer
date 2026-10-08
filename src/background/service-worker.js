/**
 * SanitizerPro
 * Manifest V3 Service Worker
 *
 * Responsibilities:
 * - Initialize extension state.
 * - Persist non-sensitive configuration.
 * - Coordinate content scripts, popup, and options pages.
 * - Validate incoming protocol messages.
 * - Maintain lightweight runtime statistics.
 * - Never persist or log raw user content.
 *
 * Security model:
 * - Raw prompts remain in the content-script context.
 * - Raw clipboard contents remain in the content-script context.
 * - Uploaded file contents are never persisted here.
 * - Detected secret values are never persisted here.
 * - No remote scanning or telemetry is performed.
 */

import {
  cloneDefaultConfig,
  DEFAULT_CONFIG,
  validateConfig,
  PROTECTION_MODES,
} from "../config/defaults.js";

import {
  MESSAGE_TYPES,
  EVENT_TYPES,
  CONTEXT_TYPES,
  MESSAGE_STATUS,
  ERROR_CODES,
  PROTOCOL_VERSION,
  createSuccessResponse,
  createErrorResponse,
  isValidMessage,
  isKnownMessageType,
  isPlainObject,
  sanitizeForLog,
} from "../config/constants.js";

import {
  getPlatformByHostname,
  getPlatformByUrl,
  getPlatformSummary,
} from "../config/platforms.js";

/**
 * Storage keys.
 *
 * Keep storage keys centralized to avoid accidental collisions.
 */
const STORAGE_KEYS = Object.freeze({
  CONFIG: "sanitizerpro_config",
  STATS: "sanitizerpro_stats",
});

/**
 * Maximum runtime statistics retained.
 *
 * Statistics contain counters only.
 * They never contain user content.
 */
const DEFAULT_STATS = Object.freeze({
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
  searchEvents: 0,
  sendEvents: 0,

  startedAt: 0,
  updatedAt: 0,
});

/**
 * Runtime-only state.
 *
 * This state is intentionally small because MV3 service workers
 * can be terminated and restarted by Chrome.
 */
const runtimeState = {
  initialized: false,
  initializing: null,
  config: null,
  stats: null,
};

/**
 * Initialize the service worker.
 *
 * Event listeners are registered synchronously below.
 * Actual initialization is performed lazily and during startup events.
 */
async function initialize() {
  if (runtimeState.initialized) {
    return runtimeState;
  }

  if (runtimeState.initializing) {
    return runtimeState.initializing;
  }

  runtimeState.initializing = initializeInternal();

  try {
    await runtimeState.initializing;
    return runtimeState;
  } finally {
    runtimeState.initializing = null;
  }
}

/**
 * Internal initialization.
 */
async function initializeInternal() {
  const [storedConfig, storedStats] = await Promise.all([
    loadConfig(),
    loadStats(),
  ]);

  runtimeState.config = storedConfig;
  runtimeState.stats = storedStats;
  runtimeState.initialized = true;

  await touchStats();

  return runtimeState;
}

/**
 * Load configuration.
 */
async function loadConfig() {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.CONFIG);
    const stored = result?.[STORAGE_KEYS.CONFIG];

    if (!stored) {
      const defaults = cloneDefaultConfig();

      await chrome.storage.local.set({
        [STORAGE_KEYS.CONFIG]: defaults,
      });

      return defaults;
    }

    const validation = validateConfig(stored);

    if (!validation.valid) {
      console.warn(
        "SanitizerPro: invalid stored configuration. Restoring defaults.",
      );

      const defaults = cloneDefaultConfig();

      await chrome.storage.local.set({
        [STORAGE_KEYS.CONFIG]: defaults,
      });

      return defaults;
    }

    return mergeWithDefaults(stored);
  } catch (error) {
    console.error(
      "SanitizerPro: configuration initialization failed.",
      sanitizeForLog({
        error: error?.message || String(error),
      }),
    );

    return cloneDefaultConfig();
  }
}

/**
 * Load statistics.
 *
 * Only numeric counters are accepted.
 */
async function loadStats() {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.STATS);
    const stored = result?.[STORAGE_KEYS.STATS];

    if (!stored || !isPlainObject(stored)) {
      return createDefaultStats();
    }

    return normalizeStats(stored);
  } catch (error) {
    console.error(
      "SanitizerPro: statistics initialization failed.",
      sanitizeForLog({
        error: error?.message || String(error),
      }),
    );

    return createDefaultStats();
  }
}

/**
 * Merge stored configuration over current defaults.
 *
 * This allows future versions to add new configuration properties
 * without breaking existing installations.
 */
function mergeWithDefaults(stored) {
  const defaults = cloneDefaultConfig();

  return deepMerge(defaults, stored);
}

/**
 * Deep merge plain objects.
 */
function deepMerge(base, override) {
  if (!isPlainObject(base)) {
    return override;
  }

  if (!isPlainObject(override)) {
    return base;
  }

  const result = {
    ...base,
  };

  for (const [key, value] of Object.entries(override)) {
    if (
      isPlainObject(result[key]) &&
      isPlainObject(value)
    ) {
      result[key] = deepMerge(result[key], value);
    } else {
      result[key] = value;
    }
  }

  return result;
}

/**
 * Create a fresh statistics object.
 */
function createDefaultStats() {
  const now = Date.now();

  return {
    ...DEFAULT_STATS,
    startedAt: now,
    updatedAt: now,
  };
}

/**
 * Normalize statistics loaded from storage.
 *
 * Any unexpected value is discarded.
 */
function normalizeStats(value) {
  const defaults = createDefaultStats();

  const numericKeys = [
    "scans",
    "allowed",
    "warned",
    "masked",
    "blocked",
    "failed",

    "pasteEvents",
    "dropEvents",
    "uploadEvents",
    "submitEvents",
    "searchEvents",
    "sendEvents",

    "startedAt",
    "updatedAt",
  ];

  for (const key of numericKeys) {
    if (
      typeof value[key] === "number" &&
      Number.isFinite(value[key]) &&
      value[key] >= 0
    ) {
      defaults[key] = Math.floor(value[key]);
    }
  }

  return defaults;
}

/**
 * Persist configuration.
 *
 * The configuration is validated before storage.
 */
async function saveConfig(config) {
  const validation = validateConfig(config);

  if (!validation.valid) {
    throw new Error("Configuration validation failed.");
  }

  await chrome.storage.local.set({
    [STORAGE_KEYS.CONFIG]: config,
  });

  runtimeState.config = config;
}

/**
 * Persist statistics.
 */
async function saveStats() {
  if (!runtimeState.stats) {
    return;
  }

  runtimeState.stats.updatedAt = Date.now();

  await chrome.storage.local.set({
    [STORAGE_KEYS.STATS]: normalizeStats(runtimeState.stats),
  });
}

/**
 * Update the statistics timestamp.
 */
async function touchStats() {
  if (!runtimeState.stats) {
    runtimeState.stats = createDefaultStats();
  }

  runtimeState.stats.updatedAt = Date.now();

  await saveStats();
}

/**
 * Increment a statistic.
 */
async function incrementStat(name, amount = 1) {
  if (!runtimeState.stats) {
    runtimeState.stats = createDefaultStats();
  }

  if (
    typeof runtimeState.stats[name] !== "number" ||
    !Number.isFinite(runtimeState.stats[name])
  ) {
    runtimeState.stats[name] = 0;
  }

  runtimeState.stats[name] += amount;
  runtimeState.stats.updatedAt = Date.now();

  await saveStats();
}

/**
 * Return a safe statistics snapshot.
 */
function getStatsSnapshot() {
  return normalizeStats(runtimeState.stats || DEFAULT_STATS);
}

/**
 * Return a safe configuration snapshot.
 *
 * The configuration itself must not contain sensitive runtime data.
 */
function getConfigSnapshot() {
  return cloneObject(runtimeState.config || DEFAULT_CONFIG);
}

/**
 * Clone a plain object using structuredClone when available.
 */
function cloneObject(value) {
  if (
    typeof structuredClone === "function"
  ) {
    return structuredClone(value);
  }

  return deepMerge({}, value);
}

/**
 * Determine the sender context.
 */
function getSenderContext(sender) {
  if (!sender) {
    return CONTEXT_TYPES.UNKNOWN;
  }

  if (sender.tab) {
    return CONTEXT_TYPES.CONTENT;
  }

  if (sender.url?.startsWith("chrome-extension://")) {
    if (sender.url.includes("popup.html")) {
      return CONTEXT_TYPES.POPUP;
    }

    if (sender.url.includes("options.html")) {
      return CONTEXT_TYPES.OPTIONS;
    }
  }

  return CONTEXT_TYPES.UNKNOWN;
}

/**
 * Validate that a sender is allowed to communicate with the service worker.
 *
 * Content scripts must originate from an actual tab.
 * Extension pages must originate from this extension.
 */
function isTrustedSender(sender) {
  if (!sender) {
    return false;
  }

  if (sender.tab?.id !== undefined) {
    return true;
  }

  if (
    typeof sender.id === "string" &&
    sender.id === chrome.runtime.id
  ) {
    return true;
  }

  return false;
}

/**
 * Extract the sender tab ID safely.
 */
function getSenderTabId(sender) {
  if (
    sender?.tab &&
    Number.isInteger(sender.tab.id) &&
    sender.tab.id >= 0
  ) {
    return sender.tab.id;
  }

  return null;
}

/**
 * Check whether a URL belongs to a supported platform.
 */
function resolvePlatform(url) {
  if (typeof url !== "string" || !url) {
    return null;
  }

  try {
    return getPlatformByUrl(url);
  } catch {
    return null;
  }
}

/**
 * Handle PING.
 */
async function handlePing(message) {
  return createSuccessResponse(
    message.requestId,
    {
      online: true,
      initialized: runtimeState.initialized,
      protocolVersion: PROTOCOL_VERSION,
      timestamp: Date.now(),
    },
  );
}

/**
 * Handle GET_EXTENSION_INFO.
 */
async function handleGetExtensionInfo(message) {
  const manifest = chrome.runtime.getManifest();

  return createSuccessResponse(
    message.requestId,
    {
      name: manifest.name,
      version: manifest.version,
      manifestVersion: manifest.manifest_version,
      protocolVersion: PROTOCOL_VERSION,
    },
  );
}

/**
 * Handle GET_CONFIG.
 */
async function handleGetConfig(message) {
  return createSuccessResponse(
    message.requestId,
    {
      config: getConfigSnapshot(),
    },
  );
}

/**
 * Handle SET_CONFIG.
 */
async function handleSetConfig(message) {
  const payload = message.payload;

  if (!isPlainObject(payload.config)) {
    return createErrorResponse(
      message.requestId,
      ERROR_CODES.INVALID_PAYLOAD,
      "A valid configuration object is required.",
    );
  }

  const validation = validateConfig(payload.config);

  if (!validation.valid) {
    return createErrorResponse(
      message.requestId,
      ERROR_CODES.CONFIG_INVALID,
      "The supplied configuration is invalid.",
    );
  }

  const merged = mergeWithDefaults(payload.config);

  await saveConfig(merged);

  await reportInternalEvent(EVENT_TYPES.CONFIG_CHANGED);

  return createSuccessResponse(
    message.requestId,
    {
      config: getConfigSnapshot(),
    },
  );
}

/**
 * Handle RESET_CONFIG.
 */
async function handleResetConfig(message) {
  const defaults = cloneDefaultConfig();

  await saveConfig(defaults);

  await reportInternalEvent(EVENT_TYPES.CONFIG_CHANGED);

  return createSuccessResponse(
    message.requestId,
    {
      config: getConfigSnapshot(),
    },
  );
}

/**
 * Handle GET_STATUS.
 */
async function handleGetStatus(message, sender) {
  const tabId = getSenderTabId(sender);

  let tab = null;

  if (tabId !== null) {
    try {
      tab = await chrome.tabs.get(tabId);
    } catch {
      tab = null;
    }
  }

  const platform = tab?.url
    ? resolvePlatform(tab.url)
    : null;

  const config = runtimeState.config || DEFAULT_CONFIG;

  return createSuccessResponse(
    message.requestId,
    {
      enabled: config.protection?.enabled ?? true,
      mode:
        config.protection?.mode ||
        PROTECTION_MODES.ACTIVE,

      platform: platform
        ? {
            id: platform.id,
            name: platform.name,
            category: platform.category,
          }
        : null,

      tabId,

      stats: getStatsSnapshot(),
    },
  );
}

/**
 * Handle SET_PROTECTION_MODE.
 */
async function handleSetProtectionMode(message) {
  const mode = message.payload?.mode;

  if (!Object.values(PROTECTION_MODES).includes(mode)) {
    return createErrorResponse(
      message.requestId,
      ERROR_CODES.INVALID_PAYLOAD,
      "Invalid protection mode.",
    );
  }

  const config = getConfigSnapshot();

  if (!config.protection) {
    config.protection = {};
  }

  config.protection.mode = mode;

  if (mode === PROTECTION_MODES.DISABLED) {
    config.protection.enabled = false;
  } else {
    config.protection.enabled = true;
  }

  await saveConfig(config);

  await reportInternalEvent(EVENT_TYPES.CONFIG_CHANGED);

  return createSuccessResponse(
    message.requestId,
    {
      mode,
      enabled: config.protection.enabled,
    },
  );
}

/**
 * Handle GET_PLATFORM.
 */
async function handleGetPlatform(message, sender) {
  let url = message.payload?.url;

  if (!url && sender?.tab?.url) {
    url = sender.tab.url;
  }

  if (typeof url !== "string" || !url) {
    return createErrorResponse(
      message.requestId,
      ERROR_CODES.PLATFORM_UNKNOWN,
      "The current page platform could not be determined.",
    );
  }

  const platform = resolvePlatform(url);

  if (!platform) {
    return createSuccessResponse(
      message.requestId,
      {
        supported: false,
        platform: null,
      },
      MESSAGE_STATUS.IGNORED,
    );
  }

  return createSuccessResponse(
    message.requestId,
    {
      supported: true,
      platform: {
        id: platform.id,
        name: platform.name,
        category: platform.category,
        domains: platform.domains,
        capabilities: platform.capabilities,
      },
    },
  );
}

/**
 * Handle GET_PLATFORM_SUMMARY.
 */
async function handleGetPlatformSummary(message) {
  const summary = getPlatformSummary();

  return createSuccessResponse(
    message.requestId,
    {
      summary,
    },
  );
}

/**
 * Handle CONTENT_READY.
 *
 * Content scripts report readiness but do not send page content.
 */
async function handleContentReady(message, sender) {
  const tabId = getSenderTabId(sender);

  let platform = null;

  if (sender?.tab?.url) {
    platform = resolvePlatform(sender.tab.url);
  }

  return createSuccessResponse(
    message.requestId,
    {
      ready: true,
      tabId,
      platform: platform
        ? {
            id: platform.id,
            name: platform.name,
            category: platform.category,
          }
        : null,
    },
  );
}

/**
 * Handle PLATFORM_DETECTED.
 */
async function handlePlatformDetected(message, sender) {
  const platformId = message.payload?.platformId;

  if (
    typeof platformId !== "string" ||
    platformId.length === 0 ||
    platformId.length > 256
  ) {
    return createErrorResponse(
      message.requestId,
      ERROR_CODES.INVALID_PAYLOAD,
      "A valid platform ID is required.",
    );
  }

  return createSuccessResponse(
    message.requestId,
    {
      detected: true,
      platformId,
      tabId: getSenderTabId(sender),
    },
  );
}

/**
 * Handle REPORT_EVENT.
 *
 * Only event metadata is accepted.
 * Raw content is explicitly rejected.
 */
async function handleReportEvent(message) {
  const eventType = message.payload?.eventType;

  if (typeof eventType !== "string") {
    return createErrorResponse(
      message.requestId,
      ERROR_CODES.INVALID_PAYLOAD,
      "A valid event type is required.",
    );
  }

  const allowedEvents = new Set([
    EVENT_TYPES.INPUT_DETECTED,
    EVENT_TYPES.PASTE_DETECTED,
    EVENT_TYPES.DROP_DETECTED,
    EVENT_TYPES.UPLOAD_DETECTED,
    EVENT_TYPES.SUBMIT_DETECTED,
    EVENT_TYPES.SEND_DETECTED,
    EVENT_TYPES.SEARCH_DETECTED,
    EVENT_TYPES.SCAN_STARTED,
    EVENT_TYPES.SCAN_COMPLETED,
    EVENT_TYPES.SCAN_FAILED,
    EVENT_TYPES.POLICY_EVALUATED,
    EVENT_TYPES.ACTION_ALLOWED,
    EVENT_TYPES.ACTION_WARNED,
    EVENT_TYPES.ACTION_MASKED,
    EVENT_TYPES.ACTION_BLOCKED,
    EVENT_TYPES.ERROR,
  ]);

  if (!allowedEvents.has(eventType)) {
    return createErrorResponse(
      message.requestId,
      ERROR_CODES.INVALID_PAYLOAD,
      "Unsupported event type.",
    );
  }

  await updateStatsFromEvent(eventType);

  return createSuccessResponse(
    message.requestId,
    {
      recorded: true,
    },
  );
}

/**
 * Update statistics based on a safe event type.
 */
async function updateStatsFromEvent(eventType) {
  switch (eventType) {
    case EVENT_TYPES.SCAN_COMPLETED:
      await incrementStat("scans");
      break;

    case EVENT_TYPES.ACTION_ALLOWED:
      await incrementStat("allowed");
      break;

    case EVENT_TYPES.ACTION_WARNED:
      await incrementStat("warned");
      break;

    case EVENT_TYPES.ACTION_MASKED:
      await incrementStat("masked");
      break;

    case EVENT_TYPES.ACTION_BLOCKED:
      await incrementStat("blocked");
      break;

    case EVENT_TYPES.SCAN_FAILED:
      await incrementStat("failed");
      break;

    case EVENT_TYPES.PASTE_DETECTED:
      await incrementStat("pasteEvents");
      break;

    case EVENT_TYPES.DROP_DETECTED:
      await incrementStat("dropEvents");
      break;

    case EVENT_TYPES.UPLOAD_DETECTED:
      await incrementStat("uploadEvents");
      break;

    case EVENT_TYPES.SUBMIT_DETECTED:
      await incrementStat("submitEvents");
      break;

    case EVENT_TYPES.SEARCH_DETECTED:
      await incrementStat("searchEvents");
      break;

    case EVENT_TYPES.SEND_DETECTED:
      await incrementStat("sendEvents");
      break;

    default:
      break;
  }
}

/**
 * Handle GET_STATS.
 */
async function handleGetStats(message) {
  return createSuccessResponse(
    message.requestId,
    {
      stats: getStatsSnapshot(),
    },
  );
}

/**
 * Handle RESET_STATS.
 */
async function handleResetStats(message) {
  runtimeState.stats = createDefaultStats();

  await saveStats();

  return createSuccessResponse(
    message.requestId,
    {
      stats: getStatsSnapshot(),
    },
  );
}

/**
 * Handle messages.
 */
async function handleMessage(message, sender) {
  await initialize();

  if (!isValidMessage(message)) {
    return createErrorResponse(
      null,
      ERROR_CODES.INVALID_MESSAGE,
      "Invalid SanitizerPro message.",
    );
  }

  switch (message.type) {
    case MESSAGE_TYPES.PING:
      return handlePing(message);

    case MESSAGE_TYPES.GET_EXTENSION_INFO:
      return handleGetExtensionInfo(message);

    case MESSAGE_TYPES.GET_CONFIG:
      return handleGetConfig(message);

    case MESSAGE_TYPES.SET_CONFIG:
      return handleSetConfig(message);

    case MESSAGE_TYPES.RESET_CONFIG:
      return handleResetConfig(message);

    case MESSAGE_TYPES.GET_STATUS:
      return handleGetStatus(message, sender);

    case MESSAGE_TYPES.SET_PROTECTION_MODE:
      return handleSetProtectionMode(message);

    case MESSAGE_TYPES.GET_PLATFORM:
      return handleGetPlatform(message, sender);

    case MESSAGE_TYPES.GET_PLATFORM_SUMMARY:
      return handleGetPlatformSummary(message);

    case MESSAGE_TYPES.CONTENT_READY:
      return handleContentReady(message, sender);

    case MESSAGE_TYPES.PLATFORM_DETECTED:
      return handlePlatformDetected(message, sender);

    case MESSAGE_TYPES.REPORT_EVENT:
      return handleReportEvent(message);

    case MESSAGE_TYPES.GET_STATS:
      return handleGetStats(message);

    case MESSAGE_TYPES.RESET_STATS:
      return handleResetStats(message);

    /**
     * Raw scanning is intentionally not performed by the service worker.
     *
     * The content context should own the scanner so raw user content does
     * not need to cross into the background context.
     */
    case MESSAGE_TYPES.SCAN_TEXT:
    case MESSAGE_TYPES.SCAN_FILE:
      return createErrorResponse(
        message.requestId,
        ERROR_CODES.UNSUPPORTED_MESSAGE,
        "Scanning must be performed in the protected content context.",
      );

    case MESSAGE_TYPES.EVALUATE_FINDINGS:
    case MESSAGE_TYPES.REQUEST_ACTION:
      return createErrorResponse(
        message.requestId,
        ERROR_CODES.UNSUPPORTED_MESSAGE,
        "Policy evaluation must be performed in the protected content context.",
      );

    case MESSAGE_TYPES.SHOW_WARNING:
    case MESSAGE_TYPES.SHOW_BLOCK:
    case MESSAGE_TYPES.MASK_CONTENT:
      return createErrorResponse(
        message.requestId,
        ERROR_CODES.UNSUPPORTED_MESSAGE,
        "UI actions must be performed by the protected page context.",
      );

    default:
      return createErrorResponse(
        message.requestId,
        ERROR_CODES.UNSUPPORTED_MESSAGE,
        "Unsupported SanitizerPro message.",
      );
  }
}

/**
 * Report an internal event without passing raw data.
 */
async function reportInternalEvent(eventType) {
  if (!Object.values(EVENT_TYPES).includes(eventType)) {
    return;
  }

  await updateStatsFromEvent(eventType);
}

/**
 * Broadcast configuration changes to active tabs.
 *
 * The content script receives only configuration metadata.
 * No user content is included.
 */
async function broadcastConfigChanged() {
  const tabs = await chrome.tabs.query({});

  const message = {
    version: PROTOCOL_VERSION,
    type: MESSAGE_TYPES.GET_STATUS,
    requestId: `config-${Date.now()}`,
    timestamp: Date.now(),
    source: CONTEXT_TYPES.BACKGROUND,
    payload: {
      configurationChanged: true,
    },
  };

  for (const tab of tabs) {
    if (!Number.isInteger(tab.id)) {
      continue;
    }

    if (
      typeof tab.url !== "string" ||
      !/^https?:\/\//i.test(tab.url)
    ) {
      continue;
    }

    try {
      await chrome.tabs.sendMessage(tab.id, message);
    } catch {
      /**
       * It is normal for some tabs to have no content script.
       * Do not treat this as an extension failure.
       */
    }
  }
}

/**
 * Register installation/startup behavior.
 */
chrome.runtime.onInstalled.addListener(async (details) => {
  try {
    await initialize();

    if (details.reason === "install") {
      console.info("SanitizerPro installed.");
    }

    if (details.reason === "update") {
      console.info(
        "SanitizerPro updated.",
        sanitizeForLog({
          previousVersion: details.previousVersion || null,
        }),
      );
    }
  } catch (error) {
    console.error(
      "SanitizerPro installation initialization failed.",
      sanitizeForLog({
        error: error?.message || String(error),
      }),
    );
  }
});

/**
 * Handle browser startup.
 */
chrome.runtime.onStartup.addListener(async () => {
  try {
    await initialize();
  } catch (error) {
    console.error(
      "SanitizerPro startup initialization failed.",
      sanitizeForLog({
        error: error?.message || String(error),
      }),
    );
  }
});

/**
 * Runtime message listener.
 *
 * MV3 supports promise-based message responses in current Chrome versions.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!isTrustedSender(sender)) {
    sendResponse(
      createErrorResponse(
        null,
        ERROR_CODES.PERMISSION_DENIED,
        "Untrusted message sender.",
      ),
    );

    return false;
  }

  handleMessage(message, sender)
    .then((response) => {
      sendResponse(response);
    })
    .catch((error) => {
      console.error(
        "SanitizerPro message handler failed.",
        sanitizeForLog({
          error: error?.message || String(error),
          messageType:
            isPlainObject(message) && typeof message.type === "string"
              ? message.type
              : null,
        }),
      );

      sendResponse(
        createErrorResponse(
          isPlainObject(message)
            ? message.requestId
            : null,
          ERROR_CODES.INTERNAL_ERROR,
          "The extension could not complete the requested operation.",
        ),
      );
    });

  return true;
});

/**
 * Configuration changes originating from popup/options pages.
 *
 * We intentionally do not mirror raw configuration data into logs.
 */
chrome.storage.onChanged.addListener(async (changes, areaName) => {
  if (areaName !== "local") {
    return;
  }

  if (changes[STORAGE_KEYS.CONFIG]) {
    try {
      const newConfig = changes[STORAGE_KEYS.CONFIG].newValue;

      if (!newConfig) {
        runtimeState.config = cloneDefaultConfig();
      } else {
        const validation = validateConfig(newConfig);

        if (validation.valid) {
          runtimeState.config = mergeWithDefaults(newConfig);
        }
      }

      await reportInternalEvent(EVENT_TYPES.CONFIG_CHANGED);
    } catch (error) {
      console.error(
        "SanitizerPro configuration change handling failed.",
        sanitizeForLog({
          error: error?.message || String(error),
        }),
      );
    }
  }

  if (changes[STORAGE_KEYS.STATS]) {
    const newStats = changes[STORAGE_KEYS.STATS].newValue;

    if (newStats && isPlainObject(newStats)) {
      runtimeState.stats = normalizeStats(newStats);
    }
  }
});

/**
 * Initialize immediately when the service worker starts.
 *
 * The service worker may be suspended and recreated later, so every
 * request handler also calls initialize().
 */
void initialize().catch((error) => {
  console.error(
    "SanitizerPro service worker initialization failed.",
    sanitizeForLog({
      error: error?.message || String(error),
    }),
  );
});
