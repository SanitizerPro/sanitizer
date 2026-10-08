/**
 * SanitizerPro Default Configuration
 *
 * IMPORTANT:
 * This file contains policy configuration only.
 *
 * It must never contain:
 * - API keys
 * - passwords
 * - secrets
 * - user prompts
 * - clipboard contents
 * - uploaded file contents
 * - detected sensitive values
 */

export const ACTIONS = Object.freeze({
  ALLOW: "allow",
  WARN: "warn",
  MASK: "mask",
  BLOCK: "block"
});

export const PROTECTION_MODES = Object.freeze({
  ACTIVE: "active",
  MONITOR: "monitor",
  DISABLED: "disabled"
});

export const DATA_CATEGORIES = Object.freeze({
  SECRET: "secret",
  CREDENTIAL: "credential",
  PRIVATE_KEY: "private_key",
  TOKEN: "token",
  API_KEY: "api_key",
  PASSWORD: "password",

  PII: "pii",
  EMAIL: "email",
  PHONE: "phone",
  ADDRESS: "address",
  PERSON_NAME: "person_name",

  FINANCIAL: "financial",
  CREDIT_CARD: "credit_card",
  BANK_ACCOUNT: "bank_account",
  IBAN: "iban",

  HEALTH: "health",

  INTERNAL: "internal",
  CONFIDENTIAL: "confidential",
  SOURCE_CODE: "source_code",
  DATABASE: "database",
  INFRASTRUCTURE: "infrastructure",

  UNKNOWN: "unknown"
});

export const SEVERITY = Object.freeze({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical"
});

/*
 * Default action for each category.
 *
 * The most dangerous credential material is blocked.
 * Lower-confidence personal or business information
 * initially generates a warning.
 */
export const DEFAULT_CATEGORY_ACTIONS = Object.freeze({
  [DATA_CATEGORIES.SECRET]: ACTIONS.BLOCK,
  [DATA_CATEGORIES.CREDENTIAL]: ACTIONS.BLOCK,
  [DATA_CATEGORIES.PRIVATE_KEY]: ACTIONS.BLOCK,
  [DATA_CATEGORIES.TOKEN]: ACTIONS.BLOCK,
  [DATA_CATEGORIES.API_KEY]: ACTIONS.BLOCK,
  [DATA_CATEGORIES.PASSWORD]: ACTIONS.BLOCK,

  [DATA_CATEGORIES.PII]: ACTIONS.WARN,
  [DATA_CATEGORIES.EMAIL]: ACTIONS.WARN,
  [DATA_CATEGORIES.PHONE]: ACTIONS.WARN,
  [DATA_CATEGORIES.ADDRESS]: ACTIONS.WARN,
  [DATA_CATEGORIES.PERSON_NAME]: ACTIONS.WARN,

  [DATA_CATEGORIES.FINANCIAL]: ACTIONS.WARN,
  [DATA_CATEGORIES.CREDIT_CARD]: ACTIONS.BLOCK,
  [DATA_CATEGORIES.BANK_ACCOUNT]: ACTIONS.BLOCK,
  [DATA_CATEGORIES.IBAN]: ACTIONS.BLOCK,

  [DATA_CATEGORIES.HEALTH]: ACTIONS.WARN,

  [DATA_CATEGORIES.INTERNAL]: ACTIONS.WARN,
  [DATA_CATEGORIES.CONFIDENTIAL]: ACTIONS.WARN,
  [DATA_CATEGORIES.SOURCE_CODE]: ACTIONS.WARN,
  [DATA_CATEGORIES.DATABASE]: ACTIONS.BLOCK,
  [DATA_CATEGORIES.INFRASTRUCTURE]: ACTIONS.WARN,

  [DATA_CATEGORIES.UNKNOWN]: ACTIONS.ALLOW
});

/*
 * Severity associated with each category.
 */
export const DEFAULT_CATEGORY_SEVERITY = Object.freeze({
  [DATA_CATEGORIES.SECRET]: SEVERITY.CRITICAL,
  [DATA_CATEGORIES.CREDENTIAL]: SEVERITY.CRITICAL,
  [DATA_CATEGORIES.PRIVATE_KEY]: SEVERITY.CRITICAL,
  [DATA_CATEGORIES.TOKEN]: SEVERITY.CRITICAL,
  [DATA_CATEGORIES.API_KEY]: SEVERITY.CRITICAL,
  [DATA_CATEGORIES.PASSWORD]: SEVERITY.CRITICAL,

  [DATA_CATEGORIES.PII]: SEVERITY.MEDIUM,
  [DATA_CATEGORIES.EMAIL]: SEVERITY.LOW,
  [DATA_CATEGORIES.PHONE]: SEVERITY.MEDIUM,
  [DATA_CATEGORIES.ADDRESS]: SEVERITY.MEDIUM,
  [DATA_CATEGORIES.PERSON_NAME]: SEVERITY.LOW,

  [DATA_CATEGORIES.FINANCIAL]: SEVERITY.HIGH,
  [DATA_CATEGORIES.CREDIT_CARD]: SEVERITY.CRITICAL,
  [DATA_CATEGORIES.BANK_ACCOUNT]: SEVERITY.CRITICAL,
  [DATA_CATEGORIES.IBAN]: SEVERITY.CRITICAL,

  [DATA_CATEGORIES.HEALTH]: SEVERITY.HIGH,

  [DATA_CATEGORIES.INTERNAL]: SEVERITY.HIGH,
  [DATA_CATEGORIES.CONFIDENTIAL]: SEVERITY.HIGH,
  [DATA_CATEGORIES.SOURCE_CODE]: SEVERITY.MEDIUM,
  [DATA_CATEGORIES.DATABASE]: SEVERITY.CRITICAL,
  [DATA_CATEGORIES.INFRASTRUCTURE]: SEVERITY.HIGH,

  [DATA_CATEGORIES.UNKNOWN]: SEVERITY.LOW
});

/*
 * Protection boundaries.
 *
 * We do not scan every individual keystroke by default.
 * Continuous keystroke scanning can create unnecessary
 * CPU overhead and poor typing performance.
 *
 * SanitizerPro scans at data-transfer boundaries:
 *
 * paste
 * drop
 * upload
 * submit
 * send
 * search
 */
export const INPUT_PROTECTION = Object.freeze({
  paste: true,
  drop: true,
  upload: true,
  formSubmit: true,
  sendButton: true,
  keyboardSubmit: true,
  searchSubmit: true,

  /*
   * Optional live scanning.
   * Disabled by default.
   */
  liveTypingScan: false,

  /*
   * Delay before evaluating a live typing event if
   * liveTypingScan is later enabled.
   */
  liveScanDebounceMs: 350
});

/*
 * Maximum content sizes.
 *
 * These limits protect browser performance and prevent
 * pathological inputs from consuming excessive CPU.
 */
export const SCAN_LIMITS = Object.freeze({
  maxTextCharacters: 250000,

  maxClipboardCharacters: 250000,

  maxFileBytes: 10 * 1024 * 1024,

  maxFileNameCharacters: 512,

  maxFindingsPerScan: 100,

  maxRuleMatchesPerFinding: 10,

  maxNormalizedTextCharacters: 250000,

  maxScanTimeMs: 1500
});

/*
 * Supported text file extensions.
 *
 * Binary formats will be handled separately.
 */
export const TEXT_FILE_EXTENSIONS = Object.freeze([
  ".txt",
  ".csv",
  ".tsv",
  ".json",
  ".xml",
  ".yaml",
  ".yml",
  ".md",
  ".markdown",
  ".log",
  ".ini",
  ".conf",
  ".cfg",
  ".env",

  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",

  ".py",
  ".java",
  ".c",
  ".h",
  ".cpp",
  ".hpp",
  ".cs",
  ".go",
  ".rs",
  ".php",
  ".rb",
  ".swift",
  ".kt",
  ".kts",

  ".sql",
  ".sh",
  ".bash",
  ".zsh",
  ".ps1",
  ".bat",
  ".cmd",

  ".html",
  ".htm",
  ".css",
  ".scss",
  ".sass",

  ".tf",
  ".tfvars",

  ".properties",
  ".toml"
]);

/*
 * MIME types that can normally be scanned as text.
 */
export const TEXT_MIME_TYPES = Object.freeze([
  "text/plain",
  "text/csv",
  "text/tab-separated-values",
  "text/html",
  "text/css",
  "text/javascript",
  "application/javascript",
  "application/json",
  "application/xml",
  "text/xml",
  "application/x-yaml",
  "text/yaml",
  "application/sql"
]);

/*
 * Runtime privacy settings.
 *
 * SanitizerPro is local-first.
 *
 * No remote scanning by default.
 * No telemetry by default.
 */
export const PRIVACY_DEFAULTS = Object.freeze({
  localScanning: true,

  cloudScanning: false,

  telemetry: false,

  crashReporting: false,

  usageAnalytics: false,

  storeScanHistory: false,

  storeDetectedValues: false,

  storeClipboardContent: false,

  storeUploadedFiles: false
});

/*
 * UI defaults.
 */
export const UI_DEFAULTS = Object.freeze({
  showNotifications: true,

  showWarnings: true,

  showBlockDialog: true,

  showMaskedPreview: true,

  compactNotifications: false,

  theme: "system",

  warningAutoCloseMs: 0
});

/*
 * Protection defaults.
 */
export const PROTECTION_DEFAULTS = Object.freeze({
  mode: PROTECTION_MODES.ACTIVE,

  enabled: true,

  protectAIPlatforms: true,

  protectSearchEngines: true,

  protectCodingPlatforms: true,

  protectGenericWebInputs: false,

  scanPaste: true,

  scanUploads: true,

  scanDragDrop: true,

  scanSubmit: true,

  scanSearchQueries: true,

  scanSendActions: true,

  liveTypingScan: false
});

/*
 * Masking configuration.
 *
 * The original value must NEVER be persisted.
 */
export const MASK_DEFAULTS = Object.freeze({
  enabled: true,

  replacement: "[REDACTED]",

  preserveLength: false,

  preserveType: true
});

/*
 * Detection confidence thresholds.
 *
 * A finding should not be blocked merely because a weak
 * heuristic fired.
 */
export const DETECTION_THRESHOLDS = Object.freeze({
  minimumConfidence: 0.60,

  warningConfidence: 0.70,

  blockConfidence: 0.90,

  criticalConfidence: 0.80
});

/*
 * Risk score thresholds.
 *
 * These are separate from individual rule confidence.
 */
export const RISK_THRESHOLDS = Object.freeze({
  low: 0,
  medium: 30,
  high: 60,
  critical: 85
});

/*
 * Platform defaults.
 */
export const PLATFORM_DEFAULTS = Object.freeze({
  unknownAI: {
    enabled: true,
    action: ACTIONS.WARN
  },

  unknownSearch: {
    enabled: true,
    action: ACTIONS.WARN
  },

  unknownWebsite: {
    enabled: false,
    action: ACTIONS.ALLOW
  }
});

/*
 * File scanning defaults.
 */
export const FILE_SCAN_DEFAULTS = Object.freeze({
  enabled: true,

  scanTextFiles: true,

  scanFileNames: true,

  scanMetadata: false,

  maxFileBytes: SCAN_LIMITS.maxFileBytes,

  rejectOversizedFiles: false
});

/*
 * Rate protection prevents repeated scanning of the
 * exact same content in a short period.
 *
 * IMPORTANT:
 * The implementation must use hashes/fingerprints,
 * not persistent raw content.
 */
export const SCAN_CACHE_DEFAULTS = Object.freeze({
  enabled: true,

  ttlMs: 5000,

  maxEntries: 100
});

/*
 * Service worker runtime defaults.
 */
export const SERVICE_WORKER_DEFAULTS = Object.freeze({
  initializationTimeoutMs: 5000,

  messageTimeoutMs: 5000,

  maximumPendingMessages: 100
});

/*
 * Complete default configuration.
 *
 * This object is intentionally composed from the immutable
 * configuration objects above.
 */
export const DEFAULT_CONFIG = Object.freeze({
  version: 1,

  protection: Object.freeze({
    ...PROTECTION_DEFAULTS
  }),

  privacy: Object.freeze({
    ...PRIVACY_DEFAULTS
  }),

  ui: Object.freeze({
    ...UI_DEFAULTS
  }),

  masking: Object.freeze({
    ...MASK_DEFAULTS
  }),

  inputProtection: Object.freeze({
    ...INPUT_PROTECTION
  }),

  scanLimits: Object.freeze({
    ...SCAN_LIMITS
  }),

  fileScanning: Object.freeze({
    ...FILE_SCAN_DEFAULTS
  }),

  detectionThresholds: Object.freeze({
    ...DETECTION_THRESHOLDS
  }),

  riskThresholds: Object.freeze({
    ...RISK_THRESHOLDS
  }),

  platformDefaults: Object.freeze({
    unknownAI: Object.freeze({
      ...PLATFORM_DEFAULTS.unknownAI
    }),

    unknownSearch: Object.freeze({
      ...PLATFORM_DEFAULTS.unknownSearch
    }),

    unknownWebsite: Object.freeze({
      ...PLATFORM_DEFAULTS.unknownWebsite
    })
  }),

  scanCache: Object.freeze({
    ...SCAN_CACHE_DEFAULTS
  }),

  serviceWorker: Object.freeze({
    ...SERVICE_WORKER_DEFAULTS
  }),

  categoryActions: Object.freeze({
    ...DEFAULT_CATEGORY_ACTIONS
  }),

  categorySeverity: Object.freeze({
    ...DEFAULT_CATEGORY_SEVERITY
  })
});

/**
 * Return a deep-enough clone for configuration mutation.
 *
 * This is intentionally JSON based because this configuration
 * contains only JSON-compatible primitives and objects.
 */
export function cloneDefaultConfig() {
  return JSON.parse(
    JSON.stringify(DEFAULT_CONFIG)
  );
}

/**
 * Determine the default action for a data category.
 */
export function getDefaultAction(category) {
  return (
    DEFAULT_CATEGORY_ACTIONS[category] ??
    ACTIONS.ALLOW
  );
}

/**
 * Determine the default severity for a data category.
 */
export function getDefaultSeverity(category) {
  return (
    DEFAULT_CATEGORY_SEVERITY[category] ??
    SEVERITY.LOW
  );
}

/**
 * Validate a configuration object.
 *
 * This function validates structure only.
 * It does not inspect user content.
 */
export function validateConfig(config) {
  if (
    !config ||
    typeof config !== "object"
  ) {
    return {
      valid: false,
      errors: [
        "Configuration must be an object."
      ]
    };
  }

  const errors = [];

  if (
    typeof config.version !== "number"
  ) {
    errors.push(
      "Configuration version is missing."
    );
  }

  if (
    !config.protection ||
    typeof config.protection !== "object"
  ) {
    errors.push(
      "Protection configuration is missing."
    );
  }

  if (
    !config.privacy ||
    typeof config.privacy !== "object"
  ) {
    errors.push(
      "Privacy configuration is missing."
    );
  }

  if (
    config.privacy?.cloudScanning === true
  ) {
    errors.push(
      "Cloud scanning must be explicitly enabled through a separate user action."
    );
  }

  if (
    config.privacy?.storeDetectedValues === true
  ) {
    errors.push(
      "Detected sensitive values must never be persisted."
    );
  }

  if (
    config.privacy?.storeClipboardContent === true
  ) {
    errors.push(
      "Clipboard content must never be persisted."
    );
  }

  if (
    config.privacy?.storeUploadedFiles === true
  ) {
    errors.push(
      "Uploaded files must never be persisted."
    );
  }

  if (
    typeof config.scanLimits?.maxTextCharacters !==
      "number" ||
    config.scanLimits.maxTextCharacters <= 0
  ) {
    errors.push(
      "maxTextCharacters must be a positive number."
    );
  }

  if (
    typeof config.scanLimits?.maxFileBytes !==
      "number" ||
    config.scanLimits.maxFileBytes <= 0
  ) {
    errors.push(
      "maxFileBytes must be a positive number."
    );
  }

  if (
    typeof config.detectionThresholds
      ?.minimumConfidence !== "number" ||
    config.detectionThresholds.minimumConfidence <
      0 ||
    config.detectionThresholds.minimumConfidence >
      1
  ) {
    errors.push(
      "minimumConfidence must be between 0 and 1."
    );
  }

  if (
    typeof config.detectionThresholds
      ?.blockConfidence !== "number" ||
    config.detectionThresholds.blockConfidence <
      0 ||
    config.detectionThresholds.blockConfidence >
      1
  ) {
    errors.push(
      "blockConfidence must be between 0 and 1."
    );
  }

  return {
    valid: errors.length === 0,
    errors
  };
}
