/**
 * SanitizerPro
 * Platform Detector
 *
 * Detects the current AI, search, coding, productivity, or generic
 * web destination from the page URL and lightweight DOM signals.
 *
 * Design goals:
 * - URL-first detection for reliability.
 * - DOM detection as a fallback for dynamically routed applications.
 * - No network requests.
 * - No page-content collection.
 * - No prompt/clipboard/file-content access.
 * - Safe operation on SPAs where the URL changes without a reload.
 */

import {
  getPlatformByUrl,
  getPlatformByHostname,
  GENERIC_PLATFORMS,
  PLATFORM_CATEGORIES,
} from "../config/platforms.js";

import {
  MESSAGE_TYPES,
  CONTEXT_TYPES,
  createMessage,
} from "../config/constants.js";

/**
 * Detection timing.
 */
const DETECTOR_CONFIG = Object.freeze({
  INITIAL_DELAY_MS: 0,
  ROUTE_CHECK_DELAY_MS: 50,
  DOM_OBSERVER_DEBOUNCE_MS: 250,
  MAX_DOM_CHECKS_PER_WINDOW: 20,
  DOM_CHECK_WINDOW_MS: 5000,
});

/**
 * Generic AI/search signals.
 *
 * These are deliberately conservative. Generic detection should never
 * cause SanitizerPro to claim that every website is an AI platform.
 */
const GENERIC_SIGNALS = Object.freeze({
  AI_HOST_TERMS: Object.freeze([
    "chat",
    "ai",
    "assistant",
    "copilot",
    "agent",
    "llm",
    "prompt",
    "generative",
    "genai",
  ]),

  SEARCH_HOST_TERMS: Object.freeze([
    "search",
    "query",
    "find",
  ]),

  AI_DOM_TERMS: Object.freeze([
    "chat",
    "assistant",
    "copilot",
    "prompt",
    "generative ai",
    "ask ai",
    "ask anything",
    "ai assistant",
  ]),

  SEARCH_DOM_TERMS: Object.freeze([
    "search",
    "search results",
    "search query",
    "web results",
  ]),
});

/**
 * Selectors used only for lightweight capability detection.
 *
 * We do not read values from these elements here.
 * Input monitoring will be handled by a separate module.
 */
const DOM_SELECTORS = Object.freeze([
  "textarea",
  "input[type='text']",
  "input[type='search']",
  "[contenteditable='true']",
  "[role='textbox']",
]);

/**
 * Current detection state.
 */
const state = {
  initialized: false,
  current: null,

  observer: null,
  routeTimer: null,
  domTimer: null,

  lastUrl: null,

  domChecks: [],
};

/**
 * Initialize platform detection.
 */
export function initializePlatformDetector({
  onDetected = null,
  observeDom = true,
} = {}) {
  if (state.initialized) {
    return getDetectionResult();
  }

  state.initialized = true;

  state.lastUrl = getCurrentUrl();

  const initialResult = detectPlatform();

  state.current = initialResult;

  if (typeof onDetected === "function") {
    safeCallback(onDetected, initialResult);
  }

  if (observeDom) {
    startDomObservation(onDetected);
    startRouteObservation(onDetected);
  }

  return initialResult;
}

/**
 * Stop platform detection observers.
 */
export function destroyPlatformDetector() {
  if (state.observer) {
    state.observer.disconnect();
    state.observer = null;
  }

  if (state.routeTimer) {
    clearTimeout(state.routeTimer);
    state.routeTimer = null;
  }

  if (state.domTimer) {
    clearTimeout(state.domTimer);
    state.domTimer = null;
  }

  state.initialized = false;
}

/**
 * Detect the current platform.
 */
export function detectPlatform(url = getCurrentUrl()) {
  const normalizedUrl = normalizeUrl(url);

  if (!normalizedUrl) {
    return createUnknownResult();
  }

  /**
   * Primary detection:
   * exact platform registry lookup.
   */
  const registeredPlatform = findRegisteredPlatform(normalizedUrl);

  if (registeredPlatform) {
    return createRegisteredResult(
      registeredPlatform,
      normalizedUrl,
      "registry",
    );
  }

  /**
   * Secondary detection:
   * generic AI/search detection.
   */
  const genericResult = detectGenericPlatform(normalizedUrl);

  if (genericResult) {
    return genericResult;
  }

  return createUnknownResult(normalizedUrl);
}

/**
 * Find a platform from the central registry.
 */
function findRegisteredPlatform(url) {
  try {
    return getPlatformByUrl(url);
  } catch {
    return null;
  }
}

/**
 * Generic AI/search detection.
 *
 * This exists so newly launched or unregistered AI websites can still
 * receive protection when their hostname and DOM strongly indicate
 * an AI/search workflow.
 */
function detectGenericPlatform(url) {
  let parsed;

  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  const hostname = parsed.hostname.toLowerCase();

  const hostSignals = getHostnameSignals(hostname);

  const domSignals = getDomSignals();

  const hasAIHostSignal = hostSignals.ai.length > 0;
  const hasSearchHostSignal = hostSignals.search.length > 0;

  const hasAIDomSignal = domSignals.ai.length > 0;
  const hasSearchDomSignal = domSignals.search.length > 0;

  const inputPresent = hasLikelyInput();

  /**
   * Strong generic AI signal:
   *
   * AI host term + input
   * OR
   * AI DOM signal + input
   * OR
   * AI host term + AI DOM signal.
   */
  if (
    (hasAIHostSignal && inputPresent) ||
    (hasAIDomSignal && inputPresent) ||
    (hasAIHostSignal && hasAIDomSignal)
  ) {
    return createGenericResult(
      GENERIC_PLATFORMS.AI,
      url,
      "generic-ai",
      {
        hostSignals: hostSignals.ai,
        domSignals: domSignals.ai,
      },
    );
  }

  /**
   * Strong generic search signal:
   *
   * Search host term + input
   * OR
   * search DOM signal + input.
   */
  if (
    (hasSearchHostSignal && inputPresent) ||
    (hasSearchDomSignal && inputPresent)
  ) {
    return createGenericResult(
      GENERIC_PLATFORMS.SEARCH,
      url,
      "generic-search",
      {
        hostSignals: hostSignals.search,
        domSignals: domSignals.search,
      },
    );
  }

  return null;
}

/**
 * Get signals from hostname.
 */
function getHostnameSignals(hostname) {
  const ai = [];
  const search = [];

  for (const term of GENERIC_SIGNALS.AI_HOST_TERMS) {
    if (hostnameContainsToken(hostname, term)) {
      ai.push(term);
    }
  }

  for (const term of GENERIC_SIGNALS.SEARCH_HOST_TERMS) {
    if (hostnameContainsToken(hostname, term)) {
      search.push(term);
    }
  }

  return {
    ai,
    search,
  };
}

/**
 * Prevent overly broad substring matching.
 *
 * Example:
 * - "chat.example.com" should match "chat".
 * - "search.example.com" should match "search".
 * - "communication.example.com" should not accidentally match
 *   unrelated fragments.
 */
function hostnameContainsToken(hostname, token) {
  if (!hostname || !token) {
    return false;
  }

  const escaped = escapeRegExp(token);

  const pattern = new RegExp(
    `(^|[.-])${escaped}([.-]|$)`,
    "i",
  );

  return pattern.test(hostname);
}

/**
 * Inspect lightweight DOM signals.
 *
 * We inspect labels, placeholders, aria labels, and visible text.
 * We never read input values here.
 */
function getDomSignals() {
  const ai = [];
  const search = [];

  const candidates = [];

  try {
    candidates.push(
      ...document.querySelectorAll(
        "textarea, input, [contenteditable='true'], [role='textbox'], button",
      ),
    );
  } catch {
    return {
      ai,
      search,
    };
  }

  const maxElements = Math.min(candidates.length, 100);

  for (let index = 0; index < maxElements; index += 1) {
    const element = candidates[index];

    if (!isElementVisible(element)) {
      continue;
    }

    const metadata = getElementMetadata(element);

    if (!metadata) {
      continue;
    }

    const aiMatches = matchTerms(
      metadata,
      GENERIC_SIGNALS.AI_DOM_TERMS,
    );

    const searchMatches = matchTerms(
      metadata,
      GENERIC_SIGNALS.SEARCH_DOM_TERMS,
    );

    for (const match of aiMatches) {
      if (!ai.includes(match)) {
        ai.push(match);
      }
    }

    for (const match of searchMatches) {
      if (!search.includes(match)) {
        search.push(match);
      }
    }
  }

  return {
    ai,
    search,
  };
}

/**
 * Extract safe UI metadata from an element.
 *
 * No input value is read.
 */
function getElementMetadata(element) {
  if (!element || typeof element.getAttribute !== "function") {
    return "";
  }

  const values = [
    element.getAttribute("placeholder"),
    element.getAttribute("aria-label"),
    element.getAttribute("title"),
    element.getAttribute("name"),
    element.getAttribute("data-placeholder"),
    element.getAttribute("data-testid"),
  ];

  return values
    .filter(
      (value) =>
        typeof value === "string" &&
        value.length > 0,
    )
    .join(" ")
    .slice(0, 2048)
    .toLowerCase();
}

/**
 * Match known terms against safe DOM metadata.
 */
function matchTerms(value, terms) {
  if (!value) {
    return [];
  }

  const matches = [];

  for (const term of terms) {
    if (value.includes(term)) {
      matches.push(term);
    }
  }

  return matches;
}

/**
 * Determine whether a likely user input exists.
 *
 * This does not read the value of the input.
 */
function hasLikelyInput() {
  try {
    for (const selector of DOM_SELECTORS) {
      const elements = document.querySelectorAll(selector);

      const maxElements = Math.min(elements.length, 20);

      for (let index = 0; index < maxElements; index += 1) {
        if (isElementVisible(elements[index])) {
          return true;
        }
      }
    }
  } catch {
    return false;
  }

  return false;
}

/**
 * Check whether an element is visible enough to be relevant.
 */
function isElementVisible(element) {
  if (!element) {
    return false;
  }

  if (
    element.disabled === true ||
    element.hidden === true
  ) {
    return false;
  }

  try {
    const style = window.getComputedStyle(element);

    if (
      style.display === "none" ||
      style.visibility === "hidden" ||
      style.opacity === "0"
    ) {
      return false;
    }

    const rect = element.getBoundingClientRect();

    return (
      rect.width > 0 &&
      rect.height > 0
    );
  } catch {
    return true;
  }
}

/**
 * Start observing DOM changes.
 *
 * Modern AI applications are frequently SPAs and render their input
 * interfaces asynchronously. MutationObserver lets us detect those
 * changes without polling continuously.
 */
function startDomObservation(onDetected) {
  if (
    typeof MutationObserver === "undefined" ||
    !document.documentElement
  ) {
    return;
  }

  state.observer = new MutationObserver(() => {
    scheduleDomDetection(onDetected);
  });

  state.observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
}

/**
 * Schedule a DOM detection pass.
 */
function scheduleDomDetection(onDetected) {
  if (state.domTimer) {
    return;
  }

  if (!consumeDomCheckBudget()) {
    return;
  }

  state.domTimer = setTimeout(() => {
    state.domTimer = null;

    const result = detectPlatform();

    if (hasDetectionChanged(result)) {
      state.current = result;

      if (typeof onDetected === "function") {
        safeCallback(onDetected, result);
      }
    }
  }, DETECTOR_CONFIG.DOM_OBSERVER_DEBOUNCE_MS);
}

/**
 * Start lightweight SPA route monitoring.
 */
function startRouteObservation(onDetected) {
  const check = () => {
    const currentUrl = getCurrentUrl();

    if (currentUrl !== state.lastUrl) {
      state.lastUrl = currentUrl;

      const result = detectPlatform(currentUrl);

      if (hasDetectionChanged(result)) {
        state.current = result;

        if (typeof onDetected === "function") {
          safeCallback(onDetected, result);
        }
      }
    }

    state.routeTimer = setTimeout(
      check,
      DETECTOR_CONFIG.ROUTE_CHECK_DELAY_MS,
    );
  };

  state.routeTimer = setTimeout(
    check,
    DETECTOR_CONFIG.ROUTE_CHECK_DELAY_MS,
  );
}

/**
 * Rate-limit DOM detection.
 */
function consumeDomCheckBudget() {
  const now = Date.now();

  state.domChecks = state.domChecks.filter(
    (timestamp) =>
      now - timestamp <
      DETECTOR_CONFIG.DOM_CHECK_WINDOW_MS,
  );

  if (
    state.domChecks.length >=
    DETECTOR_CONFIG.MAX_DOM_CHECKS_PER_WINDOW
  ) {
    return false;
  }

  state.domChecks.push(now);

  return true;
}

/**
 * Determine whether the detection result changed.
 */
function hasDetectionChanged(next) {
  if (!state.current) {
    return true;
  }

  return (
    state.current.platformId !== next.platformId ||
    state.current.category !== next.category ||
    state.current.detectionMethod !== next.detectionMethod ||
    state.current.url !== next.url
  );
}

/**
 * Return the current detection result.
 */
export function getDetectionResult() {
  if (state.current) {
    return cloneDetectionResult(state.current);
  }

  return detectPlatform();
}

/**
 * Check whether the current page is an AI destination.
 */
export function isCurrentAIPlatform() {
  const result = getDetectionResult();

  return (
    result.category === PLATFORM_CATEGORIES.AI_ASSISTANT ||
    result.category === PLATFORM_CATEGORIES.AI_CODING ||
    result.category === PLATFORM_CATEGORIES.PRODUCTIVITY_AI ||
    result.category === PLATFORM_CATEGORIES.GENERIC_AI
  );
}

/**
 * Check whether the current page is a search destination.
 */
export function isCurrentSearchPlatform() {
  const result = getDetectionResult();

  return (
    result.category === PLATFORM_CATEGORIES.AI_SEARCH ||
    result.category === PLATFORM_CATEGORIES.SEARCH_ENGINE ||
    result.category === PLATFORM_CATEGORIES.GENERIC_SEARCH
  );
}

/**
 * Check whether the current page is a coding platform.
 */
export function isCurrentCodingPlatform() {
  return (
    getDetectionResult().category ===
    PLATFORM_CATEGORIES.AI_CODING
  );
}

/**
 * Check whether the current platform is supported by the registry.
 */
export function isRegisteredPlatform() {
  return (
    getDetectionResult().detectionMethod ===
    "registry"
  );
}

/**
 * Send platform detection to the service worker.
 *
 * Only platform metadata is sent.
 * No page content is included.
 */
export async function reportPlatformToBackground() {
  const result = getDetectionResult();

  try {
    const message = createMessage(
      MESSAGE_TYPES.PLATFORM_DETECTED,
      {
        platformId: result.platformId,
        category: result.category,
        detectionMethod: result.detectionMethod,
        hostname: result.hostname,
      },
      {
        source: CONTEXT_TYPES.CONTENT,
      },
    );

    return await chrome.runtime.sendMessage(message);
  } catch {
    return null;
  }
}

/**
 * Send content-ready notification.
 */
export async function reportContentReady() {
  try {
    const message = createMessage(
      MESSAGE_TYPES.CONTENT_READY,
      {
        platformId: getDetectionResult().platformId,
      },
      {
        source: CONTEXT_TYPES.CONTENT,
      },
    );

    return await chrome.runtime.sendMessage(message);
  } catch {
    return null;
  }
}

/**
 * Create a registered platform result.
 */
function createRegisteredResult(
  platform,
  url,
  detectionMethod,
) {
  let parsed;

  try {
    parsed = new URL(url);
  } catch {
    parsed = null;
  }

  return {
    supported: true,
    registered: true,

    platformId: platform.id,
    name: platform.name,

    category: platform.category,

    url,
    hostname: parsed?.hostname || null,

    detectionMethod,

    capabilities: Array.isArray(platform.capabilities)
      ? [...platform.capabilities]
      : [],

    domains: Array.isArray(platform.domains)
      ? [...platform.domains]
      : [],

    confidence: 1,
  };
}

/**
 * Create a generic platform result.
 */
function createGenericResult(
  platform,
  url,
  detectionMethod,
  evidence = {},
) {
  let parsed;

  try {
    parsed = new URL(url);
  } catch {
    parsed = null;
  }

  return {
    supported: true,
    registered: false,

    platformId: platform.id,
    name: platform.name,

    category: platform.category,

    url,
    hostname: parsed?.hostname || null,

    detectionMethod,

    capabilities: Array.isArray(platform.capabilities)
      ? [...platform.capabilities]
      : [],

    domains: [],

    confidence: calculateGenericConfidence(evidence),

    evidence: {
      hostSignals: Array.isArray(evidence.hostSignals)
        ? [...evidence.hostSignals]
        : [],

      domSignals: Array.isArray(evidence.domSignals)
        ? [...evidence.domSignals]
        : [],
    },
  };
}

/**
 * Calculate generic detection confidence.
 *
 * Generic detection must remain below registry-level confidence.
 */
function calculateGenericConfidence(evidence) {
  const hostCount = Array.isArray(evidence.hostSignals)
    ? evidence.hostSignals.length
    : 0;

  const domCount = Array.isArray(evidence.domSignals)
    ? evidence.domSignals.length
    : 0;

  if (hostCount > 0 && domCount > 0) {
    return 0.9;
  }

  if (hostCount > 0 || domCount > 0) {
    return 0.75;
  }

  return 0.5;
}

/**
 * Create unknown result.
 */
function createUnknownResult(url = getCurrentUrl()) {
  let parsed = null;

  try {
    parsed = new URL(url);
  } catch {
    // Ignore invalid URL.
  }

  return {
    supported: false,
    registered: false,

    platformId: null,
    name: null,

    category: null,

    url: url || null,
    hostname: parsed?.hostname || null,

    detectionMethod: "unknown",

    capabilities: [],
    domains: [],

    confidence: 0,
  };
}

/**
 * Normalize a URL.
 */
function normalizeUrl(url) {
  if (typeof url !== "string" || !url.trim()) {
    return null;
  }

  try {
    const parsed = new URL(url);

    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:"
    ) {
      return null;
    }

    return parsed.href;
  } catch {
    return null;
  }
}

/**
 * Get current page URL safely.
 */
function getCurrentUrl() {
  try {
    return window.location.href;
  } catch {
    return null;
  }
}

/**
 * Clone detection data before returning it.
 */
function cloneDetectionResult(result) {
  if (!result) {
    return null;
  }

  return {
    ...result,

    capabilities: Array.isArray(result.capabilities)
      ? [...result.capabilities]
      : [],

    domains: Array.isArray(result.domains)
      ? [...result.domains]
      : [],

    evidence: result.evidence
      ? {
          hostSignals: Array.isArray(
            result.evidence.hostSignals,
          )
            ? [...result.evidence.hostSignals]
            : [],

          domSignals: Array.isArray(
            result.evidence.domSignals,
          )
            ? [...result.evidence.domSignals]
            : [],
        }
      : undefined,
  };
}

/**
 * Escape a string for use inside a regular expression.
 */
function escapeRegExp(value) {
  return String(value).replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&",
  );
}

/**
 * Execute callbacks defensively.
 */
function safeCallback(callback, value) {
  try {
    callback(value);
  } catch (error) {
    console.error(
      "SanitizerPro platform detector callback failed.",
      error,
    );
  }
}

/**
 * Expose the detector state for diagnostics.
 *
 * This does not expose page content.
 */
export function getDetectorDiagnostics() {
  return {
    initialized: state.initialized,
    current: getDetectionResult(),
    observerActive: Boolean(state.observer),
    routeMonitorActive: Boolean(state.routeTimer),
  };
}
