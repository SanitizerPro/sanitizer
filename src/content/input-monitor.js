/**
 * SanitizerPro
 * Content Input Monitor
 *
 * Responsibilities:
 * - Discover editable input elements.
 * - Track dynamically created/removed inputs.
 * - Detect focus changes.
 * - Detect input activity without scanning raw values.
 * - Detect composition/IME activity.
 * - Identify likely send/submit/search controls.
 * - Identify Enter-key submission candidates.
 * - Provide safe metadata to higher-level content monitors.
 *
 * Privacy:
 * - Never sends input values to the background service worker.
 * - Never stores input values.
 * - Never reads clipboard contents.
 * - Never reads uploaded file contents.
 * - Does not perform live sensitive-data scanning.
 *
 * Higher-level monitors are responsible for:
 * - paste-monitor.js
 * - drop-monitor.js
 * - upload-monitor.js
 * - submit-monitor.js
 */

import {
  INPUT_PROTECTION,
  PROTECTION_DEFAULTS
} from "../config/defaults.js";

import {
  EVENT_TYPES,
  SOURCE_TYPES
} from "../config/constants.js";

import {
  isCurrentAIPlatform,
  isCurrentSearchPlatform,
  isCurrentCodingPlatform
} from "./platform-detector.js";

/* -------------------------------------------------------------------------- */
/* Configuration                                                               */
/* -------------------------------------------------------------------------- */

const CONFIG = Object.freeze({
  mutationDebounceMs: 50,
  metadataMaxLength: 160,
  buttonTextMaxLength: 100,
  inputScanBatchSize: 100,

  /*
   * These selectors identify actual editable controls.
   *
   * Password fields are deliberately excluded because SanitizerPro is
   * intended to protect data being submitted to AI/search destinations,
   * not interfere with ordinary password-manager/browser behavior.
   */
  editableSelectors: [
    "textarea",
    "input:not([type])",
    "input[type='text']",
    "input[type='search']",
    "input[type='email']",
    "input[type='url']",
    "input[type='tel']",
    "[contenteditable='true']",
    "[contenteditable='plaintext-only']",
    "[role='textbox']"
  ].join(","),

  /*
   * Controls that may represent send, submit, search, or generation actions.
   */
  actionSelectors: [
    "button",
    "input[type='submit']",
    "input[type='button']",
    "[role='button']",
    "[role='link']"
  ].join(","),

  /*
   * Metadata attributes commonly used by modern React/Vue/Svelte/etc.
   * applications to identify controls.
   */
  metadataAttributes: [
    "aria-label",
    "aria-labelledby",
    "title",
    "name",
    "placeholder",
    "data-testid",
    "data-test-id",
    "data-testid",
    "data-qa",
    "data-cy",
    "data-action",
    "data-command",
    "data-slot"
  ],

  /*
   * UI words used only to classify controls.
   *
   * These are NOT sensitive-data rules.
   */
  sendTerms: [
    "send",
    "submit",
    "ask",
    "generate",
    "continue",
    "run",
    "execute",
    "create",
    "rewrite",
    "summarize",
    "compose",
    "search",
    "go"
  ],

  searchTerms: [
    "search",
    "find",
    "query",
    "look up",
    "lookup",
    "web search",
    "search web",
    "search the web"
  ],

  generateTerms: [
    "generate",
    "create",
    "write",
    "compose",
    "rewrite",
    "summarize",
    "translate",
    "complete",
    "continue",
    "run"
  ]
});

/* -------------------------------------------------------------------------- */
/* Internal state                                                              */
/* -------------------------------------------------------------------------- */

const state = {
  initialized: false,
  destroyed: false,

  observer: null,
  mutationTimer: null,

  trackedInputs: new Set(),
  trackedActions: new Set(),

  elementState: new WeakMap(),

  activeInput: null,

  compositionActive: false,
  compositionTarget: null,

  lastInputTimestamp: 0,
  lastInputEventType: null,

  lastActionTarget: null,
  lastActionTimestamp: 0,

  stats: {
    discoveredInputs: 0,
    discoveredActions: 0,
    inputEvents: 0,
    focusEvents: 0,
    compositionEvents: 0,
    actionCandidates: 0,
    searchCandidates: 0,
    submitCandidates: 0,
    mutations: 0
  },

  callbacks: {
    onInputDetected: null,
    onFocusChanged: null,
    onCompositionChanged: null,
    onSubmitCandidate: null,
    onSearchCandidate: null,
    onActionCandidate: null
  },

  listeners: []
};

/* -------------------------------------------------------------------------- */
/* Utility functions                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Safely execute a callback.
 *
 * The monitor must never break the host page because an extension callback
 * throws an exception.
 *
 * @param {Function|null} callback
 * @param {...any} args
 */
function invokeCallback(callback, ...args) {
  if (typeof callback !== "function") {
    return;
  }

  try {
    callback(...args);
  } catch (error) {
    safeDebug("Callback error", error);
  }
}

/**
 * Debug logging.
 *
 * Logging is intentionally disabled by default.
 *
 * @param {string} message
 * @param {any} details
 */
function safeDebug(message, details = undefined) {
  /*
   * Do not log user input or sensitive values.
   */
  if (!globalThis?.SANITIZERPRO_DEBUG) {
    return;
  }

  try {
    if (details === undefined) {
      console.debug("[SanitizerPro][InputMonitor]", message);
    } else {
      console.debug("[SanitizerPro][InputMonitor]", message, details);
    }
  } catch {
    // Ignore logging failures.
  }
}

/**
 * Return a safe string with a maximum length.
 *
 * @param {*} value
 * @param {number} maxLength
 * @returns {string}
 */
function safeString(value, maxLength = CONFIG.metadataMaxLength) {
  if (typeof value !== "string") {
    return "";
  }

  const normalized = value
    .replace(/\s+/g, " ")
    .trim();

  if (!normalized) {
    return "";
  }

  return normalized.slice(0, maxLength);
}

/**
 * Normalize a metadata attribute value.
 *
 * @param {Element} element
 * @param {string} attribute
 * @returns {string}
 */
function getAttributeValue(element, attribute) {
  if (!(element instanceof Element)) {
    return "";
  }

  try {
    return safeString(
      element.getAttribute(attribute),
      CONFIG.metadataMaxLength
    );
  } catch {
    return "";
  }
}

/**
 * Check whether an element is connected to the current document.
 *
 * @param {Element} element
 * @returns {boolean}
 */
function isConnectedElement(element) {
  return (
    element instanceof Element &&
    element.isConnected &&
    element.ownerDocument === document
  );
}

/**
 * Check whether an element is visible enough to be a real UI control.
 *
 * This deliberately avoids expensive layout calculations such as
 * getBoundingClientRect() on every mutation.
 *
 * @param {Element} element
 * @returns {boolean}
 */
function isPotentiallyVisible(element) {
  if (!(element instanceof Element)) {
    return false;
  }

  if (
    element.hasAttribute("hidden") ||
    element.getAttribute("aria-hidden") === "true"
  ) {
    return false;
  }

  const style = getComputedStyle(element);

  if (
    style.display === "none" ||
    style.visibility === "hidden"
  ) {
    return false;
  }

  return true;
}

/**
 * Determine whether an element is disabled.
 *
 * @param {Element} element
 * @returns {boolean}
 */
function isDisabledElement(element) {
  if (!(element instanceof Element)) {
    return true;
  }

  if (
    element.hasAttribute("disabled") ||
    element.getAttribute("aria-disabled") === "true"
  ) {
    return true;
  }

  return false;
}

/**
 * Determine whether an element is read-only.
 *
 * @param {Element} element
 * @returns {boolean}
 */
function isReadOnlyElement(element) {
  if (!(element instanceof Element)) {
    return true;
  }

  if (
    element.hasAttribute("readonly") ||
    element.getAttribute("aria-readonly") === "true"
  ) {
    return true;
  }

  return false;
}

/**
 * Check whether the element represents a supported editable field.
 *
 * @param {Element|null} element
 * @returns {boolean}
 */
function isEditableElement(element) {
  if (!(element instanceof Element)) {
    return false;
  }

  /*
   * Exclude password fields.
   */
  if (
    element instanceof HTMLInputElement &&
    element.type.toLowerCase() === "password"
  ) {
    return false;
  }

  /*
   * Exclude hidden inputs.
   */
  if (
    element instanceof HTMLInputElement &&
    element.type.toLowerCase() === "hidden"
  ) {
    return false;
  }

  if (isDisabledElement(element)) {
    return false;
  }

  if (isReadOnlyElement(element)) {
    return false;
  }

  /*
   * Native textarea.
   */
  if (element instanceof HTMLTextAreaElement) {
    return true;
  }

  /*
   * Native text/search/etc input.
   */
  if (element instanceof HTMLInputElement) {
    const type = element.type.toLowerCase();

    return [
      "text",
      "search",
      "email",
      "url",
      "tel"
    ].includes(type);
  }

  /*
   * Contenteditable.
   */
  if (
    element.hasAttribute("contenteditable") &&
    element.getAttribute("contenteditable") !== "false"
  ) {
    return true;
  }

  /*
   * ARIA textbox.
   */
  if (
    element.getAttribute("role")?.toLowerCase() === "textbox"
  ) {
    return true;
  }

  return false;
}

/**
 * Resolve the actual editable root from an event target.
 *
 * Modern AI applications frequently place spans/divs inside a
 * contenteditable container.
 *
 * @param {*} target
 * @returns {Element|null}
 */
function resolveEditableElement(target) {
  if (!(target instanceof Element)) {
    return null;
  }

  if (isEditableElement(target)) {
    return target;
  }

  const closest = target.closest(CONFIG.editableSelectors);

  if (closest && isEditableElement(closest)) {
    return closest;
  }

  return null;
}

/**
 * Return an element's input type.
 *
 * @param {Element} element
 * @returns {string}
 */
function getInputType(element) {
  if (!(element instanceof Element)) {
    return "unknown";
  }

  if (element instanceof HTMLTextAreaElement) {
    return "textarea";
  }

  if (element instanceof HTMLInputElement) {
    const type = element.type?.toLowerCase();

    if (type === "search") {
      return "search";
    }

    return type || "text";
  }

  if (
    element.getAttribute("role")?.toLowerCase() === "textbox"
  ) {
    return "textbox";
  }

  if (element.hasAttribute("contenteditable")) {
    return "contenteditable";
  }

  return "unknown";
}

/**
 * Determine whether the field is a search field.
 *
 * @param {Element} element
 * @returns {boolean}
 */
function isSearchInput(element) {
  if (!(element instanceof Element)) {
    return false;
  }

  if (
    element instanceof HTMLInputElement &&
    element.type.toLowerCase() === "search"
  ) {
    return true;
  }

  const metadata = getElementMetadata(element);

  const combined = [
    metadata.ariaLabel,
    metadata.title,
    metadata.name,
    metadata.placeholder,
    metadata.testId
  ]
    .join(" ")
    .toLowerCase();

  if (CONFIG.searchTerms.some((term) => combined.includes(term))) {
    return true;
  }

  return isCurrentSearchPlatform();
}

/**
 * Get a safe metadata object for an editable element.
 *
 * IMPORTANT:
 * This function never reads `.value` or `.textContent` from the input.
 *
 * @param {Element} element
 * @returns {object}
 */
function getElementMetadata(element) {
  if (!(element instanceof Element)) {
    return {
      tagName: "",
      inputType: "unknown",
      ariaLabel: "",
      ariaLabelledBy: "",
      title: "",
      name: "",
      placeholder: "",
      testId: "",
      dataAction: "",
      dataCommand: "",
      dataSlot: ""
    };
  }

  return {
    tagName: element.tagName.toLowerCase(),
    inputType: getInputType(element),

    ariaLabel: getAttributeValue(element, "aria-label"),
    ariaLabelledBy: getAttributeValue(element, "aria-labelledby"),
    title: getAttributeValue(element, "title"),
    name: getAttributeValue(element, "name"),
    placeholder: getAttributeValue(element, "placeholder"),

    testId:
      getAttributeValue(element, "data-testid") ||
      getAttributeValue(element, "data-test-id") ||
      getAttributeValue(element, "data-qa") ||
      getAttributeValue(element, "data-cy"),

    dataAction: getAttributeValue(element, "data-action"),
    dataCommand: getAttributeValue(element, "data-command"),
    dataSlot: getAttributeValue(element, "data-slot")
  };
}

/**
 * Return a stable element identifier for this page session.
 *
 * This is intentionally held only in memory.
 *
 * @param {Element} element
 * @returns {string}
 */
function getElementSessionId(element) {
  if (!(element instanceof Element)) {
    return "";
  }

  const existing = state.elementState.get(element);

  if (existing?.sessionId) {
    return existing.sessionId;
  }

  const randomPart = Math.random()
    .toString(36)
    .slice(2, 10);

  const sessionId = `input-${randomPart}`;

  state.elementState.set(element, {
    ...(existing || {}),
    sessionId
  });

  return sessionId;
}

/**
 * Build safe metadata for an editable element.
 *
 * No raw value is included.
 *
 * @param {Element} element
 * @returns {object|null}
 */
function buildInputMetadata(element) {
  if (!isEditableElement(element)) {
    return null;
  }

  const metadata = getElementMetadata(element);

  return {
    sessionId: getElementSessionId(element),
    tagName: metadata.tagName,
    inputType: metadata.inputType,

    isSearchInput: isSearchInput(element),

    ariaLabel: metadata.ariaLabel,
    ariaLabelledBy: metadata.ariaLabelledBy,
    title: metadata.title,
    name: metadata.name,
    placeholder: metadata.placeholder,
    testId: metadata.testId,

    dataAction: metadata.dataAction,
    dataCommand: metadata.dataCommand,
    dataSlot: metadata.dataSlot,

    platformContext: {
      ai: isCurrentAIPlatform(),
      search: isCurrentSearchPlatform(),
      coding: isCurrentCodingPlatform()
    }
  };
}

/* -------------------------------------------------------------------------- */
/* Action / button classification                                              */
/* -------------------------------------------------------------------------- */

/**
 * Return metadata from an action element without reading arbitrary page text.
 *
 * @param {Element} element
 * @returns {object}
 */
function getActionMetadata(element) {
  if (!(element instanceof Element)) {
    return {
      tagName: "",
      role: "",
      ariaLabel: "",
      title: "",
      name: "",
      testId: "",
      dataAction: "",
      dataCommand: ""
    };
  }

  return {
    tagName: element.tagName.toLowerCase(),
    role: safeString(element.getAttribute("role"), 50),

    ariaLabel: getAttributeValue(element, "aria-label"),
    title: getAttributeValue(element, "title"),
    name: getAttributeValue(element, "name"),

    testId:
      getAttributeValue(element, "data-testid") ||
      getAttributeValue(element, "data-test-id") ||
      getAttributeValue(element, "data-qa") ||
      getAttributeValue(element, "data-cy"),

    dataAction: getAttributeValue(element, "data-action"),
    dataCommand: getAttributeValue(element, "data-command")
  };
}

/**
 * Build a classification string from safe UI metadata.
 *
 * @param {Element} element
 * @returns {string}
 */
function getActionClassificationText(element) {
  const metadata = getActionMetadata(element);

  return [
    metadata.ariaLabel,
    metadata.title,
    metadata.name,
    metadata.testId,
    metadata.dataAction,
    metadata.dataCommand
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

/**
 * Determine whether an action is likely a search control.
 *
 * @param {Element} element
 * @returns {boolean}
 */
function isLikelySearchAction(element) {
  if (!(element instanceof Element)) {
    return false;
  }

  const metadata = getActionMetadata(element);

  const text = [
    metadata.ariaLabel,
    metadata.title,
    metadata.name,
    metadata.testId,
    metadata.dataAction,
    metadata.dataCommand
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return CONFIG.searchTerms.some((term) => text.includes(term));
}

/**
 * Determine whether an action is likely a send/generate/submit control.
 *
 * @param {Element} element
 * @returns {boolean}
 */
function isLikelySubmitAction(element) {
  if (!(element instanceof Element)) {
    return false;
  }

  if (isDisabledElement(element)) {
    return false;
  }

  const metadata = getActionMetadata(element);

  const text = getActionClassificationText(element);

  /*
   * Native submit controls are strong signals.
   */
  if (
    element instanceof HTMLInputElement &&
    element.type.toLowerCase() === "submit"
  ) {
    return true;
  }

  /*
   * Search buttons should be handled by search classification.
   */
  if (isLikelySearchAction(element)) {
    return true;
  }

  return CONFIG.sendTerms.some((term) => text.includes(term));
}

/**
 * Determine whether an action is relevant to AI generation.
 *
 * @param {Element} element
 * @returns {boolean}
 */
function isLikelyGenerateAction(element) {
  if (!(element instanceof Element)) {
    return false;
  }

  const text = getActionClassificationText(element);

  return CONFIG.generateTerms.some((term) => text.includes(term));
}

/**
 * Resolve an action element from an event target.
 *
 * @param {*} target
 * @returns {Element|null}
 */
function resolveActionElement(target) {
  if (!(target instanceof Element)) {
    return null;
  }

  if (target.matches(CONFIG.actionSelectors)) {
    return target;
  }

  const closest = target.closest(CONFIG.actionSelectors);

  if (closest) {
    return closest;
  }

  return null;
}

/**
 * Build safe action metadata.
 *
 * @param {Element} element
 * @returns {object|null}
 */
function buildActionMetadata(element) {
  if (!(element instanceof Element)) {
    return null;
  }

  const metadata = getActionMetadata(element);

  const search = isLikelySearchAction(element);
  const submit = isLikelySubmitAction(element);
  const generate = isLikelyGenerateAction(element);

  if (!search && !submit && !generate) {
    return null;
  }

  return {
    sessionId: getElementSessionId(element),

    tagName: metadata.tagName,
    role: metadata.role,

    ariaLabel: metadata.ariaLabel,
    title: metadata.title,
    name: metadata.name,
    testId: metadata.testId,
    dataAction: metadata.dataAction,
    dataCommand: metadata.dataCommand,

    isSearchAction: search,
    isSubmitAction: submit,
    isGenerateAction: generate,

    platformContext: {
      ai: isCurrentAIPlatform(),
      search: isCurrentSearchPlatform(),
      coding: isCurrentCodingPlatform()
    }
  };
}

/* -------------------------------------------------------------------------- */
/* Element discovery                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Track an editable element.
 *
 * @param {Element} element
 * @returns {boolean}
 */
function trackInputElement(element) {
  if (!isEditableElement(element)) {
    return false;
  }

  if (!isPotentiallyVisible(element)) {
    return false;
  }

  if (state.trackedInputs.has(element)) {
    return false;
  }

  state.trackedInputs.add(element);

  state.elementState.set(element, {
    ...(state.elementState.get(element) || {}),
    trackedAt: Date.now(),
    inputType: getInputType(element)
  });

  state.stats.discoveredInputs += 1;

  return true;
}

/**
 * Track an action element.
 *
 * @param {Element} element
 * @returns {boolean}
 */
function trackActionElement(element) {
  if (!(element instanceof Element)) {
    return false;
  }

  if (!isPotentiallyVisible(element)) {
    return false;
  }

  if (isDisabledElement(element)) {
    return false;
  }

  if (!element.matches(CONFIG.actionSelectors)) {
    return false;
  }

  if (
    !isLikelySubmitAction(element) &&
    !isLikelySearchAction(element) &&
    !isLikelyGenerateAction(element)
  ) {
    return false;
  }

  if (state.trackedActions.has(element)) {
    return false;
  }

  state.trackedActions.add(element);

  state.elementState.set(element, {
    ...(state.elementState.get(element) || {}),
    trackedAt: Date.now(),
    action: true
  });

  state.stats.discoveredActions += 1;

  return true;
}

/**
 * Remove disconnected elements from tracking sets.
 */
function cleanupDisconnectedElements() {
  for (const element of state.trackedInputs) {
    if (!isConnectedElement(element)) {
      state.trackedInputs.delete(element);

      if (state.activeInput === element) {
        state.activeInput = null;
      }
    }
  }

  for (const element of state.trackedActions) {
    if (!isConnectedElement(element)) {
      state.trackedActions.delete(element;
    }
  }
}

/**
 * Scan a root for editable and action controls.
 *
 * @param {Node} root
 */
function scanRoot(root) {
  if (!(root instanceof Element) && !(root instanceof Document)) {
    return;
  }

  let inputElements = [];
  let actionElements = [];

  try {
    if (root instanceof Element && isEditableElement(root)) {
      inputElements.push(root);
    }

    if (
      root instanceof Element &&
      root.matches(CONFIG.actionSelectors)
    ) {
      actionElements.push(root);
    }

    inputElements = inputElements.concat(
      Array.from(
        root.querySelectorAll(CONFIG.editableSelectors)
      )
    );

    actionElements = actionElements.concat(
      Array.from(
        root.querySelectorAll(CONFIG.actionSelectors)
      )
    );
  } catch (error) {
    safeDebug("Root scan failed", error);
    return;
  }

  /*
   * Protect the monitor from pathological pages with huge DOM trees.
   */
  for (
    let index = 0;
    index < inputElements.length &&
    index < CONFIG.inputScanBatchSize;
    index += 1
  ) {
    trackInputElement(inputElements[index]);
  }

  for (
    let index = 0;
    index < actionElements.length &&
    index < CONFIG.inputScanBatchSize;
    index += 1
  ) {
    trackActionElement(actionElements[index]);
  }
}

/**
 * Schedule a DOM rescan.
 */
function scheduleMutationScan() {
  if (state.mutationTimer !== null) {
    return;
  }

  state.mutationTimer = globalThis.setTimeout(() => {
    state.mutationTimer = null;

    if (state.destroyed) {
      return;
    }

    cleanupDisconnectedElements();

    if (document.documentElement) {
      scanRoot(document.documentElement);
    }
  }, CONFIG.mutationDebounceMs);
}

/* -------------------------------------------------------------------------- */
/* Event handling                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Handle focus entering an editable field.
 *
 * @param {FocusEvent} event
 */
function handleFocusIn(event) {
  if (state.destroyed) {
    return;
  }

  const input = resolveEditableElement(event.target);

  if (!input) {
    return;
  }

  trackInputElement(input);

  state.activeInput = input;
  state.stats.focusEvents += 1;

  const metadata = buildInputMetadata(input);

  invokeCallback(
    state.callbacks.onFocusChanged,
    {
      type: EVENT_TYPES.INPUT_DETECTED,
      sourceType: SOURCE_TYPES.TYPING,
      action: "focus",
      timestamp: Date.now(),
      input: metadata
    }
  );
}

/**
 * Handle focus leaving an editable field.
 *
 * @param {FocusEvent} event
 */
function handleFocusOut(event) {
  if (state.destroyed) {
    return;
  }

  const input = resolveEditableElement(event.target);

  if (!input) {
    return;
  }

  if (state.activeInput === input) {
    state.activeInput = null;
  }

  const metadata = buildInputMetadata(input);

  invokeCallback(
    state.callbacks.onFocusChanged,
    {
      type: EVENT_TYPES.INPUT_DETECTED,
      sourceType: SOURCE_TYPES.TYPING,
      action: "blur",
      timestamp: Date.now(),
      input: metadata
    }
  );
}

/**
 * Handle input events.
 *
 * IMPORTANT:
 * This function deliberately does NOT read:
 * - event.target.value
 * - innerText
 * - textContent
 * - innerHTML
 *
 * The actual sensitive scan will happen only at transfer boundaries.
 *
 * @param {InputEvent} event
 */
function handleInput(event) {
  if (state.destroyed) {
    return;
  }

  const input = resolveEditableElement(event.target);

  if (!input) {
    return;
  }

  trackInputElement(input);

  state.lastInputTimestamp = Date.now();
  state.lastInputEventType = event.inputType || "input";
  state.stats.inputEvents += 1;

  /*
   * Live typing scanning is intentionally disabled by default.
   *
   * We only notify the local content orchestration layer that input activity
   * occurred. No raw data leaves this context.
   */
  if (!INPUT_PROTECTION.liveTypingScan) {
    invokeCallback(
      state.callbacks.onInputDetected,
      {
        type: EVENT_TYPES.INPUT_DETECTED,
        sourceType: SOURCE_TYPES.TYPING,
        action: "input",
        timestamp: state.lastInputTimestamp,
        input: buildInputMetadata(input),
        inputType: event.inputType || "input",
        isComposing:
          Boolean(event.isComposing) ||
          state.compositionActive
      }
    );

    return;
  }

  /*
   * Live scanning is an explicit configuration option.
   *
   * Even when enabled, this monitor still does not scan the value.
   * The content orchestration layer decides when and how to invoke the
   * local scanner.
   */
  invokeCallback(
    state.callbacks.onInputDetected,
    {
      type: EVENT_TYPES.INPUT_DETECTED,
      sourceType: SOURCE_TYPES.TYPING,
      action: "input",
      timestamp: Date.now(),
      input: buildInputMetadata(input),
      inputType: event.inputType || "input",
      isComposing:
        Boolean(event.isComposing) ||
        state.compositionActive,
      liveScanRequested: true,
      debounceMs: INPUT_PROTECTION.liveScanDebounceMs
    }
  );
}

/**
 * Handle beforeinput.
 *
 * This event is useful for identifying browser-level input sources such as:
 * - insertFromPaste
 * - insertFromDrop
 * - insertText
 * - insertCompositionText
 *
 * No blocking occurs here. Dedicated monitors own paste/drop behavior.
 *
 * @param {InputEvent} event
 */
function handleBeforeInput(event) {
  if (state.destroyed) {
    return;
  }

  const input = resolveEditableElement(event.target);

  if (!input) {
    return;
  }

  trackInputElement(input);

  const inputType = event.inputType || "";

  /*
   * Paste and drop are handled by their dedicated monitors.
   * We only provide a local signal.
   */
  if (
    inputType === "insertFromPaste" ||
    inputType === "insertFromDrop"
  ) {
    invokeCallback(
      state.callbacks.onInputDetected,
      {
        type: EVENT_TYPES.INPUT_DETECTED,
        sourceType:
          inputType === "insertFromPaste"
            ? SOURCE_TYPES.PASTE
            : SOURCE_TYPES.DROP,
        action: "beforeinput",
        timestamp: Date.now(),
        input: buildInputMetadata(input),
        inputType
      }
    );
  }
}

/**
 * Handle composition start for IME input.
 *
 * @param {CompositionEvent} event
 */
function handleCompositionStart(event) {
  if (state.destroyed) {
    return;
  }

  const input = resolveEditableElement(event.target);

  if (!input) {
    return;
  }

  trackInputElement(input);

  state.compositionActive = true;
  state.compositionTarget = input;
  state.stats.compositionEvents += 1;

  invokeCallback(
    state.callbacks.onCompositionChanged,
    {
      type: EVENT_TYPES.INPUT_DETECTED,
      sourceType: SOURCE_TYPES.TYPING,
      action: "compositionstart",
      timestamp: Date.now(),
      input: buildInputMetadata(input),
      active: true
    }
  );
}

/**
 * Handle composition end for IME input.
 *
 * @param {CompositionEvent} event
 */
function handleCompositionEnd(event) {
  if (state.destroyed) {
    return;
  }

  const input = resolveEditableElement(event.target);

  if (!input) {
    return;
  }

  trackInputElement(input);

  state.compositionActive = false;
  state.compositionTarget = null;
  state.stats.compositionEvents += 1;

  invokeCallback(
    state.callbacks.onCompositionChanged,
    {
      type: EVENT_TYPES.INPUT_DETECTED,
      sourceType: SOURCE_TYPES.TYPING,
      action: "compositionend",
      timestamp: Date.now(),
      input: buildInputMetadata(input),
      active: false
    }
  );
}

/**
 * Determine whether Enter is a likely send/submit key.
 *
 * This is intentionally conservative.
 *
 * @param {KeyboardEvent} event
 * @param {Element} input
 * @returns {boolean}
 */
function isLikelySubmitKey(event, input) {
  if (!(event instanceof KeyboardEvent)) {
    return false;
  }

  if (event.key !== "Enter") {
    return false;
  }

  if (event.isComposing || state.compositionActive) {
    return false;
  }

  /*
   * Shift+Enter is normally newline in AI chat interfaces.
   */
  if (event.shiftKey) {
    return false;
  }

  /*
   * Modifier combinations are usually commands, not send.
   */
  if (
    event.ctrlKey ||
    event.altKey ||
    event.metaKey
  ) {
    return false;
  }

  if (!isEditableElement(input)) {
    return false;
  }

  /*
   * Search inputs are also commonly submitted with Enter.
   */
  return true;
}

/**
 * Handle keyboard activity.
 *
 * @param {KeyboardEvent} event
 */
function handleKeyDown(event) {
  if (state.destroyed) {
    return;
  }

  const input = resolveEditableElement(event.target);

  if (!input) {
    return;
  }

  trackInputElement(input);

  if (!isLikelySubmitKey(event, input)) {
    return;
  }

  const searchInput = isSearchInput(input);

  const metadata = buildInputMetadata(input);

  state.stats.submitCandidates += 1;

  if (searchInput) {
    state.stats.searchCandidates += 1;
  }

  /*
   * Do not preventDefault here.
   *
   * submit-monitor.js will eventually perform the actual policy evaluation.
   */
  const payload = {
    type: searchInput
      ? EVENT_TYPES.SEARCH_DETECTED
      : EVENT_TYPES.SEND_DETECTED,

    sourceType: searchInput
      ? SOURCE_TYPES.SEARCH
      : SOURCE_TYPES.KEYBOARD_SEND,

    action: "enter",
    timestamp: Date.now(),

    input: metadata,

    keyboard: {
      key: "Enter",
      shiftKey: Boolean(event.shiftKey),
      ctrlKey: Boolean(event.ctrlKey),
      altKey: Boolean(event.altKey),
      metaKey: Boolean(event.metaKey)
    }
  };

  invokeCallback(
    searchInput
      ? state.callbacks.onSearchCandidate
      : state.callbacks.onSubmitCandidate,
    payload
  );
}

/**
 * Handle click events for send/search/generate controls.
 *
 * @param {MouseEvent} event
 */
function handleClick(event) {
  if (state.destroyed) {
    return;
  }

  const action = resolveActionElement(event.target);

  if (!action) {
    return;
  }

  if (!isPotentiallyVisible(action)) {
    return;
  }

  if (isDisabledElement(action)) {
    return;
  }

  const metadata = buildActionMetadata(action);

  if (!metadata) {
    return;
  }

  trackActionElement(action);

  state.lastActionTarget = action;
  state.lastActionTimestamp = Date.now();

  state.stats.actionCandidates += 1;

  if (metadata.isSearchAction) {
    state.stats.searchCandidates += 1;

    invokeCallback(
      state.callbacks.onSearchCandidate,
      {
        type: EVENT_TYPES.SEARCH_DETECTED,
        sourceType: SOURCE_TYPES.SEARCH,
        action: "click",
        timestamp: Date.now(),
        control: metadata,
        activeInput: buildInputMetadata(state.activeInput)
      }
    );

    return;
  }

  if (
    metadata.isSubmitAction ||
    metadata.isGenerateAction
  ) {
    state.stats.submitCandidates += 1;

    invokeCallback(
      state.callbacks.onSubmitCandidate,
      {
        type: EVENT_TYPES.SEND_DETECTED,
        sourceType: SOURCE_TYPES.SEND,
        action: "click",
        timestamp: Date.now(),
        control: metadata,
        activeInput: buildInputMetadata(state.activeInput)
      }
    );
  }

  invokeCallback(
    state.callbacks.onActionCandidate,
    {
      type: EVENT_TYPES.SEND_DETECTED,
      sourceType: SOURCE_TYPES.SEND,
      action: "click",
      timestamp: Date.now(),
      control: metadata,
      activeInput: buildInputMetadata(state.activeInput)
    }
  );
}

/**
 * Handle form submissions.
 *
 * This is intentionally metadata-only.
 *
 * @param {SubmitEvent} event
 */
function handleSubmit(event) {
  if (state.destroyed) {
    return;
  }

  const form = event.target;

  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  /*
   * Find an editable field associated with this form without reading its
   * contents.
   */
  let input = null;

  try {
    input = form.querySelector(CONFIG.editableSelectors);
  } catch {
    input = null;
  }

  if (!input || !isEditableElement(input)) {
    input = state.activeInput;
  }

  const metadata = buildInputMetadata(input);

  const search =
    Boolean(input && isSearchInput(input)) ||
    isCurrentSearchPlatform();

  if (search) {
    state.stats.searchCandidates += 1;

    invokeCallback(
      state.callbacks.onSearchCandidate,
      {
        type: EVENT_TYPES.SEARCH_DETECTED,
        sourceType: SOURCE_TYPES.SEARCH,
        action: "form-submit",
        timestamp: Date.now(),
        form: {
          method: safeString(form.getAttribute("method"), 20),
          action: safeString(form.getAttribute("action"), 200)
        },
        input: metadata
      }
    );

    return;
  }

  state.stats.submitCandidates += 1;

  invokeCallback(
    state.callbacks.onSubmitCandidate,
    {
      type: EVENT_TYPES.SUBMIT_DETECTED,
      sourceType: SOURCE_TYPES.SUBMIT,
      action: "form-submit",
      timestamp: Date.now(),
      form: {
        method: safeString(form.getAttribute("method"), 20),
        action: safeString(form.getAttribute("action"), 200)
      },
      input: metadata
    }
  );
}

/* -------------------------------------------------------------------------- */
/* Mutation observer                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Handle DOM mutations.
 *
 * @param {MutationRecord[]} mutations
 */
function handleMutations(mutations) {
  if (state.destroyed) {
    return;
  }

  if (!Array.isArray(mutations) || mutations.length === 0) {
    return;
  }

  state.stats.mutations += mutations.length;

  /*
   * Do not scan every mutation synchronously.
   *
   * Modern AI applications can generate hundreds or thousands of DOM
   * mutations during rendering.
   */
  scheduleMutationScan();
}

/**
 * Start the MutationObserver.
 */
function initializeMutationObserver() {
  if (typeof MutationObserver === "undefined") {
    return;
  }

  if (!document.documentElement) {
    return;
  }

  state.observer = new MutationObserver(handleMutations);

  state.observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
}

/* -------------------------------------------------------------------------- */
/* Event registration                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Register a DOM event listener and remember it for cleanup.
 *
 * @param {EventTarget} target
 * @param {string} eventName
 * @param {EventListener} handler
 * @param {boolean|AddEventListenerOptions} options
 */
function addListener(target, eventName, handler, options = false) {
  target.addEventListener(
    eventName,
    handler,
    options
  );

  state.listeners.push({
    target,
    eventName,
    handler,
    options
  });
}

/**
 * Register all required event listeners.
 */
function initializeEventListeners() {
  /*
   * Capture phase is important because modern frontend applications often
   * stopPropagation() inside component handlers.
   */
  addListener(
    document,
    "focusin",
    handleFocusIn,
    true
  );

  addListener(
    document,
    "focusout",
    handleFocusOut,
    true
  );

  addListener(
    document,
    "beforeinput",
    handleBeforeInput,
    true
  );

  addListener(
    document,
    "input",
    handleInput,
    true
  );

  addListener(
    document,
    "compositionstart",
    handleCompositionStart,
    true
  );

  addListener(
    document,
    "compositionend",
    handleCompositionEnd,
    true
  );

  addListener(
    document,
    "keydown",
    handleKeyDown,
    true
  );

  addListener(
    document,
    "click",
    handleClick,
    true
  );

  addListener(
    document,
    "submit",
    handleSubmit,
    true
  );
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Initialize the input monitor.
 *
 * @param {object} options
 * @returns {object}
 */
export function initializeInputMonitor(options = {}) {
  if (state.initialized && !state.destroyed) {
    return getInputMonitorDiagnostics();
  }

  state.destroyed = false;
  state.initialized = true;

  state.callbacks.onInputDetected =
    typeof options.onInputDetected === "function"
      ? options.onInputDetected
      : null;

  state.callbacks.onFocusChanged =
    typeof options.onFocusChanged === "function"
      ? options.onFocusChanged
      : null;

  state.callbacks.onCompositionChanged =
    typeof options.onCompositionChanged === "function"
      ? options.onCompositionChanged
      : null;

  state.callbacks.onSubmitCandidate =
    typeof options.onSubmitCandidate === "function"
      ? options.onSubmitCandidate
      : null;

  state.callbacks.onSearchCandidate =
    typeof options.onSearchCandidate === "function"
      ? options.onSearchCandidate
      : null;

  state.callbacks.onActionCandidate =
    typeof options.onActionCandidate === "function"
      ? options.onActionCandidate
      : null;

  /*
   * Discover controls that already exist.
   */
  if (document.documentElement) {
    scanRoot(document.documentElement);
  }

  /*
   * Observe controls created later by React/Vue/Svelte/etc.
   */
  initializeMutationObserver();

  /*
   * Register DOM event listeners.
   */
  initializeEventListeners();

  safeDebug("Input monitor initialized");

  return getInputMonitorDiagnostics();
}

/**
 * Destroy the monitor and release all DOM observers/listeners.
 */
export function destroyInputMonitor() {
  if (!state.initialized) {
    return;
  }

  state.destroyed = true;

  if (state.observer) {
    try {
      state.observer.disconnect();
    } catch {
      // Ignore observer cleanup failures.
    }

    state.observer = null;
  }

  if (state.mutationTimer !== null) {
    globalThis.clearTimeout(state.mutationTimer);
    state.mutationTimer = null;
  }

  for (const listener of state.listeners) {
    try {
      listener.target.removeEventListener(
        listener.eventName,
        listener.handler,
        listener.options
      );
    } catch {
      // Ignore individual listener cleanup failures.
    }
  }

  state.listeners.length = 0;

  state.trackedInputs.clear();
  state.trackedActions.clear();

  state.activeInput = null;
  state.compositionTarget = null;
  state.compositionActive = false;
  state.lastActionTarget = null;

  state.callbacks.onInputDetected = null;
  state.callbacks.onFocusChanged = null;
  state.callbacks.onCompositionChanged = null;
  state.callbacks.onSubmitCandidate = null;
  state.callbacks.onSearchCandidate = null;
  state.callbacks.onActionCandidate = null;

  state.initialized = false;

  safeDebug("Input monitor destroyed");
}

/**
 * Get the currently focused editable element.
 *
 * @returns {Element|null}
 */
export function getActiveInput() {
  if (
    state.activeInput &&
    isConnectedElement(state.activeInput) &&
    isEditableElement(state.activeInput)
  ) {
    return state.activeInput;
  }

  return null;
}

/**
 * Get safe metadata for the currently active input.
 *
 * @returns {object|null}
 */
export function getActiveInputMetadata() {
  return buildInputMetadata(getActiveInput());
}

/**
 * Get safe metadata for a supplied input element.
 *
 * @param {Element|null} element
 * @returns {object|null}
 */
export function getInputMetadata(element) {
  return buildInputMetadata(element);
}

/**
 * Determine whether the supplied element is a supported input.
 *
 * @param {Element|null} element
 * @returns {boolean}
 */
export function isSupportedInput(element) {
  return isEditableElement(element);
}

/**
 * Determine whether an element is a likely action control.
 *
 * @param {Element|null} element
 * @returns {boolean}
 */
export function isActionControl(element) {
  return Boolean(
    element &&
    isLikelySubmitAction(element)
  );
}

/**
 * Determine whether an element is likely a search control.
 *
 * @param {Element|null} element
 * @returns {boolean}
 */
export function isSearchControl(element) {
  return Boolean(
    element &&
    isLikelySearchAction(element)
  );
}

/**
 * Determine whether an element is likely a generation control.
 *
 * @param {Element|null} element
 * @returns {boolean}
 */
export function isGenerateControl(element) {
  return Boolean(
    element &&
    isLikelyGenerateAction(element)
  );
}

/**
 * Find all currently tracked editable elements.
 *
 * @returns {Element[]}
 */
export function getTrackedInputs() {
  cleanupDisconnectedElements();

  return Array.from(state.trackedInputs);
}

/**
 * Find all currently tracked action elements.
 *
 * @returns {Element[]}
 */
export function getTrackedActions() {
  cleanupDisconnectedElements();

  return Array.from(state.trackedActions);
}

/**
 * Return the current composition state.
 *
 * @returns {object}
 */
export function getCompositionState() {
  return {
    active: state.compositionActive,
    target: state.compositionTarget,
    targetMetadata: buildInputMetadata(
      state.compositionTarget
    )
  };
}

/**
 * Return monitor diagnostics.
 *
 * This contains only operational metadata and counters.
 * No input values are included.
 *
 * @returns {object}
 */
export function getInputMonitorDiagnostics() {
  cleanupDisconnectedElements();

  return {
    initialized: state.initialized,
    destroyed: state.destroyed,

    trackedInputs: state.trackedInputs.size,
    trackedActions: state.trackedActions.size,

    activeInput: Boolean(getActiveInput()),

    compositionActive: state.compositionActive,

    lastInputTimestamp: state.lastInputTimestamp,
    lastInputEventType: state.lastInputEventType,

    lastActionTimestamp: state.lastActionTimestamp,

    protection: {
      paste: Boolean(INPUT_PROTECTION.paste),
      drop: Boolean(INPUT_PROTECTION.drop),
      upload: Boolean(INPUT_PROTECTION.upload),
      formSubmit: Boolean(INPUT_PROTECTION.formSubmit),
      sendButton: Boolean(INPUT_PROTECTION.sendButton),
      keyboardSubmit: Boolean(INPUT_PROTECTION.keyboardSubmit),
      searchSubmit: Boolean(INPUT_PROTECTION.searchSubmit),
      liveTypingScan: Boolean(INPUT_PROTECTION.liveTypingScan),
      liveScanDebounceMs:
        INPUT_PROTECTION.liveScanDebounceMs
    },

    defaults: {
      protectionEnabled:
        Boolean(PROTECTION_DEFAULTS.enabled),
      protectAIPlatforms:
        Boolean(PROTECTION_DEFAULTS.protectAIPlatforms),
      protectSearchEngines:
        Boolean(PROTECTION_DEFAULTS.protectSearchEngines),
      protectCodingPlatforms:
        Boolean(PROTECTION_DEFAULTS.protectCodingPlatforms)
    },

    stats: {
      ...state.stats
    }
  };
}

/**
 * Manually rescan the DOM for newly created controls.
 *
 * @returns {object}
 */
export function refreshInputMonitor() {
  if (state.destroyed) {
    return getInputMonitorDiagnostics();
  }

  if (document.documentElement) {
    scanRoot(document.documentElement);
  }

  cleanupDisconnectedElements();

  return getInputMonitorDiagnostics();
}

/**
 * Return whether live typing scanning should currently be requested.
 *
 * This is intentionally separate from actual scanning.
 *
 * @returns {boolean}
 */
export function isLiveTypingScanEnabled() {
  return Boolean(INPUT_PROTECTION.liveTypingScan);
}

/**
 * Return the most recent input event metadata.
 *
 * @returns {object}
 */
export function getLastInputActivity() {
  return {
    timestamp: state.lastInputTimestamp,
    eventType: state.lastInputEventType,
    activeInput: getActiveInputMetadata()
  };
}

/**
 * Return whether the monitor has been initialized.
 *
 * @returns {boolean}
 */
export function isInputMonitorInitialized() {
  return state.initialized && !state.destroyed;
}

/**
 * Return a compact event source classification for the active page.
 *
 * @returns {string}
 */
export function getCurrentInputContext() {
  if (isCurrentSearchPlatform()) {
    return SOURCE_TYPES.SEARCH;
  }

  if (
    isCurrentAIPlatform() ||
    isCurrentCodingPlatform()
  ) {
    return SOURCE_TYPES.TYPING;
  }

  return SOURCE_TYPES.UNKNOWN;
}
