/**
 * SanitizerPro
 * Paste Monitor
 *
 * Responsibilities:
 * - Intercept paste operations on supported editable controls.
 * - Read clipboard text locally from ClipboardEvent.clipboardData.
 * - Never send clipboard contents to the service worker.
 * - Enforce configured clipboard/text size limits.
 * - Delegate scanning/policy decisions to the content orchestration layer.
 * - Support ALLOW, WARN, MASK, and BLOCK decisions.
 * - Safely reinsert approved or masked text when the original paste is
 *   prevented.
 *
 * Privacy:
 * - Clipboard contents remain inside the content-script execution context.
 * - Clipboard contents are never persisted.
 * - Clipboard contents are never logged.
 * - Clipboard contents are never sent to chrome.runtime messaging.
 * - No clipboardRead extension permission is required.
 *
 * Integration:
 *
 * initializePasteMonitor({
 *   onPaste: async (payload) => {
 *     return {
 *       action: "allow" | "warn" | "mask" | "block",
 *       replacementText: "...",
 *       warningAcknowledged: true
 *     };
 *   }
 * });
 *
 * The scanner/policy engine will be integrated by content.js later.
 */

import {
  INPUT_PROTECTION,
  SCAN_LIMITS,
  PROTECTION_DEFAULTS,
  ACTIONS
} from "../config/defaults.js";

import {
  EVENT_TYPES,
  SOURCE_TYPES
} from "../config/constants.js";

import {
  getActiveInput,
  getInputMetadata,
  isSupportedInput
} from "./input-monitor.js";

/* -------------------------------------------------------------------------- */
/* Configuration                                                               */
/* -------------------------------------------------------------------------- */

const CONFIG = Object.freeze({
  /*
   * Maximum clipboard text handled by this module.
   *
   * This must never exceed the global scanner limit.
   */
  maxClipboardCharacters:
    Number.isFinite(SCAN_LIMITS.maxClipboardCharacters)
      ? SCAN_LIMITS.maxClipboardCharacters
      : 250000,

  /*
   * Maximum metadata lengths.
   */
  maxMimeTypeLength: 100,
  maxTextTypeLength: 100,

  /*
   * Timeout protects the page from a broken asynchronous policy callback.
   *
   * This is intentionally short because the paste operation is blocked
   * while policy evaluation is pending.
   */
  decisionTimeoutMs: 5000,

  /*
   * Maximum amount of time allowed for a duplicate-event suppression window.
   */
  duplicateWindowMs: 100,

  /*
   * Supported text MIME types.
   */
  textMimeTypes: new Set([
    "text/plain",
    "text/csv",
    "text/tab-separated-values",
    "text/html",
    "application/json",
    "application/xml",
    "text/xml"
  ]),

  /*
   * HTML paste is never directly inserted as trusted HTML by SanitizerPro.
   *
   * If HTML is required later, it must pass through a dedicated sanitizer.
   */
  allowHtmlInsertion: false,

  /*
   * Controls that are definitely not intended for text pasting.
   */
  excludedInputTypes: new Set([
    "password",
    "hidden",
    "file",
    "number",
    "date",
    "datetime-local",
    "month",
    "time",
    "week",
    "color",
    "range",
    "checkbox",
    "radio",
    "button",
    "submit",
    "reset"
  ])
});

/* -------------------------------------------------------------------------- */
/* Internal state                                                              */
/* -------------------------------------------------------------------------- */

const state = {
  initialized: false,
  destroyed: false,

  listeners: [],

  callbacks: {
    onPaste: null,
    onDecision: null,
    onBlocked: null,
    onWarning: null,
    onMasked: null,
    onAllowed: null,
    onError: null
  },

  stats: {
    pasteEvents: 0,
    supportedPasteEvents: 0,
    ignoredPasteEvents: 0,
    oversizedPasteEvents: 0,
    emptyPasteEvents: 0,
    decisionRequests: 0,
    allowed: 0,
    warned: 0,
    masked: 0,
    blocked: 0,
    errors: 0,
    reinsertionAttempts: 0,
    reinsertionFailures: 0
  },

  lastPasteTimestamp: 0,
  lastPasteSessionId: "",
  processing: false,
  processingPromise: null
};

/* -------------------------------------------------------------------------- */
/* Safe utilities                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Debug logging.
 *
 * Raw clipboard data must never be logged.
 *
 * @param {string} message
 * @param {unknown} details
 */
function safeDebug(message, details = undefined) {
  if (!globalThis?.SANITIZERPRO_DEBUG) {
    return;
  }

  try {
    if (details === undefined) {
      console.debug("[SanitizerPro][PasteMonitor]", message);
      return;
    }

    console.debug(
      "[SanitizerPro][PasteMonitor]",
      message,
      details
    );
  } catch {
    // Ignore logging failures.
  }
}

/**
 * Safely invoke a callback.
 *
 * @param {Function|null} callback
 * @param  {...unknown} args
 * @returns {unknown}
 */
function invokeCallback(callback, ...args) {
  if (typeof callback !== "function") {
    return undefined;
  }

  try {
    return callback(...args);
  } catch (error) {
    safeDebug("Callback failed", {
      name: error?.name || "Error"
    });

    return undefined;
  }
}

/**
 * Safely invoke an async callback.
 *
 * @param {Function|null} callback
 * @param  {...unknown} args
 * @returns {Promise<unknown>}
 */
async function invokeAsyncCallback(callback, ...args) {
  if (typeof callback !== "function") {
    return undefined;
  }

  try {
    return await callback(...args);
  } catch (error) {
    safeDebug("Async callback failed", {
      name: error?.name || "Error"
    });

    return undefined;
  }
}

/**
 * Normalize a safe metadata string.
 *
 * @param {*} value
 * @param {number} maxLength
 * @returns {string}
 */
function safeString(value, maxLength = 160) {
  if (typeof value !== "string") {
    return "";
  }

  return value
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

/**
 * Create a small in-memory request identifier.
 *
 * @returns {string}
 */
function createPasteRequestId() {
  const randomPart = Math.random()
    .toString(36)
    .slice(2, 12);

  return `paste-${Date.now().toString(36)}-${randomPart}`;
}

/* -------------------------------------------------------------------------- */
/* Input validation                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Determine whether the current protection configuration allows paste
 * monitoring.
 *
 * @returns {boolean}
 */
function isPasteProtectionEnabled() {
  if (!PROTECTION_DEFAULTS.enabled) {
    return false;
  }

  return Boolean(INPUT_PROTECTION.paste);
}

/**
 * Determine whether an input element can safely receive text.
 *
 * @param {Element|null} element
 * @returns {boolean}
 */
function isPasteTargetSupported(element) {
  if (!isSupportedInput(element)) {
    return false;
  }

  if (
    element instanceof HTMLInputElement &&
    CONFIG.excludedInputTypes.has(
      element.type.toLowerCase()
    )
  ) {
    return false;
  }

  if (
    element.hasAttribute("disabled") ||
    element.getAttribute("aria-disabled") === "true"
  ) {
    return false;
  }

  if (
    element.hasAttribute("readonly") ||
    element.getAttribute("aria-readonly") === "true"
  ) {
    return false;
  }

  return true;
}

/**
 * Resolve the actual paste target.
 *
 * @param {EventTarget|null} target
 * @returns {Element|null}
 */
function resolvePasteTarget(target) {
  if (!(target instanceof Element)) {
    return null;
  }

  if (isPasteTargetSupported(target)) {
    return target;
  }

  /*
   * contenteditable applications commonly dispatch the event from a child
   * span/div rather than the editable root.
   */
  const closestEditable = target.closest(
    [
      "textarea",
      "input:not([type='password'])",
      "[contenteditable='true']",
      "[contenteditable='plaintext-only']",
      "[role='textbox']"
    ].join(",")
  );

  if (
    closestEditable &&
    isPasteTargetSupported(closestEditable)
  ) {
    return closestEditable;
  }

  /*
   * Fall back to the active input tracked by input-monitor.js.
   */
  const activeInput = getActiveInput();

  if (isPasteTargetSupported(activeInput)) {
    return activeInput;
  }

  return null;
}

/* -------------------------------------------------------------------------- */
/* Clipboard extraction                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Determine whether a clipboard DataTransfer object contains text.
 *
 * @param {DataTransfer|null} clipboardData
 * @returns {boolean}
 */
function hasTextClipboardData(clipboardData) {
  if (!clipboardData) {
    return false;
  }

  try {
    if (
      typeof clipboardData.types?.includes === "function" &&
      clipboardData.types.includes("text/plain")
    ) {
      return true;
    }

    if (
      typeof clipboardData.getData === "function"
    ) {
      const text = clipboardData.getData("text/plain");

      return typeof text === "string" && text.length > 0;
    }
  } catch {
    return false;
  }

  return false;
}

/**
 * Extract plain text from the clipboard.
 *
 * IMPORTANT:
 * - This is the only point where clipboard text is read.
 * - The returned text remains local.
 * - No logging occurs.
 *
 * @param {ClipboardEvent} event
 * @returns {{success: boolean, text: string, mimeType: string, error: string}}
 */
function extractClipboardText(event) {
  if (!(event instanceof ClipboardEvent)) {
    return {
      success: false,
      text: "",
      mimeType: "",
      error: "invalid_event"
    };
  }

  const clipboardData = event.clipboardData;

  if (!clipboardData) {
    return {
      success: false,
      text: "",
      mimeType: "",
      error: "clipboard_data_unavailable"
    };
  }

  try {
    const types = Array.from(
      clipboardData.types || []
    );

    /*
     * Prefer plain text.
     *
     * We intentionally do not trust text/html directly.
     */
    if (types.includes("text/plain")) {
      const text = clipboardData.getData("text/plain");

      if (typeof text !== "string") {
        return {
          success: false,
          text: "",
          mimeType: "text/plain",
          error: "invalid_text_data"
        };
      }

      return {
        success: true,
        text,
        mimeType: "text/plain",
        error: ""
      };
    }

    /*
     * Some browsers/pages expose text/plain through getData even when the
     * type list is incomplete.
     */
    const fallbackText =
      clipboardData.getData("text/plain");

    if (
      typeof fallbackText === "string" &&
      fallbackText.length > 0
    ) {
      return {
        success: true,
        text: fallbackText,
        mimeType: "text/plain",
        error: ""
      };
    }

    /*
     * Do not automatically insert HTML.
     *
     * HTML may contain:
     * - markup
     * - tracking payloads
     * - links
     * - event attributes
     * - embedded content
     *
     * A later dedicated rich-content sanitizer can handle this.
     */
    if (types.includes("text/html")) {
      return {
        success: false,
        text: "",
        mimeType: "text/html",
        error: "plain_text_unavailable"
      };
    }

    return {
      success: false,
      text: "",
      mimeType: "",
      error: "no_supported_text_type"
    };
  } catch (error) {
    return {
      success: false,
      text: "",
      mimeType: "",
      error:
        error?.name === "SecurityError"
          ? "clipboard_security_error"
          : "clipboard_read_failed"
    };
  }
}

/**
 * Check whether the clipboard text exceeds the configured limit.
 *
 * @param {string} text
 * @returns {boolean}
 */
function isClipboardTextOversized(text) {
  return (
    typeof text === "string" &&
    text.length > CONFIG.maxClipboardCharacters
  );
}

/* -------------------------------------------------------------------------- */
/* Event metadata                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Build safe paste metadata.
 *
 * The actual clipboard text is intentionally not included here.
 *
 * @param {Element} target
 * @param {object} clipboardInfo
 * @param {string} requestId
 * @returns {object}
 */
function buildPasteMetadata(
  target,
  clipboardInfo,
  requestId
) {
  const inputMetadata = getInputMetadata(target);

  return {
    requestId,

    eventType: EVENT_TYPES.PASTE_DETECTED,
    sourceType: SOURCE_TYPES.PASTE,

    timestamp: Date.now(),

    input: inputMetadata,

    clipboard: {
      mimeType: safeString(
        clipboardInfo.mimeType,
        CONFIG.maxMimeTypeLength
      ),

      /*
       * Length is metadata only. The actual clipboard content is not stored
       * here.
       */
      characterCount:
        typeof clipboardInfo.text === "string"
          ? clipboardInfo.text.length
          : 0
    }
  };
}

/* -------------------------------------------------------------------------- */
/* Decision normalization                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Normalize a policy action.
 *
 * @param {*} action
 * @returns {string}
 */
function normalizeAction(action) {
  if (typeof action !== "string") {
    return ACTIONS.ALLOW;
  }

  const normalized = action.toLowerCase();

  switch (normalized) {
    case ACTIONS.ALLOW:
      return ACTIONS.ALLOW;

    case ACTIONS.WARN:
      return ACTIONS.WARN;

    case ACTIONS.MASK:
      return ACTIONS.MASK;

    case ACTIONS.BLOCK:
      return ACTIONS.BLOCK;

    default:
      return ACTIONS.ALLOW;
  }
}

/**
 * Normalize a policy callback response.
 *
 * Supported response examples:
 *
 * {
 *   action: "allow"
 * }
 *
 * {
 *   action: "mask",
 *   replacementText: "[REDACTED]"
 * }
 *
 * {
 *   action: "warn",
 *   warningAcknowledged: true
 * }
 *
 * @param {*} decision
 * @param {string} originalText
 * @returns {object}
 */
function normalizeDecision(decision, originalText) {
  /*
   * A missing callback result means the higher-level layer has not yet
   * implemented policy evaluation. In that situation, allow the paste
   * instead of silently deleting user data.
   */
  if (!decision || typeof decision !== "object") {
    return {
      action: ACTIONS.ALLOW,
      replacementText: originalText,
      warningAcknowledged: false,
      reason: "no_policy_decision"
    };
  }

  const action = normalizeAction(decision.action);

  let replacementText = originalText;

  if (
    action === ACTIONS.MASK &&
    typeof decision.replacementText === "string"
  ) {
    replacementText = decision.replacementText;
  }

  return {
    action,

    replacementText,

    warningAcknowledged:
      decision.warningAcknowledged === true,

    reason:
      safeString(
        decision.reason,
        200
      ) || "policy_decision",

    findingCount:
      Number.isFinite(decision.findingCount)
        ? Math.max(0, decision.findingCount)
        : 0,

    riskScore:
      Number.isFinite(decision.riskScore)
        ? Math.max(0, Math.min(100, decision.riskScore))
        : null
  };
}

/* -------------------------------------------------------------------------- */
/* Decision timeout                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Race a policy decision against a timeout.
 *
 * On timeout we fail open by default so that a broken callback does not
 * destroy user input. Enterprise/block-by-default behavior can be introduced
 * later through explicit configuration.
 *
 * @param {Promise<unknown>} promise
 * @returns {Promise<unknown>}
 */
async function withDecisionTimeout(promise) {
  const timeoutMs =
    Number.isFinite(CONFIG.decisionTimeoutMs) &&
    CONFIG.decisionTimeoutMs > 0
      ? CONFIG.decisionTimeoutMs
      : 5000;

  let timeoutId = null;

  try {
    const timeoutPromise = new Promise((resolve) => {
      timeoutId = globalThis.setTimeout(() => {
        resolve({
          action: ACTIONS.ALLOW,
          replacementText: null,
          warningAcknowledged: false,
          reason: "policy_timeout"
        });
      }, timeoutMs);
    });

    return await Promise.race([
      promise,
      timeoutPromise
    ]);
  } finally {
    if (timeoutId !== null) {
      globalThis.clearTimeout(timeoutId);
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Text insertion                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Dispatch a safe input/change event after programmatic insertion.
 *
 * @param {Element} element
 */
function dispatchInputEvent(element) {
  try {
    element.dispatchEvent(
      new InputEvent("input", {
        bubbles: true,
        cancelable: false,
        inputType: "insertFromPaste",
        data: null
      })
    );
  } catch {
    try {
      element.dispatchEvent(
        new Event("input", {
          bubbles: true,
          cancelable: false
        })
      );
    } catch {
      // Ignore event dispatch failures.
    }
  }
}

/**
 * Set the value of a native input/textarea while preserving the framework's
 * normal property setter behavior as much as possible.
 *
 * @param {HTMLInputElement|HTMLTextAreaElement} element
 * @param {string} text
 * @returns {boolean}
 */
function setNativeTextValue(element, text) {
  if (
    !(
      element instanceof HTMLInputElement ||
      element instanceof HTMLTextAreaElement
    )
  ) {
    return false;
  }

  try {
    const prototype =
      element instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement.prototype
        : HTMLInputElement.prototype;

    const descriptor =
      Object.getOwnPropertyDescriptor(
        prototype,
        "value"
      );

    if (descriptor?.set) {
      descriptor.set.call(element, text);
    } else {
      element.value = text;
    }

    dispatchInputEvent(element);

    return true;
  } catch {
    return false;
  }
}

/**
 * Get the current selection range for a contenteditable element.
 *
 * @returns {Range|null}
 */
function getCurrentSelectionRange() {
  try {
    const selection =
      globalThis.getSelection?.();

    if (!selection || selection.rangeCount === 0) {
      return null;
    }

    return selection.getRangeAt(0);
  } catch {
    return null;
  }
}

/**
 * Insert text into a contenteditable element.
 *
 * We use execCommand("insertText") where available because it gives modern
 * web editors a better opportunity to process the insertion through their
 * normal input pipeline.
 *
 * No arbitrary HTML is inserted.
 *
 * @param {Element} element
 * @param {string} text
 * @returns {boolean}
 */
function insertContentEditableText(element, text) {
  if (
    !(
      element instanceof Element &&
      element.isContentEditable
    )
  ) {
    return false;
  }

  try {
    element.focus();

    const selectionRange =
      getCurrentSelectionRange();

    if (
      selectionRange &&
      !element.contains(selectionRange.commonAncestorContainer)
    ) {
      /*
       * Selection belongs to another element.
       * Do not accidentally modify it.
       */
      return false;
    }

    /*
     * Only plain text is inserted.
     */
    if (
      typeof document.execCommand === "function"
    ) {
      const success = document.execCommand(
        "insertText",
        false,
        text
      );

      if (success) {
        return true;
      }
    }

    /*
     * Fallback for contenteditable implementations where execCommand is
     * unavailable.
     */
    const range =
      selectionRange ||
      document.createRange();

    if (!selectionRange) {
      range.selectNodeContents(element);
      range.collapse(false);
    }

    range.deleteContents();

    const textNode =
      document.createTextNode(text);

    range.insertNode(textNode);

    range.setStartAfter(textNode);
    range.collapse(true);

    const selection =
      globalThis.getSelection?.();

    if (selection) {
      selection.removeAllRanges();
      selection.addRange(range);
    }

    dispatchInputEvent(element);

    return true;
  } catch {
    return false;
  }
}

/**
 * Insert text into an ARIA textbox/contenteditable implementation.
 *
 * @param {Element} element
 * @param {string} text
 * @returns {boolean}
 */
function insertTextIntoElement(element, text) {
  if (!element) {
    return false;
  }

  /*
   * Native text controls.
   */
  if (
    element instanceof HTMLInputElement ||
    element instanceof HTMLTextAreaElement
  ) {
    return setNativeTextValue(element, text);
  }

  /*
   * Contenteditable.
   */
  if (
    element instanceof Element &&
    element.isContentEditable
  ) {
    return insertContentEditableText(
      element,
      text
    );
  }

  /*
   * Some applications expose role="textbox" on a contenteditable root.
   */
  if (
    element instanceof Element &&
    element.getAttribute("role")?.toLowerCase() ===
      "textbox"
  ) {
    if (element.isContentEditable) {
      return insertContentEditableText(
        element,
        text
      );
    }
  }

  return false;
}

/**
 * Reinsert approved/masked text.
 *
 * @param {Element} target
 * @param {string} text
 * @returns {boolean}
 */
function reinsertText(target, text) {
  if (
    !(target instanceof Element) ||
    typeof text !== "string"
  ) {
    return false;
  }

  state.stats.reinsertionAttempts += 1;

  const success = insertTextIntoElement(
    target,
    text
  );

  if (!success) {
    state.stats.reinsertionFailures += 1;
  }

  return success;
}

/* -------------------------------------------------------------------------- */
/* Warning handling                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Ask the higher-level layer to handle a warning.
 *
 * The warning handler can return:
 *
 * {
 *   acknowledged: true
 * }
 *
 * or:
 *
 * {
 *   action: "allow"
 * }
 *
 * or:
 *
 * {
 *   action: "block"
 * }
 *
 * @param {object} payload
 * @returns {Promise<object>}
 */
async function handleWarning(payload) {
  const result =
    await invokeAsyncCallback(
      state.callbacks.onWarning,
      payload
    );

  if (
    result &&
    typeof result === "object"
  ) {
    return result;
  }

  /*
   * If no warning UI exists yet, default to blocking the paste.
   *
   * This is safer than allowing detected sensitive data to leave the browser
   * while the warning subsystem is incomplete.
   */
  return {
    action: ACTIONS.BLOCK,
    warningAcknowledged: false,
    reason: "warning_handler_unavailable"
  };
}

/* -------------------------------------------------------------------------- */
/* Policy evaluation                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Evaluate a paste through the configured callback.
 *
 * @param {object} payload
 * @param {string} text
 * @returns {Promise<object>}
 */
async function evaluatePaste(payload, text) {
  state.stats.decisionRequests += 1;

  /*
   * No callback means scanning/policy is not connected yet.
   *
   * Fail open during development so the monitor does not destroy normal
   * browser behavior before scanner.js and policy-engine.js are connected.
   */
  if (typeof state.callbacks.onPaste !== "function") {
    return {
      action: ACTIONS.ALLOW,
      replacementText: text,
      warningAcknowledged: false,
      reason: "scanner_not_connected"
    };
  }

  const callbackPromise =
    invokeAsyncCallback(
      state.callbacks.onPaste,
      {
        ...payload,

        /*
         * The clipboard text is available only to this local callback.
         *
         * content.js must NOT forward this field to chrome.runtime.sendMessage.
         */
        text
      }
    );

  const rawDecision =
    await withDecisionTimeout(
      Promise.resolve(callbackPromise)
    );

  return normalizeDecision(
    rawDecision,
    text
  );
}

/* -------------------------------------------------------------------------- */
/* Action execution                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Execute the selected paste policy.
 *
 * @param {ClipboardEvent} event
 * @param {Element} target
 * @param {string} text
 * @param {object} payload
 * @param {object} initialDecision
 * @returns {Promise<object>}
 */
async function executeDecision(
  event,
  target,
  text,
  payload,
  initialDecision
) {
  let decision = normalizeDecision(
    initialDecision,
    text
  );

  /*
   * ALLOW
   */
  if (decision.action === ACTIONS.ALLOW) {
    state.stats.allowed += 1;

    /*
     * If the original event has already been prevented, manually reinsert.
     */
    if (event.defaultPrevented) {
      const inserted = reinsertText(
        target,
        text
      );

      if (!inserted) {
        state.stats.errors += 1;

        invokeCallback(
          state.callbacks.onError,
          {
            type: "paste_reinsertion_failed",
            requestId: payload.requestId,
            action: ACTIONS.ALLOW
          }
        );
      }
    }

    invokeCallback(
      state.callbacks.onAllowed,
      {
        ...payload,
        action: ACTIONS.ALLOW
      }
    );

    invokeCallback(
      state.callbacks.onDecision,
      {
        ...payload,
        action: ACTIONS.ALLOW
      }
    );

    return decision;
  }

  /*
   * WARN
   *
   * Warning handling is delegated to the higher-level UI layer.
   */
  if (decision.action === ACTIONS.WARN) {
    state.stats.warned += 1;

    const warningResult =
      await handleWarning({
        ...payload,
        action: ACTIONS.WARN,
        findingCount: decision.findingCount,
        riskScore: decision.riskScore,
        reason: decision.reason
      });

    const warningAction =
      normalizeAction(
        warningResult?.action
      );

    /*
     * User/application explicitly allows after warning.
     */
    if (
      warningAction === ACTIONS.ALLOW ||
      warningResult?.warningAcknowledged === true
    ) {
      const inserted =
        event.defaultPrevented
          ? reinsertText(target, text)
          : true;

      if (!inserted) {
        state.stats.errors += 1;

        invokeCallback(
          state.callbacks.onError,
          {
            type: "paste_reinsertion_failed",
            requestId: payload.requestId,
            action: ACTIONS.WARN
          }
        );
      }

      invokeCallback(
        state.callbacks.onAllowed,
        {
          ...payload,
          action: ACTIONS.WARN,
          warningAcknowledged: true
        }
      );

      invokeCallback(
        state.callbacks.onDecision,
        {
          ...payload,
          action: ACTIONS.WARN,
          warningAcknowledged: true
        }
      );

      return {
        ...decision,
        action: ACTIONS.ALLOW,
        warningAcknowledged: true
      };
    }

    /*
     * User/application chooses masking after warning.
     */
    if (warningAction === ACTIONS.MASK) {
      const replacementText =
        typeof warningResult?.replacementText ===
        "string"
          ? warningResult.replacementText
          : decision.replacementText;

      const inserted =
        reinsertText(
          target,
          replacementText
        );

      if (!inserted) {
        state.stats.errors += 1;

        invokeCallback(
          state.callbacks.onError,
          {
            type: "paste_reinsertion_failed",
            requestId: payload.requestId,
            action: ACTIONS.MASK
          }
        );
      }

      state.stats.masked += 1;

      invokeCallback(
        state.callbacks.onMasked,
        {
          ...payload,
          action: ACTIONS.MASK
        }
      );

      invokeCallback(
        state.callbacks.onDecision,
        {
          ...payload,
          action: ACTIONS.MASK
        }
      );

      return {
        ...decision,
        action: ACTIONS.MASK,
        replacementText
      };
    }

    /*
     * Anything else means the warning did not receive explicit approval.
     */
    state.stats.blocked += 1;

    invokeCallback(
      state.callbacks.onBlocked,
      {
        ...payload,
        action: ACTIONS.BLOCK,
        reason:
          warningResult?.reason ||
          "warning_not_acknowledged"
      }
    );

    invokeCallback(
      state.callbacks.onDecision,
      {
        ...payload,
        action: ACTIONS.BLOCK,
        reason:
          warningResult?.reason ||
          "warning_not_acknowledged"
      }
    );

    return {
      ...decision,
      action: ACTIONS.BLOCK,
      reason:
        warningResult?.reason ||
        "warning_not_acknowledged"
    };
  }

  /*
   * MASK
   */
  if (decision.action === ACTIONS.MASK) {
    const replacementText =
      typeof decision.replacementText === "string"
        ? decision.replacementText
        : "";

    const inserted =
      reinsertText(
        target,
        replacementText
      );

    if (!inserted) {
      state.stats.errors += 1;

      invokeCallback(
        state.callbacks.onError,
        {
          type: "paste_reinsertion_failed",
          requestId: payload.requestId,
          action: ACTIONS.MASK
        }
      );
    }

    state.stats.masked += 1;

    invokeCallback(
      state.callbacks.onMasked,
      {
        ...payload,
        action: ACTIONS.MASK
      }
    );

    invokeCallback(
      state.callbacks.onDecision,
      {
        ...payload,
        action: ACTIONS.MASK
      }
    );

    return {
      ...decision,
      replacementText
    };
  }

  /*
   * BLOCK
   */
  if (decision.action === ACTIONS.BLOCK) {
    state.stats.blocked += 1;

    invokeCallback(
      state.callbacks.onBlocked,
      {
        ...payload,
        action: ACTIONS.BLOCK,
        reason: decision.reason
      }
    );

    invokeCallback(
      state.callbacks.onDecision,
      {
        ...payload,
        action: ACTIONS.BLOCK,
        reason: decision.reason
      }
    );

    return decision;
  }

  /*
   * Defensive fallback.
   */
  state.stats.allowed += 1;

  if (event.defaultPrevented) {
    reinsertText(target, text);
  }

  return {
    ...decision,
    action: ACTIONS.ALLOW,
    reason: "defensive_allow"
  };
}

/* -------------------------------------------------------------------------- */
/* Paste event handling                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Handle a paste event.
 *
 * @param {ClipboardEvent} event
 */
async function handlePaste(event) {
  if (state.destroyed) {
    return;
  }

  state.stats.pasteEvents += 1;

  /*
   * Protection disabled.
   *
   * Do not intercept the paste.
   */
  if (!isPasteProtectionEnabled()) {
    state.stats.ignoredPasteEvents += 1;
    return;
  }

  const target =
    resolvePasteTarget(event.target);

  if (!target) {
    state.stats.ignoredPasteEvents += 1;
    return;
  }

  /*
   * Prevent overlapping policy evaluations from racing each other.
   */
  if (state.processing) {
    state.stats.ignoredPasteEvents += 1;

    /*
     * Do not block a legitimate browser paste just because another paste
     * evaluation is running.
     */
    return;
  }

  const clipboardInfo =
    extractClipboardText(event);

  if (!clipboardInfo.success) {
    state.stats.ignoredPasteEvents += 1;

    invokeCallback(
      state.callbacks.onError,
      {
        type: "paste_extraction_failed",
        error: clipboardInfo.error,
        mimeType: clipboardInfo.mimeType
      }
    );

    /*
     * Do not preventDefault here. If we cannot obtain the clipboard data,
     * normal browser behavior continues.
     */
    return;
  }

  const text = clipboardInfo.text;

  if (!text) {
    state.stats.emptyPasteEvents += 1;
    return;
  }

  /*
   * Oversized content is not silently truncated.
   *
   * Truncating before scanning could allow a sensitive value near the
   * truncated boundary to escape detection.
   */
  if (isClipboardTextOversized(text)) {
    state.stats.oversizedPasteEvents += 1;

    /*
     * Oversized clipboard data is blocked because the configured scanner
     * cannot guarantee complete inspection.
     */
    event.preventDefault();

    const requestId =
      createPasteRequestId();

    const payload =
      buildPasteMetadata(
        target,
        clipboardInfo,
        requestId
      );

    invokeCallback(
      state.callbacks.onBlocked,
      {
        ...payload,
        action: ACTIONS.BLOCK,
        reason: "clipboard_size_exceeded"
      }
    );

    invokeCallback(
      state.callbacks.onDecision,
      {
        ...payload,
        action: ACTIONS.BLOCK,
        reason: "clipboard_size_exceeded"
      }
    );

    state.stats.blocked += 1;

    return;
  }

  const now = Date.now();

  /*
   * Suppress duplicate paste events occasionally produced by host-page
   * wrappers without permanently disabling paste monitoring.
   */
  if (
    state.lastPasteSessionId &&
    now - state.lastPasteTimestamp <
      CONFIG.duplicateWindowMs
  ) {
    state.stats.ignoredPasteEvents += 1;
    return;
  }

  const requestId =
    createPasteRequestId();

  state.lastPasteTimestamp = now;
  state.lastPasteSessionId = requestId;

  const payload =
    buildPasteMetadata(
      target,
      clipboardInfo,
      requestId
    );

  state.stats.supportedPasteEvents += 1;

  /*
   * The policy layer needs the paste to be held while scanning.
   */
  event.preventDefault();

  state.processing = true;

  const processingPromise =
    (async () => {
      try {
        const decision =
          await evaluatePaste(
            payload,
            text
          );

        return await executeDecision(
          event,
          target,
          text,
          payload,
          decision
        );
      } catch (error) {
        state.stats.errors += 1;

        safeDebug(
          "Paste processing failed",
          {
            name:
              error?.name ||
              "Error"
          }
        );

        /*
         * Fail closed for an already intercepted paste.
         *
         * We do not silently insert unscanned data after a processing error.
         */
        state.stats.blocked += 1;

        invokeCallback(
          state.callbacks.onBlocked,
          {
            ...payload,
            action: ACTIONS.BLOCK,
            reason: "paste_processing_error"
          }
        );

        invokeCallback(
          state.callbacks.onError,
          {
            type: "paste_processing_error",
            requestId,
            action: ACTIONS.BLOCK,
            error:
              error?.name ||
              "Error"
          }
        );

        return {
          action: ACTIONS.BLOCK,
          reason: "paste_processing_error"
        };
      } finally {
        state.processing = false;
        state.processingPromise = null;
      }
    })();

  state.processingPromise =
    processingPromise;

  await processingPromise;
}

/* -------------------------------------------------------------------------- */
/* Event registration                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Register an event listener and remember it for cleanup.
 *
 * @param {EventTarget} target
 * @param {string} eventName
 * @param {EventListener} handler
 * @param {boolean|AddEventListenerOptions} options
 */
function addListener(
  target,
  eventName,
  handler,
  options = false
) {
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
 * Register paste handling.
 */
function registerListeners() {
  /*
   * Capture phase allows SanitizerPro to observe the paste before many
   * application-level handlers.
   */
  addListener(
    document,
    "paste",
    handlePaste,
    true
  );
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Initialize the paste monitor.
 *
 * @param {object} options
 * @returns {object}
 */
export function initializePasteMonitor(
  options = {}
) {
  if (
    state.initialized &&
    !state.destroyed
  ) {
    return getPasteMonitorDiagnostics();
  }

  state.destroyed = false;
  state.initialized = true;

  state.callbacks.onPaste =
    typeof options.onPaste === "function"
      ? options.onPaste
      : null;

  state.callbacks.onDecision =
    typeof options.onDecision === "function"
      ? options.onDecision
      : null;

  state.callbacks.onBlocked =
    typeof options.onBlocked === "function"
      ? options.onBlocked
      : null;

  state.callbacks.onWarning =
    typeof options.onWarning === "function"
      ? options.onWarning
      : null;

  state.callbacks.onMasked =
    typeof options.onMasked === "function"
      ? options.onMasked
      : null;

  state.callbacks.onAllowed =
    typeof options.onAllowed === "function"
      ? options.onAllowed
      : null;

  state.callbacks.onError =
    typeof options.onError === "function"
      ? options.onError
      : null;

  registerListeners();

  safeDebug("Paste monitor initialized");

  return getPasteMonitorDiagnostics();
}

/**
 * Destroy the paste monitor.
 */
export function destroyPasteMonitor() {
  if (!state.initialized) {
    return;
  }

  state.destroyed = true;

  for (const listener of state.listeners) {
    try {
      listener.target.removeEventListener(
        listener.eventName,
        listener.handler,
        listener.options
      );
    } catch {
      // Ignore cleanup failures.
    }
  }

  state.listeners.length = 0;

  state.callbacks.onPaste = null;
  state.callbacks.onDecision = null;
  state.callbacks.onBlocked = null;
  state.callbacks.onWarning = null;
  state.callbacks.onMasked = null;
  state.callbacks.onAllowed = null;
  state.callbacks.onError = null;

  state.processing = false;
  state.processingPromise = null;

  state.initialized = false;

  safeDebug("Paste monitor destroyed");
}

/**
 * Return whether the paste monitor is initialized.
 *
 * @returns {boolean}
 */
export function isPasteMonitorInitialized() {
  return (
    state.initialized &&
    !state.destroyed
  );
}

/**
 * Return whether paste protection is currently enabled.
 *
 * @returns {boolean}
 */
export function isPasteProtectionEnabledForMonitor() {
  return isPasteProtectionEnabled();
}

/**
 * Return whether the monitor is currently processing a paste.
 *
 * @returns {boolean}
 */
export function isPasteProcessing() {
  return state.processing;
}

/**
 * Wait for an active paste operation to complete.
 *
 * @returns {Promise<unknown>}
 */
export async function waitForPasteProcessing() {
  if (!state.processingPromise) {
    return null;
  }

  try {
    return await state.processingPromise;
  } catch {
    return null;
  }
}

/**
 * Return paste monitor diagnostics.
 *
 * No clipboard content is returned.
 *
 * @returns {object}
 */
export function getPasteMonitorDiagnostics() {
  return {
    initialized: state.initialized,
    destroyed: state.destroyed,

    protectionEnabled:
      isPasteProtectionEnabled(),

    processing:
      state.processing,

    configuration: {
      pasteProtection:
        Boolean(INPUT_PROTECTION.paste),

      maximumClipboardCharacters:
        CONFIG.maxClipboardCharacters,

      decisionTimeoutMs:
        CONFIG.decisionTimeoutMs,

      allowHtmlInsertion:
        CONFIG.allowHtmlInsertion
    },

    lastPaste: {
      timestamp:
        state.lastPasteTimestamp,

      /*
       * This is an in-memory request identifier only.
       */
      requestId:
        state.lastPasteSessionId
    },

    stats: {
      ...state.stats
    }
  };
}

/**
 * Extract text from a ClipboardEvent for internal callers.
 *
 * This function intentionally returns the actual text, so it should only be
 * called from content-script code that is part of the local scanning path.
 *
 * It must never be passed to chrome.runtime.sendMessage().
 *
 * @param {ClipboardEvent} event
 * @returns {object}
 */
export function getClipboardTextFromEvent(
  event
) {
  return extractClipboardText(event);
}

/**
 * Check whether clipboard text is within the configured scan boundary.
 *
 * @param {string} text
 * @returns {boolean}
 */
export function isClipboardTextWithinLimit(
  text
) {
  return (
    typeof text === "string" &&
    text.length <=
      CONFIG.maxClipboardCharacters
  );
}

/**
 * Manually insert approved or masked text into an editable target.
 *
 * This is intentionally exported for content.js and policy handlers.
 *
 * @param {Element} target
 * @param {string} text
 * @returns {boolean}
 */
export function insertPasteText(
  target,
  text
) {
  if (
    !isPasteTargetSupported(target)
  ) {
    return false;
  }

  if (
    typeof text !== "string"
  ) {
    return false;
  }

  return reinsertText(
    target,
    text
  );
}

/**
 * Return the maximum clipboard character limit.
 *
 * @returns {number}
 */
export function getMaximumClipboardCharacters() {
  return CONFIG.maxClipboardCharacters;
}

/**
 * Return the current paste protection configuration.
 *
 * @returns {object}
 */
export function getPasteProtectionConfig() {
  return {
    enabled:
      Boolean(PROTECTION_DEFAULTS.enabled),

    paste:
      Boolean(INPUT_PROTECTION.paste),

    maxClipboardCharacters:
      CONFIG.maxClipboardCharacters,

    decisionTimeoutMs:
      CONFIG.decisionTimeoutMs
  };
}
