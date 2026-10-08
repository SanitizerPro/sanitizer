import {
  SCAN_LIMITS,
  PROTECTION_DEFAULTS,
  ACTIONS
} from "../config/defaults.js";

import {
  EVENT_TYPES,
  SOURCE_TYPES
} from "../config/constants.js";

const FORM_SELECTOR = "form";

const SUBMIT_CONTROL_SELECTOR = [
  "button[type='submit']",
  "input[type='submit']",
  "button:not([type])",
  "[role='button']"
].join(",");

const TEXT_CONTROL_SELECTOR = [
  "textarea",
  "input:not([type='hidden'])",
  "input:not([type='password'])",
  "[contenteditable='true']",
  "[contenteditable='plaintext-only']",
  "[role='textbox']"
].join(",");

const EXCLUDED_INPUT_TYPES = new Set([
  "hidden",
  "password",
  "file",
  "submit",
  "button",
  "reset",
  "image",
  "checkbox",
  "radio",
  "range",
  "color"
]);

const SENSITIVE_CONTROL_ATTRIBUTES = Object.freeze([
  "data-private",
  "data-sensitive",
  "data-confidential"
]);

const state = {
  initialized: false,
  destroyed: false,

  config: {
    enabled: PROTECTION_DEFAULTS.enabled,
    scanSubmit: PROTECTION_DEFAULTS.scanSubmit,
    mode: PROTECTION_DEFAULTS.mode,

    defaultAction: ACTIONS.WARN,

    includeEmptyFields: false,

    includeNonTextControls: false,

    maximumFieldsPerForm: 100,

    maximumTextPerField:
      SCAN_LIMITS.maxTextCharacters,

    maximumTotalText:
      SCAN_LIMITS.maxTextCharacters
  },

  callbacks: {
    onSubmit: null,
    onWarning: null,
    onAllowed: null,
    onBlocked: null,
    onMasked: null,
    onError: null,
    onEvent: null
  },

  listeners: [],

  trackedForms: new Set(),

  /*
   * Forms that are intentionally allowed to continue.
   *
   * requestSubmit() generates another submit event, so a guard is
   * required to prevent SanitizerPro from recursively intercepting
   * its own approved submission.
   */
  approvedSubmissions: new WeakSet(),

  /*
   * Forms currently waiting for scanner/policy evaluation.
   */
  processingForms: new WeakSet(),

  /*
   * Prevent duplicate submit processing caused by applications
   * that trigger multiple submit-like events.
   */
  pendingOperations: new WeakMap(),

  counters: {
    formsDetected: 0,
    formsTracked: 0,

    submitEvents: 0,
    submitAttempts: 0,

    textFieldsDetected: 0,
    fieldsScanned: 0,

    allowedSubmissions: 0,
    warnedSubmissions: 0,
    maskedSubmissions: 0,
    blockedSubmissions: 0,

    emptySubmissions: 0,
    oversizedFields: 0,
    oversizedForms: 0,

    duplicateSubmissions: 0,
    recursiveSubmissions: 0,

    scannerUnavailable: 0,
    scannerFailures: 0,

    errors: 0
  }
};

function now() {
  return Date.now();
}

function createOperationId() {
  return `submit_${now()}_${Math.random()
    .toString(36)
    .slice(2, 10)}`;
}

function isObject(value) {
  return (
    value !== null &&
    typeof value === "object"
  );
}

function isElement(value) {
  return (
    value instanceof Element ||
    value instanceof HTMLElement ||
    value instanceof HTMLFormElement ||
    value instanceof HTMLInputElement ||
    value instanceof HTMLTextAreaElement ||
    value instanceof HTMLButtonElement
  );
}

function isConnectedElement(element) {
  return Boolean(
    element &&
    typeof element.isConnected === "boolean" &&
    element.isConnected
  );
}

function safeCallback(callback, payload) {
  if (typeof callback !== "function") {
    return undefined;
  }

  try {
    return callback(payload);
  } catch (error) {
    handleError(error, "callback");
    return undefined;
  }
}

function handleError(
  error,
  context = "unknown"
) {
  state.counters.errors += 1;

  const payload = {
    type: EVENT_TYPES.ERROR,
    sourceType: SOURCE_TYPES.SUBMIT,
    context,
    error:
      error instanceof Error
        ? error.message
        : String(error),
    timestamp: now()
  };

  safeCallback(
    state.callbacks.onError,
    payload
  );

  safeCallback(
    state.callbacks.onEvent,
    payload
  );
}

function emitEvent(
  type,
  payload = {}
) {
  const event = {
    type,
    sourceType: SOURCE_TYPES.SUBMIT,
    timestamp: now(),
    ...payload
  };

  safeCallback(
    state.callbacks.onEvent,
    event
  );

  return event;
}

function normalizeAction(action) {
  switch (action) {
    case ACTIONS.ALLOW:
    case ACTIONS.WARN:
    case ACTIONS.MASK:
    case ACTIONS.BLOCK:
      return action;

    default:
      return (
        state.config.defaultAction ||
        ACTIONS.WARN
      );
  }
}

function isExcludedInputType(
  input
) {
  if (!input) {
    return true;
  }

  const type = String(
    input.type || ""
  )
    .trim()
    .toLowerCase();

  return EXCLUDED_INPUT_TYPES.has(
    type
  );
}

function isDisabledControl(
  control
) {
  if (!control) {
    return true;
  }

  return Boolean(
    control.disabled ||
    control.readOnly ||
    control.hidden ||
    control.getAttribute?.(
      "aria-disabled"
    ) === "true"
  );
}

function isContentEditableControl(
  element
) {
  if (!element) {
    return false;
  }

  const value =
    element.getAttribute?.(
      "contenteditable"
    );

  return (
    value === "true" ||
    value === "plaintext-only"
  );
}

function isTextControl(
  element
) {
  if (!element) {
    return false;
  }

  if (
    isContentEditableControl(element)
  ) {
    return true;
  }

  if (
    element instanceof
    HTMLTextAreaElement
  ) {
    return true;
  }

  if (
    element instanceof
    HTMLInputElement
  ) {
    return !isExcludedInputType(
      element
    );
  }

  const role =
    element.getAttribute?.(
      "role"
    );

  return role === "textbox";
}

function isSensitiveMarkedControl(
  element
) {
  if (!element) {
    return false;
  }

  return SENSITIVE_CONTROL_ATTRIBUTES.some(
    (attribute) =>
      element.hasAttribute?.(
        attribute
      )
  );
}

function getElementLabel(
  element
) {
  if (!element) {
    return "";
  }

  const candidates = [
    element.getAttribute?.(
      "aria-label"
    ),
    element.getAttribute?.(
      "placeholder"
    ),
    element.getAttribute?.(
      "name"
    ),
    element.getAttribute?.(
      "id"
    ),
    element.getAttribute?.(
      "title"
    )
  ];

  for (
    const candidate of candidates
  ) {
    if (
      typeof candidate ===
        "string" &&
      candidate.trim()
    ) {
      return candidate
        .trim()
        .slice(0, 300);
    }
  }

  return "";
}

function getElementName(
  element
) {
  if (!element) {
    return "";
  }

  return String(
    element.getAttribute?.(
      "name"
    ) ||
      element.getAttribute?.(
        "id"
      ) ||
      ""
  ).slice(0, 300);
}

function getSafeControlMetadata(
  element
) {
  if (!element) {
    return null;
  }

  const metadata = {
    tagName: String(
      element.tagName || ""
    ).toLowerCase(),

    type: String(
      element.getAttribute?.(
        "type"
      ) || ""
    ).toLowerCase(),

    name: getElementName(
      element
    ),

    label: getElementLabel(
      element
    ),

    role: String(
      element.getAttribute?.(
        "role"
      ) || ""
    ).toLowerCase(),

    required: Boolean(
      element.required
    ),

    disabled: Boolean(
      element.disabled
    ),

    readOnly: Boolean(
      element.readOnly
    ),

    contentEditable:
      isContentEditableControl(
        element
      ),

    sensitiveMarked:
      isSensitiveMarkedControl(
        element
      )
  };

  return metadata;
}

function getFormMetadata(
  form
) {
  if (!form) {
    return null;
  }

  return {
    method: String(
      form.getAttribute?.(
        "method"
      ) || "get"
    ).toLowerCase(),

    action:
      getSafeFormAction(form),

    enctype: String(
      form.getAttribute?.(
        "enctype"
      ) || ""
    ).toLowerCase(),

    target: String(
      form.getAttribute?.(
        "target"
      ) || ""
    ).slice(0, 100),

    id: String(
      form.getAttribute?.(
        "id"
      ) || ""
    ).slice(0, 200),

    name: String(
      form.getAttribute?.(
        "name"
      ) || ""
    ).slice(0, 200)
  };
}

function getSafeFormAction(
  form
) {
  if (!form) {
    return "";
  }

  try {
    const action =
      form.getAttribute?.(
        "action"
      );

    if (!action) {
      return "";
    }

    /*
     * Do not expose query strings, fragments, or credentials.
     */
    const url = new URL(
      action,
      window.location.href
    );

    return `${url.protocol}//${url.host}${url.pathname}`.slice(
      0,
      1000
    );
  } catch {
    return "";
  }
}

function findParentForm(
  element
) {
  if (!element) {
    return null;
  }

  if (
    element instanceof
    HTMLFormElement
  ) {
    return element;
  }

  if (
    typeof element.closest ===
    "function"
  ) {
    const form =
      element.closest(
        FORM_SELECTOR
      );

    if (
      form instanceof
      HTMLFormElement
    ) {
      return form;
    }
  }

  return null;
}

function getSubmitter(
  event,
  form
) {
  if (
    event &&
    event.submitter &&
    isElement(event.submitter)
  ) {
    return event.submitter;
  }

  if (
    form &&
    form.__sanitizerProSubmitter &&
    isConnectedElement(
      form.__sanitizerProSubmitter
    )
  ) {
    return form.__sanitizerProSubmitter;
  }

  return null;
}

function rememberSubmitter(
  form,
  submitter
) {
  if (
    !form ||
    !submitter
  ) {
    return;
  }

  try {
    Object.defineProperty(
      form,
      "__sanitizerProSubmitter",
      {
        value: submitter,
        writable: true,
        configurable: true
      }
    );
  } catch {
    /*
     * Fallback if the page prevents defining the property.
     */
    try {
      form.__sanitizerProSubmitter =
        submitter;
    } catch {
      // Ignore.
    }
  }
}

function clearSubmitter(
  form
) {
  if (!form) {
    return;
  }

  try {
    delete form.__sanitizerProSubmitter;
  } catch {
    try {
      form.__sanitizerProSubmitter =
        null;
    } catch {
      // Ignore.
    }
  }
}

function getFormControls(
  form
) {
  if (!form) {
    return [];
  }

  try {
    return Array.from(
      form.elements || []
    );
  } catch (error) {
    handleError(
      error,
      "getFormControls"
    );

    return [];
  }
}

function shouldIncludeControl(
  control
) {
  if (!control) {
    return false;
  }

  if (
    !isTextControl(control)
  ) {
    return false;
  }

  if (
    isExcludedInputType(control)
  ) {
    return false;
  }

  if (
    isDisabledControl(control)
  ) {
    return false;
  }

  return true;
}

function getControlText(
  control
) {
  if (!control) {
    return "";
  }

  if (
    isContentEditableControl(
      control
    )
  ) {
    return String(
      control.innerText ||
      control.textContent ||
      ""
    );
  }

  if (
    control instanceof
    HTMLTextAreaElement
  ) {
    return String(
      control.value || ""
    );
  }

  if (
    control instanceof
    HTMLInputElement
  ) {
    return String(
      control.value || ""
    );
  }

  const value =
    control.value;

  if (
    typeof value ===
    "string"
  ) {
    return value;
  }

  return String(
    control.textContent || ""
  );
}

function normalizeFieldText(
  text
) {
  return String(
    text || ""
  )
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .trim();
}

function truncateText(
  text,
  maximum
) {
  const normalized =
    String(text || "");

  if (
    normalized.length <=
    maximum
  ) {
    return {
      text: normalized,
      truncated: false
    };
  }

  return {
    text:
      normalized.slice(
        0,
        maximum
      ),
    truncated: true
  };
}

function createFieldSnapshot(
  control,
  index
) {
  const rawText =
    getControlText(control);

  const normalizedText =
    normalizeFieldText(
      rawText
    );

  const truncated =
    truncateText(
      normalizedText,
      state.config
        .maximumTextPerField
    );

  return {
    index,

    metadata:
      getSafeControlMetadata(
        control
      ),

    /*
     * The actual value remains local.
     *
     * content.js/scanner.js consumes this object directly.
     */
    text:
      truncated.text,

    originalLength:
      normalizedText.length,

    truncated:
      truncated.truncated,

    empty:
      normalizedText.length === 0
  };
}

function collectFormFields(
  form
) {
  const controls =
    getFormControls(form);

  const fields = [];

  let totalTextLength = 0;

  for (
    const control of controls
  ) {
    if (
      fields.length >=
      state.config
        .maximumFieldsPerForm
    ) {
      break;
    }

    if (
      !shouldIncludeControl(
        control
      )
    ) {
      continue;
    }

    state.counters
      .textFieldsDetected += 1;

    const field =
      createFieldSnapshot(
        control,
        fields.length
      );

    if (
      field.empty &&
      !state.config
        .includeEmptyFields
    ) {
      continue;
    }

    if (
      field.truncated
    ) {
      state.counters
        .oversizedFields += 1;
    }

    totalTextLength +=
      field.text.length;

    fields.push(field);

    if (
      totalTextLength >=
      state.config
        .maximumTotalText
    ) {
      break;
    }
  }

  if (
    totalTextLength >
    state.config.maximumTotalText
  ) {
    state.counters
      .oversizedForms += 1;
  }

  /*
   * Enforce total form text limit.
   */
  let remaining =
    state.config
      .maximumTotalText;

  for (
    const field of fields
  ) {
    if (
      remaining <= 0
    ) {
      field.text = "";
      field.truncated = true;
      continue;
    }

    if (
      field.text.length >
      remaining
    ) {
      field.text =
        field.text.slice(
          0,
          remaining
        );

      field.truncated = true;
    }

    remaining -=
      field.text.length;
  }

  return fields;
}

function collectNonTextControls(
  form
) {
  if (
    !state.config
      .includeNonTextControls
  ) {
    return [];
  }

  const controls =
    getFormControls(form);

  const result = [];

  for (
    const control of controls
  ) {
    if (!control) {
      continue;
    }

    if (
      isTextControl(control)
    ) {
      continue;
    }

    if (
      isExcludedInputType(
        control
      )
    ) {
      continue;
    }

    if (
      isDisabledControl(
        control
      )
    ) {
      continue;
    }

    const metadata =
      getSafeControlMetadata(
        control
      );

    let value = "";

    if (
      control instanceof
      HTMLSelectElement
    ) {
      value =
        control.value || "";
    } else if (
      control instanceof
      HTMLInputElement
    ) {
      value =
        control.value || "";
    }

    result.push({
      metadata,
      value:
        String(value).slice(
          0,
          1000
        )
    });
  }

  return result;
}

function createSubmissionSnapshot(
  form,
  event,
  operationId
) {
  const fields =
    collectFormFields(form);

  const nonTextControls =
    collectNonTextControls(
      form
    );

  const totalTextLength =
    fields.reduce(
      (total, field) =>
        total + field.text.length,
      0
    );

  if (
    fields.length === 0
  ) {
    state.counters
      .emptySubmissions += 1;
  }

  return {
    operationId,

    sourceType:
      SOURCE_TYPES.SUBMIT,

    timestamp: now(),

    form:
      getFormMetadata(form),

    submitter:
      getSafeControlMetadata(
        getSubmitter(
          event,
          form
        )
      ),

    fields,

    nonTextControls,

    statistics: {
      fieldCount:
        fields.length,

      nonTextControlCount:
        nonTextControls.length,

      totalTextLength,

      hasTruncatedFields:
        fields.some(
          (field) =>
            field.truncated
        ),

      hasSensitiveMarkedFields:
        fields.some(
          (field) =>
            field.metadata
              ?.sensitiveMarked
        )
    }
  };
}

function hasSubmissionData(
  snapshot
) {
  if (!snapshot) {
    return false;
  }

  if (
    snapshot.fields?.some(
      (field) =>
        typeof field.text ===
          "string" &&
        field.text.length > 0
    )
  ) {
    return true;
  }

  if (
    snapshot.nonTextControls?.some(
      (control) =>
        typeof control.value ===
          "string" &&
        control.value.length > 0
    )
  ) {
    return true;
  }

  return false;
}

function getSubmissionText(
  snapshot
) {
  if (!snapshot) {
    return "";
  }

  return snapshot.fields
    .map(
      (field) =>
        field.text
    )
    .filter(Boolean)
    .join("\n");
}

function clearSensitiveSnapshotData(
  snapshot
) {
  if (!snapshot) {
    return;
  }

  if (
    Array.isArray(
      snapshot.fields
    )
  ) {
    for (
      const field of
        snapshot.fields
    ) {
      field.text = "";
    }
  }

  if (
    Array.isArray(
      snapshot.nonTextControls
    )
  ) {
    for (
      const control of
        snapshot.nonTextControls
    ) {
      control.value = "";
    }
  }
}

function getPendingOperation(
  form
) {
  return state.pendingOperations.get(
    form
  );
}

function setPendingOperation(
  form,
  operation
) {
  state.pendingOperations.set(
    form,
    operation
  );
}

function clearPendingOperation(
  form
) {
  state.pendingOperations.delete(
    form
  );
}

function isCurrentlyProcessing(
  form
) {
  return state.processingForms.has(
    form
  );
}

function markProcessing(
  form
) {
  state.processingForms.add(
    form
  );
}

function unmarkProcessing(
  form
) {
  state.processingForms.delete(
    form
  );
}

function isApprovedSubmission(
  form
) {
  return state.approvedSubmissions.has(
    form
  );
}

function markApprovedSubmission(
  form
) {
  state.approvedSubmissions.add(
    form
  );
}

function isProtectionEnabled() {
  if (
    !state.initialized ||
    state.destroyed
  ) {
    return false;
  }

  if (
    !state.config.enabled
  ) {
    return false;
  }

  if (
    state.config.mode ===
    "disabled"
  ) {
    return false;
  }

  if (
    !state.config.scanSubmit
  ) {
    return false;
  }

  return true;
}

function preventSubmission(
  event
) {
  try {
    event.preventDefault();
    event.stopImmediatePropagation();
  } catch (error) {
    handleError(
      error,
      "preventSubmission"
    );
  }
}

function getFormSubmissionMethod(
  form
) {
  if (!form) {
    return "get";
  }

  return String(
    form.getAttribute?.(
      "method"
    ) || "get"
  )
    .trim()
    .toLowerCase();
}

function isFormConnected(
  form
) {
  return (
    form instanceof
      HTMLFormElement &&
    isConnectedElement(form)
  );
}

async function invokeSubmitCallback(
  snapshot
) {
  if (
    typeof state.callbacks
      .onSubmit !==
    "function"
  ) {
    state.counters
      .scannerUnavailable += 1;

    return ACTIONS.BLOCK;
  }

  try {
    state.counters
      .fieldsScanned +=
      snapshot.fields.length;

    const result =
      await Promise.resolve(
        state.callbacks.onSubmit(
          snapshot
        )
      );

    return normalizeAction(
      result
    );
  } catch (error) {
    state.counters
      .scannerFailures += 1;

    handleError(
      error,
      "submitCallback"
    );

    return ACTIONS.BLOCK;
  }
}

async function invokeWarningCallback(
  snapshot
) {
  if (
    typeof state.callbacks
      .onWarning !==
    "function"
  ) {
    return ACTIONS.BLOCK;
  }

  try {
    const result =
      await Promise.resolve(
        state.callbacks.onWarning(
          snapshot
        )
      );

    return normalizeAction(
      result
    );
  } catch (error) {
    handleError(
      error,
      "submitWarningCallback"
    );

    return ACTIONS.BLOCK;
  }
}

function notifyAllowed(
  snapshot,
  reason = null
) {
  state.counters
    .allowedSubmissions += 1;

  const payload = {
    ...snapshot,
    action: ACTIONS.ALLOW,
    reason
  };

  /*
   * Raw field text is not passed to event consumers after the
   * decision. This prevents accidental logging/UI persistence.
   */
  clearSensitiveSnapshotData(
    payload
  );

  safeCallback(
    state.callbacks.onAllowed,
    payload
  );

  emitEvent(
    EVENT_TYPES.ACTION_ALLOWED,
    {
      operationId:
        snapshot.operationId,
      reason
    }
  );
}

function notifyBlocked(
  snapshot,
  reason
) {
  state.counters
    .blockedSubmissions += 1;

  const payload = {
    ...snapshot,
    action: ACTIONS.BLOCK,
    reason
  };

  clearSensitiveSnapshotData(
    payload
  );

  safeCallback(
    state.callbacks.onBlocked,
    payload
  );

  emitEvent(
    EVENT_TYPES.ACTION_BLOCKED,
    {
      operationId:
        snapshot.operationId,
      reason
    }
  );
}

function notifyMasked(
  snapshot,
  reason
) {
  state.counters
    .maskedSubmissions += 1;

  const payload = {
    ...snapshot,
    action: ACTIONS.MASK,
    reason
  };

  clearSensitiveSnapshotData(
    payload
  );

  safeCallback(
    state.callbacks.onMasked,
    payload
  );

  emitEvent(
    EVENT_TYPES.ACTION_MASKED,
    {
      operationId:
        snapshot.operationId,
      reason
    }
  );
}

function replaceControlText(
  control,
  text
) {
  if (!control) {
    return false;
  }

  try {
    if (
      isContentEditableControl(
        control
      )
    ) {
      control.textContent =
        text;

      control.dispatchEvent(
        new InputEvent(
          "input",
          {
            bubbles: true,
            inputType:
              "insertText",
            data: text
          }
        )
      );

      return true;
    }

    if (
      control instanceof
      HTMLTextAreaElement ||
      control instanceof
      HTMLInputElement
    ) {
      const prototype =
        control instanceof
        HTMLTextAreaElement
          ? HTMLTextAreaElement
              .prototype
          : HTMLInputElement
              .prototype;

      const descriptor =
        Object.getOwnPropertyDescriptor(
          prototype,
          "value"
        );

      if (
        descriptor?.set
      ) {
        descriptor.set.call(
          control,
          text
        );
      } else {
        control.value =
          text;
      }

      control.dispatchEvent(
        new Event(
          "input",
          {
            bubbles: true
          }
        )
      );

      return true;
    }

    if (
      "value" in control
    ) {
      control.value =
        text;

      control.dispatchEvent(
        new Event(
          "input",
          {
            bubbles: true
          }
        )
      );

      return true;
    }
  } catch (error) {
    handleError(
      error,
      "replaceControlText"
    );
  }

  return false;
}

function maskText(
  text
) {
  if (!text) {
    return "";
  }

  /*
   * This is only a conservative fallback.
   *
   * The real rule-specific masking engine will eventually replace
   * exact sensitive spans while preserving the surrounding content.
   */
  return String(text).replace(
    /\S+/g,
    "[REDACTED]"
  );
}

function maskSubmission(
  form,
  snapshot
) {
  if (!form || !snapshot) {
    return false;
  }

  let maskedAnything =
    false;

  const controls =
    getFormControls(form);

  for (
    const control of controls
  ) {
    if (
      !shouldIncludeControl(
        control
      )
    ) {
      continue;
    }

    const currentText =
      getControlText(control);

    if (!currentText) {
      continue;
    }

    const masked =
      maskText(currentText);

    if (
      masked === currentText
    ) {
      continue;
    }

    if (
      replaceControlText(
        control,
        masked
      )
    ) {
      maskedAnything = true;
    }
  }

  return maskedAnything;
}

async function continueApprovedSubmission(
  form,
  submitter
) {
  if (
    !isFormConnected(form)
  ) {
    return false;
  }

  try {
    markApprovedSubmission(
      form
    );

    /*
     * requestSubmit() preserves normal browser validation and submit
     * event behavior. The WeakSet guard lets the generated submit
     * event pass through exactly once.
     */
    if (
      typeof form.requestSubmit ===
      "function"
    ) {
      if (
        submitter &&
        submitter.form === form &&
        typeof submitter.click ===
          "function"
      ) {
        /*
         * Calling requestSubmit(submitter) is preferable to click(),
         * because click() can trigger application-level handlers
         * more than once in some SPA implementations.
         */
        form.requestSubmit(
          submitter
        );
      } else {
        form.requestSubmit();
      }

      return true;
    }

    /*
     * Legacy fallback.
     *
     * HTMLFormElement.prototype.submit() bypasses the submit event.
     * This is only used when requestSubmit() is unavailable.
     */
    const nativeSubmit =
      HTMLFormElement.prototype
        .submit;

    nativeSubmit.call(form);

    return true;
  } catch (error) {
    handleError(
      error,
      "continueApprovedSubmission"
    );

    return false;
  } finally {
    /*
     * requestSubmit() dispatches the submit event synchronously in
     * normal browser implementations, so this guard can be removed
     * after the call returns.
     */
    clearSubmitter(form);
  }
}

async function handleAllowedSubmission(
  form,
  snapshot,
  submitter,
  reason = null
) {
  notifyAllowed(
    snapshot,
    reason
  );

  const continued =
    await continueApprovedSubmission(
      form,
      submitter
    );

  if (!continued) {
    state.counters
      .blockedSubmissions += 1;

    emitEvent(
      EVENT_TYPES.ACTION_BLOCKED,
      {
        operationId:
          snapshot.operationId,
        reason:
          "approved_submission_failed"
      }
    );

    return ACTIONS.BLOCK;
  }

  return ACTIONS.ALLOW;
}

async function handleMaskedSubmission(
  form,
  snapshot,
  submitter,
  reason = null
) {
  const masked =
    maskSubmission(
      form,
      snapshot
    );

  if (!masked) {
    notifyBlocked(
      snapshot,
      "masking_failed"
    );

    return ACTIONS.BLOCK;
  }

  state.counters
    .maskedSubmissions += 1;

  notifyMasked(
    snapshot,
    reason || "policy_mask"
  );

  const continued =
    await continueApprovedSubmission(
      form,
      submitter
    );

  if (!continued) {
    state.counters
      .blockedSubmissions += 1;

    emitEvent(
      EVENT_TYPES.ACTION_BLOCKED,
      {
        operationId:
          snapshot.operationId,
        reason:
          "masked_submission_failed"
      }
    );

    return ACTIONS.BLOCK;
  }

  return ACTIONS.MASK;
}

async function evaluateSubmission(
  event,
  form
) {
  const operationId =
    createOperationId();

  const submitter =
    getSubmitter(
      event,
      form
    );

  const snapshot =
    createSubmissionSnapshot(
      form,
      event,
      operationId
    );

  const text =
    getSubmissionText(
      snapshot
    );

  emitEvent(
    EVENT_TYPES.SUBMIT_DETECTED,
    {
      operationId,

      form:
        snapshot.form,

      submitter:
        snapshot.submitter,

      fieldCount:
        snapshot.statistics
          .fieldCount,

      textLength:
        text.length
    }
  );

  if (
    !hasSubmissionData(
      snapshot
    )
  ) {
    /*
     * Empty forms do not contain sensitive payloads. Allow them to
     * proceed without invoking the scanner.
     */
    const result =
      await handleAllowedSubmission(
        form,
        snapshot,
        submitter,
        "empty_submission"
      );

    return result;
  }

  let decision =
    await invokeSubmitCallback(
      snapshot
    );

  decision =
    normalizeAction(
      decision
    );

  if (
    decision === ACTIONS.ALLOW
  ) {
    return handleAllowedSubmission(
      form,
      snapshot,
      submitter,
      "policy_allow"
    );
  }

  if (
    decision === ACTIONS.WARN
  ) {
    state.counters
      .warnedSubmissions += 1;

    const warningDecision =
      await invokeWarningCallback(
        snapshot
      );

    if (
      warningDecision ===
      ACTIONS.ALLOW
    ) {
      return handleAllowedSubmission(
        form,
        snapshot,
        submitter,
        "warning_approved"
      );
    }

    if (
      warningDecision ===
      ACTIONS.MASK
    ) {
      return handleMaskedSubmission(
        form,
        snapshot,
        submitter,
        "warning_mask"
      );
    }

    notifyBlocked(
      snapshot,
      "warning_rejected"
    );

    return ACTIONS.BLOCK;
  }

  if (
    decision === ACTIONS.MASK
  ) {
    return handleMaskedSubmission(
      form,
      snapshot,
      submitter,
      "policy_mask"
    );
  }

  notifyBlocked(
    snapshot,
    "policy_block"
  );

  return ACTIONS.BLOCK;
}

async function handleSubmitEvent(
  event
) {
  if (
    !isProtectionEnabled()
  ) {
    return;
  }

  const form =
    event?.target;

  if (
    !(form instanceof
      HTMLFormElement)
  ) {
    return;
  }

  state.counters
    .submitEvents += 1;

  /*
   * This is the second submit generated by our own approved
   * requestSubmit() call. Allow it to proceed.
   */
  if (
    isApprovedSubmission(form)
  ) {
    state.counters
      .recursiveSubmissions += 1;

    return;
  }

  /*
   * Prevent duplicate concurrent scans of the same form.
   */
  if (
    isCurrentlyProcessing(form)
  ) {
    state.counters
      .duplicateSubmissions += 1;

    preventSubmission(event);

    emitEvent(
      EVENT_TYPES.ACTION_BLOCKED,
      {
        reason:
          "submission_already_processing"
      }
    );

    return;
  }

  const pending =
    getPendingOperation(form);

  if (pending) {
    state.counters
      .duplicateSubmissions += 1;

    preventSubmission(event);

    return;
  }

  state.counters
    .submitAttempts += 1;

  const submitter =
    getSubmitter(
      event,
      form
    );

  rememberSubmitter(
    form,
    submitter
  );

  /*
   * Stop the browser's normal form submission until local policy
   * evaluation has completed.
   */
  preventSubmission(event);

  const operation = {
    operationId:
      createOperationId(),

    startedAt: now()
  };

  setPendingOperation(
    form,
    operation
  );

  markProcessing(form);

  try {
    const result =
      await evaluateSubmission(
        event,
        form
      );

    return result;
  } catch (error) {
    state.counters
      .scannerFailures += 1;

    handleError(
      error,
      "handleSubmitEvent"
    );

    notifyBlocked(
      {
        operationId:
          operation.operationId,
        form:
          getFormMetadata(form),
        fields: []
      },
      "unexpected_submission_error"
    );

    return ACTIONS.BLOCK;
  } finally {
    clearPendingOperation(
      form
    );

    unmarkProcessing(form);

    clearSubmitter(form);
  }
}

function handleSubmitControlClick(
  event
) {
  if (
    !state.initialized ||
    state.destroyed
  ) {
    return;
  }

  const target =
    event?.target;

  if (
    !target ||
    !isElement(target)
  ) {
    return;
  }

  const control =
    target.closest?.(
      SUBMIT_CONTROL_SELECTOR
    );

  if (!control) {
    return;
  }

  const form =
    findParentForm(control);

  if (!form) {
    return;
  }

  rememberSubmitter(
    form,
    control
  );
}

function handleKeyDown(
  event
) {
  if (
    !state.initialized ||
    state.destroyed
  ) {
    return;
  }

  if (
    event?.key !== "Enter"
  ) {
    return;
  }

  const target =
    event?.target;

  if (
    !target ||
    !isElement(target)
  ) {
    return;
  }

  if (
    !isTextControl(target)
  ) {
    return;
  }

  const form =
    findParentForm(target);

  if (!form) {
    return;
  }

  /*
   * We intentionally do not prevent Enter here.
   *
   * The browser's resulting submit event is the authoritative
   * boundary and will be intercepted by handleSubmitEvent().
   */
}

function trackForm(form) {
  if (
    !(form instanceof
      HTMLFormElement)
  ) {
    return false;
  }

  if (
    state.trackedForms.has(form)
  ) {
    return true;
  }

  state.trackedForms.add(form);

  state.counters
    .formsTracked += 1;

  return true;
}

function scanExistingForms() {
  if (
    typeof document ===
    "undefined"
  ) {
    return;
  }

  const forms =
    document.querySelectorAll(
      FORM_SELECTOR
    );

  for (
    const form of forms
  ) {
    trackForm(form);
  }

  state.counters
    .formsDetected =
    forms.length;
}

function handleMutationRecords(
  records
) {
  for (
    const record of records
  ) {
    if (
      record.type !==
      "childList"
    ) {
      continue;
    }

    for (
      const node of
        record.addedNodes
    ) {
      if (
        !isElement(node)
      ) {
        continue;
      }

      if (
        node instanceof
        HTMLFormElement
      ) {
        trackForm(node);
      }

      if (
        typeof node.querySelectorAll ===
        "function"
      ) {
        const forms =
          node.querySelectorAll(
            FORM_SELECTOR
          );

        for (
          const form of forms
        ) {
          trackForm(form);
        }
      }
    }
  }

  cleanupDisconnectedForms();
}

function cleanupDisconnectedForms() {
  for (
    const form of
      state.trackedForms
  ) {
    if (
      !isConnectedElement(
        form
      )
    ) {
      state.trackedForms.delete(
        form
      );
    }
  }
}

function installMutationObserver() {
  if (
    typeof MutationObserver ===
      "undefined" ||
    !document.documentElement
  ) {
    return;
  }

  const observer =
    new MutationObserver(
      handleMutationRecords
    );

  observer.observe(
    document.documentElement,
    {
      childList: true,
      subtree: true
    }
  );

  state.listeners.push({
    target: observer,
    observer: true
  });
}

function addListener(
  target,
  eventName,
  handler,
  options = true
) {
  if (
    !target ||
    typeof target.addEventListener !==
      "function"
  ) {
    return;
  }

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

function installListeners() {
  removeListeners();

  if (
    typeof document ===
    "undefined"
  ) {
    return;
  }

  /*
   * Capture phase is intentional.
   *
   * Many modern AI/search applications attach their own handlers
   * to forms and controls. Capturing lets SanitizerPro establish
   * its protection boundary before ordinary bubbling handlers.
   */
  addListener(
    document,
    "submit",
    handleSubmitEvent,
    true
  );

  addListener(
    document,
    "click",
    handleSubmitControlClick,
    true
  );

  addListener(
    document,
    "keydown",
    handleKeyDown,
    true
  );

  installMutationObserver();
}

function removeListeners() {
  for (
    const listener of
      state.listeners
  ) {
    try {
      if (
        listener.observer &&
        listener.target
      ) {
        listener.target.disconnect();
        continue;
      }

      listener.target.removeEventListener(
        listener.eventName,
        listener.handler,
        listener.options
      );
    } catch {
      /*
       * Ignore cleanup failures.
       */
    }
  }

  state.listeners = [];
}

function mergeConfig(
  config = {}
) {
  if (
    !isObject(config)
  ) {
    return;
  }

  if (
    typeof config.enabled ===
    "boolean"
  ) {
    state.config.enabled =
      config.enabled;
  }

  if (
    typeof config.scanSubmit ===
    "boolean"
  ) {
    state.config.scanSubmit =
      config.scanSubmit;
  }

  if (
    typeof config.mode ===
    "string"
  ) {
    state.config.mode =
      config.mode;
  }

  if (
    typeof config.defaultAction ===
    "string"
  ) {
    state.config.defaultAction =
      normalizeAction(
        config.defaultAction
      );
  }

  if (
    typeof config.includeEmptyFields ===
    "boolean"
  ) {
    state.config
      .includeEmptyFields =
      config.includeEmptyFields;
  }

  if (
    typeof config.includeNonTextControls ===
    "boolean"
  ) {
    state.config
      .includeNonTextControls =
      config.includeNonTextControls;
  }

  if (
    Number.isFinite(
      Number(
        config.maximumFieldsPerForm
      )
    )
  ) {
    state.config
      .maximumFieldsPerForm =
      Math.max(
        1,
        Math.min(
          500,
          Number(
            config.maximumFieldsPerForm
          )
        )
      );
  }

  if (
    Number.isFinite(
      Number(
        config.maximumTextPerField
      )
    )
  ) {
    state.config
      .maximumTextPerField =
      Math.max(
        1,
        Math.min(
          SCAN_LIMITS.maxTextCharacters,
          Number(
            config.maximumTextPerField
          )
        )
      );
  }

  if (
    Number.isFinite(
      Number(
        config.maximumTotalText
      )
    )
  ) {
    state.config
      .maximumTotalText =
      Math.max(
        1,
        Math.min(
          SCAN_LIMITS.maxTextCharacters,
          Number(
            config.maximumTotalText
          )
        )
      );
  }
}

function setCallbacks(
  callbacks = {}
) {
  if (
    !isObject(callbacks)
  ) {
    return;
  }

  const callbackNames = [
    "onSubmit",
    "onWarning",
    "onAllowed",
    "onBlocked",
    "onMasked",
    "onError",
    "onEvent"
  ];

  for (
    const callbackName of
      callbackNames
  ) {
    if (
      callbacks[callbackName] ===
        null ||
      typeof callbacks[callbackName] ===
        "function"
    ) {
      state.callbacks[
        callbackName
      ] =
        callbacks[
          callbackName
        ];
    }
  }
}

function initialize(
  options = {}
) {
  if (
    state.initialized &&
    !state.destroyed
  ) {
    if (options.config) {
      mergeConfig(
        options.config
      );
    }

    if (options.callbacks) {
      setCallbacks(
        options.callbacks
      );
    }

    scanExistingForms();

    return getSubmitMonitorDiagnostics();
  }

  state.destroyed = false;

  mergeConfig(
    options.config || {}
  );

  setCallbacks(
    options.callbacks || {}
  );

  installListeners();

  state.initialized = true;

  scanExistingForms();

  emitEvent(
    EVENT_TYPES.CONTENT_READY,
    {
      component:
        "submit-monitor"
    }
  );

  return getSubmitMonitorDiagnostics();
}

function destroy() {
  removeListeners();

  state.trackedForms.clear();

  state.initialized = false;
  state.destroyed = true;

  for (
    const callbackName of
      Object.keys(
        state.callbacks
      )
  ) {
    state.callbacks[
      callbackName
    ] = null;
  }
}

function updateConfig(
  config = {}
) {
  mergeConfig(config);

  if (
    state.initialized &&
    !state.destroyed
  ) {
    installListeners();
    scanExistingForms();
  }

  return getSubmitMonitorDiagnostics();
}

function getSubmitMonitorConfig() {
  return {
    enabled:
      state.config.enabled,

    scanSubmit:
      state.config.scanSubmit,

    mode:
      state.config.mode,

    defaultAction:
      state.config.defaultAction,

    includeEmptyFields:
      state.config
        .includeEmptyFields,

    includeNonTextControls:
      state.config
        .includeNonTextControls,

    maximumFieldsPerForm:
      state.config
        .maximumFieldsPerForm,

    maximumTextPerField:
      state.config
        .maximumTextPerField,

    maximumTotalText:
      state.config
        .maximumTotalText
  };
}

function getSubmitMonitorDiagnostics() {
  return {
    initialized:
      state.initialized,

    destroyed:
      state.destroyed,

    trackedForms:
      state.trackedForms.size,

    processingForms:
      countProcessingForms(),

    config:
      getSubmitMonitorConfig(),

    counters: {
      ...state.counters
    },

    listeners:
      state.listeners.length,

    callbacks: {
      onSubmit:
        typeof state.callbacks
          .onSubmit ===
        "function",

      onWarning:
        typeof state.callbacks
          .onWarning ===
        "function",

      onAllowed:
        typeof state.callbacks
          .onAllowed ===
        "function",

      onBlocked:
        typeof state.callbacks
          .onBlocked ===
        "function",

      onMasked:
        typeof state.callbacks
          .onMasked ===
        "function",

      onError:
        typeof state.callbacks
          .onError ===
        "function",

      onEvent:
        typeof state.callbacks
          .onEvent ===
        "function"
    }
  };
}

function countProcessingForms() {
  let count = 0;

  for (
    const form of
      state.trackedForms
  ) {
    if (
      state.processingForms.has(
        form
      )
    ) {
      count += 1;
    }
  }

  return count;
}

function getTrackedForms() {
  return Array.from(
    state.trackedForms
  ).filter(
    isConnectedElement
  );
}

function getFormSnapshot(
  form
) {
  if (
    !(form instanceof
      HTMLFormElement)
  ) {
    return null;
  }

  return createSubmissionSnapshot(
    form,
    null,
    createOperationId()
  );
}

function isSubmitMonitorInitialized() {
  return (
    state.initialized &&
    !state.destroyed
  );
}

function isFormBeingProcessed(
  form
) {
  if (!form) {
    return false;
  }

  return isCurrentlyProcessing(
    form
  );
}

function getPendingSubmission(
  form
) {
  if (!form) {
    return null;
  }

  return (
    getPendingOperation(
      form
    ) || null
  );
}

function clearPendingSubmission(
  form
) {
  if (!form) {
    return;
  }

  clearPendingOperation(
    form
  );

  unmarkProcessing(form);
}

function getSubmitCapabilities() {
  return {
    formSubmitInterception:
      true,

    dynamicFormMonitoring:
      true,

    submitterTracking:
      true,

    enterKeyAwareness:
      true,

    localFormSnapshot:
      true,

    localPolicyEvaluation:
      true,

    sensitiveDataToBackground:
      false,

    persistentSubmissionStorage:
      false,

    networkSubmissionScanning:
      false,

    fileScanning:
      false,

    fileMasking:
      false
  };
}

export {
  initialize,
  destroy,
  updateConfig,
  setCallbacks,

  getSubmitMonitorConfig,
  getSubmitMonitorDiagnostics,
  getSubmitCapabilities,

  getTrackedForms,
  getFormSnapshot,

  isSubmitMonitorInitialized,
  isFormBeingProcessed,

  getPendingSubmission,
  clearPendingSubmission,

  collectFormFields,
  getSubmissionText,
  hasSubmissionData,

  getSafeControlMetadata,
  getFormMetadata,

  findParentForm,
  getSubmitter,

  isTextControl,
  isContentEditableControl,
  isSensitiveMarkedControl
};
